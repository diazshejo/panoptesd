//! Definicion de tipos de anomalia y evaluacion de reglas contra el estado
//! de un proceso. Se usa un enum con dispatch estatico (match) en vez de
//! `Vec<Box<dyn Rule>>`: evita allocaciones en el heap y la indireccion de
//! vtable en un camino que se ejecuta por cada proceso, en cada tick.

use crate::config::Config;
use crate::process::ProcessState;
use std::fs;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnomalyKind {
    CpuSustained,
    MemoryOutOfRange,
    RootNotWhitelisted,
    EphemeralProcess,
    NewListenPort,
    UnexpectedOutboundConnection,
    /// No es una anomalia real: la auditoria de rutina que dispara el
    /// scheduler semanal de Telegram. Comparte el mismo tipo para poder
    /// viajar por el mismo `TriggerJob`/pool de workers/historial que las
    /// anomalias de verdad, pero se excluye explicitamente de los conteos
    /// de "anomalias detectadas" en los reportes.
    ScheduledAudit,
}

impl AnomalyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyKind::CpuSustained => "cpu_sustained",
            AnomalyKind::MemoryOutOfRange => "memory_out_of_range",
            AnomalyKind::RootNotWhitelisted => "root_not_whitelisted",
            AnomalyKind::EphemeralProcess => "ephemeral_process",
            AnomalyKind::NewListenPort => "nuevo_puerto_listen",
            AnomalyKind::UnexpectedOutboundConnection => "conexion_saliente_no_esperada",
            AnomalyKind::ScheduledAudit => "scheduled_weekly_audit",
        }
    }

    /// False para `ScheduledAudit`: es mantenimiento de rutina, no una
    /// deteccion. Los reportes de status/resumen usan esto para no contar
    /// la auditoria programada como si fuera una anomalia.
    pub fn is_real_anomaly(&self) -> bool {
        !matches!(self, AnomalyKind::ScheduledAudit)
    }
}

pub struct AnomalyEvent {
    pub kind: AnomalyKind,
    pub detail: String,
}

/// Evalua las reglas de CPU/memoria/root-whitelist para un proceso ya
/// actualizado en el tick actual. Las reglas de proceso efimero y red se
/// evaluan aparte (necesitan contexto adicional: desaparicion de PID y
/// tabla de conexiones, respectivamente).
pub fn evaluate(config: &Config, pid: i32, state: &mut ProcessState, now: Instant) -> Vec<AnomalyEvent> {
    let mut events = Vec::new();

    let cpu_cfg = &config.rules.cpu;
    if cpu_cfg.enabled {
        if state.cpu_percent >= cpu_cfg.threshold_percent {
            let since = *state.cpu_over_since.get_or_insert(now);
            let sustained = now.duration_since(since).as_secs();
            if sustained >= cpu_cfg.sustained_secs {
                events.push(AnomalyEvent {
                    kind: AnomalyKind::CpuSustained,
                    detail: format!(
                        "cpu={:.1}% sostenido {}s (umbral {:.1}% / {}s)",
                        state.cpu_percent, sustained, cpu_cfg.threshold_percent, cpu_cfg.sustained_secs
                    ),
                });
            }
        } else {
            state.cpu_over_since = None;
        }
    }

    let mem_cfg = &config.rules.memory;
    if mem_cfg.enabled {
        let max_bytes = mem_cfg.max_rss_mb * 1024 * 1024;
        if state.rss_bytes > max_bytes {
            events.push(AnomalyEvent {
                kind: AnomalyKind::MemoryOutOfRange,
                detail: format!(
                    "rss={}MB excede maximo {}MB",
                    state.rss_bytes / 1024 / 1024,
                    mem_cfg.max_rss_mb
                ),
            });
        }
    }

    let root_cfg = &config.rules.root_whitelist;
    if root_cfg.enabled && state.uid == 0 && !is_kernel_thread(pid, state.ppid) {
        let allowed = root_cfg
            .allowed_names
            .iter()
            .any(|n| n == &state.comm);
        if !allowed {
            events.push(AnomalyEvent {
                kind: AnomalyKind::RootNotWhitelisted,
                detail: format!("proceso '{}' corre como root y no esta en la whitelist", state.comm),
            });
        }
    }

    events
}

/// True si `pid` es un kernel thread (no un proceso de usuario real
/// corriendo como root): o es hijo directo de `kthreadd` (PPID 2), o no
/// tiene un binario real detras (`/proc/<pid>/exe` no resuelve). Los
/// kernel threads tienen nombres dinamicos (`kworker/*`, `irq/*`,
/// `card1-crtc*`, etc.) que no se pueden whitelistear uno por uno, asi que
/// se excluyen de `root_not_whitelisted` antes de mirar el nombre.
///
/// El chequeo de PPID no cuesta una lectura extra (ya viene del mismo
/// parseo de `/proc/<pid>/stat` que da uid/cpu/rss); el de `exe` si la
/// necesita, pero con corto circuito: solo se llama si el PPID no fue
/// suficiente para descartarlo, y solo se invoca para procesos root (este
/// chequeo vive detras de `state.uid == 0` en `evaluate`).
fn is_kernel_thread(pid: i32, ppid: i32) -> bool {
    const KTHREADD_PID: i32 = 2;
    if ppid == KTHREADD_PID {
        return true;
    }
    !has_real_exe(pid)
}

/// True si `/proc/<pid>/exe` resuelve a un binario real. Los kernel
/// threads no tienen ejecutable de usuario detras: el symlink no existe o
/// falla con ENOENT/EACCES segun el kernel. Un target que contenga
/// "(deleted)" (binario borrado del disco despues de ejecutarse) tampoco
/// cuenta como un binario real vigente.
fn has_real_exe(pid: i32) -> bool {
    match fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(target) => !target.to_string_lossy().contains("(deleted)"),
        Err(_) => false,
    }
}

/// Evalua la regla de proceso efimero cuando un PID que estaba siendo
/// trackeado desaparece de /proc. Se llama con el ultimo estado conocido.
pub fn evaluate_ephemeral(config: &Config, state: &ProcessState, now: Instant) -> Option<AnomalyEvent> {
    let cfg = &config.rules.ephemeral;
    if !cfg.enabled {
        return None;
    }
    let lifetime = now.duration_since(state.first_seen).as_secs();
    if lifetime < cfg.max_lifetime_secs {
        Some(AnomalyEvent {
            kind: AnomalyKind::EphemeralProcess,
            detail: format!(
                "proceso vivio {}s (umbral {}s) — posible malware/cryptominer efimero",
                lifetime, cfg.max_lifetime_secs
            ),
        })
    } else {
        None
    }
}

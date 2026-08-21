//! Definicion de tipos de anomalia y evaluacion de reglas contra el estado
//! de un proceso. Se usa un enum con dispatch estatico (match) en vez de
//! `Vec<Box<dyn Rule>>`: evita allocaciones en el heap y la indireccion de
//! vtable en un camino que se ejecuta por cada proceso, en cada tick.

use crate::config::Config;
use crate::process::ProcessState;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnomalyKind {
    CpuSustained,
    MemoryOutOfRange,
    RootNotWhitelisted,
    EphemeralProcess,
    UnexpectedNetwork,
}

impl AnomalyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyKind::CpuSustained => "cpu_sustained",
            AnomalyKind::MemoryOutOfRange => "memory_out_of_range",
            AnomalyKind::RootNotWhitelisted => "root_not_whitelisted",
            AnomalyKind::EphemeralProcess => "ephemeral_process",
            AnomalyKind::UnexpectedNetwork => "unexpected_network",
        }
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
pub fn evaluate(config: &Config, state: &mut ProcessState, now: Instant) -> Vec<AnomalyEvent> {
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
    if root_cfg.enabled && state.uid == 0 {
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

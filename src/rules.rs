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
    HostMemoryPressure,
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
            AnomalyKind::HostMemoryPressure => "host_memory_pressure",
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
pub fn evaluate(
    config: &Config,
    _pid: i32,
    state: &mut ProcessState,
    now: Instant,
) -> Vec<AnomalyEvent> {
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
                        state.cpu_percent,
                        sustained,
                        cpu_cfg.threshold_percent,
                        cpu_cfg.sustained_secs
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
    if root_cfg.enabled && state.uid == 0 && !is_kernel_thread(state.flags) && !state.is_audit {
        let allowed = root_cfg.allowed_names.iter().any(|n| n == &state.comm);
        if !allowed {
            events.push(AnomalyEvent {
                kind: AnomalyKind::RootNotWhitelisted,
                detail: format!(
                    "proceso '{}' corre como root y no esta en la whitelist",
                    state.comm
                ),
            });
        }
    }

    events
}

/// PF_KTHREAD: no confundir exe inaccesible o borrado con un hilo del kernel.
fn is_kernel_thread(flags: u64) -> bool {
    flags & 0x0020_0000 != 0
}

/// Evalua la regla de proceso efimero cuando un PID que estaba siendo
/// trackeado desaparece de /proc. Se llama con el ultimo estado conocido.
pub fn evaluate_ephemeral(
    config: &Config,
    state: &ProcessState,
    now: Instant,
) -> Option<AnomalyEvent> {
    let cfg = &config.rules.ephemeral;
    if !cfg.enabled || state.is_audit {
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

/// Una lectura ausente corta la continuidad: no se inventa presion durante huecos.
#[derive(Default)]
pub struct HostMemoryTracker {
    low_since: Option<Instant>,
}

impl HostMemoryTracker {
    pub fn evaluate(
        &mut self,
        cfg: &crate::config::HostMemoryConfig,
        sample: Option<(u64, u64)>,
        now: Instant,
    ) -> Option<AnomalyEvent> {
        let Some((total, available)) = sample.filter(|(t, a)| *t > 0 && a <= t) else {
            self.low_since = None;
            return None;
        };
        let percent = available as f64 * 100.0 / total as f64;
        let low = available < cfg.min_available_mb * 1024 || percent < cfg.min_available_percent;
        if !cfg.enabled || !low {
            self.low_since = None;
            return None;
        }
        let since = *self.low_since.get_or_insert(now);
        if now.duration_since(since).as_secs() < cfg.sustained_secs {
            return None;
        }
        Some(AnomalyEvent {
            kind: AnomalyKind::HostMemoryPressure,
            detail: format!(
                "MemAvailable={}MiB / {}MiB ({:.1}%) durante {}s; umbrales <{}MiB o <{:.1}%",
                available / 1024,
                total / 1024,
                percent,
                now.duration_since(since).as_secs(),
                cfg.min_available_mb,
                cfg.min_available_percent
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{config, state};
    use std::time::Duration;

    #[test]
    fn unexpected_root_including_deleted_or_unreadable_exe_still_alerts() {
        let cfg = config();
        let now = Instant::now();
        let mut s = state("sh", "/tmp/sh (deleted)", 1, 42, now);
        for exe in [Some("/tmp/sh (deleted)".into()), None] {
            s.exe = exe;
            assert!(evaluate(&cfg, 1234, &mut s, now)
                .iter()
                .any(|e| e.kind == AnomalyKind::RootNotWhitelisted));
        }
        s.flags = 0x0020_0000;
        assert!(!evaluate(&cfg, 1234, &mut s, now)
            .iter()
            .any(|e| e.kind == AnomalyKind::RootNotWhitelisted));
    }

    #[test]
    fn own_audit_children_do_not_recurse_but_memory_and_cpu_remain_covered() {
        let mut cfg = config();
        cfg.rules.cpu.sustained_secs = 0;
        let now = Instant::now();
        for name in ["sh", "grep", "find", "python3"] {
            let mut s = state(name, &format!("/usr/bin/{name}"), 5, 42, now);
            s.is_audit = true;
            s.rss_bytes = (cfg.rules.memory.max_rss_mb + 1) * 1048576;
            s.cpu_percent = 200.0;
            let kinds: Vec<_> = evaluate(&cfg, 1234, &mut s, now)
                .into_iter()
                .map(|e| e.kind)
                .collect();
            assert_eq!(
                kinds,
                [AnomalyKind::CpuSustained, AnomalyKind::MemoryOutOfRange]
            );
            assert!(evaluate_ephemeral(&cfg, &s, now).is_none());
            s.is_audit = false;
            assert!(evaluate(&cfg, 1234, &mut s, now)
                .iter()
                .any(|e| e.kind == AnomalyKind::RootNotWhitelisted));
        }
    }

    #[test]
    fn rss_threshold_is_configurable_and_independent_of_root() {
        let mut cfg = config();
        let now = Instant::now();
        let mut s = state("polybot", "/opt/polybot", 1, 42, now);
        s.uid = 1000;
        cfg.rules.memory.max_rss_mb = 512;
        s.rss_bytes = 512 * 1048576;
        assert!(evaluate(&cfg, 42, &mut s, now).is_empty());
        s.rss_bytes += 1;
        assert_eq!(
            evaluate(&cfg, 42, &mut s, now)[0].kind,
            AnomalyKind::MemoryOutOfRange
        );
        cfg.rules.memory.max_rss_mb = 1024;
        assert!(evaluate(&cfg, 42, &mut s, now).is_empty());
    }

    #[test]
    fn host_memory_requires_continuity_and_recovers() {
        let cfg = crate::config::HostMemoryConfig {
            enabled: true,
            min_available_mb: 256,
            min_available_percent: 15.0,
            sustained_secs: 10,
        };
        let mut tracker = HostMemoryTracker::default();
        let t = Instant::now();
        let low = Some((2048 * 1024, 200 * 1024));
        assert!(tracker.evaluate(&cfg, low, t).is_none());
        assert!(tracker
            .evaluate(&cfg, low, t + Duration::from_secs(9))
            .is_none());
        assert_eq!(
            tracker
                .evaluate(&cfg, low, t + Duration::from_secs(10))
                .unwrap()
                .kind,
            AnomalyKind::HostMemoryPressure
        );
        assert!(tracker
            .evaluate(
                &cfg,
                Some((2048 * 1024, 1024 * 1024)),
                t + Duration::from_secs(11)
            )
            .is_none());
        assert!(tracker
            .evaluate(&cfg, low, t + Duration::from_secs(12))
            .is_none());
        assert!(tracker
            .evaluate(&cfg, None, t + Duration::from_secs(20))
            .is_none());
        assert!(tracker
            .evaluate(&cfg, low, t + Duration::from_secs(23))
            .is_none());
    }

    #[test]
    fn host_absolute_and_relative_thresholds_are_independent() {
        let mut cfg = crate::config::HostMemoryConfig {
            sustained_secs: 0,
            ..Default::default()
        };
        let mut tracker = HostMemoryTracker::default();
        let t = Instant::now();
        assert!(tracker
            .evaluate(&cfg, Some((8192 * 1024, 512 * 1024)), t)
            .is_some()); // porcentaje
        cfg.min_available_percent = 0.0;
        assert!(tracker
            .evaluate(&cfg, Some((8192 * 1024, 512 * 1024)), t)
            .is_none());
        assert!(tracker
            .evaluate(&cfg, Some((512 * 1024, 200 * 1024)), t)
            .is_some()); // absoluto
        assert!(tracker
            .evaluate(&cfg, Some((512 * 1024, 256 * 1024)), t)
            .is_none());
        assert!(tracker.evaluate(&cfg, Some((0, 0)), t).is_none());
        cfg.enabled = false;
        assert!(tracker.evaluate(&cfg, Some((512 * 1024, 1)), t).is_none());
    }
}

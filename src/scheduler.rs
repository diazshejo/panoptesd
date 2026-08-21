//! Dos hilos nativos, independientes del loop de monitoreo: uno manda el
//! status del servidor cada `status_interval_hours`, el otro dispara una
//! auditoria de rutina y el resumen semanal en el dia/hora configurados.
//! Ninguno usa tokio ni un scheduler de cron externo: ambos son
//! "calcular cuanto falta, dormir interrumpible, actuar, repetir".

use crate::config::Config;
use crate::history::AuditHistory;
use crate::hoststats;
use crate::rules::AnomalyKind;
use crate::signals;
use crate::telegram::{self, TelegramClient};
use crate::timefmt;
use crate::trigger::TriggerJob;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub fn spawn_status_scheduler(
    config: Arc<Config>,
    shutdown: Arc<AtomicBool>,
    telegram: Arc<TelegramClient>,
    history: Arc<AuditHistory>,
    watched_count: Arc<AtomicUsize>,
    daemon_start: Instant,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("status-scheduler".to_string())
        .spawn(move || {
            let interval = Duration::from_secs(config.telegram.status_interval_hours.max(1) * 3600);
            while !shutdown.load(Ordering::Relaxed) {
                signals::sleep_interruptible(interval, &shutdown);
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                send_status_report(&config, &telegram, &history, &watched_count, daemon_start);
            }
        })
        .expect("no se pudo lanzar el scheduler de status")
}

fn send_status_report(
    config: &Config,
    telegram: &TelegramClient,
    history: &AuditHistory,
    watched_count: &AtomicUsize,
    daemon_start: Instant,
) {
    let now = timefmt::unix_now();
    let cutoff_12h = now.saturating_sub(12 * 3600);

    let system_uptime = hoststats::system_uptime_secs()
        .map(hoststats::format_uptime)
        .unwrap_or_else(|| "desconocido".to_string());
    let cpu = hoststats::cpu_percent(Duration::from_secs(1));
    let (mem_total, mem_avail) = match hoststats::mem_total_available_kb() {
        Some((t, a)) => (Some(t), Some(a)),
        None => (None, None),
    };
    let disks: Vec<hoststats::DiskUsage> = config
        .telegram
        .disk_paths
        .iter()
        .filter_map(|p| hoststats::disk_usage(p))
        .collect();
    let daemon_uptime = hoststats::format_uptime(daemon_start.elapsed().as_secs());
    let last_anomaly = history.last_real_anomaly();

    let text = telegram::format_status_report(
        &timefmt::format_utc(now),
        &system_uptime,
        cpu,
        mem_total,
        mem_avail,
        &disks,
        watched_count.load(Ordering::Relaxed),
        history.count_real_anomalies_since(cutoff_12h),
        env!("CARGO_PKG_VERSION"),
        &daemon_uptime,
        last_anomaly.as_ref(),
    );

    if let Err(e) = telegram.send(&text) {
        tracing::error!(error = %e, "no se pudo enviar reporte de status a Telegram");
    }
}

pub fn spawn_weekly_scheduler(
    config: Arc<Config>,
    shutdown: Arc<AtomicBool>,
    telegram: Arc<TelegramClient>,
    history: Arc<AuditHistory>,
    tx: SyncSender<TriggerJob>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("weekly-scheduler".to_string())
        .spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                let wait = seconds_until_next_weekly(&config);
                signals::sleep_interruptible(Duration::from_secs(wait), &shutdown);
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                run_weekly(&telegram, &history, &tx, &shutdown);
            }
        })
        .expect("no se pudo lanzar el scheduler semanal")
}

/// Segundos hasta la proxima ocurrencia de (weekly_summary_day,
/// weekly_summary_hour) en UTC. Aritmetica simple sobre segundos-desde-
/// epoch, sin libreria de calendario: no hace falta mas que esto para
/// "el proximo domingo a las 23:00".
fn seconds_until_next_weekly(config: &Config) -> u64 {
    let now = timefmt::unix_now();
    let (cur_wday, cur_hour) = timefmt::weekday_and_hour(now);
    let target_wday = config.telegram.weekly_summary_weekday();
    let target_hour = config.telegram.weekly_summary_hour as i32;

    let mut days_ahead = (target_wday - cur_wday + 7) % 7;
    if days_ahead == 0 && cur_hour >= target_hour {
        days_ahead = 7;
    }

    let seconds_since_midnight = now % 86400;
    let today_midnight = now - seconds_since_midnight;
    let target_unix = today_midnight + days_ahead as u64 * 86400 + target_hour as u64 * 3600;

    target_unix.saturating_sub(now).max(1)
}

fn run_weekly(telegram: &TelegramClient, history: &AuditHistory, tx: &SyncSender<TriggerJob>, shutdown: &AtomicBool) {
    let job = TriggerJob {
        pid: 0,
        name: "system".to_string(),
        user: "system".to_string(),
        kind: AnomalyKind::ScheduledAudit,
        detail: "Chequeo de rutina programado (semanal)".to_string(),
    };

    // Send (no try_send): este hilo no tiene apuro, preferimos esperar
    // lugar en la cola antes que perder la auditoria semanal.
    if tx.send(job).is_err() {
        tracing::error!("no se pudo encolar la auditoria semanal: pool de workers cerrado");
    } else {
        // Margen para que el worker corra el script antes de armar el
        // resumen (tipicamente termina en <1s; ver scripts/auditoria.sh).
        // Si no llega a tiempo, simplemente aparece en el resumen de la
        // semana siguiente: no es critico para un reporte periodico.
        signals::sleep_interruptible(Duration::from_secs(5), shutdown);
    }

    let now = timefmt::unix_now();
    let week_ago = now.saturating_sub(7 * 24 * 3600);
    let records = history.since(week_ago);
    let text = telegram::format_weekly_summary(&records, &timefmt::format_utc(week_ago), &timefmt::format_utc(now));

    if let Err(e) = telegram.send(&text) {
        tracing::error!(error = %e, "no se pudo enviar el resumen semanal a Telegram");
    }
}

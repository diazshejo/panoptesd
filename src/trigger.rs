//! Cooldown por (pid, tipo de anomalia) y pool acotado de hilos que
//! ejecutan el script de auditoria externo sin bloquear el loop principal.
//! Los mismos workers son quienes mandan la alerta de Telegram (si esta
//! habilitado) y quienes anotan el resultado en el historial compartido
//! que despues leen los schedulers de status/resumen semanal.

use crate::history::{AuditHistory, AuditRecord};
use crate::rules::AnomalyKind;
use crate::telegram::{self, TelegramClient};
use crate::timefmt;
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub struct TriggerJob {
    pub pid: i32,
    pub name: String,
    pub user: String,
    pub kind: AnomalyKind,
    pub detail: String,
}

/// Lanza N hilos worker que consumen jobs de un channel acotado y corren
/// el script de auditoria. El channel es bounded para que, si hay una
/// rafaga de anomalias, el productor (loop principal) pueda descartar con
/// try_send en vez de bloquearse esperando lugar en la cola.
pub fn spawn_worker_pool(
    script_path: String,
    workers: usize,
    telegram: Option<Arc<TelegramClient>>,
    history: Arc<AuditHistory>,
) -> (SyncSender<TriggerJob>, Vec<JoinHandle<()>>) {
    let (tx, rx) = sync_channel::<TriggerJob>(256);
    let rx = Arc::new(Mutex::new(rx));
    let mut handles = Vec::with_capacity(workers.max(1));

    for id in 0..workers.max(1) {
        let rx = Arc::clone(&rx);
        let script_path = script_path.clone();
        let telegram = telegram.clone();
        let history = Arc::clone(&history);
        let handle = std::thread::Builder::new()
            .name(format!("audit-worker-{id}"))
            .spawn(move || loop {
                let job = {
                    let lock = rx.lock().expect("mutex de cola de auditoria envenenado");
                    lock.recv()
                };
                match job {
                    Ok(job) => handle_job(&script_path, &job, telegram.as_deref(), &history),
                    Err(_) => break, // channel cerrado: shutdown, cola drenada
                }
            })
            .expect("no se pudo lanzar hilo worker de auditoria");
        handles.push(handle);
    }

    (tx, handles)
}

fn handle_job(script_path: &str, job: &TriggerJob, telegram: Option<&TelegramClient>, history: &AuditHistory) {
    let unix_ts = timefmt::unix_now();

    // La alerta de Telegram sale primero (es lo mas urgente y lo mas
    // rapido de mandar); el script de auditoria, mas pesado, va despues.
    // Si Telegram esta caido o el token es invalido, solo se loguea: el
    // resto del flujo (log + script + historial) sigue igual.
    if let Some(client) = telegram {
        if job.kind.is_real_anomaly() {
            let text = telegram::format_anomaly_alert(
                job.pid,
                &job.name,
                &job.user,
                job.kind.as_str(),
                &job.detail,
                &timefmt::format_utc(unix_ts),
            );
            if let Err(e) = client.send(&text) {
                tracing::error!(pid = job.pid, error = %e, "no se pudo enviar alerta a Telegram");
            }
        }
    }

    let success = run_script(script_path, job);

    history.push(AuditRecord {
        unix_ts,
        pid: job.pid,
        name: job.name.clone(),
        user: job.user.clone(),
        kind: job.kind,
        detail: job.detail.clone(),
        script_success: success,
    });
}

/// Corre el script de auditoria y devuelve si termino con exit code 0.
fn run_script(script_path: &str, job: &TriggerJob) -> bool {
    tracing::info!(
        pid = job.pid,
        name = %job.name,
        user = %job.user,
        anomaly = job.kind.as_str(),
        detail = %job.detail,
        "ejecutando script de auditoria"
    );

    let result = Command::new(script_path)
        .arg(job.pid.to_string())
        .arg(&job.name)
        .arg(&job.user)
        .arg(job.kind.as_str())
        .arg(&job.detail)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    match result {
        Ok(mut child) => match child.wait() {
            Ok(status) => {
                if !status.success() {
                    tracing::warn!(pid = job.pid, status = %status, "script de auditoria termino con error");
                }
                status.success()
            }
            Err(e) => {
                tracing::error!(pid = job.pid, error = %e, "fallo esperando al script de auditoria");
                false
            }
        },
        Err(e) => {
            tracing::error!(
                pid = job.pid,
                script = script_path,
                error = %e,
                "no se pudo ejecutar el script de auditoria"
            );
            false
        }
    }
}

/// Tracker de cooldown: evita re-disparar el mismo (pid, tipo) dentro de
/// la ventana configurada. Se barre periodicamente para no crecer sin
/// limite con PIDs que ya no existen.
pub struct CooldownTracker {
    last_fired: HashMap<(i32, AnomalyKind), Instant>,
    cooldown: Duration,
}

impl CooldownTracker {
    pub fn new(cooldown: Duration) -> Self {
        CooldownTracker {
            last_fired: HashMap::new(),
            cooldown,
        }
    }

    /// Devuelve true si corresponde disparar (y registra el disparo).
    pub fn should_fire(&mut self, pid: i32, kind: AnomalyKind, now: Instant) -> bool {
        match self.last_fired.get(&(pid, kind)) {
            Some(&last) if now.duration_since(last) < self.cooldown => false,
            _ => {
                self.last_fired.insert((pid, kind), now);
                true
            }
        }
    }

    /// Elimina entradas mas viejas que 2x el cooldown (limpieza periodica,
    /// no en cada tick).
    pub fn sweep(&mut self, now: Instant) {
        let cooldown = self.cooldown;
        self.last_fired
            .retain(|_, &mut last| now.duration_since(last) < cooldown * 2);
    }
}

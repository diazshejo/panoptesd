//! Colas independientes de notificacion y auditoria; cooldown confirmado al enviar.
use crate::history::{AuditHistory, AuditRecord};
use crate::rules::AnomalyKind;
use crate::telegram::{self, TelegramClient};
use crate::timefmt;
use std::collections::{HashMap, HashSet};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EventKey {
    Process(i32, u64, AnomalyKind),
    Root(String),
    HostMemory,
}

#[derive(Clone)]
pub struct TriggerJob {
    pub pid: i32,
    pub name: String,
    pub user: String,
    pub kind: AnomalyKind,
    pub detail: String,
    pub run_audit: bool,
    pub key: Option<EventKey>,
}

impl TriggerJob {
    pub fn is_memory(&self) -> bool {
        matches!(
            self.kind,
            AnomalyKind::MemoryOutOfRange | AnomalyKind::HostMemoryPressure
        )
    }
}

#[derive(Default)]
struct DeliveryState {
    pending: HashSet<EventKey>,
    sent: HashMap<EventKey, Instant>,
}

#[derive(Clone)]
pub struct CooldownTracker {
    state: Arc<Mutex<DeliveryState>>,
    cooldown: Duration,
}

impl CooldownTracker {
    pub fn new(cooldown: Duration) -> Self {
        Self {
            state: Arc::default(),
            cooldown,
        }
    }

    pub fn reserve(&self, key: &EventKey, now: Instant) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.pending.contains(key)
            || state
                .sent
                .get(key)
                .is_some_and(|last| now.duration_since(*last) < self.cooldown)
        {
            return false;
        }
        state.pending.insert(key.clone());
        true
    }

    pub fn finish(&self, key: &EventKey, success: bool, now: Instant) {
        let mut state = self.state.lock().unwrap();
        state.pending.remove(key);
        if success {
            state.sent.insert(key.clone(), now);
        }
    }

    pub fn sweep(&self, now: Instant) {
        self.state
            .lock()
            .unwrap()
            .sent
            .retain(|_, last| now.duration_since(*last) < self.cooldown);
    }
}

/// Solo grupos creados por este daemon. El mutex cubre spawn + registro,
/// evitando que el scanner vea al hijo antes de registrar su grupo.
pub type AuditGroups = Arc<Mutex<HashSet<i32>>>;

#[derive(Clone)]
pub struct EventSender {
    pub normal: SyncSender<TriggerJob>,
    memory: SyncSender<TriggerJob>,
}

impl EventSender {
    pub fn enqueue(
        &self,
        mut job: TriggerJob,
        key: EventKey,
        cooldowns: &CooldownTracker,
        now: Instant,
    ) -> bool {
        if !cooldowns.reserve(&key, now) {
            return false;
        }
        job.key = Some(key.clone());
        let tx = if job.is_memory() {
            &self.memory
        } else {
            &self.normal
        };
        match tx.try_send(job) {
            Ok(()) => true,
            Err(e) => {
                cooldowns.finish(&key, false, now);
                tracing::error!(?key, error = %e, "cola de notificacion llena/cerrada; sin consumir cooldown");
                false
            }
        }
    }
}

pub fn spawn_worker_pool(
    script_path: String,
    workers: usize,
    telegram: Option<Arc<TelegramClient>>,
    history: Arc<AuditHistory>,
    cooldowns: CooldownTracker,
    audit_groups: AuditGroups,
    audit_timeout: Duration,
) -> (EventSender, Vec<JoinHandle<()>>) {
    let (audit_tx, audit_rx) = sync_channel::<TriggerJob>(256);
    let audit_rx = Arc::new(Mutex::new(audit_rx));
    let mut handles = Vec::new();
    for id in 0..workers {
        let rx = Arc::clone(&audit_rx);
        let path = script_path.clone();
        let history = Arc::clone(&history);
        let groups = Arc::clone(&audit_groups);
        handles.push(
            std::thread::Builder::new()
                .name(format!("audit-worker-{id}"))
                .spawn(move || loop {
                    let job = rx.lock().unwrap().recv();
                    let Ok(job) = job else {
                        break;
                    };
                    let success = run_script(&path, &job, &groups, audit_timeout);
                    record(&history, &job, success);
                })
                .unwrap(),
        );
    }
    let (normal, normal_rx) = sync_channel::<TriggerJob>(256);
    let (memory, memory_rx) = sync_channel::<TriggerJob>(64);
    for (name, rx) in [("notifications", normal_rx), ("memory-notify", memory_rx)] {
        let telegram = telegram.clone();
        let audits = audit_tx.clone();
        let history = history.clone();
        let cooldowns = cooldowns.clone();
        handles.push(std::thread::Builder::new().name(name.into()).spawn(move || {
            while let Ok(job) = rx.recv() {
                tracing::info!(pid = job.pid, anomaly = job.kind.as_str(), detail = %job.detail, "notificando anomalia");
                let delivered = notify_job(&job, telegram.as_deref());
                if let Some(key) = &job.key { cooldowns.finish(key, delivered, Instant::now()); }
                if job.run_audit {
                    if audits.try_send(job.clone()).is_err() {
                        tracing::error!(pid = job.pid, "cola de auditoria llena; notificacion ya procesada");
                        record(&history, &job, false);
                    }
                } else { record(&history, &job, true); }
            }
        }).unwrap());
    }
    (EventSender { normal, memory }, handles)
}

fn notify_job(job: &TriggerJob, client: Option<&TelegramClient>) -> bool {
    if !job.kind.is_real_anomaly() {
        return true;
    }
    let Some(client) = client else {
        tracing::warn!(
            anomaly = job.kind.as_str(),
            "Telegram deshabilitado: evento solo local"
        );
        return true;
    };
    let text = telegram::format_anomaly_alert(
        job.pid,
        &job.name,
        &job.user,
        job.kind.as_str(),
        &job.detail,
        &timefmt::format_utc(timefmt::unix_now()),
    );
    // Reintentos de transporte independientes del cooldown de deteccion.
    for attempt in 1..=3 {
        match client.send(&text) {
            Ok(()) => {
                tracing::info!(
                    pid = job.pid,
                    anomaly = job.kind.as_str(),
                    attempt,
                    "Telegram confirmo alerta"
                );
                return true;
            }
            Err(e) => {
                tracing::error!(pid = job.pid, anomaly = job.kind.as_str(), attempt, error = %e, "fallo Telegram")
            }
        }
        if attempt < 3 {
            std::thread::sleep(Duration::from_secs(attempt));
        }
    }
    false
}

fn record(history: &AuditHistory, job: &TriggerJob, success: bool) {
    history.push(AuditRecord {
        unix_ts: timefmt::unix_now(),
        pid: job.pid,
        name: job.name.clone(),
        user: job.user.clone(),
        kind: job.kind,
        detail: job.detail.clone(),
        script_success: success,
    });
}

fn run_script(
    script_path: &str,
    job: &TriggerJob,
    groups: &AuditGroups,
    timeout: Duration,
) -> bool {
    let mut registry = groups.lock().unwrap();
    let result = Command::new(script_path)
        .process_group(0)
        .arg(job.pid.to_string())
        .arg(&job.name)
        .arg(&job.user)
        .arg(job.kind.as_str())
        .arg(&job.detail)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = result else {
        tracing::error!(script = script_path, "no se pudo lanzar auditoria");
        return false;
    };
    let pgid = child.id() as i32;
    registry.insert(pgid);
    drop(registry);
    let start = Instant::now();
    let success = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Err(e) => {
                tracing::error!(error = %e, "fallo esperando auditoria");
                break false;
            }
            Ok(None) if start.elapsed() >= timeout => {
                tracing::error!(pgid, "auditoria excedio timeout");
                break false;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    // El script no puede dejar auxiliares en segundo plano al finalizar.
    let mut registry = groups.lock().unwrap();
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
    let _ = child.wait();
    registry.remove(&pgid);
    success
}

#[cfg(test)]
pub fn test_channels(
    capacity: usize,
) -> (
    EventSender,
    std::sync::mpsc::Receiver<TriggerJob>,
    std::sync::mpsc::Receiver<TriggerJob>,
) {
    let (normal, rx) = sync_channel(capacity);
    let (memory, mem_rx) = sync_channel(capacity);
    (EventSender { normal, memory }, rx, mem_rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(kind: AnomalyKind) -> TriggerJob {
        TriggerJob {
            pid: 42,
            name: "polybot".into(),
            user: "deploy".into(),
            kind,
            detail: "memoria".into(),
            run_audit: false,
            key: None,
        }
    }

    #[test]
    fn cooldown_is_per_rule_and_incarnation_and_only_after_delivery() {
        let t = Instant::now();
        let tracker = CooldownTracker::new(Duration::from_secs(30));
        let mem = EventKey::Process(42, 1, AnomalyKind::MemoryOutOfRange);
        let root = EventKey::Process(42, 1, AnomalyKind::RootNotWhitelisted);
        assert!(tracker.reserve(&root, t));
        tracker.finish(&root, true, t);
        assert!(tracker.reserve(&mem, t));
        assert!(!tracker.reserve(&mem, t)); // en vuelo
        tracker.finish(&mem, false, t);
        assert!(tracker.reserve(&mem, t)); // fallo: sin cooldown
        tracker.finish(&mem, true, t);
        assert!(!tracker.reserve(&mem, t + Duration::from_secs(29)));
        assert!(tracker.reserve(&mem, t + Duration::from_secs(30)));
        assert!(tracker.reserve(&EventKey::Process(42, 2, AnomalyKind::MemoryOutOfRange), t));
        assert!(tracker.reserve(&EventKey::HostMemory, t));
    }

    #[test]
    fn memory_has_reserved_queue_and_full_queue_does_not_consume_cooldown() {
        let t = Instant::now();
        let tracker = CooldownTracker::new(Duration::from_secs(300));
        let (tx, _normal, memory) = test_channels(1);
        assert!(tx.enqueue(
            job(AnomalyKind::RootNotWhitelisted),
            EventKey::Root("one".into()),
            &tracker,
            t
        ));
        assert!(!tx.enqueue(
            job(AnomalyKind::RootNotWhitelisted),
            EventKey::Root("two".into()),
            &tracker,
            t
        ));
        assert!(tx.enqueue(
            job(AnomalyKind::HostMemoryPressure),
            EventKey::HostMemory,
            &tracker,
            t
        ));
        let rss = EventKey::Process(42, 1, AnomalyKind::MemoryOutOfRange);
        assert!(!tx.enqueue(job(AnomalyKind::MemoryOutOfRange), rss.clone(), &tracker, t));
        memory.try_recv().unwrap();
        assert!(tx.enqueue(job(AnomalyKind::MemoryOutOfRange), rss, &tracker, t));
    }

    #[test]
    fn sustained_host_pressure_reaches_telegram_and_delivery_is_confirmed() {
        let (client, server) = crate::telegram::tests::mock_client(vec![(200, r#"{"ok":true}"#)]);
        let t = Instant::now();
        let cfg = crate::config::HostMemoryConfig {
            sustained_secs: 5,
            ..Default::default()
        };
        let mut detector = crate::rules::HostMemoryTracker::default();
        let sample = Some((2_000_000, 100_000));
        assert!(detector.evaluate(&cfg, sample, t).is_none());
        let event = detector
            .evaluate(&cfg, sample, t + Duration::from_secs(5))
            .unwrap();
        let tracker = CooldownTracker::new(Duration::from_secs(300));
        let (tx, handles) = spawn_worker_pool(
            "/bin/true".into(),
            1,
            Some(Arc::new(client)),
            Arc::new(AuditHistory::new()),
            tracker.clone(),
            Arc::default(),
            Duration::from_secs(1),
        );
        let mut j = job(event.kind);
        j.detail = event.detail;
        assert!(tx.enqueue(j, EventKey::HostMemory, &tracker, t));
        drop(tx);
        for h in handles {
            h.join().unwrap();
        }
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("host%5C_memory%5C_pressure"));
        assert!(requests[0].contains("MemAvailable"));
        assert!(!tracker.reserve(&EventKey::HostMemory, Instant::now()));
    }

    #[test]
    fn failed_telegram_send_is_retried_before_cooldown() {
        let (client, server) = crate::telegram::tests::mock_client(vec![
            (500, r#"{"ok":false}"#),
            (200, r#"{"ok":true}"#),
        ]);
        assert!(notify_job(
            &job(AnomalyKind::MemoryOutOfRange),
            Some(&client)
        ));
        assert_eq!(server.join().unwrap().len(), 2);
    }

    #[test]
    fn exhausted_delivery_does_not_silence_next_memory_sample() {
        let (client, server) =
            crate::telegram::tests::mock_client(vec![(503, r#"{"ok":false}"#); 3]);
        let tracker = CooldownTracker::new(Duration::from_secs(300));
        let (tx, handles) = spawn_worker_pool(
            "/bin/true".into(),
            1,
            Some(Arc::new(client)),
            Arc::new(AuditHistory::new()),
            tracker.clone(),
            Arc::default(),
            Duration::from_secs(1),
        );
        assert!(tx.enqueue(
            job(AnomalyKind::HostMemoryPressure),
            EventKey::HostMemory,
            &tracker,
            Instant::now()
        ));
        drop(tx);
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(server.join().unwrap().len(), 3);
        assert!(tracker.reserve(&EventKey::HostMemory, Instant::now()));
    }

    #[test]
    fn launched_audit_process_group_is_registered_and_removed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("panoptesd-audit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("audit.sh");
        std::fs::write(&script, "#!/bin/sh\nsleep 10 &\nwait\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let groups: AuditGroups = Arc::default();
        let worker_groups = groups.clone();
        let path = script.to_string_lossy().into_owned();
        let worker = std::thread::spawn(move || {
            run_script(
                &path,
                &job(AnomalyKind::RootNotWhitelisted),
                &worker_groups,
                Duration::from_secs(1),
            )
        });
        let start = Instant::now();
        let mut found = false;
        while start.elapsed() < Duration::from_millis(800) {
            let registry = groups.lock().unwrap();
            if let Some(&pgid) = registry.iter().next() {
                let sample = crate::process::read_process(
                    pgid,
                    crate::process::page_size(),
                    &mut String::new(),
                )
                .unwrap();
                assert_eq!(sample.pgrp, pgid);
                found = true;
                break;
            }
            drop(registry);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(found);
        assert!(!worker.join().unwrap()); // timeout evita bloqueo indefinido
        assert!(groups.lock().unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

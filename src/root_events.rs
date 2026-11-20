//! Agrupacion temporal de root: nunca autoriza nombres ni descarta integrantes.
use crate::process::ProcessState;
use crate::rules::AnomalyKind;
use crate::trigger::{CooldownTracker, EventKey, EventSender, TriggerJob};
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

const GROUP_EXES: &[&str] = &[
    "/usr/bin/apt",
    "/usr/bin/apt-get",
    "/usr/bin/dpkg",
    "/usr/libexec/packagekitd",
    "/usr/lib/packagekit/packagekitd",
    "/usr/bin/run-parts",
    "/usr/bin/systemctl",
    "/usr/sbin/sshd",
    "/usr/lib/openssh/sshd-session",
];

fn trusted_group_exe(exe: &str) -> bool {
    if !GROUP_EXES.contains(&exe) {
        return false;
    }
    // Verificar ejecutable Y directorios: no confiar en comm ni argv[0].
    trusted_root_exe(exe)
}

pub fn trusted_root_exe(exe: &str) -> bool {
    let path = std::path::Path::new(exe);
    if !path.is_absolute() || !path.is_file() {
        return false;
    }
    let Ok(resolved) = std::fs::canonicalize(path) else {
        return false;
    };
    // Verificar tanto la ruta original como el destino de enlaces simbolicos.
    [path, resolved.as_path()].iter().all(|p| {
        p.ancestors()
            .all(|a| std::fs::metadata(a).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0))
    })
}

pub fn context(pid: i32, states: &HashMap<i32, ProcessState>) -> String {
    context_with(pid, states, trusted_group_exe)
}

fn context_with(
    pid: i32,
    states: &HashMap<i32, ProcessState>,
    trusted: impl Fn(&str) -> bool,
) -> String {
    let origin = &states[&pid];
    let mut current_pid = pid;
    let mut group = None;
    // Ancestro de mantenimiento mas alto observado en este snapshot. El limite
    // tambien evita ciclos por una lectura concurrente de /proc.
    for _ in 0..64 {
        let Some(state) = states.get(&current_pid) else {
            break;
        };
        let is_ssh = matches!(
            state.exe.as_deref(),
            Some("/usr/sbin/sshd" | "/usr/lib/openssh/sshd-session")
        );
        if state.uid == 0
            && state.exe.as_deref().is_some_and(&trusted)
            && !(is_ssh && state.ppid == 1)
        {
            group = Some(format!(
                "actividad:{}:{}:{}",
                current_pid,
                state.starttime,
                state.exe.as_deref().unwrap()
            ));
        }
        // La sesion SSH agrupa MOTD/shell/auxiliares; no el listener global.
        if is_ssh && group.is_some() {
            break;
        }
        if state.ppid <= 1 || state.ppid == current_pid {
            break;
        }
        let Some(parent) = states.get(&state.ppid) else {
            break;
        };
        if parent.starttime > state.starttime {
            break;
        }
        current_pid = state.ppid;
    }
    group.unwrap_or_else(|| {
        // Identidad conservadora: mismo ejecutable/comm y misma instancia
        // del padre agrupan auxiliares repetidos, no todos los shells del host.
        let parent_start = states
            .get(&origin.ppid)
            .filter(|p| p.starttime <= origin.starttime)
            .map(|p| p.starttime);
        match (&origin.exe, parent_start) {
            (exe, Some(start)) => format!(
                "exe:{exe:?}:comm:{:?}:padre:{}:{start}",
                origin.comm, origin.ppid
            ),
            _ => format!("proceso:{pid}:{}", origin.starttime),
        }
    })
}

struct Batch {
    since: Instant,
    members: HashMap<(i32, u64), String>,
    extra_observations: u64,
    representative: TriggerJob,
}

#[derive(Default)]
pub struct RootBatches {
    batches: HashMap<String, Batch>,
}

impl RootBatches {
    pub fn observe(&mut self, context: String, pid: i32, state: &ProcessState, now: Instant) {
        // Acotar memoria aun durante una caida prolongada de Telegram.
        // La saturacion se reporta como grupo y cada miembro queda en log.
        let context = if self.batches.len() >= 512 && !self.batches.contains_key(&context) {
            tracing::error!(
                context,
                "agrupacion root saturada; usando resumen de desborde"
            );
            "desborde-root: consultar log de integrantes".to_string()
        } else {
            context
        };
        let batch = self.batches.entry(context).or_insert_with(|| Batch {
            since: now,
            members: HashMap::new(),
            extra_observations: 0,
            representative: TriggerJob {
                pid,
                name: state.comm.clone(),
                user: state.username.clone(),
                kind: AnomalyKind::RootNotWhitelisted,
                detail: String::new(),
                run_audit: !state.is_audit,
                key: None,
            },
        });
        let identity = (pid, state.starttime);
        if batch.members.contains_key(&identity) {
            return;
        }
        let detail = format!(
            "pid={pid} start={} comm={:?} exe={:?} ppid={}",
            state.starttime, state.comm, state.exe, state.ppid
        );
        tracing::warn!(detail, "root fuera de whitelist: integrante de grupo");
        if batch.members.len() < 128 {
            batch
                .members
                .insert(identity, format!("{} (PID {pid})", state.comm));
        } else {
            batch.extra_observations += 1;
        }
    }

    pub fn flush(
        &mut self,
        window: Duration,
        now: Instant,
        tx: &EventSender,
        cooldowns: &CooldownTracker,
    ) {
        self.batches.retain(|context, batch| {
            if now.duration_since(batch.since) < window { return true; }
            let mut members: Vec<_> = batch.members.values().collect();
            members.sort();
            let examples: Vec<_> = members.iter().take(3).map(|s| s.chars().take(160).collect::<String>()).collect();
            let mut job = batch.representative.clone();

            job.detail = format!("Se observaron {} procesos con permisos de administrador fuera de la lista permitida ({} observaciones adicionales). Ejemplos: {}. El detalle completo está en el registro de panoptesd.",
                members.len(), batch.extra_observations, examples.join("; "));
            !tx.enqueue(job, EventKey::Root(context.clone()), cooldowns, now)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules;
    use crate::test_support::{config, state};
    use crate::trigger::test_channels;

    #[test]
    fn ssh_helpers_group_by_session_not_global_listener() {
        let t = Instant::now();
        let states = HashMap::from([
            (10, state("sshd", "/usr/sbin/sshd", 1, 1, t)),
            (20, state("sshd", "/usr/sbin/sshd", 10, 2, t)),
            (21, state("sh", "/usr/bin/dash", 20, 3, t)),
            (22, state("run-parts", "/usr/bin/run-parts", 21, 4, t)),
            (
                23,
                state("landscape-sysin", "/usr/bin/python3.12", 22, 5, t),
            ),
            (30, state("sshd", "/usr/sbin/sshd", 10, 6, t)),
            (31, state("sh", "/usr/bin/dash", 30, 7, t)),
        ]);
        let context = |pid| context_with(pid, &states, |e| GROUP_EXES.contains(&e));
        assert_eq!(context(21), context(23));
        assert_ne!(context(21), context(31));
        assert_ne!(context(21), context(10));
        assert_ne!(context_with(23, &states, |_| false), context(23));
    }

    #[test]
    fn missing_exe_helpers_share_parent_context_without_hiding_them() {
        let t = Instant::now();
        let mut states = HashMap::from([
            (1, state("systemd", "/usr/lib/systemd/systemd", 0, 1, t)),
            (100, state("(sd-close)", "", 1, 10, t)),
            (101, state("(sd-close)", "", 1, 11, t)),
            (102, state("other", "", 1, 12, t)),
        ]);
        for pid in [100, 101, 102] {
            states.get_mut(&pid).unwrap().exe = None;
        }
        assert_eq!(context(100, &states), context(101, &states));
        assert_ne!(context(100, &states), context(102, &states));
        let mut batches = RootBatches::default();
        for pid in [100, 101] {
            batches.observe(context(pid, &states), pid, &states[&pid], t);
        }
        let (tx, rx, _) = test_channels(8);
        batches.flush(
            Duration::ZERO,
            t,
            &tx,
            &CooldownTracker::new(Duration::ZERO),
        );
        let job = rx.try_recv().unwrap();
        assert!(job.detail.contains("2 procesos"));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn package_update_groups_helpers_without_authorizing_generic_names() {
        let now = Instant::now();
        let mut states = HashMap::from([
            (100, state("apt-get", "/usr/bin/apt-get", 1, 10, now)),
            (101, state("dpkg", "/usr/bin/dpkg", 100, 11, now)),
            (102, state("sh", "/usr/bin/dash", 101, 12, now)),
            (
                103,
                state("https", "/usr/lib/apt/methods/https", 100, 13, now),
            ),
            (104, state("python3", "/usr/bin/python3", 102, 14, now)),
            (200, state("sh", "/tmp/sh", 1, 15, now)),
            (201, state("apt-get", "/tmp/apt-get", 1, 16, now)),
        ]);
        let context = |pid| context_with(pid, &states, |e| GROUP_EXES.contains(&e));
        for pid in 101..=104 {
            assert_eq!(context(pid), context(100));
        }
        assert_ne!(context(200), context(100));
        assert_ne!(context(201), context(100));
        assert_ne!(context_with(100, &states, |_| false), context(100)); // ejecutable no confiable
        let group = context(100);
        let mut batches = RootBatches::default();
        for pid in 100..=104 {
            let s = states.get_mut(&pid).unwrap();
            assert!(rules::evaluate(&config(), pid, s, now)
                .iter()
                .any(|e| e.kind == AnomalyKind::RootNotWhitelisted));
            batches.observe(group.clone(), pid, s, now);
        }
        batches.observe("unexpected".into(), 200, &states[&200], now);
        let (tx, rx, _) = test_channels(8);
        let cooldowns = CooldownTracker::new(Duration::from_secs(300));
        batches.flush(Duration::from_secs(10), now, &tx, &cooldowns);
        assert!(rx.try_recv().is_err());
        batches.flush(
            Duration::from_secs(10),
            now + Duration::from_secs(10),
            &tx,
            &cooldowns,
        );
        let jobs = [rx.try_recv().unwrap(), rx.try_recv().unwrap()];
        assert!(jobs.iter().any(|j| j.detail.contains("5 procesos")));
        assert!(jobs.iter().any(|j| j.pid == 200));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn root_repeats_after_cooldown_and_short_lived_members_are_retained() {
        let t = Instant::now();
        let s = state("unexpected", "/tmp/unexpected", 1, 42, t);
        let mut batches = RootBatches::default();
        let (tx, rx, _) = test_channels(8);
        let cooldowns = CooldownTracker::new(Duration::from_secs(30));
        batches.observe("unexpected".into(), 500, &s, t);
        batches.flush(Duration::ZERO, t, &tx, &cooldowns);
        let job = rx.try_recv().unwrap();
        cooldowns.finish(job.key.as_ref().unwrap(), true, t);
        batches.observe("unexpected".into(), 501, &s, t + Duration::from_secs(1));
        batches.flush(Duration::ZERO, t + Duration::from_secs(29), &tx, &cooldowns);
        assert!(rx.try_recv().is_err());
        // Aunque PID 501 ya no se observe, no se descarta su evidencia.
        batches.flush(Duration::ZERO, t + Duration::from_secs(30), &tx, &cooldowns);
        assert!(rx.try_recv().unwrap().detail.contains("PID 501"));
    }
}

mod config;
mod logging;
mod network;
mod process;
mod rules;
mod signals;
mod trigger;
mod userdb;

use config::Config;
use process::ProcessState;
use rules::AnomalyKind;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc::SyncSender;
use std::time::{Duration, Instant};
use trigger::{CooldownTracker, TriggerJob};
use userdb::UserDb;

/// Cada cuantos ciclos se hace la limpieza de cooldowns vencidos. No hace
/// falta barrer en cada tick, es una operacion de mantenimiento.
const COOLDOWN_SWEEP_EVERY_CYCLES: u64 = 30;
/// TTL del cache de /etc/passwd.
const USERDB_TTL: Duration = Duration::from_secs(300);

fn parse_config_path() -> PathBuf {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" || arg == "-c" {
            if let Some(path) = args.next() {
                return PathBuf::from(path);
            }
        }
    }
    PathBuf::from("/etc/panoptesd/config.toml")
}

fn main() -> anyhow::Result<()> {
    let config_path = parse_config_path();
    let config = Config::load(&config_path)?;

    let _log_guards = logging::init(&config);
    tracing::info!(config = ?config_path, "panoptesd iniciando");

    if !std::path::Path::new(&config.audit_script_path).exists() {
        tracing::warn!(
            script = %config.audit_script_path,
            "el script de auditoria configurado no existe todavia (se validara al dispararse)"
        );
    }

    let shutdown = signals::setup_shutdown_flag();
    let (tx, worker_handles) = trigger::spawn_worker_pool(
        config.audit_script_path.clone(),
        config.script_worker_threads,
    );

    run_loop(&config, &shutdown, &tx);

    tracing::info!("señal de apagado recibida, cerrando cola de auditoria y esperando workers");
    drop(tx);
    for handle in worker_handles {
        let _ = handle.join();
    }
    tracing::info!("panoptesd detenido limpiamente");
    Ok(())
}

fn run_loop(config: &Config, shutdown: &std::sync::atomic::AtomicBool, tx: &SyncSender<TriggerJob>) {
    let ticks_per_sec = process::clock_ticks_per_sec();
    let page_size = process::page_size();
    let poll_interval = Duration::from_secs(config.poll_interval_secs);
    let cooldown = Duration::from_secs(config.cooldown_secs);

    let mut states: HashMap<i32, ProcessState> = HashMap::new();
    let mut cooldowns = CooldownTracker::new(cooldown);
    let mut userdb = UserDb::load();

    // Buffers reutilizados entre ciclos para no reallocar en cada tick.
    let mut pid_buf: Vec<i32> = Vec::with_capacity(512);
    let mut seen_pids: HashSet<i32> = HashSet::with_capacity(512);
    let mut stat_buf = String::with_capacity(256);

    let mut cycle: u64 = 0;

    while !shutdown.load(Ordering::Relaxed) {
        let tick_start = Instant::now();
        cycle += 1;

        userdb.refresh_if_stale(USERDB_TTL);

        process::list_pids(&mut pid_buf);
        seen_pids.clear();

        for &pid in pid_buf.iter() {
            let sample = match process::read_process(pid, page_size, &mut stat_buf) {
                Some(s) => s,
                None => continue, // proceso desaparecio entre el listado y la lectura
            };
            seen_pids.insert(pid);

            let now = Instant::now();
            // Patron Entry para evitar un doble borrow mutable de `states`
            // (get_mut en el brazo Some + insert en el brazo None sobre el
            // mismo mapa no compila de forma directa).
            let state: &mut ProcessState = match states.entry(pid) {
                Entry::Occupied(mut occ) => {
                    let uid_changed = occ.get().uid != sample.uid;
                    occ.get_mut().update(&sample, now, ticks_per_sec);
                    if uid_changed {
                        occ.get_mut().username = userdb.lookup(sample.uid);
                    }
                    occ.into_mut()
                }
                Entry::Vacant(vac) => {
                    let username = userdb.lookup(sample.uid);
                    vac.insert(ProcessState::new(&sample, username, now))
                }
            };

            let events = rules::evaluate(config, state, now);
            for event in events {
                dispatch(tx, &mut cooldowns, pid, state, event, now);
            }
        }

        // Procesos que estaban trackeados y ya no aparecen en /proc: se
        // evalua la regla de vida efimera antes de descartarlos.
        states.retain(|&pid, state| {
            if seen_pids.contains(&pid) {
                return true;
            }
            let now = Instant::now();
            if let Some(event) = rules::evaluate_ephemeral(config, state, now) {
                dispatch(tx, &mut cooldowns, pid, state, event, now);
            }
            false
        });

        if config.network.enabled && cycle.is_multiple_of(config.network.check_every_n_cycles) {
            check_network(config, &states, &pid_buf, tx, &mut cooldowns);
        }

        if cycle.is_multiple_of(COOLDOWN_SWEEP_EVERY_CYCLES) {
            cooldowns.sweep(Instant::now());
        }

        let elapsed = tick_start.elapsed();
        let remaining = poll_interval.saturating_sub(elapsed);
        signals::sleep_interruptible(remaining, shutdown);
    }
}

fn dispatch(
    tx: &SyncSender<TriggerJob>,
    cooldowns: &mut CooldownTracker,
    pid: i32,
    state: &ProcessState,
    event: rules::AnomalyEvent,
    now: Instant,
) {
    if !cooldowns.should_fire(pid, event.kind, now) {
        return;
    }
    let job = TriggerJob {
        pid,
        name: state.comm.clone(),
        user: state.username.clone(),
        kind: event.kind,
        detail: event.detail,
    };
    if let Err(e) = tx.try_send(job) {
        tracing::warn!(pid, error = %e, "cola de auditoria llena, evento descartado");
    }
}

fn check_network(
    config: &Config,
    states: &HashMap<i32, ProcessState>,
    pids: &[i32],
    tx: &SyncSender<TriggerJob>,
    cooldowns: &mut CooldownTracker,
) {
    let connections = network::parse_tcp_connections("/proc/net/tcp");
    if connections.is_empty() {
        return;
    }
    let inode_to_pid = network::build_inode_to_pid(pids);

    for conn in &connections {
        if network::is_allowed(conn, &config.network.allowed_remote_ports, &config.network.allowed_cidrs_v4) {
            continue;
        }
        let pid = match inode_to_pid.get(&conn.inode) {
            Some(&pid) => pid,
            None => continue,
        };
        let state = match states.get(&pid) {
            Some(s) => s,
            None => continue,
        };
        let now = Instant::now();
        let event = rules::AnomalyEvent {
            kind: AnomalyKind::UnexpectedNetwork,
            detail: format!("conexion inesperada a {}:{}", conn.remote_ip, conn.remote_port),
        };
        dispatch(tx, cooldowns, pid, state, event, now);
    }
}

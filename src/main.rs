mod config;
mod history;
mod hoststats;
mod logging;
mod network;
mod process;
mod rules;
mod scheduler;
mod signals;
mod telegram;
mod timefmt;
mod trigger;
mod userdb;

use config::Config;
use history::AuditHistory;
use process::ProcessState;
use rules::AnomalyKind;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::time::{Duration, Instant};
use telegram::TelegramClient;
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

/// Arma el cliente de Telegram si `telegram.enabled = true` en la config.
/// El token y el chat_id salen de variables de entorno (nunca del TOML).
/// Si faltan o estan vacias, se loguea el error y Telegram queda
/// deshabilitado para toda la corrida: nunca es motivo para no arrancar.
fn build_telegram_client(config: &Config) -> Option<Arc<TelegramClient>> {
    if !config.telegram.enabled {
        return None;
    }
    let token = std::env::var("TELEGRAM_BOT_TOKEN").unwrap_or_default();
    let chat_id = std::env::var("TELEGRAM_CHAT_ID").unwrap_or_default();
    if token.is_empty() || chat_id.is_empty() {
        tracing::error!(
            "telegram.enabled=true pero TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID no estan \
             seteados (o vacios); Telegram queda deshabilitado para esta corrida"
        );
        return None;
    }
    let timeout = Duration::from_secs(config.telegram.request_timeout_secs);
    Some(Arc::new(TelegramClient::new(token, chat_id, timeout)))
}

fn main() -> anyhow::Result<()> {
    let daemon_start = Instant::now();
    let config_path = parse_config_path();
    let config = Arc::new(Config::load(&config_path)?);

    let _log_guards = logging::init(&config);
    tracing::info!(config = ?config_path, "panoptesd iniciando");

    if !std::path::Path::new(&config.audit_script_path).exists() {
        tracing::warn!(
            script = %config.audit_script_path,
            "el script de auditoria configurado no existe todavia (se validara al dispararse)"
        );
    }

    let shutdown = signals::setup_shutdown_flag();
    let history = Arc::new(AuditHistory::new());
    let watched_count = Arc::new(AtomicUsize::new(0));
    let telegram_client = build_telegram_client(&config);

    let (tx, worker_handles) = trigger::spawn_worker_pool(
        config.audit_script_path.clone(),
        config.script_worker_threads,
        telegram_client.clone(),
        Arc::clone(&history),
    );

    let mut scheduler_handles = Vec::new();
    if let Some(client) = &telegram_client {
        tracing::info!("integracion con Telegram habilitada: status periodico y resumen semanal activos");
        scheduler_handles.push(scheduler::spawn_status_scheduler(
            Arc::clone(&config),
            Arc::clone(&shutdown),
            Arc::clone(client),
            Arc::clone(&history),
            Arc::clone(&watched_count),
            daemon_start,
        ));
        scheduler_handles.push(scheduler::spawn_weekly_scheduler(
            Arc::clone(&config),
            Arc::clone(&shutdown),
            Arc::clone(client),
            Arc::clone(&history),
            tx.clone(),
        ));
    }

    run_loop(&config, &shutdown, &tx, &watched_count);

    tracing::info!("señal de apagado recibida, cerrando cola de auditoria y esperando workers");
    drop(tx);
    for handle in scheduler_handles {
        let _ = handle.join();
    }
    for handle in worker_handles {
        let _ = handle.join();
    }
    tracing::info!("panoptesd detenido limpiamente");
    Ok(())
}

fn run_loop(
    config: &Config,
    shutdown: &std::sync::atomic::AtomicBool,
    tx: &SyncSender<TriggerJob>,
    watched_count: &AtomicUsize,
) {
    let ticks_per_sec = process::clock_ticks_per_sec();
    let page_size = process::page_size();
    let poll_interval = Duration::from_secs(config.poll_interval_secs);
    let cooldown = Duration::from_secs(config.cooldown_secs);

    let mut states: HashMap<i32, ProcessState> = HashMap::new();
    let mut cooldowns = CooldownTracker::new(cooldown);
    let mut userdb = UserDb::load();
    // Linea de base de puertos LISTEN: None hasta el primer chequeo de red
    // (asi el primer ciclo solo releva lo que ya estaba escuchando al
    // arrancar, sin alertar por eso).
    let mut listen_baseline: Option<HashSet<(i32, u16, network::Protocol)>> = None;

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

            let events = rules::evaluate(config, pid, state, now);
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
            check_network(config, &states, &pid_buf, tx, &mut cooldowns, &mut listen_baseline);
        }

        if cycle.is_multiple_of(COOLDOWN_SWEEP_EVERY_CYCLES) {
            cooldowns.sweep(Instant::now());
        }

        watched_count.store(states.len(), Ordering::Relaxed);

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

/// Orquesta las dos reglas de red, ambas gateadas por el mismo
/// `network.check_every_n_cycles` desde `run_loop`. El mapeo inodo->pid se
/// arma una sola vez y se comparte entre las dos: es el paso costoso
/// (recorre /proc/<pid>/fd de todos los procesos).
fn check_network(
    config: &Config,
    states: &HashMap<i32, ProcessState>,
    pids: &[i32],
    tx: &SyncSender<TriggerJob>,
    cooldowns: &mut CooldownTracker,
    listen_baseline: &mut Option<HashSet<(i32, u16, network::Protocol)>>,
) {
    let inode_to_pid = network::build_inode_to_pid(pids);
    check_unexpected_outbound(config, states, &inode_to_pid, tx, cooldowns);
    check_new_listen_ports(config, states, &inode_to_pid, tx, cooldowns, listen_baseline);
}

/// Regla `conexion_saliente_no_esperada`: conexiones TCP ESTABLISHED cuya
/// IP remota no cae en ningun CIDR permitido (ni su puerto esta en la
/// whitelist de puertos remotos). Solo IPv4, igual que la whitelist de
/// CIDRs de la config.
fn check_unexpected_outbound(
    config: &Config,
    states: &HashMap<i32, ProcessState>,
    inode_to_pid: &HashMap<u64, i32>,
    tx: &SyncSender<TriggerJob>,
    cooldowns: &mut CooldownTracker,
) {
    let connections = network::parse_tcp_connections("/proc/net/tcp");
    if connections.is_empty() {
        return;
    }

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
            kind: AnomalyKind::UnexpectedOutboundConnection,
            detail: format!("conexion saliente a {}:{} fuera de los CIDRs permitidos", conn.remote_ip, conn.remote_port),
        };
        dispatch(tx, cooldowns, pid, state, event, now);
    }
}

/// Regla `nuevo_puerto_listen`: compara los sockets en LISTEN/bindeados
/// (tcp/tcp6/udp/udp6) de este ciclo contra el snapshot del ciclo
/// anterior. El primer chequeo desde que arranca el daemon (baseline =
/// None) solo releva lo que ya estaba escuchando, sin alertar: si
/// alertara ahi, cualquier servicio ya corriendo al arrancar (sshd, etc.)
/// se reportaria como "nuevo".
fn check_new_listen_ports(
    config: &Config,
    states: &HashMap<i32, ProcessState>,
    inode_to_pid: &HashMap<u64, i32>,
    tx: &SyncSender<TriggerJob>,
    cooldowns: &mut CooldownTracker,
    baseline: &mut Option<HashSet<(i32, u16, network::Protocol)>>,
) {
    let mut sockets = network::parse_listen_tcp("/proc/net/tcp", false);
    sockets.extend(network::parse_listen_tcp("/proc/net/tcp6", true));
    sockets.extend(network::parse_listen_udp("/proc/net/udp", false));
    sockets.extend(network::parse_listen_udp("/proc/net/udp6", true));

    let mut current: HashMap<(i32, u16, network::Protocol), &network::ListenSocket> = HashMap::new();
    for sock in &sockets {
        if let Some(&pid) = inode_to_pid.get(&sock.inode) {
            current.insert((pid, sock.local_port, sock.protocol), sock);
        }
    }
    let current_keys: HashSet<(i32, u16, network::Protocol)> = current.keys().copied().collect();

    let previous = match baseline.take() {
        Some(prev) => prev,
        None => {
            *baseline = Some(current_keys);
            return;
        }
    };

    for &(pid, port, protocol) in current_keys.difference(&previous) {
        if config.network.allowed_listen_ports.contains(&port) {
            continue;
        }
        let state = match states.get(&pid) {
            Some(s) => s,
            None => continue,
        };
        let sock = match current.get(&(pid, port, protocol)) {
            Some(s) => s,
            None => continue,
        };
        let now = Instant::now();
        let event = rules::AnomalyEvent {
            kind: AnomalyKind::NewListenPort,
            detail: format!("{} escuchando en {}:{} (nuevo)", protocol.as_str(), sock.local_ip, port),
        };
        dispatch(tx, cooldowns, pid, state, event, now);
    }

    *baseline = Some(current_keys);
}

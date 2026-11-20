mod config;
mod history;
mod hoststats;
mod logging;
mod network;
mod process;
mod root_events;
mod rules;
mod scheduler;
mod signals;
mod ssh_watch;
mod telegram;
#[cfg(test)]
mod test_support;
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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use telegram::TelegramClient;
use trigger::{AuditGroups, CooldownTracker, EventKey, EventSender, TriggerJob};
use userdb::UserDb;

/// Cada cuantos ciclos se hace la limpieza de cooldowns vencidos. No hace
/// falta barrer en cada tick, es una operacion de mantenimiento.
const COOLDOWN_SWEEP_EVERY_CYCLES: u64 = 30;
/// TTL del cache de /etc/passwd.
const USERDB_TTL: Duration = Duration::from_secs(300);

const DEFAULT_CONFIG_PATH: &str = "/etc/panoptesd/config.toml";

/// Argumentos de linea de comandos. Se parsean a mano: son dos flags, no
/// justifica sumar `clap` a un daemon que se precia de pocas dependencias.
struct Cli {
    config_path: PathBuf,
    /// `--send-telegram "<mensaje>"`: modo "fire and exit" que manda un
    /// mensaje por Telegram y termina, sin arrancar el loop de monitoreo
    /// ni los schedulers. Pensado para cron/scripts externos.
    send_telegram: Option<String>,
}

fn usage() -> String {
    format!(
        "uso: panoptesd [--config <ruta>] [--send-telegram \"<mensaje>\"]\n\
         \n\
         Sin --send-telegram arranca el daemon de monitoreo.\n\
         Con --send-telegram envia <mensaje> por Telegram (segun [telegram] de la\n\
         config y TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID del entorno) y sale:\n\
         0 = enviado (o telegram.enabled=false), 1 = fallo el envio, 2 = uso invalido.\n\
         \n\
         --config, -c <ruta>   config TOML (default: {DEFAULT_CONFIG_PATH})"
    )
}

/// Devuelve `Err(mensaje)` ante un argumento invalido; el caller lo imprime
/// a stderr y sale con codigo 2 (convencion de "uso invalido").
fn parse_cli<I: Iterator<Item = String>>(mut args: I) -> Result<Cli, String> {
    let mut cli = Cli {
        config_path: PathBuf::from(DEFAULT_CONFIG_PATH),
        send_telegram: None,
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                cli.config_path = PathBuf::from(args.next().ok_or("--config requiere una ruta")?);
            }
            "--send-telegram" => {
                // Un "mensaje" que empieza con `--` es casi seguro el flag
                // siguiente (`--send-telegram --config x`): mejor cortar
                // aca que mandar "--config" al chat.
                let msg = match args.next() {
                    Some(m) if !m.starts_with("--") => m,
                    _ => return Err("--send-telegram requiere el mensaje a enviar".to_string()),
                };
                if msg.trim().is_empty() {
                    return Err("--send-telegram: el mensaje no puede estar vacio".to_string());
                }
                cli.send_telegram = Some(msg);
            }
            "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            other => return Err(format!("argumento desconocido: {other}\n\n{}", usage())),
        }
    }
    Ok(cli)
}

/// Arma el cliente de Telegram a partir de `telegram.enabled` /
/// `request_timeout_secs` de la config y de TELEGRAM_BOT_TOKEN /
/// TELEGRAM_CHAT_ID del entorno (nunca del TOML). Lo comparten el daemon y
/// el modo `--send-telegram`, asi los dos leen las credenciales igual.
///
/// `Ok(None)` = Telegram deshabilitado por config; `Err` = habilitado pero
/// faltan (o estan vacias) las variables de entorno.
fn telegram_client_from_env(config: &Config) -> Result<Option<TelegramClient>, String> {
    if !config.telegram.enabled {
        return Ok(None);
    }
    let token = std::env::var("TELEGRAM_BOT_TOKEN").unwrap_or_default();
    let chat_id = std::env::var("TELEGRAM_CHAT_ID").unwrap_or_default();
    if token.is_empty() || chat_id.is_empty() {
        return Err(
            "telegram.enabled=true pero TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID no estan \
             seteados (o vacios)"
                .to_string(),
        );
    }
    let timeout = Duration::from_secs(config.telegram.request_timeout_secs);
    Ok(Some(TelegramClient::new(token, chat_id, timeout)))
}

/// Si Telegram esta requerido pero faltan credenciales, fallar al iniciar
/// en vez de operar inadvertidamente sin notificaciones.
fn build_telegram_client(config: &Config) -> anyhow::Result<Option<Arc<TelegramClient>>> {
    match telegram_client_from_env(config) {
        Ok(client) => Ok(client.map(Arc::new)),
        Err(e) => {
            anyhow::bail!("{e}; no se inicia con notificaciones requeridas sin credenciales")
        }
    }
}

/// Modo `--send-telegram`: manda un unico mensaje y devuelve el codigo de
/// salida del proceso. No inicializa tracing a proposito: esto lo invoca
/// un cron o un script, y lo que necesita es el error en stderr y un
/// exit code, no lineas en el log del daemon.
fn run_send_telegram(config: &Config, message: &str) -> i32 {
    let client = match telegram_client_from_env(config) {
        Ok(Some(client)) => client,
        Ok(None) => return 0, // telegram.enabled=false: no es error, no hay nada que mandar
        Err(e) => {
            eprintln!("panoptesd --send-telegram: {e}");
            return 1;
        }
    };
    // El mensaje viene crudo de afuera (paths, timestamps, etc.): pasa por
    // el mismo escape que los campos dinamicos de las alertas.
    let text = telegram::format_external_message(message);
    match client.send(&text) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("panoptesd --send-telegram: fallo el envio a Telegram: {e}");
            1
        }
    }
}

fn main() -> anyhow::Result<()> {
    let daemon_start = Instant::now();
    let cli = match parse_cli(std::env::args().skip(1)) {
        Ok(cli) => cli,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };
    let config_path = cli.config_path;
    let config = Arc::new(Config::load(&config_path)?);

    // Modo "fire and exit": se resuelve antes de inicializar logging,
    // señales, workers y schedulers. Nada del daemon arranca.
    if let Some(message) = cli.send_telegram {
        std::process::exit(run_send_telegram(&config, &message));
    }

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
    let telegram_client = build_telegram_client(&config)?;
    let cooldowns = CooldownTracker::new(Duration::from_secs(config.cooldown_secs));
    let audit_groups: AuditGroups = Arc::new(Mutex::new(HashSet::new()));
    tracing::info!(poll_secs = config.poll_interval_secs, cooldown_secs = config.cooldown_secs,
        rss_mb = config.rules.memory.max_rss_mb, host_memory = ?config.rules.host_memory,
        "configuracion efectiva de memoria");
    if let Some((total, available)) = hoststats::mem_total_available_kb() {
        tracing::info!(
            total_kib = total,
            available_kib = available,
            "memoria al iniciar"
        );
        if config.rules.memory.enabled && config.rules.memory.max_rss_mb >= total / 1024 {
            tracing::warn!("umbral RSS >= RAM del host; no protege contra OOM del host ni cgroup");
        }
    }

    let (tx, worker_handles) = trigger::spawn_worker_pool(
        config.audit_script_path.clone(),
        config.script_worker_threads,
        telegram_client.clone(),
        Arc::clone(&history),
        cooldowns.clone(),
        audit_groups.clone(),
        Duration::from_secs(config.audit_timeout_secs),
    );

    let mut scheduler_handles = Vec::new();
    if let Some(client) = &telegram_client {
        tracing::info!(
            "integracion con Telegram habilitada: status periodico y resumen semanal activos"
        );
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
            tx.normal.clone(),
        ));
    }

    // Hilo propio, independiente del loop de /proc: bloquea leyendo el
    // journal de sshd y no pasa por reglas ni cooldown.
    let ssh_watch_handle = if config.ssh_watch.enabled {
        tracing::info!(unit = %config.ssh_watch.unit_name, "monitoreo de logins SSH habilitado");
        Some(ssh_watch::spawn(
            Arc::clone(&config),
            Arc::clone(&shutdown),
            telegram_client.clone(),
        ))
    } else {
        None
    };

    run_loop(
        &config,
        &shutdown,
        &tx,
        &watched_count,
        cooldowns,
        &audit_groups,
    );

    tracing::info!("señal de apagado recibida, cerrando cola de auditoria y esperando workers");
    drop(tx);
    if let Some(handle) = ssh_watch_handle {
        handle.stop_and_join();
    }
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
    tx: &EventSender,
    watched_count: &AtomicUsize,
    mut cooldowns: CooldownTracker,
    audit_groups: &AuditGroups,
) {
    let ticks_per_sec = process::clock_ticks_per_sec();
    let page_size = process::page_size();
    let poll_interval = Duration::from_secs(config.poll_interval_secs);

    let mut states: HashMap<i32, ProcessState> = HashMap::new();
    let mut host_memory = rules::HostMemoryTracker::default();
    let mut root_batches = root_events::RootBatches::default();
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
            // Coordinar lectura y registro con spawn/cleanup del worker.
            let audit_registry = audit_groups.lock().unwrap();
            let sample = match process::read_process(pid, page_size, &mut stat_buf) {
                Some(s) => s,
                None => continue, // proceso desaparecio entre el listado y la lectura
            };
            let is_audit = audit_registry.contains(&sample.pgrp);
            drop(audit_registry);
            seen_pids.insert(pid);

            let now = Instant::now();
            // Patron Entry para evitar un doble borrow mutable de `states`
            // (get_mut en el brazo Some + insert en el brazo None sobre el
            // mismo mapa no compila de forma directa).
            let state: &mut ProcessState = match states.entry(pid) {
                Entry::Occupied(mut occ) => {
                    if occ.get().starttime != sample.starttime {
                        occ.insert(ProcessState::new(&sample, userdb.lookup(sample.uid), now));
                    }
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

            // Conservar procedencia para auxiliares ya finalizados/zombies.
            // update la revoca si abandonan el grupo; un PID nuevo empieza limpio.
            state.is_audit |= is_audit;
        }

        // Evaluar despues de recolectar: contexto de ancestros independiente
        // del orden en que readdir devuelve los PIDs.
        let root_contexts: HashMap<_, _> = seen_pids
            .iter()
            .map(|&pid| (pid, root_events::context(pid, &states)))
            .collect();
        for &pid in &seen_pids {
            let now = Instant::now();
            let state = states.get_mut(&pid).unwrap();
            let events = rules::evaluate(config, pid, state, now);
            for event in events {
                if event.kind == AnomalyKind::RootNotWhitelisted {
                    root_batches.observe(root_contexts[&pid].clone(), pid, state, now);
                } else {
                    dispatch(tx, &mut cooldowns, pid, state, event, now);
                }
            }
        }

        root_batches.flush(
            Duration::from_secs(config.rules.root_whitelist.group_window_secs),
            Instant::now(),
            tx,
            &cooldowns,
        );
        let memory_sample = hoststats::mem_total_available_kb();
        if memory_sample.is_none() {
            tracing::warn!("no se pudo leer MemAvailable/MemTotal");
        }
        if let Some(event) =
            host_memory.evaluate(&config.rules.host_memory, memory_sample, Instant::now())
        {
            tx.enqueue(
                TriggerJob {
                    pid: 0,
                    name: "host".into(),
                    user: "system".into(),
                    kind: event.kind,
                    detail: event.detail,
                    run_audit: true,
                    key: None,
                },
                EventKey::HostMemory,
                &cooldowns,
                Instant::now(),
            );
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
            check_network(
                config,
                &states,
                &pid_buf,
                tx,
                &mut cooldowns,
                &mut listen_baseline,
            );
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
    tx: &EventSender,
    cooldowns: &mut CooldownTracker,
    pid: i32,
    state: &ProcessState,
    event: rules::AnomalyEvent,
    now: Instant,
) {
    let key = EventKey::Process(pid, state.starttime, event.kind);
    let job = TriggerJob {
        pid,
        name: state.comm.clone(),
        user: state.username.clone(),
        kind: event.kind,
        detail: event.detail,
        run_audit: !state.is_audit,
        key: None,
    };
    tx.enqueue(job, key, cooldowns, now);
}

/// Orquesta las dos reglas de red, ambas gateadas por el mismo
/// `network.check_every_n_cycles` desde `run_loop`. El mapeo inodo->pid se
/// arma una sola vez y se comparte entre las dos: es el paso costoso
/// (recorre /proc/<pid>/fd de todos los procesos).
fn check_network(
    config: &Config,
    states: &HashMap<i32, ProcessState>,
    pids: &[i32],
    tx: &EventSender,
    cooldowns: &mut CooldownTracker,
    listen_baseline: &mut Option<HashSet<(i32, u16, network::Protocol)>>,
) {
    let inode_to_pid = network::build_inode_to_pid(pids);

    // Los sockets en escucha se leen una sola vez y sirven a las dos reglas:
    // `nuevo_puerto_listen` los compara contra su baseline y
    // `conexion_saliente_no_esperada` usa los puertos TCP en LISTEN para
    // reconocer conexiones entrantes.
    let mut listen_sockets = network::parse_listen_tcp("/proc/net/tcp", false);
    listen_sockets.extend(network::parse_listen_tcp("/proc/net/tcp6", true));
    listen_sockets.extend(network::parse_listen_udp("/proc/net/udp", false));
    listen_sockets.extend(network::parse_listen_udp("/proc/net/udp6", true));
    let tcp_listen_ports: HashSet<u16> = listen_sockets
        .iter()
        .filter(|s| s.protocol == network::Protocol::Tcp)
        .map(|s| s.local_port)
        .collect();

    check_unexpected_outbound(
        config,
        states,
        &inode_to_pid,
        &tcp_listen_ports,
        tx,
        cooldowns,
    );
    check_new_listen_ports(
        config,
        states,
        &inode_to_pid,
        &listen_sockets,
        tx,
        cooldowns,
        listen_baseline,
    );
}

/// Regla `conexion_saliente_no_esperada`: conexiones TCP ESTABLISHED
/// SALIENTES cuya IP remota no cae en ningun CIDR permitido (ni su puerto
/// esta en la whitelist de puertos remotos). Solo IPv4, igual que la
/// whitelist de CIDRs de la config.
///
/// /proc/net/tcp no distingue el sentido de un socket ESTABLISHED: una
/// sesion ssh entrante (local 22, remoto efimero) se ve igual que una
/// saliente. Sin este filtro cada login por ssh desde una IP fuera de los
/// CIDRs disparaba una falsa alerta. Las entrantes se descartan aca: si el
/// puerto local no deberia estar escuchando, es asunto de
/// `nuevo_puerto_listen`, no de esta regla.
fn check_unexpected_outbound(
    config: &Config,
    states: &HashMap<i32, ProcessState>,
    inode_to_pid: &HashMap<u64, i32>,
    tcp_listen_ports: &HashSet<u16>,
    tx: &EventSender,
    cooldowns: &mut CooldownTracker,
) {
    let connections = network::parse_tcp_connections("/proc/net/tcp");
    if connections.is_empty() {
        return;
    }
    let ephemeral = network::local_port_range();

    for conn in &connections {
        if network::is_inbound(
            conn,
            &config.network.allowed_listen_ports,
            tcp_listen_ports,
            ephemeral,
        ) {
            continue;
        }
        if network::is_allowed(
            conn,
            &config.network.allowed_remote_ports,
            &config.network.allowed_cidrs_v4,
        ) {
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
            detail: format!(
                "conexion saliente a {}:{} (puerto local {}) fuera de los CIDRs permitidos",
                conn.remote_ip, conn.remote_port, conn.local_port
            ),
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
    sockets: &[network::ListenSocket],
    tx: &EventSender,
    cooldowns: &mut CooldownTracker,
    baseline: &mut Option<HashSet<(i32, u16, network::Protocol)>>,
) {
    let mut current: HashMap<(i32, u16, network::Protocol), &network::ListenSocket> =
        HashMap::new();
    for sock in sockets {
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
            detail: format!(
                "{} escuchando en {}:{} (nuevo)",
                protocol.as_str(),
                sock.local_ip,
                port
            ),
        };
        dispatch(tx, cooldowns, pid, state, event, now);
    }

    *baseline = Some(current_keys);
}

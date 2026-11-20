//! Monitoreo de logins SSH exitosos leyendo el journal de sshd en tiempo
//! real. Es un modulo aparte del motor de anomalias: no hace polling de
//! /proc ni pasa por reglas, cooldown, pool de auditoria ni historial.
//!
//! Mecanismo: se lanza `journalctl -f -u <unit> -o cat -n 0` como
//! subproceso con stdout en un pipe y un hilo dedicado lo lee linea por
//! linea con `BufReader::lines()`. La lectura BLOQUEA hasta que journald
//! entrega una linea nueva, asi que sin logins el hilo no consume CPU.
//! `-n 0` evita que `-f` reproduzca las ultimas 10 lineas al arrancar (un
//! login de ayer no es un evento de hoy). `-o cat` deja solo el MESSAGE,
//! sin timestamp ni prefijo de host/unit, que es lo que se parsea.
//!
//! Solo se reconoce el patron de login exitoso:
//! `Accepted (password|publickey) for <user> from <ip> port <port> ...`
//! Cada match dispara una alerta inmediata a Telegram, sin cooldown: un
//! login exitoso es siempre relevante y poco frecuente.
//!
//! Si journalctl muere (rotacion de journald, señal, etc.) se loguea, se
//! espera un rato y se relanza; nunca tumba el daemon. En el shutdown el
//! hilo principal mata al subproceso para desbloquear la lectura.

use crate::config::Config;
use crate::signals;
use crate::telegram::{self, TelegramClient};
use crate::timefmt;
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Espera base entre reintentos de lanzar journalctl.
const RETRY_DELAY_MIN: Duration = Duration::from_secs(5);
/// Tope del backoff: si journalctl falla en cadena (binario ausente, unit
/// inexistente) no se spamea el log cada 5s para siempre.
const RETRY_DELAY_MAX: Duration = Duration::from_secs(60);
/// Si el subproceso vivio al menos este tiempo antes de morir, la caida
/// se considera aislada y el proximo reintento vuelve a la espera base.
const HEALTHY_RUN: Duration = Duration::from_secs(60);

/// Handle del hilo lector. `stop_and_join()` mata al journalctl en curso
/// (lo unico que desbloquea el `lines()`) y espera al hilo.
pub struct SshWatchHandle {
    child: Arc<Mutex<Option<Child>>>,
    thread: JoinHandle<()>,
}

impl SshWatchHandle {
    pub fn stop_and_join(self) {
        if let Ok(mut slot) = self.child.lock() {
            if let Some(child) = slot.as_mut() {
                let _ = child.kill();
            }
        }
        let _ = self.thread.join();
    }
}

/// Login exitoso parseado de una linea de sshd.
#[derive(Debug, PartialEq, Eq)]
pub struct SshLogin {
    pub user: String,
    pub ip: String,
    /// "password" | "publickey".
    pub method: String,
    pub port: u16,
}

pub fn spawn(
    config: Arc<Config>,
    shutdown: Arc<AtomicBool>,
    telegram: Option<Arc<TelegramClient>>,
) -> SshWatchHandle {
    let child: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(None));
    let child_slot = Arc::clone(&child);
    let thread = thread::Builder::new()
        .name("ssh-watch".to_string())
        .spawn(move || run(&config, &shutdown, telegram.as_deref(), &child_slot))
        .expect("no se pudo lanzar el hilo de ssh_watch");
    SshWatchHandle { child, thread }
}

fn run(
    config: &Config,
    shutdown: &AtomicBool,
    telegram: Option<&TelegramClient>,
    child_slot: &Mutex<Option<Child>>,
) {
    let unit = config.ssh_watch.unit_name.as_str();
    if telegram.is_none() {
        tracing::warn!(
            unit,
            "ssh_watch habilitado pero Telegram no esta disponible: los logins solo se van a loguear"
        );
    }
    let mut delay = RETRY_DELAY_MIN;

    while !shutdown.load(Ordering::Relaxed) {
        let started = Instant::now();
        match spawn_journalctl(unit) {
            Ok((child, stdout)) => {
                // Se guarda el Child bajo el lock chequeando `shutdown` en la
                // misma seccion critica: `stop_and_join()` solo se invoca con
                // la bandera ya en true, asi que o bien el hilo principal ve
                // el Child aca y lo mata, o bien este hilo ve la bandera y
                // lo mata el mismo. No hay ventana donde quede un journalctl
                // vivo con nadie leyendolo.
                if !store_child(child_slot, shutdown, child) {
                    break;
                }
                tracing::info!(unit, "ssh_watch: journalctl lanzado, esperando logins");
                read_stream(stdout, telegram);
                reap_child(child_slot, unit);
            }
            Err(e) => {
                tracing::error!(unit, error = %e, "ssh_watch: no se pudo lanzar journalctl");
            }
        }

        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        // Caida aislada (journalctl vivio un rato): se reintenta a los 5s.
        // Fallas en cadena (binario ausente, unit inexistente): backoff
        // 5s, 10s, 20s, 40s, 60s, 60s...
        if started.elapsed() >= HEALTHY_RUN {
            delay = RETRY_DELAY_MIN;
        }
        tracing::warn!(
            unit,
            retry_secs = delay.as_secs(),
            "ssh_watch: relanzando journalctl"
        );
        signals::sleep_interruptible(delay, shutdown);
        delay = (delay * 2).min(RETRY_DELAY_MAX);
    }
    tracing::info!("ssh_watch detenido");
}

fn spawn_journalctl(unit: &str) -> std::io::Result<(Child, ChildStdout)> {
    let mut child = Command::new("journalctl")
        .args(["-f", "-n", "0", "-o", "cat", "--no-pager", "-u", unit])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // stderr se hereda: si journalctl se queja (unit inexistente, sin
        // permisos) queda en el mismo journal/log que el daemon.
        .stderr(Stdio::inherit())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("stdout de journalctl no disponible"))?;
    Ok((child, stdout))
}

/// Devuelve `false` si el shutdown ya empezo (el child se mata aca mismo).
fn store_child(slot: &Mutex<Option<Child>>, shutdown: &AtomicBool, mut child: Child) -> bool {
    let mut guard = match slot.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if shutdown.load(Ordering::Relaxed) {
        let _ = child.kill();
        let _ = child.wait();
        return false;
    }
    *guard = Some(child);
    true
}

/// Saca el Child del slot y lo espera (reap), logueando como termino.
fn reap_child(slot: &Mutex<Option<Child>>, unit: &str) {
    let child = match slot.lock() {
        Ok(mut g) => g.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    };
    if let Some(mut child) = child {
        match child.wait() {
            Ok(status) => tracing::warn!(unit, status = %status, "ssh_watch: journalctl termino"),
            Err(e) => tracing::error!(unit, error = %e, "ssh_watch: fallo esperando a journalctl"),
        }
    }
}

/// Lee lineas hasta EOF (journalctl murio o lo mataron) o error de lectura.
fn read_stream(stdout: ChildStdout, telegram: Option<&TelegramClient>) {
    let reader = BufReader::new(stdout);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "ssh_watch: error leyendo stdout de journalctl");
                break;
            }
        };
        if let Some(login) = parse_accepted(&line) {
            handle_login(&login, telegram);
        }
    }
}

fn handle_login(login: &SshLogin, telegram: Option<&TelegramClient>) {
    let timestamp = timefmt::format_utc(timefmt::unix_now());
    tracing::info!(
        user = %login.user,
        ip = %login.ip,
        method = %login.method,
        port = login.port,
        "login SSH exitoso"
    );
    if let Some(client) = telegram {
        let text = telegram::format_ssh_login_alert(
            &login.user,
            &login.ip,
            &login.method,
            login.port,
            &timestamp,
        );
        if let Err(e) = client.send(&text) {
            tracing::error!(error = %e, "ssh_watch: fallo el envio de la alerta de login a Telegram");
        }
    }
}

/// Reconoce `Accepted (password|publickey) for <user> from <ip> port <port>`
/// en cualquier posicion de la linea (por si el formato de salida trae un
/// prefijo). Cualquier otro mensaje de sshd (fallos, desconexiones, otros
/// metodos de autenticacion) devuelve `None`.
pub fn parse_accepted(line: &str) -> Option<SshLogin> {
    const MARKER: &str = "Accepted ";
    let idx = line.find(MARKER)?;
    let mut tokens = line[idx + MARKER.len()..].split_whitespace();

    let method = tokens.next()?;
    if method != "password" && method != "publickey" {
        return None;
    }
    if tokens.next()? != "for" {
        return None;
    }
    let user = tokens.next()?;
    if tokens.next()? != "from" {
        return None;
    }
    let ip = tokens.next()?;
    if tokens.next()? != "port" {
        return None;
    }
    let port: u16 = tokens.next()?.parse().ok()?;

    Some(SshLogin {
        user: user.to_string(),
        ip: ip.to_string(),
        method: method.to_string(),
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_publickey_login() {
        let line = "Accepted publickey for sdiaz from 192.168.1.50 port 51234 ssh2: ED25519 SHA256:abc/def+ghi";
        let login = parse_accepted(line).expect("deberia matchear");
        assert_eq!(
            login,
            SshLogin {
                user: "sdiaz".into(),
                ip: "192.168.1.50".into(),
                method: "publickey".into(),
                port: 51234,
            }
        );
    }

    #[test]
    fn parses_password_login_ipv6() {
        let line = "Accepted password for root from 2001:db8::1 port 2222 ssh2";
        let login = parse_accepted(line).unwrap();
        assert_eq!(login.user, "root");
        assert_eq!(login.ip, "2001:db8::1");
        assert_eq!(login.method, "password");
        assert_eq!(login.port, 2222);
    }

    #[test]
    fn parses_with_prefix() {
        // Por si alguien cambia -o cat por un formato con prefijo.
        let line = "Aug 25 10:00:00 host sshd[1234]: Accepted publickey for u_1 from 10.0.0.2 port 40000 ssh2";
        let login = parse_accepted(line).unwrap();
        assert_eq!(login.user, "u_1");
        assert_eq!(login.ip, "10.0.0.2");
    }

    #[test]
    fn ignores_other_messages() {
        for line in [
            "Failed password for root from 1.2.3.4 port 5555 ssh2",
            "Accepted keyboard-interactive/pam for x from 1.2.3.4 port 1 ssh2",
            "Disconnected from user sdiaz 192.168.1.50 port 51234",
            "Accepted publickey for sdiaz from 192.168.1.50",
            "Accepted publickey for sdiaz from 192.168.1.50 port notanumber ssh2",
            "Accepted publickey for sdiaz from 192.168.1.50 port 99999 ssh2",
            "",
        ] {
            assert!(
                parse_accepted(line).is_none(),
                "no deberia matchear: {line:?}"
            );
        }
    }
}

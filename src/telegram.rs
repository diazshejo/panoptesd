//! Cliente Telegram (sincrono, via `ureq`) y formateo de los tipos de
//! mensaje: alerta de anomalia, login SSH exitoso, status cada 12h,
//! resumen semanal y mensaje externo (`--send-telegram`).
//!
//! El envio nunca puede tumbar el daemon: `send()` devuelve `Result` y
//! quien lo llama solo loguea el error, nunca hace `unwrap`/`expect` ni
//! propaga hacia el loop de monitoreo.

use crate::history::AuditRecord;
use crate::hoststats::DiskUsage;
use std::time::Duration;

pub struct TelegramClient {
    token: String,
    chat_id: String,
    agent: ureq::Agent,
}

impl TelegramClient {
    pub fn new(token: String, chat_id: String, timeout: Duration) -> Self {
        let agent = ureq::AgentBuilder::new().timeout(timeout).build();
        TelegramClient { token, chat_id, agent }
    }

    /// Envia `text` como mensaje de Telegram (Markdown legacy). Bloquea el
    /// hilo que lo llama hasta `timeout`; por eso nunca se llama desde el
    /// loop principal de monitoreo, solo desde los workers de auditoria y
    /// los threads de los schedulers.
    pub fn send(&self, text: &str) -> Result<(), String> {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.token);
        self.agent
            .post(&url)
            .send_form(&[
                ("chat_id", self.chat_id.as_str()),
                ("text", text),
                ("parse_mode", "Markdown"),
            ])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// Escapa los caracteres especiales del Markdown "legacy" de Telegram
/// (`_ * \` [`) en contenido que no controlamos (nombre de proceso, usuario,
/// detalle de la regla, tipo de anomalia, path de disco). Sin esto, un
/// numero impar de guiones bajos (p.ej. `conexion_saliente_no_esperada`)
/// deja una entidad sin cerrar y la API responde 400 "can't parse
/// entities": la alerta nunca llega.
///
/// Solo esos cuatro caracteres son escapables en Markdown legacy; `]`, `)`
/// o `\` sueltos son inertes y un backslash delante de ellos se mostraria
/// literalmente, asi que no se tocan. Aplicar SOLO a datos dinamicos, nunca
/// a los literales de formato del template.
pub fn escape_markdown(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '_' | '*' | '`' | '[') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Envuelve `s` en un span de codigo (`` `...` ``). Dentro de un span de
/// codigo Telegram copia el texto literal y NO interpreta escapes (un `\_`
/// se veria tal cual), asi que aqui no se escapa: el unico caracter que
/// puede romper el span es el backtick, que se sustituye por una comilla.
fn code_span(s: &str) -> String {
    format!("`{}`", s.replace('`', "'"))
}

pub fn format_anomaly_alert(pid: i32, name: &str, user: &str, kind: &str, detail: &str, timestamp: &str) -> String {
    format!(
        "🚨 *Anomalia detectada*\n\
         *Timestamp:* {timestamp}\n\
         *PID:* `{pid}`\n\
         *Proceso:* {}\n\
         *Usuario:* {}\n\
         *Tipo:* {}\n\
         *Detalle:* {}",
        code_span(name),
        escape_markdown(user),
        escape_markdown(kind),
        escape_markdown(detail),
    )
}

/// Alerta de login SSH exitoso (`ssh_watch`). Usuario e IP salen de texto
/// libre del journal de sshd, asi que se escapan igual que los campos
/// dinamicos de las alertas de anomalia; el metodo tambien, por si el
/// parser algun dia acepta variantes con `_`/`-`.
pub fn format_ssh_login_alert(user: &str, ip: &str, method: &str, port: u16, timestamp: &str) -> String {
    format!(
        "🔑 *Login SSH exitoso*\n\
         *Timestamp:* {timestamp}\n\
         *Usuario:* {}\n\
         *Origen:* {}\n\
         *Puerto origen:* `{port}`\n\
         *Metodo:* {}",
        escape_markdown(user),
        escape_markdown(ip),
        escape_markdown(method),
    )
}

/// Mensaje enviado desde afuera del daemon (`panoptesd --send-telegram`),
/// tipicamente por un script o un cron. Lleva su propio encabezado, como
/// los otros tres tipos de mensaje, para distinguirlo en el chat. El
/// cuerpo es texto libre que no controlamos (nombres de archivo con `_`,
/// timestamps, etc.): se escapa entero, igual que los campos dinamicos de
/// las alertas.
pub fn format_external_message(message: &str) -> String {
    format!("📣 *Mensaje de panoptesd*\n{}", escape_markdown(message))
}

#[allow(clippy::too_many_arguments)]
pub fn format_status_report(
    timestamp: &str,
    system_uptime: &str,
    cpu_pct: Option<f32>,
    mem_total_kb: Option<u64>,
    mem_avail_kb: Option<u64>,
    disks: &[DiskUsage],
    watched_count: usize,
    anomalies_last_12h: usize,
    daemon_version: &str,
    daemon_uptime: &str,
    last_anomaly: Option<&AuditRecord>,
) -> String {
    let mut msg = format!(
        "📊 *Status de panoptesd*\n\
         *Timestamp:* {timestamp}\n\n\
         *Servidor*\n\
         • Uptime: {system_uptime}\n"
    );

    match cpu_pct {
        Some(p) => msg.push_str(&format!("• CPU: {p:.1}%\n")),
        None => msg.push_str("• CPU: no disponible\n"),
    }

    match (mem_total_kb, mem_avail_kb) {
        (Some(total), Some(avail)) => {
            let used_pct = if total > 0 {
                100.0 * (1.0 - avail as f64 / total as f64)
            } else {
                0.0
            };
            msg.push_str(&format!(
                "• Memoria: {} usada / {} total ({used_pct:.0}%)\n",
                crate::hoststats::format_gb((total - avail) * 1024),
                crate::hoststats::format_gb(total * 1024),
            ));
        }
        _ => msg.push_str("• Memoria: no disponible\n"),
    }

    if disks.is_empty() {
        msg.push_str("• Disco: sin paths configurados\n");
    } else {
        for d in disks {
            let used = d.total_bytes.saturating_sub(d.avail_bytes);
            let used_pct = if d.total_bytes > 0 {
                100.0 * used as f64 / d.total_bytes as f64
            } else {
                0.0
            };
            msg.push_str(&format!(
                "• Disco {}: {} usado / {} total ({used_pct:.0}%)\n",
                escape_markdown(&d.path),
                crate::hoststats::format_gb(used),
                crate::hoststats::format_gb(d.total_bytes),
            ));
        }
    }

    msg.push_str(&format!(
        "\n*Monitoreo*\n\
         • Procesos vigilados: {watched_count}\n\
         • Anomalias (ultimas 12h): {anomalies_last_12h}\n\n\
         *Daemon*\n\
         • Version: {daemon_version}\n\
         • Corriendo hace: {daemon_uptime}\n"
    ));

    match last_anomaly {
        Some(a) => msg.push_str(&format!(
            "• Ultima anomalia: {} — {} (PID {}) — {}\n",
            escape_markdown(a.kind.as_str()),
            code_span(&a.name),
            a.pid,
            escape_markdown(&a.detail),
        )),
        None => msg.push_str("• Ultima anomalia: ninguna registrada\n"),
    }

    msg
}

pub fn format_weekly_summary(records: &[AuditRecord], week_start: &str, week_end: &str) -> String {
    let anomalies: Vec<&AuditRecord> = records.iter().filter(|r| r.kind.is_real_anomaly()).collect();
    let routine_count = records.len() - anomalies.len();

    if anomalies.is_empty() {
        let mut msg = format!(
            "🗂️ *Resumen semanal de auditoria*\n\
             *Periodo:* {week_start} — {week_end}\n\n\
             Sin anomalias esta semana."
        );
        if routine_count > 0 {
            msg.push_str(&format!(
                "\n(se corrieron {routine_count} auditoria(s) de rutina programada, sin hallazgos que reportar)"
            ));
        }
        return msg;
    }

    let mut msg = format!(
        "🗂️ *Resumen semanal de auditoria*\n\
         *Periodo:* {week_start} — {week_end}\n\
         *Auditorias por anomalia:* {}\n",
        anomalies.len()
    );
    if routine_count > 0 {
        msg.push_str(&format!("*Auditorias de rutina:* {routine_count}\n"));
    }
    msg.push('\n');

    for a in &anomalies {
        let ts = crate::timefmt::format_utc(a.unix_ts);
        let script_marker = if a.script_success { "✅" } else { "⚠️ script fallo" };
        msg.push_str(&format!(
            "• {ts} — PID `{}` {} ({}) — *{}*: {} \\[{script_marker}]\n",
            a.pid,
            code_span(&a.name),
            escape_markdown(&a.user),
            escape_markdown(a.kind.as_str()),
            escape_markdown(&a.detail),
        ));
    }

    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_markdown_escapes_only_legacy_special_chars() {
        assert_eq!(escape_markdown("a_b*c`d[e"), "a\\_b\\*c\\`d\\[e");
        // `]`, `)` y `\\` no son escapables en Markdown legacy: se dejan tal cual.
        assert_eq!(escape_markdown("x] (y) \\z"), "x] (y) \\z");
        assert_eq!(escape_markdown(""), "");
    }

    #[test]
    fn external_message_escapes_body_and_keeps_header() {
        let msg = format_external_message("backup_2026-08-25.tar.gz ok [3 files] *done*");
        let mut lines = msg.lines();
        assert_eq!(lines.next(), Some("📣 *Mensaje de panoptesd*"));
        assert_eq!(
            lines.next(),
            Some("backup\\_2026-08-25.tar.gz ok \\[3 files] \\*done\\*")
        );
        assert_eq!(lines.next(), None);
    }

    #[test]
    fn ssh_login_alert_escapes_user_and_ip_but_keeps_header() {
        let msg = format_ssh_login_alert("deploy_bot", "10.0.0.1", "publickey", 51234, "2026-08-25 10:00:00 UTC");
        assert!(msg.starts_with("🔑 *Login SSH exitoso*\n"));
        assert!(msg.contains("*Usuario:* deploy\\_bot\n"));
        assert!(msg.contains("*Origen:* 10.0.0.1\n"));
        assert!(msg.contains("*Puerto origen:* `51234`\n"));
        assert!(msg.contains("*Metodo:* publickey"));
        assert!(msg.contains("*Timestamp:* 2026-08-25 10:00:00 UTC\n"));
    }

    #[test]
    fn code_span_never_escapes_but_neutralizes_backticks() {
        assert_eq!(code_span("my_proc*"), "`my_proc*`");
        assert_eq!(code_span("a`b"), "`a'b`");
    }

    #[test]
    fn anomaly_alert_escapes_dynamic_fields_but_keeps_headers() {
        let msg = format_anomaly_alert(
            42,
            "python3_worker",
            "svc_user",
            "conexion_saliente_no_esperada",
            "conexion a 10.0.0.1:443 desde *algo* raro_",
            "2026-08-25 10:00:00 UTC",
        );
        assert!(msg.contains("*Tipo:* conexion\\_saliente\\_no\\_esperada"));
        assert!(msg.contains("*Usuario:* svc\\_user"));
        assert!(msg.contains("*Detalle:* conexion a 10.0.0.1:443 desde \\*algo\\* raro\\_"));
        // nombre de proceso va en code span sin escapes
        assert!(msg.contains("*Proceso:* `python3_worker`"));
        // los encabezados en negrita se conservan sin escapar
        assert!(msg.starts_with("🚨 *Anomalia detectada*\n"));
        assert!(msg.contains("*PID:* `42`"));
    }

    #[test]
    fn dynamic_fields_have_balanced_markers_after_escaping() {
        // Fuera de code spans, cada `_`/`*` dinamico debe ir precedido de `\\`.
        let msg = format_anomaly_alert(1, "p", "u_", "a_b_c", "d*e", "t");
        for line in msg.lines().filter(|l| !l.contains('`')) {
            let bytes = line.as_bytes();
            let mut i = 0;
            let mut unescaped_underscores = 0;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'_' {
                    unescaped_underscores += 1;
                }
                i += 1;
            }
            assert_eq!(unescaped_underscores, 0, "linea con `_` sin escapar: {line}");
        }
    }
}

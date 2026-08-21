//! Cliente Telegram (sincrono, via `ureq`) y formateo de los tres tipos de
//! mensaje: alerta de anomalia, status cada 12h, resumen semanal.
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
/// (`_ * \` [`) en contenido que no controlamos (nombre de proceso, detalle
/// de la regla). Sin esto, un nombre de proceso con un guion bajo o una
/// comilla suelta puede romper el parseo completo del mensaje en la API de
/// Telegram (responde 400 y la alerta nunca llega).
fn escape_md(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '_' | '*' | '`' | '[') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

pub fn format_anomaly_alert(pid: i32, name: &str, user: &str, kind: &str, detail: &str, timestamp: &str) -> String {
    format!(
        "🚨 *Anomalia detectada*\n\
         *Timestamp:* {timestamp}\n\
         *PID:* `{pid}`\n\
         *Proceso:* `{}`\n\
         *Usuario:* {}\n\
         *Tipo:* {kind}\n\
         *Detalle:* {}",
        escape_md(name),
        escape_md(user),
        escape_md(detail),
    )
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
                d.path,
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
            "• Ultima anomalia: {} — `{}` (PID {}) — {}\n",
            a.kind.as_str(),
            escape_md(&a.name),
            a.pid,
            escape_md(&a.detail),
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
            "• {ts} — PID `{}` `{}` ({}) — *{}*: {} [{script_marker}]\n",
            a.pid,
            escape_md(&a.name),
            escape_md(&a.user),
            a.kind.as_str(),
            escape_md(&a.detail),
        ));
    }

    msg
}

//! Metricas de sistema (no por-proceso) para el reporte de status cada
//! 12h: uptime, %CPU agregado, memoria, disco. Se leen bajo demanda, sin
//! mantener estado entre llamadas: esto corre dos veces por dia, asi que
//! ni el muestreo de 1 segundo para %CPU pesa en el presupuesto de
//! CPU/memoria del daemon.

use std::ffi::CString;
use std::fs;
use std::thread;
use std::time::Duration;

/// Uptime del servidor (no del daemon) en segundos, leido de /proc/uptime.
pub fn system_uptime_secs() -> Option<u64> {
    let content = fs::read_to_string("/proc/uptime").ok()?;
    let first = content.split_whitespace().next()?;
    first.parse::<f64>().ok().map(|f| f as u64)
}

/// %CPU agregado del sistema, muestreado con una ventana de `sample_for`.
/// Bloquea el hilo que lo llama durante ese tiempo (a proposito: solo lo
/// usa el scheduler de status, nunca el loop de monitoreo).
pub fn cpu_percent(sample_for: Duration) -> Option<f32> {
    let (idle0, total0) = read_proc_stat_cpu()?;
    thread::sleep(sample_for);
    let (idle1, total1) = read_proc_stat_cpu()?;

    let delta_idle = idle1.saturating_sub(idle0) as f32;
    let delta_total = total1.saturating_sub(total0) as f32;
    if delta_total <= 0.0 {
        return None;
    }
    Some((1.0 - delta_idle / delta_total) * 100.0)
}

fn read_proc_stat_cpu() -> Option<(u64, u64)> {
    let content = fs::read_to_string("/proc/stat").ok()?;
    let line = content.lines().next()?; // primera linea: "cpu  user nice system idle iowait irq softirq steal ..."
    let mut fields = line.split_whitespace();
    if fields.next() != Some("cpu") {
        return None;
    }
    let values: Vec<u64> = fields.filter_map(|f| f.parse::<u64>().ok()).collect();
    if values.len() < 5 {
        return None;
    }
    let idle = values[3] + values.get(4).copied().unwrap_or(0); // idle + iowait
    let total: u64 = values.iter().sum();
    Some((idle, total))
}

/// (total_kb, disponible_kb) de /proc/meminfo.
pub fn mem_total_available_kb() -> Option<(u64, u64)> {
    let content = fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = None;
    let mut available = None;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = parse_kb_field(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available = parse_kb_field(rest);
        }
    }
    Some((total?, available?))
}

fn parse_kb_field(s: &str) -> Option<u64> {
    s.trim().split_whitespace().next()?.parse().ok()
}

pub struct DiskUsage {
    pub path: String,
    pub total_bytes: u64,
    pub avail_bytes: u64,
}

/// Uso de disco por statvfs(2), sin depender de `df`/subprocesos. Se llama
/// para cada path configurado en `telegram.disk_paths`.
pub fn disk_usage(path: &str) -> Option<DiskUsage> {
    let c_path = CString::new(path).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return None;
    }
    let frsize = stat.f_frsize as u64;
    Some(DiskUsage {
        path: path.to_string(),
        total_bytes: frsize * stat.f_blocks as u64,
        avail_bytes: frsize * stat.f_bavail as u64,
    })
}

/// Formatea bytes como GB con un decimal (suficiente para un reporte,
/// no hace falta una crate de unidades para esto).
pub fn format_gb(bytes: u64) -> String {
    format!("{:.1}GB", bytes as f64 / 1_073_741_824.0)
}

/// Formatea un uptime en segundos como "Xd Yh Zm".
pub fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    format!("{days}d {hours}h {minutes}m")
}

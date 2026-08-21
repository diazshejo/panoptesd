//! Lectura manual de /proc/<pid>/stat y estado persistente por proceso.
//!
//! Se evita el crate `procfs` a proposito: aca solo necesitamos 4 campos
//! (comm, utime, stime, rss en paginas) de un unico archivo por proceso,
//! mas el uid (obtenido gratis via metadata del directorio /proc/<pid>,
//! sin abrir ni parsear /proc/<pid>/status). Parsear a mano con buffers
//! reutilizados evita allocaciones y lecturas de archivos que no usamos.

use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

/// Ticks de reloj por segundo del kernel (via sysconf), tipicamente 100.
pub fn clock_ticks_per_sec() -> u64 {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 {
        ticks as u64
    } else {
        100
    }
}

/// Tamaño de pagina de memoria del sistema (via sysconf), tipicamente 4096.
pub fn page_size() -> u64 {
    let sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if sz > 0 {
        sz as u64
    } else {
        4096
    }
}

/// Snapshot crudo de un proceso leido en el tick actual. El pid no se
/// guarda aca: quien llama a `read_process` ya lo tiene (es el argumento),
/// asi que agregarlo como campo seria un dato redundante sin uso.
pub struct ProcSample {
    pub comm: String,
    pub uid: u32,
    pub utime: u64,
    pub stime: u64,
    pub rss_bytes: u64,
}

/// Lee /proc/<pid>/stat y el uid (owner del directorio /proc/<pid>).
/// Devuelve None si el proceso desaparecio entre el readdir y esta lectura
/// (condicion de carrera normal, no es un error).
pub fn read_process(pid: i32, page_size: u64, buf: &mut String) -> Option<ProcSample> {
    let stat_path = format!("/proc/{}/stat", pid);

    buf.clear();
    let mut file = fs::File::open(&stat_path).ok()?;
    file.read_to_string(buf).ok()?;

    // comm puede contener espacios y parentesis, asi que se busca el
    // ultimo ')' para no confundir el parseo con el contenido del nombre.
    let last_paren = buf.rfind(')')?;
    let first_paren = buf.find('(')?;
    if first_paren >= last_paren {
        return None;
    }
    let comm = buf[first_paren + 1..last_paren].to_string();
    let rest = buf[last_paren + 1..].trim_start();

    // Array fijo en stack: evita el Vec heap-allocado de collect().
    // Indice 0 = campo "state" (campo 3 del /proc/<pid>/stat real).
    const N: usize = 22; // hasta el campo rss (campo 24) inclusive
    let mut fields: [&str; N] = [""; N];
    let mut it = rest.split_whitespace();
    for slot in fields.iter_mut() {
        *slot = it.next().unwrap_or("");
    }

    // utime = campo 14 -> indice post-comm 11
    // stime = campo 15 -> indice post-comm 12
    // rss   = campo 24 -> indice post-comm 21
    let utime: u64 = fields[11].parse().ok()?;
    let stime: u64 = fields[12].parse().ok()?;
    let rss_pages: u64 = fields[21].parse().ok()?;

    // uid: metadata del propio directorio /proc/<pid> refleja el euid del
    // proceso (evita parsear /proc/<pid>/status solo por esta linea).
    let uid = fs::metadata(format!("/proc/{}", pid)).ok()?.uid();

    Some(ProcSample {
        comm,
        uid,
        utime,
        stime,
        rss_bytes: rss_pages * page_size,
    })
}

/// Itera los PIDs actualmente vivos leyendo /proc (solo entradas numericas).
pub fn list_pids(buf: &mut Vec<i32>) {
    buf.clear();
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "no se pudo leer /proc");
            return;
        }
    };
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if let Ok(pid) = name.parse::<i32>() {
                buf.push(pid);
            }
        }
    }
}

/// Estado persistente de un proceso entre ciclos de polling. Vive en el
/// HashMap principal del loop y se actualiza in-place para minimizar
/// allocaciones (el String `comm`/`username` solo se reasigna si cambia).
pub struct ProcessState {
    pub comm: String,
    pub uid: u32,
    pub username: String,
    pub last_utime: u64,
    pub last_stime: u64,
    pub last_sample_at: Instant,
    pub cpu_percent: f32,
    pub cpu_over_since: Option<Instant>,
    pub rss_bytes: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

impl ProcessState {
    pub fn new(sample: &ProcSample, username: String, now: Instant) -> Self {
        ProcessState {
            comm: sample.comm.clone(),
            uid: sample.uid,
            username,
            last_utime: sample.utime,
            last_stime: sample.stime,
            last_sample_at: now,
            cpu_percent: 0.0,
            cpu_over_since: None,
            rss_bytes: sample.rss_bytes,
            first_seen: now,
            last_seen: now,
        }
    }

    /// Actualiza el estado con un nuevo sample y recalcula %CPU entre los
    /// dos puntos de muestreo (delta de ticks / tiempo real transcurrido).
    pub fn update(&mut self, sample: &ProcSample, now: Instant, ticks_per_sec: u64) {
        let elapsed = now.duration_since(self.last_sample_at).as_secs_f32();
        if elapsed > 0.0 {
            let delta_ticks = sample
                .utime
                .saturating_add(sample.stime)
                .saturating_sub(self.last_utime.saturating_add(self.last_stime));
            let delta_secs = delta_ticks as f32 / ticks_per_sec as f32;
            self.cpu_percent = (delta_secs / elapsed) * 100.0;
        }
        if sample.comm != self.comm {
            self.comm = sample.comm.clone();
        }
        self.uid = sample.uid;
        self.last_utime = sample.utime;
        self.last_stime = sample.stime;
        self.last_sample_at = now;
        self.rss_bytes = sample.rss_bytes;
        self.last_seen = now;
    }
}

//! Lectura manual de /proc/<pid>/stat y estado persistente por proceso.
//!
//! Se evita el crate `procfs`: se leen metricas e identidad de stat,
//! y el enlace exe para aportar contexto sin confiar solo en comm,
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
#[derive(Clone, Debug)]
pub struct ProcSample {
    pub comm: String,
    pub uid: u32,
    pub ppid: i32,
    pub starttime: u64,
    pub pgrp: i32,
    pub flags: u64,
    pub exe: Option<String>,
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

    let uid = fs::metadata(format!("/proc/{pid}")).ok()?.uid();
    let mut sample = parse_stat(buf, uid, page_size)?;
    sample.exe = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    Some(sample)
}

fn parse_stat(buf: &str, uid: u32, page_size: u64) -> Option<ProcSample> {
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

    // ppid  = campo 4  -> indice post-comm 1
    // utime = campo 14 -> indice post-comm 11
    // stime = campo 15 -> indice post-comm 12
    // rss   = campo 24 -> indice post-comm 21
    let ppid: i32 = fields[1].parse().ok()?;
    let utime: u64 = fields[11].parse().ok()?;
    let stime: u64 = fields[12].parse().ok()?;
    let rss_pages: u64 = fields[21].parse().ok()?;

    Some(ProcSample {
        comm,
        uid,
        ppid,
        starttime: fields[19].parse().ok()?,
        pgrp: fields[2].parse().ok()?,
        flags: fields[6].parse().ok()?,
        exe: None,
        utime,
        stime,
        rss_bytes: rss_pages.checked_mul(page_size)?,
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
    pub ppid: i32,
    pub username: String,
    pub starttime: u64,
    pub pgrp: i32,
    pub flags: u64,
    pub exe: Option<String>,
    pub is_audit: bool,
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
            ppid: sample.ppid,
            username,
            starttime: sample.starttime,
            pgrp: sample.pgrp,
            flags: sample.flags,
            exe: sample.exe.clone(),
            is_audit: false,
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
        self.ppid = sample.ppid;
        if self.pgrp != sample.pgrp {
            self.is_audit = false;
        }
        self.pgrp = sample.pgrp;
        self.flags = sample.flags;
        self.exe.clone_from(&sample.exe);
        self.last_utime = sample.utime;
        self.last_stime = sample.stime;
        self.last_sample_at = now;
        self.rss_bytes = sample.rss_bytes;
        self.last_seen = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_names_are_not_split_on_spaces_or_parentheses() {
        for name in ["9", "https", "(sa1)", "(fwupdmgr)", "a ) tricky (x)"] {
            // Campos 3..24, con valores distintos para detectar offsets erroneos.
            let stat =
                format!("42 ({name}) S 7 8 0 0 0 2097152 0 0 0 0 123 45 0 0 0 0 1 0 678 999 10\n");
            let s = parse_stat(&stat, 1000, 4096).unwrap();
            assert_eq!(s.comm, name);
            assert_eq!((s.ppid, s.pgrp, s.starttime), (7, 8, 678));
            assert_eq!(
                (s.utime, s.stime, s.rss_bytes, s.flags),
                (123, 45, 40960, 2097152)
            );
        }
        assert!(parse_stat("42 (broken) S", 0, 4096).is_none());
    }

    #[test]
    fn leaving_audit_group_revokes_exemption() {
        let now = Instant::now();
        let mut s = crate::test_support::state("sh", "/usr/bin/sh", 7, 123, now);
        s.is_audit = true;
        let sample = ProcSample {
            comm: "sh".into(),
            uid: 0,
            ppid: 1,
            starttime: 123,
            pgrp: 99,
            flags: 0,
            exe: Some("/usr/bin/sh".into()),
            utime: 0,
            stime: 0,
            rss_bytes: 4096,
        };
        s.update(&sample, now, 100);
        assert!(!s.is_audit);
        assert!(!ProcessState::new(&sample, "root".into(), now).is_audit);
    }

    #[test]
    fn real_proc_name_matches_comm_and_executable() {
        let pid = std::process::id() as i32;
        let sample = read_process(pid, page_size(), &mut String::new()).unwrap();
        let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap();
        assert_eq!(sample.comm, comm.trim_end());
        assert!(sample.exe.is_some());
        assert!(sample.starttime > 0);
    }
}

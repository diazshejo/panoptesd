//! Timestamps UTC via `libc` (gmtime_r + strftime), sin agregar una crate
//! de fechas: es una sola llamada FFI sobre una lib que ya enlazamos para
//! `sysconf`, y devuelve el mismo resultado que cualquier crate de fechas
//! daria para este caso de uso (formatear, nada de aritmetica de calendarios
//! ni zonas horarias).

use std::time::{SystemTime, UNIX_EPOCH};

/// Segundos desde epoch (UTC), tal como los espera `format_utc`.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Formatea segundos-desde-epoch como "YYYY-MM-DD HH:MM:SS UTC".
pub fn format_utc(unix_secs: u64) -> String {
    unsafe {
        let t = unix_secs as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        libc::gmtime_r(&t, &mut tm);

        let fmt = c"%Y-%m-%d %H:%M:%S UTC";
        let mut buf = [0u8; 32];
        let len = libc::strftime(buf.as_mut_ptr().cast(), buf.len(), fmt.as_ptr(), &tm);
        String::from_utf8_lossy(&buf[..len]).into_owned()
    }
}

/// Descompone segundos-desde-epoch en (dia de la semana 0=domingo..6=sabado,
/// hora UTC 0-23). Lo usa el scheduler semanal para saber si "ya toca".
pub fn weekday_and_hour(unix_secs: u64) -> (i32, i32) {
    unsafe {
        let t = unix_secs as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        libc::gmtime_r(&t, &mut tm);
        (tm.tm_wday, tm.tm_hour)
    }
}

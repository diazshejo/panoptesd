//! Registro de SIGTERM/SIGINT para shutdown limpio, y sleep interrumpible
//! para que el loop principal no tarde hasta `poll_interval_secs` completos
//! en reaccionar a una señal de parada.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub fn setup_shutdown_flag() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&flag))
        .expect("no se pudo registrar handler de SIGTERM");
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag))
        .expect("no se pudo registrar handler de SIGINT");
    flag
}

const SLEEP_SLICE: Duration = Duration::from_millis(200);

/// Duerme `total` de forma interrumpible: revisa el flag de shutdown cada
/// SLEEP_SLICE en vez de un solo sleep largo, para reaccionar rapido a
/// SIGTERM/SIGINT sin hacer busy-wait.
pub fn sleep_interruptible(total: Duration, shutdown: &AtomicBool) {
    let start = Instant::now();
    while start.elapsed() < total {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let remaining = total - start.elapsed();
        std::thread::sleep(remaining.min(SLEEP_SLICE));
    }
}

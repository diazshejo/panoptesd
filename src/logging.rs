//! Inicializacion de `tracing`: siempre a stdout (para journald bajo
//! systemd) y opcionalmente tambien a un archivo si se configura
//! `log_file`. Devuelve el/los guard(s) de los writers no bloqueantes;
//! hay que mantenerlos vivos durante toda la ejecucion del programa o se
//! pierden logs al hacer drop.

use crate::config::Config;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub struct LoggingGuards {
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

pub fn init(config: &Config) -> LoggingGuards {
    let filter = EnvFilter::try_new(&config.log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let stdout_layer = fmt::layer()
        .with_target(false)
        .with_writer(std::io::stdout);

    let (file_layer, guard) = match &config.log_file {
        Some(path) => {
            let path = std::path::Path::new(path);
            let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
            let filename = path
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "panoptesd.log".to_string());
            let file_appender = tracing_appender::rolling::never(dir, filename);
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            let layer = fmt::layer()
                .with_target(false)
                .with_ansi(false)
                .with_writer(non_blocking);
            (Some(layer), Some(guard))
        }
        None => (None, None),
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();

    LoggingGuards { _file_guard: guard }
}

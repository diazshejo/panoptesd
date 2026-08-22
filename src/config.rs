//! Carga y estructuras de configuracion (TOML).

use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Intervalo de polling en segundos.
    pub poll_interval_secs: u64,

    /// Nivel de log: "trace" | "debug" | "info" | "warn" | "error".
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Ruta de archivo de log opcional. Si no se especifica, solo se
    /// loguea a stdout (capturado por journald cuando corre bajo systemd).
    pub log_file: Option<String>,

    /// Ruta del script bash de auditoria a ejecutar ante una anomalia.
    pub audit_script_path: String,

    /// Cooldown (segundos) para no repetir el mismo disparo del mismo
    /// PID + tipo de anomalia en un periodo corto.
    pub cooldown_secs: u64,

    /// Cantidad de hilos del pool que ejecutan el script de auditoria.
    #[serde(default = "default_worker_threads")]
    pub script_worker_threads: usize,

    pub rules: RulesConfig,

    #[serde(default)]
    pub network: NetworkConfig,

    #[serde(default)]
    pub telegram: TelegramConfig,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_worker_threads() -> usize {
    2
}

#[derive(Debug, Deserialize, Clone)]
pub struct RulesConfig {
    pub cpu: CpuRuleConfig,
    pub memory: MemoryRuleConfig,
    pub root_whitelist: RootWhitelistConfig,
    pub ephemeral: EphemeralRuleConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CpuRuleConfig {
    pub enabled: bool,
    /// Umbral de %CPU (0-100, puede superar 100 en multicore) a partir del
    /// cual se empieza a contar el tiempo sostenido.
    pub threshold_percent: f32,
    /// Segundos que el proceso debe mantenerse por encima del umbral
    /// (sostenido, no un pico) antes de disparar la anomalia.
    pub sustained_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MemoryRuleConfig {
    pub enabled: bool,
    /// RSS maximo esperado en MB. Se prioriza el limite superior porque es
    /// el indicador practico de anomalia (fuga de memoria, cryptominer,
    /// proceso que acapara RAM); un minimo no aporta señal de anomalia.
    pub max_rss_mb: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RootWhitelistConfig {
    pub enabled: bool,
    /// Nombres de proceso (comm, tal como aparece en /proc/<pid>/stat)
    /// permitidos para correr como root sin generar alerta.
    pub allowed_names: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EphemeralRuleConfig {
    pub enabled: bool,
    /// Si un proceso aparece y desaparece en menos de esta cantidad de
    /// segundos, se considera sospechoso (posible cryptominer/malware que
    /// se relanza constantemente para evadir detección).
    pub max_lifetime_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Cada cuantos ciclos de polling se hace la correlacion de sockets
    /// (costosa: recorre /proc/<pid>/fd de todos los procesos).
    #[serde(default = "default_network_every")]
    pub check_every_n_cycles: u64,
    /// Puertos remotos considerados esperados/normales para la regla de
    /// conexiones salientes (`conexion_saliente_no_esperada`).
    #[serde(default)]
    pub allowed_remote_ports: Vec<u16>,
    /// Rangos IPv4 esperados en notacion CIDR (ej "10.0.0.0/8") para la
    /// misma regla de conexiones salientes.
    #[serde(default)]
    pub allowed_cidrs_v4: Vec<String>,
    /// Puertos locales en los que se espera que algo quede en LISTEN
    /// (tcp/tcp6) o bindeado (udp/udp6) — ej el puerto de sshd o el de un
    /// servicio propio. Un puerto nuevo que no este en esta lista dispara
    /// `nuevo_puerto_listen`.
    #[serde(default)]
    pub allowed_listen_ports: Vec<u16>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            enabled: false,
            check_every_n_cycles: default_network_every(),
            allowed_remote_ports: Vec::new(),
            allowed_cidrs_v4: Vec::new(),
            allowed_listen_ports: Vec::new(),
        }
    }
}

fn default_network_every() -> u64 {
    5
}

#[derive(Debug, Deserialize, Clone)]
pub struct TelegramConfig {
    /// El token y el chat_id NUNCA van aca: se leen de las variables de
    /// entorno TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID (via EnvironmentFile
    /// de systemd), para no dejar secretos en el repo ni en el archivo de
    /// config en texto plano.
    #[serde(default)]
    pub enabled: bool,
    /// Cada cuantas horas se envia el reporte de status.
    #[serde(default = "default_status_interval_hours")]
    pub status_interval_hours: u64,
    /// Dia (en ingles, minusculas) en que se envia el resumen semanal.
    #[serde(default = "default_weekly_day")]
    pub weekly_summary_day: String,
    /// Hora UTC (0-23) del resumen semanal.
    #[serde(default = "default_weekly_hour")]
    pub weekly_summary_hour: u8,
    /// Paths de particiones a reportar en el status (ej "/", "/var").
    #[serde(default = "default_disk_paths")]
    pub disk_paths: Vec<String>,
    /// Timeout (segundos) de las llamadas HTTP a la API de Telegram.
    #[serde(default = "default_telegram_timeout")]
    pub request_timeout_secs: u64,
}

impl Default for TelegramConfig {
    fn default() -> Self {
        TelegramConfig {
            enabled: false,
            status_interval_hours: default_status_interval_hours(),
            weekly_summary_day: default_weekly_day(),
            weekly_summary_hour: default_weekly_hour(),
            disk_paths: default_disk_paths(),
            request_timeout_secs: default_telegram_timeout(),
        }
    }
}

fn default_status_interval_hours() -> u64 {
    12
}

fn default_weekly_day() -> String {
    "sunday".to_string()
}

fn default_weekly_hour() -> u8 {
    23
}

fn default_disk_paths() -> Vec<String> {
    vec!["/".to_string()]
}

fn default_telegram_timeout() -> u64 {
    5
}

impl TelegramConfig {
    /// Convierte `weekly_summary_day` a un numero de dia de la semana
    /// (0=domingo..6=sabado, la misma convencion que `tm_wday` de libc).
    /// Dia invalido en la config -> domingo, con un warning al cargar.
    pub fn weekly_summary_weekday(&self) -> i32 {
        match self.weekly_summary_day.to_lowercase().as_str() {
            "sunday" | "domingo" => 0,
            "monday" | "lunes" => 1,
            "tuesday" | "martes" => 2,
            "wednesday" | "miercoles" | "miércoles" => 3,
            "thursday" | "jueves" => 4,
            "friday" | "viernes" => 5,
            "saturday" | "sabado" | "sábado" => 6,
            other => {
                tracing::warn!(
                    day = other,
                    "weekly_summary_day invalido, usando domingo por defecto"
                );
                0
            }
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let raw = fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("no se pudo leer config {:?}: {}", path, e))?;
        let cfg: Config = toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("config TOML invalida en {:?}: {}", path, e))?;
        Ok(cfg)
    }
}

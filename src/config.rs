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

    /// Cooldown desde entrega confirmada: por instancia+tipo, grupo root
    /// o memoria del host. No se consume ante fallos de cola/envio.
    pub cooldown_secs: u64,

    /// Cantidad de hilos del pool que ejecutan el script de auditoria.
    #[serde(default = "default_worker_threads")]
    pub script_worker_threads: usize,

    #[serde(default = "default_audit_timeout")]
    pub audit_timeout_secs: u64,

    pub rules: RulesConfig,

    #[serde(default)]
    pub network: NetworkConfig,

    #[serde(default)]
    pub telegram: TelegramConfig,

    #[serde(default)]
    pub ssh_watch: SshWatchConfig,
}

fn default_audit_timeout() -> u64 {
    30
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
    #[serde(default)]
    pub host_memory: HostMemoryConfig,
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
#[serde(default)]
pub struct HostMemoryConfig {
    pub enabled: bool,
    pub min_available_mb: u64,
    pub min_available_percent: f64,
    pub sustained_secs: u64,
}

impl Default for HostMemoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_available_mb: 256,
            min_available_percent: 15.0,
            sustained_secs: 10,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RootWhitelistConfig {
    pub enabled: bool,
    /// Nombres de proceso (comm, tal como aparece en /proc/<pid>/stat)
    /// permitidos para correr como root sin generar alerta.
    pub allowed_names: Vec<String>,
    /// Ventana para agrupar eventos relacionados; no es una whitelist.
    #[serde(default = "default_group_window")]
    pub group_window_secs: u64,
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

fn default_group_window() -> u64 {
    10
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

#[derive(Debug, Deserialize, Clone)]
pub struct SshWatchConfig {
    /// Habilita el hilo que sigue el journal de sshd (`journalctl -f`) y
    /// alerta por Telegram ante cada login exitoso. Independiente del loop
    /// de /proc y de las reglas: sin cooldown ni script de auditoria.
    #[serde(default)]
    pub enabled: bool,
    /// Unit de systemd del servidor SSH. "ssh.service" en Debian/Ubuntu;
    /// en Fedora/RHEL/Arch es "sshd.service". Ajustable sin recompilar.
    #[serde(default = "default_ssh_unit")]
    pub unit_name: String,
}

impl Default for SshWatchConfig {
    fn default() -> Self {
        SshWatchConfig {
            enabled: false,
            unit_name: default_ssh_unit(),
        }
    }
}

fn default_ssh_unit() -> String {
    "ssh.service".to_string()
}

impl Config {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.poll_interval_secs > 0,
            "poll_interval_secs debe ser > 0"
        );
        anyhow::ensure!(
            self.script_worker_threads > 0 && self.script_worker_threads <= 32,
            "script_worker_threads debe ser 1..32"
        );
        anyhow::ensure!(
            self.audit_timeout_secs > 0,
            "audit_timeout_secs debe ser > 0"
        );
        anyhow::ensure!(
            self.network.check_every_n_cycles > 0,
            "check_every_n_cycles debe ser > 0"
        );
        anyhow::ensure!(
            self.telegram.request_timeout_secs > 0,
            "request_timeout_secs debe ser > 0"
        );
        anyhow::ensure!(
            self.rules.memory.max_rss_mb > 0 && self.rules.memory.max_rss_mb <= u64::MAX / 1048576,
            "max_rss_mb fuera de rango"
        );
        let h = &self.rules.host_memory;
        anyhow::ensure!(
            h.min_available_percent.is_finite() && (0.0..100.0).contains(&h.min_available_percent),
            "min_available_percent debe estar en [0, 100)"
        );
        anyhow::ensure!(
            h.min_available_mb <= u64::MAX / 1024,
            "min_available_mb fuera de rango"
        );
        anyhow::ensure!(
            !h.enabled || h.min_available_mb > 0 || h.min_available_percent > 0.0,
            "host_memory requiere un umbral positivo"
        );
        Ok(())
    }

    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let raw = fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("no se pudo leer config {:?}: {}", path, e))?;
        let cfg: Config = toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("config TOML invalida en {:?}: {}", path, e))?;
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn example_and_old_config_load_with_host_protection() {
        let cfg = crate::test_support::config();
        cfg.validate().unwrap();
        let old = include_str!("../config/config.example.toml");
        let mut value: toml::Value = toml::from_str(old).unwrap();
        value["rules"].as_table_mut().unwrap().remove("host_memory");
        let old: Config = value.try_into().unwrap();
        assert!(old.rules.host_memory.enabled);
        old.validate().unwrap();
    }
    #[test]
    fn rejects_invalid_thresholds_and_intervals() {
        let cfg = crate::test_support::config();
        let mut c = cfg.clone();
        c.poll_interval_secs = 0;
        assert!(c.validate().is_err());
        let mut c = cfg.clone();
        c.network.check_every_n_cycles = 0;
        assert!(c.validate().is_err());
        let mut c = cfg.clone();
        c.rules.memory.max_rss_mb = u64::MAX;
        assert!(c.validate().is_err());
        let mut c = cfg.clone();
        c.rules.host_memory.min_available_percent = f64::NAN;
        assert!(c.validate().is_err());
        let mut c = cfg.clone();
        c.rules.host_memory.min_available_percent = 100.0;
        assert!(c.validate().is_err());
        let mut c = cfg;
        c.audit_timeout_secs = 0;
        assert!(c.validate().is_err());
    }
}

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
    /// Puertos remotos considerados esperados/normales.
    #[serde(default)]
    pub allowed_remote_ports: Vec<u16>,
    /// Rangos IPv4 esperados en notacion CIDR (ej "10.0.0.0/8").
    #[serde(default)]
    pub allowed_cidrs_v4: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            enabled: false,
            check_every_n_cycles: default_network_every(),
            allowed_remote_ports: Vec::new(),
            allowed_cidrs_v4: Vec::new(),
        }
    }
}

fn default_network_every() -> u64 {
    5
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

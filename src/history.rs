//! Historial en memoria de auditorias corridas (disparadas por anomalia o
//! por el scheduler semanal), compartido entre el pool de workers de
//! `trigger.rs` (que escribe) y los schedulers de Telegram (que leen).
//!
//! Vive solo en memoria: un reinicio del daemon a mitad de semana pierde
//! el historial acumulado (el resumen semanal siguiente arranca de nuevo).
//! Es una limitacion aceptada a proposito: persistirlo a disco para
//! sobrevivir reinicios agregaria I/O y un formato mas para mantener, a
//! cambio de un reporte que en el peor caso queda incompleto una vez cada
//! tanto. Documentado en el README.

use crate::rules::AnomalyKind;
use std::collections::VecDeque;
use std::sync::Mutex;

/// Cuanto tiempo se retienen los registros. Un poco mas de una semana para
/// darle margen al scheduler semanal si se atrasa.
const RETENTION_SECS: u64 = 9 * 24 * 3600;

#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub unix_ts: u64,
    pub pid: i32,
    pub name: String,
    pub user: String,
    pub kind: AnomalyKind,
    pub detail: String,
    pub script_success: bool,
}

pub struct AuditHistory {
    records: Mutex<VecDeque<AuditRecord>>,
}

impl AuditHistory {
    pub fn new() -> Self {
        AuditHistory {
            records: Mutex::new(VecDeque::new()),
        }
    }

    /// Agrega un registro y de paso descarta los que ya superaron la
    /// retencion (barrido perezoso, no hace falta un hilo aparte para esto).
    pub fn push(&self, record: AuditRecord) {
        let mut guard = self.records.lock().expect("mutex de historial envenenado");
        guard.push_back(record);
        let cutoff = self::unix_now_saturating(RETENTION_SECS);
        while guard.front().is_some_and(|r| r.unix_ts < cutoff) {
            guard.pop_front();
        }
    }

    /// Cantidad de anomalias reales (excluye auditorias de rutina) desde
    /// `since_unix`.
    pub fn count_real_anomalies_since(&self, since_unix: u64) -> usize {
        let guard = self.records.lock().expect("mutex de historial envenenado");
        guard
            .iter()
            .filter(|r| r.unix_ts >= since_unix && r.kind.is_real_anomaly())
            .count()
    }

    /// Ultima anomalia real registrada (para el reporte de status), sin
    /// importar la ventana de tiempo.
    pub fn last_real_anomaly(&self) -> Option<AuditRecord> {
        let guard = self.records.lock().expect("mutex de historial envenenado");
        guard
            .iter()
            .rev()
            .find(|r| r.kind.is_real_anomaly())
            .cloned()
    }

    /// Todos los registros (anomalias + auditorias de rutina) desde
    /// `since_unix`, para el resumen semanal.
    pub fn since(&self, since_unix: u64) -> Vec<AuditRecord> {
        let guard = self.records.lock().expect("mutex de historial envenenado");
        guard
            .iter()
            .filter(|r| r.unix_ts >= since_unix)
            .cloned()
            .collect()
    }
}

fn unix_now_saturating(retention_secs: u64) -> u64 {
    crate::timefmt::unix_now().saturating_sub(retention_secs)
}

#!/usr/bin/env bash
#
# Script de auditoria disparado por panoptesd ante una anomalia.
# Argumentos: $1=pid  $2=nombre_proceso  $3=usuario  $4=tipo_anomalia  $5=detalle (opcional)
#
# Captura estado del proceso, archivos abiertos y conexiones de red activas,
# y lo guarda todo en un log con timestamp para revision posterior.
#
# No usamos `set -e`: algunas herramientas (lsof, ss) pueden no estar
# instaladas o el proceso puede haber desaparecido entre la deteccion y la
# ejecucion de este script, y no queremos que eso aborte la auditoria a
# mitad de camino.
set -uo pipefail

PID="${1:-desconocido}"
PROC_NAME="${2:-desconocido}"
PROC_USER="${3:-desconocido}"
ANOMALY_TYPE="${4:-desconocido}"
DETAIL="${5:-}"

LOG_DIR="/var/log/panoptesd/audit"
TIMESTAMP="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
TIMESTAMP_FILE="$(date -u +'%Y%m%d_%H%M%S')"
LOG_FILE="${LOG_DIR}/audit_${TIMESTAMP_FILE}_pid${PID}.log"

mkdir -p "$LOG_DIR"

{
    echo "===================================================================="
    echo "AUDITORIA DE ANOMALIA - panoptesd"
    echo "===================================================================="
    echo "timestamp:     $TIMESTAMP"
    echo "pid:           $PID"
    echo "nombre:        $PROC_NAME"
    echo "usuario:       $PROC_USER"
    echo "tipo_anomalia: $ANOMALY_TYPE"
    echo "detalle:       $DETAIL"
    echo

    echo "--- Estado actual del proceso (ps) ---"
    if ps -p "$PID" -o pid,ppid,uid,user,pcpu,pmem,etimes,stat,cmd 2>/dev/null; then
        :
    else
        echo "[!] El proceso $PID ya no existe (posiblemente ya finalizo)."
    fi
    echo

    echo "--- Arbol de procesos padre/hijos ---"
    if command -v pstree >/dev/null 2>&1; then
        pstree -p -s "$PID" 2>/dev/null || echo "[!] pstree fallo o el proceso ya no existe."
    else
        echo "[!] pstree no disponible."
    fi
    echo

    echo "--- /proc/$PID/cmdline y /proc/$PID/exe ---"
    if [ -r "/proc/$PID/cmdline" ]; then
        tr '\0' ' ' < "/proc/$PID/cmdline"; echo
    else
        echo "[!] /proc/$PID/cmdline no accesible."
    fi
    if [ -e "/proc/$PID/exe" ]; then
        echo -n "exe -> "
        readlink -f "/proc/$PID/exe" 2>/dev/null || echo "[!] no se pudo resolver el binario."
    fi
    echo

    echo "--- Archivos abiertos (lsof) ---"
    if command -v lsof >/dev/null 2>&1; then
        lsof -p "$PID" 2>/dev/null || echo "[!] lsof no devolvio datos (proceso finalizado o sin permisos)."
    else
        echo "[!] lsof no disponible, se omite."
    fi
    echo

    echo "--- Conexiones de red activas del proceso (ss) ---"
    if command -v ss >/dev/null 2>&1; then
        ss -tunap 2>/dev/null | awk -v pid="$PID" 'NR==1 || $0 ~ ("pid="pid",")'
    elif command -v netstat >/dev/null 2>&1; then
        echo "[!] ss no disponible, usando netstat."
        netstat -tunap 2>/dev/null | grep -E "^Proto|/${PID}/" || echo "[!] sin coincidencias en netstat."
    else
        echo "[!] ni ss ni netstat disponibles."
    fi
    echo

    echo "--- Conexiones de red del sistema (contexto general) ---"
    if command -v ss >/dev/null 2>&1; then
        ss -tunap 2>/dev/null | head -n 50
    fi
    echo

    echo "--- Usuarios conectados al sistema (contexto) ---"
    who 2>/dev/null || echo "[!] who no disponible."
    echo

    echo "===================================================================="
    echo "Fin de auditoria para PID $PID"
    echo "===================================================================="
} >> "$LOG_FILE" 2>&1

logger -t panoptesd-audit "Anomalia '$ANOMALY_TYPE' en PID $PID ($PROC_NAME, usuario $PROC_USER). Detalle guardado en $LOG_FILE" 2>/dev/null || true

exit 0

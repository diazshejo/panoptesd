#!/usr/bin/env bash
# Backup semanal de Dropsmart. Las credenciales siguen en la config de mysql de root.
set -Eeuo pipefail
umask 077
BACKUP_DIR="${BACKUP_MYSQL_DIR:-/home/deploy/backups}"
RETENTION_DAYS=30
stamp="$(date +%Y%m%d_%H%M%S)_$$"
mkdir -p "$BACKUP_DIR"
dump_tmp=$(mktemp "$BACKUP_DIR/.database.XXXXXX")
grants_tmp=""
cleanup() { rm -f -- "$dump_tmp" "$grants_tmp"; }
trap cleanup EXIT
grants_tmp=$(mktemp "$BACKUP_DIR/.grants.XXXXXX")
trap 'echo "ERROR: el backup no terminó correctamente; se conservan los respaldos anteriores." >&2' ERR

# pipefail evita comprimir un volcado incompleto y anunciarlo como válido.
mysqldump -u root --routines --triggers --events --single-transaction \
    --flush-logs --databases dropsmart | gzip > "$dump_tmp"
gzip -t "$dump_tmp"

# Consultar cuentas reales en lugar de asumir tres redes de Docker fijas.
hosts=$(mysql --batch --skip-column-names -u root \
    -e "SELECT Host FROM mysql.user WHERE User = 'dropsmart';")
[[ -n "$hosts" ]] || { echo 'ERROR: no se encontraron cuentas de dropsmart para respaldar permisos.' >&2; exit 1; }
while IFS= read -r host; do
    # El host proviene de mysql.user. Escapar comillas y barras para el literal SQL.
    escaped=${host//\\/\\\\}
    escaped=${escaped//\'/\'\'}
    mysql --batch --skip-column-names -u root \
        -e "SHOW GRANTS FOR 'dropsmart'@'$escaped';" | sed 's/$/;/' >> "$grants_tmp"
done <<< "$hosts"
[[ -s "$grants_tmp" ]] || { echo 'ERROR: el respaldo de permisos está vacío.' >&2; exit 1; }

backup_file="$BACKUP_DIR/dropsmart_$stamp.sql.gz"
grants_file="$BACKUP_DIR/dropsmart_grants_$stamp.txt"
mv -- "$dump_tmp" "$backup_file"
mv -- "$grants_tmp" "$grants_file"
# Solo eliminar respaldos vencidos después de crear y verificar el nuevo.
find "$BACKUP_DIR" -maxdepth 1 -type f -name 'dropsmart_*.sql.gz' -mtime +"$RETENTION_DAYS" -delete
find "$BACKUP_DIR" -maxdepth 1 -type f -name 'dropsmart_grants_*.txt' -mtime +"$RETENTION_DAYS" -delete
printf 'Backup de MySQL y permisos completado: %s\n' "$backup_file"

#!/bin/sh
set -e

BACKUP_DEST="${BACKUP_DEST_PATH:-/backups}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILENAME="reconx_${TIMESTAMP}.dump.gz"
FILEPATH="${BACKUP_DEST}/${FILENAME}"

mkdir -p "${BACKUP_DEST}"

echo "[$(date -Iseconds)] Starting backup to ${FILEPATH}"

if pg_dump \
    --format=custom \
    --host="${POSTGRES_HOST:-postgres}" \
    --port="${POSTGRES_PORT:-5432}" \
    --username="${POSTGRES_USER}" \
    --dbname="${POSTGRES_DB}" \
    | gzip > "${FILEPATH}"; then
    SIZE=$(stat -c%s "${FILEPATH}" 2>/dev/null || stat -f%z "${FILEPATH}")
    echo "[$(date -Iseconds)] Backup complete: file=${FILENAME} size=${SIZE} bytes"
else
    echo "[$(date -Iseconds)] ERROR: Backup failed" >&2
    rm -f "${FILEPATH}"
    exit 1
fi

# Prune old backups
echo "[$(date -Iseconds)] Pruning backups older than ${RETENTION_DAYS} days"
find "${BACKUP_DEST}" -name "reconx_*.dump.gz" -mtime "+${RETENTION_DAYS}" -delete
echo "[$(date -Iseconds)] Pruning complete"

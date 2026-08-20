#!/usr/bin/env bash
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${BACKUP_DIR:?BACKUP_DIR is required and must be an explicit directory}"

if [[ "${BACKUP_DIR}" != /* || "${BACKUP_DIR}" == "/" ]]; then
  echo "BACKUP_DIR must be an absolute, non-root directory" >&2
  exit 2
fi

umask 077
mkdir -p -- "${BACKUP_DIR}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_file="${BACKUP_DIR}/wms-gsp-${timestamp}.dump"

pg_dump --dbname="${DATABASE_URL}" --format=custom --file="${backup_file}"
sha256sum "${backup_file}" > "${backup_file}.sha256"

echo "backup=${backup_file}"
echo "checksum=${backup_file}.sha256"

#!/usr/bin/env bash
set -euo pipefail

: "${BACKUP_FILE:?BACKUP_FILE is required}"
: "${RESTORE_DATABASE_URL:?RESTORE_DATABASE_URL is required}"
: "${RESTORE_TARGET_REF:?RESTORE_TARGET_REF is required and must not contain credentials}"
: "${RESTORE_EVIDENCE_DIR:?RESTORE_EVIDENCE_DIR is required}"
: "${ALLOW_NON_PRODUCTION_RESTORE:?Set ALLOW_NON_PRODUCTION_RESTORE=true for an isolated drill database}"

PYTHON_BIN="${PYTHON_BIN:-python3}"
CHECKSUM_FILE="${CHECKSUM_FILE:-${BACKUP_FILE}.sha256}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${ALLOW_NON_PRODUCTION_RESTORE}" != "true" ]]; then
  echo "Restore refused: ALLOW_NON_PRODUCTION_RESTORE must be true" >&2
  exit 2
fi

for path_name in BACKUP_FILE CHECKSUM_FILE RESTORE_EVIDENCE_DIR; do
  path_value="${!path_name}"
  if [[ "${path_value}" != /* || "${path_value}" == "/" ]]; then
    echo "${path_name} must be an absolute, non-root path" >&2
    exit 2
  fi
done

if [[ ! -f "${BACKUP_FILE}" || ! -f "${CHECKSUM_FILE}" ]]; then
  echo "Backup or checksum file is missing" >&2
  exit 2
fi

if [[ "$(dirname -- "${BACKUP_FILE}")" != "$(dirname -- "${CHECKSUM_FILE}")" ]]; then
  echo "CHECKSUM_FILE must be stored beside BACKUP_FILE" >&2
  exit 2
fi

umask 077
mkdir -p -- "${RESTORE_EVIDENCE_DIR}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
evidence_file="${RESTORE_EVIDENCE_DIR}/restore-drill-${timestamp}.json"

(
  cd -- "$(dirname -- "${BACKUP_FILE}")"
  sha256sum --check "$(basename -- "${CHECKSUM_FILE}")" >/dev/null
)
pg_restore --list "${BACKUP_FILE}" >/dev/null

existing_tables="$(psql "${RESTORE_DATABASE_URL}" -Atqc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'")"
if [[ "${existing_tables}" != "0" ]]; then
  echo "Restore refused: drill database is not empty" >&2
  exit 3
fi

pg_restore \
  --dbname="${RESTORE_DATABASE_URL}" \
  --exit-on-error \
  --no-owner \
  --no-privileges \
  "${BACKUP_FILE}"

checks="$(
  APP_ENV=development \
  AUTO_CREATE_SCHEMA=false \
  DATABASE_URL="${RESTORE_DATABASE_URL}" \
  "${PYTHON_BIN}" "${script_dir}/check-restored-db.py"
)"
completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
checksum="$(cut -d ' ' -f1 "${CHECKSUM_FILE}")"

printf '{"status":"PASS","started_at":"%s","completed_at":"%s","backup_checksum_sha256":"%s","restore_target_ref":"%s","checks":%s}\n' \
  "${started_at}" "${completed_at}" "${checksum}" "${RESTORE_TARGET_REF}" "${checks}" \
  > "${evidence_file}"

echo "evidence=${evidence_file}"

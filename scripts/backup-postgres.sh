#!/usr/bin/env bash
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${BACKUP_DIR:?BACKUP_DIR is required and must be an explicit directory}"
: "${OFFSITE_BACKUP_DIR:?OFFSITE_BACKUP_DIR is required and must be a different mount or site}"
: "${BACKUP_ALERT_DIR:?BACKUP_ALERT_DIR is required for durable failure alerts}"

RETENTION_DAYS="${RETENTION_DAYS:-90}"
ALLOW_SAME_FILESYSTEM_FOR_TESTS="${ALLOW_SAME_FILESYSTEM_FOR_TESTS:-false}"
REGISTER_BACKUP_EVIDENCE="${REGISTER_BACKUP_EVIDENCE:-true}"
WMS_APP_DIR="${WMS_APP_DIR:-/opt/wms-gsp}"
WMS_PYTHON="${WMS_PYTHON:-${WMS_APP_DIR}/.venv/bin/python}"

for directory_name in BACKUP_DIR OFFSITE_BACKUP_DIR BACKUP_ALERT_DIR; do
  directory_value="${!directory_name}"
  if [[ "${directory_value}" != /* || "${directory_value}" == "/" ]]; then
    echo "${directory_name} must be an absolute, non-root directory" >&2
    exit 2
  fi
done

if [[ "${BACKUP_DIR}" == "${OFFSITE_BACKUP_DIR}" ]]; then
  echo "OFFSITE_BACKUP_DIR must differ from BACKUP_DIR" >&2
  exit 2
fi

if [[ ! "${RETENTION_DAYS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "RETENTION_DAYS must be a positive integer" >&2
  exit 2
fi

umask 077
mkdir -p -- "${BACKUP_DIR}" "${OFFSITE_BACKUP_DIR}" "${BACKUP_ALERT_DIR}"

primary_source="$(findmnt -n -o SOURCE --target "${BACKUP_DIR}")"
offsite_source="$(findmnt -n -o SOURCE --target "${OFFSITE_BACKUP_DIR}")"
if [[
  "${primary_source}" == "${offsite_source}"
  && "${ALLOW_SAME_FILESYSTEM_FOR_TESTS}" != "true"
]]; then
  echo "OFFSITE_BACKUP_DIR must use a different filesystem or remote mount" >&2
  exit 2
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
backup_name="wms-gsp-${timestamp}.dump"
backup_file="${BACKUP_DIR}/${backup_name}"
temporary_file="${BACKUP_DIR}/.${backup_name}.partial"
evidence_file="${BACKUP_DIR}/${backup_name}.evidence.json"

on_exit() {
  exit_code=$?
  if [[ ${exit_code} -ne 0 ]]; then
    completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    alert_file="${BACKUP_ALERT_DIR}/wms-gsp-backup-failed-${timestamp}.json"
    printf '{"backup_id":"%s","backup_type":"FULL","status":"FAILED","scheduled_for":"%s","started_at":"%s","completed_at":"%s","evidence_ref":"%s","alert_evidence_ref":"%s"}\n' \
      "${timestamp}" "${started_at}" "${started_at}" "${completed_at}" \
      "${alert_file}" "${alert_file}" > "${alert_file}"
    echo "alert=${alert_file}" >&2
    if [[ "${REGISTER_BACKUP_EVIDENCE}" == "true" ]]; then
      if ! "${WMS_PYTHON}" "${WMS_APP_DIR}/scripts/register_backup_evidence.py" "${alert_file}"; then
        echo "failed to register backup failure evidence; durable alert retained at ${alert_file}" >&2
      fi
    fi
  fi
  if [[ -f "${temporary_file}" ]]; then
    rm -f -- "${temporary_file}"
  fi
}
trap on_exit EXIT

pg_dump --dbname="${DATABASE_URL}" --format=custom --file="${temporary_file}"
pg_restore --list "${temporary_file}" >/dev/null
mv -- "${temporary_file}" "${backup_file}"

(
  cd -- "${BACKUP_DIR}"
  sha256sum "${backup_name}" > "${backup_name}.sha256"
)

cp --preserve=mode,timestamps -- \
  "${backup_file}" \
  "${backup_file}.sha256" \
  "${OFFSITE_BACKUP_DIR}/"
(
  cd -- "${OFFSITE_BACKUP_DIR}"
  sha256sum --check "${backup_name}.sha256" >/dev/null
)

completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
retention_until="$(date -u -d "+${RETENTION_DAYS} days" +%Y-%m-%dT%H:%M:%SZ)"
checksum="$(cut -d ' ' -f1 "${backup_file}.sha256")"
size_bytes="$(stat -c %s "${backup_file}")"

printf '{"backup_id":"%s","backup_type":"FULL","status":"SUCCESS","scheduled_for":"%s","started_at":"%s","completed_at":"%s","checksum_sha256":"%s","size_bytes":%s,"primary_storage_ref":"%s","offsite_storage_ref":"%s","retention_until":"%s","evidence_ref":"%s"}\n' \
  "${timestamp}" "${started_at}" "${started_at}" "${completed_at}" "${checksum}" \
  "${size_bytes}" "${backup_file}" "${OFFSITE_BACKUP_DIR}/${backup_name}" \
  "${retention_until}" "${evidence_file}" > "${evidence_file}"

if [[ "${REGISTER_BACKUP_EVIDENCE}" == "true" ]]; then
  "${WMS_PYTHON}" "${WMS_APP_DIR}/scripts/register_backup_evidence.py" "${evidence_file}"
fi

trap - EXIT

echo "backup=${backup_file}"
echo "checksum=${backup_file}.sha256"
echo "offsite_backup=${OFFSITE_BACKUP_DIR}/${backup_name}"
echo "evidence=${evidence_file}"

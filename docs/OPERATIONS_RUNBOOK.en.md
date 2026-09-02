# Secrets, Backup, and Recovery Operations Runbook

[中文](OPERATIONS_RUNBOOK.md) | [English](OPERATIONS_RUNBOOK.en.md)

This runbook describes the backend operational controls. Example paths and schedules are not company SOPs. IT,
Quality, and Information Security must approve target configuration, retention, RTO/RPO, review frequency, and alert
escalation before production use.

## 1. Secret Management

Production values are injected through environment variables supplied by an external secret service, container
secret, or controlled file. Never put secret values in the repository, image, systemd unit, or ticket text.

```text
APP_ENV=production
SECRETS_PROVIDER=azure-key-vault
SECRET_KEY_VERSION_REF=kv://wms-gsp/jwt/version-id
DATABASE_CREDENTIAL_VERSION_REF=kv://wms-gsp/postgres/version-id
LDAP_CREDENTIAL_VERSION_REF=kv://wms-gsp/ldap/version-id
```

Version references are non-secret identifiers, not passwords, tokens, or connection strings. The LDAP version
reference is unnecessary when no bind service account is used.

Choose exactly one LDAP transport mode:

| Mode | Configuration | Control |
|---|---|---|
| LDAPS | `LDAP_USE_SSL=true` | Preferred; normally port 636 with certificate validation |
| StartTLS | `LDAP_START_TLS=true` | Upgrade port 389 to TLS before sending credentials |
| Plain 389 | `LDAP_ALLOW_PLAINTEXT_AUTH=true` | Disabled by default; approved isolated-network exception only |

Plain mode produces the readiness warning `LDAP_PLAINTEXT_AUTH_ENABLED`. The change record must document risk
acceptance, network isolation, access restrictions, and compensating controls. Bind passwords remain externally
injected in every mode.

Controlled rotation requires request, independent quality approval, implementation by a different system
administrator, and verification by an auditor or independent quality reviewer. Failed attempts remain as evidence.

## 2. Daily Backup

Reference systemd units are in `deploy/systemd/`. Deploy scripts under `/opt/wms-gsp/scripts/` and protect
`/etc/wms-gsp/backup.env` with mode `0600`.

```text
DATABASE_URL=<injected by the secret provider>
BACKUP_DIR=/var/backups/wms-gsp
OFFSITE_BACKUP_DIR=/mnt/wms-gsp-offsite
BACKUP_ALERT_DIR=/var/lib/wms-gsp/alerts
RETENTION_DAYS=90
```

The offsite path must be a different failure domain. The backup script creates a custom-format PostgreSQL dump,
calculates SHA-256 and size evidence, copies it offsite, writes success or failure JSON, and automatically registers
that JSON in the application evidence ledger. Registration is idempotent. Alert-file creation is evidence, not a
substitute for an actual monitored alert channel.

## 3. Environmental Offline Scan

The reference timer periodically scans approved monitoring assignments and creates device-offline alarms. It may
hold affected batches according to severity and workflow rules. This baseline does not connect a physical gateway or
send messages to external alert channels.

## 4. Expiry Control

The daily expiry scan uses an electronically approved policy. It creates or reopens alerts when their review date is
due, records maintenance/warning evidence, and applies stop-sale and quality holds at the approved threshold.
Closing an alert does not automatically release a quality hold.

## 5. Readiness and Audit Verification

- `/health` is liveness only.
- readiness verifies database access, the expected Alembic revision (`20260902_25`), and operational warnings.
- scheduled audit-chain verification persists event count, break position, result, and evidence reference.
- production supervisors should restart failed processes and alert on readiness failure, timer failure, outbox
  backlog, backup evidence failure, and chain-verification failure.

## 6. Isolated Restore Exercise

Restore to an isolated PostgreSQL instance. Verify the dump checksum, run the approved restore command, confirm the
schema revision, reconcile critical record counts and selected hash chains, measure RTO/RPO, and retain executor,
reviewer, timestamps, logs, deviations, and final independent verification. Never overwrite production for a test.

## 7. Target-Environment Acceptance Still Required

- approved secret service, initial dual-controlled rotation and rollback;
- enabled backup/audit/expiry/environment timers, real offsite or offline media, and monitored alert escalation;
- first independent restore exercise;
- physical temperature/humidity gateway, alert channels, offline replay, and clock synchronization;
- production JZT adapter, joint testing, reconciliation, and failed-message replay;
- SOPs, role matrix, training, change records, and the complete CSV package.

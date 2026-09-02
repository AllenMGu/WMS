# WMS / Pharmaceutical GSP Quality Management System

[中文](README.md) | [English](README.en.md)

[CI](https://github.com/AllenMGu/WMS/actions/workflows/ci.yml) ·
[GSP Gap Matrix](docs/GSP_GAP_ANALYSIS.en.md) ·
[CSV Validation Plan](docs/VALIDATION_PLAN.en.md) ·
[Target Architecture](docs/ARCHITECTURE.en.md) ·
[Operations Runbook](docs/OPERATIONS_RUNBOOK.en.md)

This repository contains the backend of the WMS/GSP system: the FastAPI service, database models and migrations,
automated tests, controlled-operation scripts, and validation design material. The clients are maintained separately:

- [WMS Web frontend](https://github.com/AllenMGu/WMS-frontend)
- [WMS WeChat Mini Program](https://github.com/AllenMGu/WMS-miniprogram)

Compatibility-period WMS endpoints remain under `/api`; controlled pharmaceutical workflows are under `/api/gsp`.
See the [repository split guide](docs/REPOSITORY_SPLIT.en.md) for release and deployment boundaries.

Current version: `0.16.0`. This is an engineering baseline for further development and validation, not a
commercial product approved for direct use in regulated pharmaceutical operations.

> Software alone does not demonstrate GSP compliance. Production release also requires approved procedures,
> role and access matrices, qualified master data, training, risk assessment, computerized-system validation,
> restore exercises, and ongoing change control.

## Implementation Status

The software baseline now covers:

- quality master data, partner qualification, product approval, and batch-controlled stock;
- approved purchasing, receipt, independent acceptance, sampling, and controlled printing;
- approved sales, FEFO reservation, picking, packing, trace-code verification, independent dispatch review, and shipment;
- carrier qualification, vehicle/driver control, transit events, excursions, proof of delivery, and independent closure;
- sales returns, quarantine and inspection, recalls, nonconforming-product disposition, destruction, and purchase returns;
- maintenance planning, approved expiry thresholds, recurring expiry review, automatic stop-sale and quality holds;
- blind batch stocktaking, transaction freeze, variance/CAPA references, controlled adjustment, and print evidence;
- least-privilege roles, segregation of duties, periodic review, expiry, and deprovisioning;
- append-only audit, electronic-signature, and environmental-reading hash chains with PostgreSQL serialization;
- deterministic transactional outbox claims, retry, dead-letter handling, and signed replay;
- persistent account/IP login protection, production readiness checks, backup evidence, and restore governance.
- partner periodic review, quality-system surveys, risk/CAPA, audits, deviations, complaints, incidents and adverse reactions;
- training and job assessment, controlled-document lifecycle, and facility/equipment qualification and calibration.
- owner-only CAPA task retrieval and evidence submission, followed by independent quality verification;
- controlled legacy-GSP archive batches with mapping versions, digest verification, independent reconciliation,
  immutable searchable records, and JSONL export.

Four items are intentionally deferred from this delivery:

1. the formal pharmaceutical traceability-platform adapter;
2. connection to the physical temperature/humidity gateway and external alert channels;
3. the production JZT adapter and formal joint integration testing;
4. the complete approved CSV validation package.

## LDAP Transport Modes

LDAP credentials and bind passwords must be injected at runtime and must never be saved through an API or committed
to the repository. Exactly one transport mode may be selected:

| Mode | Configuration | Intended use |
|---|---|---|
| LDAPS | `LDAP_USE_SSL=true` | Preferred encrypted LDAP connection, usually port 636 |
| StartTLS | `LDAP_START_TLS=true` | Upgrade a port 389 connection to TLS before authentication |
| Plain LDAP 389 | `LDAP_ALLOW_PLAINTEXT_AUTH=true` | Explicitly approved exception for isolated trusted networks |

Plain port 389 authentication is disabled by default. If enabled, readiness reports
`LDAP_PLAINTEXT_AUTH_ENABLED`; the deployment record should include risk acceptance, network isolation, and
compensating controls. The three switches are mutually exclusive.

## Main Controlled Workflows

### Quality and master data

- Partners, licences, agreements, authorized representatives, products, and registration evidence use independent
  review and expiry gates.
- Changes return approved records to review; expired or unapproved records block regulated transactions.
- GSP items cannot use legacy non-batch inventory paths.

### Procurement, receipt, and acceptance

- Purchase order creation, quality approval, receipt, sampling, independent acceptance, and batch-stock posting are
  separate states and responsibilities.
- Only accepted quantity becomes available batch stock; rejected or suspicious stock is held.

### Sales, packing, and shipment

- Buyer and product qualification are rechecked before approval and shipment.
- FEFO reservation, picking, packing, trace-code quantity checks, shipping-document evidence, independent review,
  and final decrement are enforced.
- Stocktaking freezes and unresolved quality or environmental events block affected movements.

### Returns, recalls, maintenance, and stocktaking

- Returned products enter quarantine before an independent quality decision.
- Recall deadlines use an electronically approved company business calendar with audit evidence.
- Approved expiry thresholds drive daily scans, maintenance evidence, stop-sale, holds, and signed closure.
- Blind counts preserve baselines, enforce transaction freezes, and require approved variance/CAPA handling.

### Audit, signatures, and integration

- Critical actions record identity, role, reason, before/after values, timestamps, and immutable chain evidence.
- Electronic signatures require local or LDAP reauthentication and a short-lived, one-time, request-bound challenge.
- External delivery uses an outbox with deterministic idempotency, concurrent claims, retry, dead-letter handling,
  and audited signed replay. No production JZT network adapter is included yet.

## Repository Layout

```text
app/
├── application.py                 # FastAPI assembly and health/readiness
├── core/                          # configuration, database and shared infrastructure
├── gsp/                           # controlled GSP quality domains
└── legacy.py                      # compatibility-period WMS API
migrations/                        # reviewed Alembic migrations
scripts/                           # backup, verification and scheduled-control scripts
deploy/systemd/                    # reference production services and timers
docs/                              # architecture, gap, integration, operations and validation documents
tests/                             # automated control and regression tests
```

## Quick Start

Python 3.12 is the supported runtime.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
alembic upgrade head
uvicorn main:app --reload
```

SQLite may be used for local development. Production must use PostgreSQL, reviewed migrations, external secret
injection, TLS at the application edge, explicit CORS origins, and the documented readiness and scheduled controls.

Required production configuration includes a strong `SECRET_KEY`, `DATABASE_URL`, `SECRETS_PROVIDER`,
`SECRET_KEY_VERSION_REF`, and `DATABASE_CREDENTIAL_VERSION_REF`. When a bind service account is configured,
`LDAP_CREDENTIAL_VERSION_REF` is also required.

## Quality Gates

The GitHub Actions workflow runs on Python 3.12 and checks:

- Ruff static analysis;
- automated tests on the quality and PostgreSQL integration jobs;
- source compilation and dependency consistency;
- reviewed Alembic upgrade, expected schema revision, and model/migration consistency.

Passing CI is engineering evidence only and does not replace approved IQ/OQ/PQ protocols, traceable execution
records, deviations, signatures, or quality release.

## Documentation

- [Target architecture](docs/ARCHITECTURE.en.md)
- [GSP gap matrix](docs/GSP_GAP_ANALYSIS.en.md)
- [Operations runbook](docs/OPERATIONS_RUNBOOK.en.md)
- [CSV validation plan](docs/VALIDATION_PLAN.en.md)
- [JZT integration boundary](docs/JZT_INTEGRATION.en.md)
- [Repository split guide](docs/REPOSITORY_SPLIT.en.md)
- [Database migration guide](migrations/README.en.md)

## Production Release Statement

Do not release this baseline as a controlled production system until the target environment, real roles and master
data, security configuration, backup and restore evidence, SOPs and training, and the complete CSV package have been
approved. The three explicitly excluded integrations/deliverables listed above remain open.

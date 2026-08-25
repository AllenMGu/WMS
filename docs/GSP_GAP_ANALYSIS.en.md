# GSP Gap Matrix

[中文](GSP_GAP_ANALYSIS.md) | [English](GSP_GAP_ANALYSIS.en.md)

Baseline date: 2026-08-24. The baseline targets common controls for pharmaceutical wholesalers and the sales,
storage, and transport activities of manufacturers. The matrix must be refined after confirming the actual business
scope, including cold chain, specially controlled products, outsourced logistics, and vaccines.

The authoritative regulatory references are listed in the [Chinese matrix](GSP_GAP_ANALYSIS.md#法规基线).

## Control Status

| Priority | Capability | Implemented software control | Production acceptance still required |
|---|---|---|---|
| P0 | Unique identity and least privilege | Approved role allowlist, segregation rules, review/expiry, deprovisioning, restricted LDAP provisioning | Quality-approved real-user access matrix and periodic review |
| P0 | Configuration and secrets | External injection, no API storage of bind passwords, account/IP throttling, secret rotation workflow | Approved secret provider, first dual-controlled rotation and rollback exercise |
| P0 | LDAP transport | LDAPS, StartTLS on 389, or an explicit mutually exclusive plain-389 exception | Prefer encryption; document risk acceptance, isolation, and compensating controls for plain 389 |
| P0 | Partner and product qualification | Licence/evidence approval, authorized representatives, registration evidence, expiry and re-review gates | Migration and independent quality review of current records |
| P0 | Batch and expiry control | Batch stock as the GSP ledger, approved expiry thresholds, recurring review and automatic stop-sale/hold | Approved thresholds and target-environment scheduled-task evidence |
| P0 | Receipt and acceptance separation | Approved purchase, receipt, sampling, independent acceptance and batch posting | Approved SOPs, sampling rules, templates and PQ execution |
| P0 | Quality holds | Holds rechecked across allocation, picking, review, shipment and affected environmental events | End-to-end execution with company deviation/recall cases |
| P0 | Audit trail and signatures | Serialized immutable chains, scheduled verification evidence, reauthentication and request-bound one-time signatures | Approved signature meanings and target LDAP failure/timeout/replay/concurrency tests |
| P0 | Backup and recovery | Self-checking backup, automatic evidence registration, offsite reference, failure evidence and governed restore exercise | Real media, alerting, scheduling and first independent restore exercise |
| P1 | Shipping and traceability | FEFO, packing, box/trace-code quantities, independent review and shipment decrement | Approved packing SOP and formal traceability-platform protocol |
| P1 | Environment | Device approval, assignments, readings, alarms, holds, deviation/CAPA decisions and reading chains | Physical gateway, alert channels, mapping, calibration, offline replay and time synchronization |
| P1 | Returns, recalls and disposition | Quarantine, independent inspection, recall timelines, recovery reconciliation, destruction and purchase returns | Approved calendar, reporting process and retention policy |
| P1 | Transport | Carrier evidence, vehicles/drivers, transit events, exceptions, delivery evidence and independent closure | Real carrier migration and mobile-operation PQ |
| P1 | JZT integration | Deterministic outbox, concurrent claims, retry, dead letter and signed replay | Formal adapter, joint testing, reconciliation and replay tests |
| P1 | Stocktaking | Automatic scope, freeze, blind count, variance/CAPA, controlled adjustment and immutable print evidence | Approved stocktake SOP and on-site PQ execution |
| P2 | CSV | Validation-plan skeleton and automated engineering gates | Complete VP/URS/RA/FS/DS/RTM/IQ/OQ/PQ/report/release package |

## Current Release Decision

The current version is suitable as a development and prototype-validation baseline only. It must not be released as
a controlled production system until target-environment qualification, secret migration and rotation, scheduled
backup and restore evidence, approved SOPs and access, and the complete CSV package are available. The physical
environmental gateway, formal JZT integration, and complete CSV package remain explicitly excluded deliverables.

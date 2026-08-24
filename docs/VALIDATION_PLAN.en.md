# CSV / Computerized System Validation Plan

[中文](VALIDATION_PLAN.md) | [English](VALIDATION_PLAN.en.md)

## Minimum Document Package

| Phase | Documents/evidence | Suggested responsibility |
|---|---|---|
| Initiation | Validation Plan (VP), inventory and boundary diagram | IT drafts; Quality approves |
| Requirements | URS, regulatory applicability and data-integrity requirements | Business/Quality with IT clarification |
| Risk | Risk Assessment (RA), critical-function classification | IT, Quality and Warehouse |
| Design | FS, DS, data dictionary, interface specification and role matrix | IT/development |
| Traceability | RTM from regulations/URS to design, tests and deviations | IT maintains; Quality reviews |
| Qualification | IQ/OQ/PQ protocols, records and objective evidence | IT executes; Business participates; Quality approves |
| Data | Migration plan, mapping, reconciliation and report | Business owns content; IT executes |
| Security | Access, audit trail, backup and recovery tests | IT with Quality witness |
| Release | Deviations/CAPA, summary report and go-live approval | Quality final approval |
| Operation | SOPs, training, change control, periodic review and DR exercises | Process owners |

## Validation Strategy

- Treat GSP blocking rules, batch allocation, holds, audit trails, signatures, backup/restore, and interface
  idempotency as high-risk controls.
- Include returns quarantine, segregation of receipt/acceptance, recall completeness, disposition/destruction witness,
  purchase return, maintenance, expiry, stocktake freeze, and business-calendar scenarios.
- The ten-business-day baseline uses an electronically approved company calendar. Test public holidays, adjusted
  working days, year boundaries, and controlled calendar changes.
- Map each rule in `app/gsp/rules.py` to at least one positive and one negative OQ case.
- Use masked but representative company master data and real approved roles for end-to-end PQ.
- Retain original/new values, reason, executor, approver and time for every retry, manual correction or migration fix.
- Execute a full isolated restore before release and reconcile critical records and hash chains within approved RTO/RPO.

GitHub Actions provides repeatable engineering evidence but does not replace approved protocols, traceable test data,
execution records, deviations, electronic or handwritten approvals, and the validation summary report.

## Suggested Release Gates

1. Every high-risk URS has passed and no high-risk deviation remains open.
2. Legacy non-batch paths are disabled for GSP products.
3. Quality has approved access; shared, test, and departed-user accounts are removed or controlled.
4. Daily backups have succeeded and an independent restore has been verified.
5. Where JZT is in production scope, quantity, batch, state, error, reconciliation, and replay tests have passed.
6. Business, Warehouse, Quality, and IT have completed approved training and the release checklist.

The complete CSV package is explicitly excluded from the current software PR and must be produced and approved as a
separate validation deliverable before controlled production release.

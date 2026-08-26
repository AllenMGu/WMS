# Database Migrations

[中文](README.md) | [English](README.en.md)

Set `AUTO_CREATE_SCHEMA=false` in production. For an empty database, execute the reviewed migration chain through the
controlled change process:

```bash
alembic upgrade head
```

Do not recreate baseline tables in an existing legacy WMS database. First reconcile and back up its schema, then use
the approved change record:

```bash
alembic stamp 20260820_00
alembic upgrade head
alembic check
```

`stamp` records a revision without changing tables, so evidence must first show that the legacy structure matches
the `20260820_00` baseline.

Before release, rehearse backup, upgrade, rollback, re-upgrade, and data reconciliation on a same-version database
copy. Retain commands, output, executor, reviewer, and timestamps in the change record.

The current migration head is `20260826_22`, which records the uploader of each partner qualification document so
that uploader and verifier separation can be enforced. Production readiness checks require the database to be at
this reviewed revision.

#!/usr/bin/env python3
"""Read-only integrity checks for an isolated restored database."""

from __future__ import annotations

import json

from app.core.database import SessionLocal
from app.gsp.audit import verify_audit_chain
from app.gsp.models import GspAuditEvent, GspDrugBatch
from app.legacy import User


def main() -> int:
    db = SessionLocal()
    try:
        audit_valid, broken_event_id = verify_audit_chain(db)
        result = {
            "users": db.query(User).count(),
            "drug_batches": db.query(GspDrugBatch).count(),
            "audit_events": db.query(GspAuditEvent).count(),
            "audit_chain_valid": audit_valid,
            "broken_event_id": broken_event_id,
        }
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if audit_valid else 2
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())


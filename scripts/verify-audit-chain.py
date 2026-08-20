#!/usr/bin/env python3
"""Run and persist the scheduled GSP audit-chain verification."""

from __future__ import annotations

import argparse

from app.core.database import SessionLocal
from app.gsp.audit import record_audit_verification
from app.legacy import User


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--actor-user-id", type=int, required=True)
    parser.add_argument("--evidence-ref", required=True)
    parser.add_argument("--reason", default="计划任务执行审计哈希链完整性校验")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        actor = db.query(User).filter(User.id == args.actor_user_id, User.is_active.is_(True)).first()
        if actor is None:
            raise SystemExit("audit verification actor is missing or inactive")
        verification = record_audit_verification(
            db,
            actor_user_id=actor.id,
            trigger_source="SCHEDULED",
            evidence_ref=args.evidence_ref,
            reason=args.reason,
        )
        db.commit()
        return 0 if verification.valid else 2
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())

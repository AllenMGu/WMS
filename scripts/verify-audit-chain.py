#!/usr/bin/env python3
"""Run and persist the scheduled GSP audit-chain verification."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.time import utc_now
from app.gsp.audit import record_audit_verification
from app.gsp.models import GspRoleAssignment
from app.legacy import User


def _scheduled_actor_id(db: Session) -> int:
    now = utc_now()
    assignment = (
        db.query(GspRoleAssignment)
        .filter(
            GspRoleAssignment.role.in_(["AUDITOR", "QUALITY_REVIEWER"]),
            GspRoleAssignment.is_active.is_(True),
            GspRoleAssignment.review_due_at > now,
            (
                GspRoleAssignment.expires_at.is_(None)
                | (GspRoleAssignment.expires_at > now)
            ),
        )
        .order_by(GspRoleAssignment.id)
        .first()
    )
    if assignment is None:
        raise SystemExit("scheduled audit verification requires an active AUDITOR or QUALITY_REVIEWER")
    return assignment.user_id


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--actor-user-id", type=int)
    parser.add_argument("--evidence-ref")
    parser.add_argument("--reason", default="计划任务执行审计哈希链完整性校验")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        actor_id = args.actor_user_id or _scheduled_actor_id(db)
        actor = db.query(User).filter(User.id == actor_id, User.is_active.is_(True)).first()
        if actor is None:
            raise SystemExit("audit verification actor is missing or inactive")
        verification = record_audit_verification(
            db,
            actor_user_id=actor.id,
            trigger_source="SCHEDULED",
            evidence_ref=args.evidence_ref or (
                "audit://scheduled/" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            ),
            reason=args.reason,
        )
        db.commit()
        return 0 if verification.valid else 2
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())

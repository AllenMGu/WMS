"""Apply approved near-expiry warning, maintenance, and stop-sale thresholds."""

from __future__ import annotations

import main  # noqa: F401
from app.core.database import SessionLocal
from app.core.time import utc_now
from app.gsp.maintenance.service import scan_expiry_controls
from app.gsp.models import GspRoleAssignment


def _scheduled_actor_id(db) -> int:
    now = utc_now()
    assignment = (
        db.query(GspRoleAssignment)
        .filter(
            GspRoleAssignment.role.in_(("MAINTENANCE", "QUALITY_MANAGER")),
            GspRoleAssignment.is_active.is_(True),
            GspRoleAssignment.review_due_at > now,
            GspRoleAssignment.expires_at.is_(None) | (GspRoleAssignment.expires_at > now),
        )
        .order_by(GspRoleAssignment.id)
        .first()
    )
    if assignment is None:
        raise RuntimeError("没有有效的 MAINTENANCE 或 QUALITY_MANAGER 岗位，无法执行近效期扫描")
    return assignment.user_id


def main_task() -> int:
    db = SessionLocal()
    try:
        alerts = scan_expiry_controls(
            db,
            actor_id=_scheduled_actor_id(db),
            source_ip="SYSTEM_TIMER",
        )
        db.commit()
        print(f"expiry control scan complete: evaluated={len(alerts)}")
        return len(alerts)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main_task()

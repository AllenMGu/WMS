"""Create overdue environment-offline alarms from the internal WMS database."""

from __future__ import annotations

import main  # noqa: F401
from app.core.database import SessionLocal
from app.core.time import utc_now
from app.gsp.environment.service import scan_offline_assignments
from app.gsp.models import GspRoleAssignment


def _scheduled_actor_id(db) -> int:
    now = utc_now()
    assignment = (
        db.query(GspRoleAssignment)
        .filter(
            GspRoleAssignment.role == "ENVIRONMENT_MONITOR",
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
        raise RuntimeError("没有有效的 ENVIRONMENT_MONITOR 岗位，无法执行离线扫描")
    return assignment.user_id


def main_task() -> int:
    db = SessionLocal()
    try:
        alarms = scan_offline_assignments(
            db,
            actor_id=_scheduled_actor_id(db),
            source_ip="SYSTEM_TIMER",
        )
        db.commit()
        print(f"environment offline scan complete: created={len(alarms)}")
        return len(alarms)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main_task()

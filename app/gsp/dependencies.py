from __future__ import annotations

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.time import utc_now
from app.gsp.models import GspRoleAssignment
from app.legacy import User, get_current_user


def require_gsp_roles(*allowed_roles: str):
    async def dependency(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        assigned = {
            row.role
            for row in db.query(GspRoleAssignment).filter(
                GspRoleAssignment.user_id == current_user.id,
                GspRoleAssignment.is_active.is_(True),
                GspRoleAssignment.review_due_at > utc_now(),
                (
                    GspRoleAssignment.expires_at.is_(None)
                    | (GspRoleAssignment.expires_at > utc_now())
                ),
            )
        }
        if assigned.intersection(allowed_roles):
            return current_user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"需要以下GSP岗位之一：{', '.join(allowed_roles)}",
        )

    return dependency


async def require_quality_manager_or_bootstrap(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    """Allow the first quality-manager assignment, then require that role."""
    now = utc_now()
    current_assignment = (
        db.query(GspRoleAssignment)
        .filter(
            GspRoleAssignment.user_id == current_user.id,
            GspRoleAssignment.role == "QUALITY_MANAGER",
            GspRoleAssignment.is_active.is_(True),
            GspRoleAssignment.review_due_at > now,
            (
                GspRoleAssignment.expires_at.is_(None)
                | (GspRoleAssignment.expires_at > now)
            ),
        )
        .first()
    )
    if current_assignment is not None:
        return current_user
    active_quality_manager = (
        db.query(GspRoleAssignment)
        .filter(
            GspRoleAssignment.role == "QUALITY_MANAGER",
            GspRoleAssignment.is_active.is_(True),
            GspRoleAssignment.review_due_at > now,
            (
                GspRoleAssignment.expires_at.is_(None)
                | (GspRoleAssignment.expires_at > now)
            ),
        )
        .first()
    )
    role_value = getattr(current_user.role, "value", current_user.role)
    if active_quality_manager is None and role_value == "admin":
        return current_user
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="需要有效的QUALITY_MANAGER岗位")

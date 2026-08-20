from __future__ import annotations

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.models import GspRoleAssignment
from app.legacy import User, get_current_user


def require_gsp_roles(*allowed_roles: str):
    async def dependency(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        role_value = getattr(current_user.role, "value", current_user.role)
        if role_value == "admin":
            return current_user
        assigned = {
            row.role
            for row in db.query(GspRoleAssignment).filter(
                GspRoleAssignment.user_id == current_user.id,
                GspRoleAssignment.is_active.is_(True),
            )
        }
        if assigned.intersection(allowed_roles):
            return current_user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"需要以下GSP岗位之一：{', '.join(allowed_roles)}",
        )

    return dependency

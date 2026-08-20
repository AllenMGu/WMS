from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.core.database import SessionLocal
from app.core.time import utc_now
from app.gsp.access_control import (
    deactivate_user_access,
    grant_gsp_role,
    review_gsp_role,
    revoke_gsp_role,
)
from app.gsp.audit import verify_audit_chain
from app.gsp.models import GspRoleAssignment
from app.gsp.schemas import RoleGrant, RoleReview
from app.legacy import User, UserRole, UserWarehouse, Warehouse


def _user(db, name: str) -> User:
    user = User(
        username=f"{name}-{uuid4().hex[:10]}",
        hashed_password="test-only",
        full_name=name,
        role=UserRole.OPERATOR,
    )
    db.add(user)
    db.flush()
    return user


def test_role_grant_review_conflict_and_revoke_are_controlled():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        grantor = _user(db, "授权人")
        reviewer = _user(db, "复核人")
        target = _user(db, "采购员")
        now = datetime.now(UTC)
        assignment = grant_gsp_role(
            db,
            payload=RoleGrant(
                user_id=target.id,
                role="procurement",
                approval_ref="OA-ACCESS-2026-001",
                review_due_at=now + timedelta(days=30),
                expires_at=now + timedelta(days=180),
                reason="经质量负责人批准采购岗位",
            ),
            actor_id=grantor.id,
        )
        assert assignment.role == "PROCUREMENT"
        assert assignment.is_active is True
        assert assignment.review_due_at.tzinfo is None

        with pytest.raises(HTTPException, match="岗位职责冲突"):
            grant_gsp_role(
                db,
                payload=RoleGrant(
                    user_id=target.id,
                    role="INSPECTOR",
                    approval_ref="OA-ACCESS-2026-002",
                    review_due_at=now + timedelta(days=30),
                    reason="冲突岗位测试",
                ),
                actor_id=grantor.id,
            )

        review_gsp_role(
            db,
            assignment=assignment,
            payload=RoleReview(
                decision="RETAIN",
                next_review_due_at=now + timedelta(days=60),
                reason="定期权限复核通过",
            ),
            actor_id=reviewer.id,
        )
        assert assignment.last_reviewed_by == reviewer.id

        revoke_gsp_role(
            db,
            assignment=assignment,
            actor_id=grantor.id,
            reason="岗位调整，撤销采购权限",
        )
        db.commit()
        assert assignment.is_active is False
        assert assignment.revocation_reason == "岗位调整，撤销采购权限"
        assert verify_audit_chain(db) == (True, None)
    finally:
        db.close()


def test_offboarding_revokes_roles_and_warehouse_access():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        actor = _user(db, "停用操作人")
        target = _user(db, "离职用户")
        warehouse = Warehouse(code=f"WH-{uuid4().hex[:10]}", name="离职测试仓", is_active=True)
        db.add(warehouse)
        db.flush()
        db.add(UserWarehouse(user_id=target.id, warehouse_id=warehouse.id, is_default=True))
        target.current_warehouse_id = warehouse.id
        assignment = GspRoleAssignment(
            user_id=target.id,
            role="WAREHOUSE_CUSTODIAN",
            granted_by=actor.id,
            approval_ref="OA-ACCESS-2026-003",
            review_due_at=utc_now() + timedelta(days=30),
            is_active=True,
        )
        db.add(assignment)
        db.flush()

        deactivate_user_access(
            db,
            user=target,
            actor_id=actor.id,
            reason="员工离职，立即撤销系统访问",
        )
        db.commit()

        assert target.is_active is False
        assert target.current_warehouse_id is None
        assert assignment.is_active is False
        assert db.query(UserWarehouse).filter(UserWarehouse.user_id == target.id).count() == 0
        assert verify_audit_chain(db) == (True, None)
    finally:
        db.close()

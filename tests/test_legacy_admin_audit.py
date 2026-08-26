import asyncio
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.core.database import SessionLocal
from app.gsp.audit import verify_audit_chain
from app.gsp.models import GspAuditEvent
from app.legacy import (
    Location,
    LocationCreate,
    LocationUpdate,
    User,
    UserCreate,
    UserRole,
    UserWarehouse,
    Warehouse,
    WarehouseCreate,
    assign_warehouse_to_user,
    create_location,
    create_user,
    create_warehouse,
    delete_location,
    unassign_warehouse_from_user,
    update_location,
)


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/test",
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 50000),
        }
    )


def _user(db, label: str, role: UserRole) -> User:
    suffix = uuid4().hex[:10]
    user = User(
        username=f"{label}-{suffix}",
        hashed_password="test-only",
        full_name=label,
        role=role,
        is_active=True,
    )
    db.add(user)
    db.flush()
    return user


def _warehouse(db, label: str) -> Warehouse:
    suffix = uuid4().hex[:10]
    warehouse = Warehouse(code=f"WH-{suffix}", name=label, is_active=True)
    db.add(warehouse)
    db.flush()
    return warehouse


def _run(coro):
    return asyncio.run(coro)


def _event(db, action: str, entity_id: str) -> GspAuditEvent:
    return (
        db.query(GspAuditEvent)
        .filter(
            GspAuditEvent.action == action,
            GspAuditEvent.entity_id == entity_id,
        )
        .order_by(GspAuditEvent.id.desc())
        .first()
    )


def test_location_maintenance_is_admin_only_and_records_actual_reason():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        admin = _user(db, "设施管理员", UserRole.ADMIN)
        operator = _user(db, "仓库操作员", UserRole.OPERATOR)
        warehouse = _warehouse(db, "常温库")
        db.commit()

        payload = LocationCreate(
            warehouse_id=warehouse.id,
            location_code=f"A-{uuid4().hex[:8]}",
            name="常温A区",
        )
        with pytest.raises(HTTPException) as denied:
            _run(
                create_location(
                    payload,
                    _request(),
                    reason="操作员越权测试",
                    current_user=operator,
                    db=db,
                )
            )
        assert denied.value.status_code == 403

        location = _run(
            create_location(
                payload,
                _request(),
                reason="质量批准新增常温库位",
                current_user=admin,
                db=db,
            )
        )
        created = _event(db, "LOCATION_CREATED", str(location.id))
        assert created.reason == "质量批准新增常温库位"
        assert created.after_data["location_code"] == payload.location_code

        _run(
            update_location(
                location.id,
                LocationUpdate(name="常温A区复核后"),
                _request(),
                reason="设施复核后修正名称",
                current_user=admin,
                db=db,
            )
        )
        updated = _event(db, "LOCATION_UPDATED", str(location.id))
        assert updated.reason == "设施复核后修正名称"
        assert updated.before_data["name"] == "常温A区"
        assert updated.after_data["name"] == "常温A区复核后"

        _run(
            delete_location(
                location.id,
                _request(),
                reason="测试库位退役删除",
                current_user=admin,
                db=db,
            )
        )
        deleted = _event(db, "LOCATION_DELETED", str(location.id))
        assert deleted.reason == "测试库位退役删除"
        assert db.query(Location).filter(Location.id == location.id).first() is None
        assert verify_audit_chain(db) == (True, None)
    finally:
        db.close()


def test_default_assignment_and_unassignment_capture_complete_access_state():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        admin = _user(db, "权限管理员", UserRole.ADMIN)
        target = _user(db, "目标操作员", UserRole.OPERATOR)
        first = _warehouse(db, "第一仓库")
        second = _warehouse(db, "第二仓库")
        db.add(
            UserWarehouse(
                user_id=target.id,
                warehouse_id=first.id,
                is_default=True,
            )
        )
        target.current_warehouse_id = first.id
        db.commit()

        _run(
            assign_warehouse_to_user(
                target.id,
                second.id,
                _request(),
                reason="批准调整默认仓库",
                is_default=True,
                current_user=admin,
                db=db,
            )
        )
        assignments = (
            db.query(UserWarehouse)
            .filter(UserWarehouse.user_id == target.id)
            .order_by(UserWarehouse.warehouse_id)
            .all()
        )
        by_warehouse = {assignment.warehouse_id: assignment for assignment in assignments}
        assert by_warehouse[first.id].is_default is False
        assert by_warehouse[second.id].is_default is True
        assert target.current_warehouse_id == second.id

        assigned = _event(db, "USER_WAREHOUSE_ASSIGNED", f"{target.id}:{second.id}")
        assert assigned.before_data["previous_default_warehouse_ids"] == [first.id]
        assert assigned.after_data["current_warehouse_id"] == second.id
        assert assigned.reason == "批准调整默认仓库"

        _run(
            unassign_warehouse_from_user(
                target.id,
                second.id,
                _request(),
                reason="岗位调整解除第二仓库",
                current_user=admin,
                db=db,
            )
        )
        assert target.current_warehouse_id == first.id
        unassigned = _event(db, "USER_WAREHOUSE_UNASSIGNED", f"{target.id}:{second.id}")
        assert unassigned.after_data["remaining_warehouse_ids"] == [first.id]
        assert unassigned.after_data["current_warehouse_id"] == first.id
        assert unassigned.reason == "岗位调整解除第二仓库"
        assert verify_audit_chain(db) == (True, None)
    finally:
        db.close()


def test_warehouse_and_user_creation_audit_automatic_access_assignments():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        actor = _user(db, "系统管理员", UserRole.ADMIN)
        other_admin = _user(db, "备用管理员", UserRole.ADMIN)
        db.commit()

        warehouse = _run(
            create_warehouse(
                WarehouseCreate(
                    code=f"WH-{uuid4().hex[:10]}",
                    name="新建受控仓库",
                    address="测试地址",
                ),
                _request(),
                reason="批准启用新仓库",
                current_user=actor,
                db=db,
            )
        )
        created = _event(db, "WAREHOUSE_CREATED", str(warehouse.id))
        assert set(created.after_data["auto_assigned_admin_user_ids"]) == {
            actor.id,
            other_admin.id,
        }
        for admin in (actor, other_admin):
            assignment_event = _event(
                db,
                "USER_WAREHOUSE_ASSIGNED",
                f"{admin.id}:{warehouse.id}",
            )
            assert assignment_event.after_data["assignment_source"] == "WAREHOUSE_CREATION"
            assert assignment_event.reason == "批准启用新仓库"
            assert admin.current_warehouse_id == warehouse.id

        new_user = _run(
            create_user(
                UserCreate(
                    username=f"operator-{uuid4().hex[:10]}",
                    password="test-only-password",
                    full_name="新操作员",
                    role=UserRole.OPERATOR,
                    warehouse_ids=[warehouse.id],
                ),
                _request(),
                reason="批准创建仓库操作员",
                current_user=actor,
                db=db,
            )
        )
        user_event = _event(db, "USER_CREATED", str(new_user.id))
        assert user_event.after_data["warehouse_ids"] == [warehouse.id]
        assignment_event = _event(
            db,
            "USER_WAREHOUSE_ASSIGNED",
            f"{new_user.id}:{warehouse.id}",
        )
        assert assignment_event.after_data["assignment_source"] == "USER_CREATION"
        assert assignment_event.reason == "批准创建仓库操作员"
        assert verify_audit_chain(db) == (True, None)
    finally:
        db.close()

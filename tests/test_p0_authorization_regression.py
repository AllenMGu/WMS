"""P0 修复回归：越权封堵（2026-09-06 审核整改）。

覆盖审核报告的 P0-2（/goods/ 增改垂直越权）与 P0-3（受控业务列表无岗位授权）：
- 无任何 GSP 岗位的普通登录账号访问 4 个受控列表接口 -> 403（修复前 200）；
- 普通账号 POST /api/goods/ -> 403（修复前可新增药品基础档案）；
- Admin 创建货物 -> 200（不破坏合法路径）；
- 已授予对应岗位的用户访问受控列表 -> 200（正例）。

依赖修复点：
- app/legacy.py: create_goods / update_goods 使用 Depends(require_admin_user)；
- app/gsp/procurement_receiving/router.py: list_orders/list_receipts 加 require_gsp_roles；
- app/gsp/sales_shipping/router.py: list_orders/list_shipments 加 require_gsp_roles。
"""

from datetime import timedelta
from uuid import uuid4

import pytest

from app.core.time import utc_now
from app.gsp.models import GspRoleAssignment
from app.legacy import User, UserRole

CONTROLLED_LISTS = [
    ("/api/gsp/procurement/orders", "PROCUREMENT"),
    ("/api/gsp/receiving/receipts", "RECEIVER"),
    ("/api/gsp/sales/orders", "SALES"),
    ("/api/gsp/shipping/shipments", "DISPATCHER"),
]


@pytest.fixture()
def ctx(tmp_path):
    """File-backed SQLite app + seeded users. get_db overridden to the
    file-backed Session so HTTP handlers and seeded data share one DB."""
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import app.application as application
    import main  # noqa: F401
    from app.core.database import Base, get_db
    from app.legacy import get_password_hash

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'db.sqlite'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    def _override_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    application.app.dependency_overrides[get_db] = _override_db

    def _user(label, role=UserRole.OPERATOR):
        u = User(
            username=f"p0-{label}-{uuid4().hex[:6]}",
            hashed_password=get_password_hash("pw-test-1"),
            full_name=label,
            role=role,
            is_active=True,
        )
        db.add(u)
        db.flush()
        return u

    admin = _user("admin", UserRole.ADMIN)
    plain = _user("plain")  # 有登录、无任何 GSP 岗位
    db.commit()

    client = TestClient(application.app)

    def _token(user):
        r = client.post(
            "/api/token",
            data={"username": user.username, "password": "pw-test-1"},
        )
        assert r.status_code == 200, r.text
        return r.json()["access_token"]

    def _auth(user):
        return {"Authorization": f"Bearer {_token(user)}"}

    def _grant(user, role):
        db.add(GspRoleAssignment(
            user_id=user.id, role=role, granted_by=admin.id,
            approval_ref=f"T-{uuid4().hex[:6]}",
            review_due_at=utc_now() + timedelta(days=30), is_active=True,
        ))
        db.commit()

    return {
        "client": client,
        "db": db,
        "admin": admin,
        "plain": plain,
        "auth": _auth,
        "grant": _grant,
        "token": _token,
    }


def test_controlled_lists_reject_user_without_any_gsp_role(ctx):
    """P0-3：无岗位用户不得读取受控业务列表（修复前返回 200）。"""
    client, plain = ctx["client"], ctx["plain"]
    for path, _ in CONTROLLED_LISTS:
        r = client.get(path, headers=ctx["auth"](plain))
        assert r.status_code == 403, f"{path} 应 403，实际 {r.status_code}: {r.text[:120]}"


def test_controlled_lists_allow_granted_role(ctx):
    """正例：授予岗位后列表可读（确认角色依赖未被过度收紧）。"""
    client = ctx["client"]
    path, role = CONTROLLED_LISTS[2]  # sales orders -> SALES
    user = ctx["plain"]
    ctx["grant"](user, role)
    r = client.get(path, headers=ctx["auth"](user))
    assert r.status_code == 200, f"{path} 应 200，实际 {r.status_code}: {r.text[:120]}"


def test_goods_create_requires_admin(ctx):
    """P0-2：普通账号不得新增货物（修复前可新增药品首营主数据）。"""
    client, plain, admin = ctx["client"], ctx["plain"], ctx["admin"]
    payload = {
        "barcode": f"P0-{uuid4().hex[:8]}",
        "name": "回归测试货物",
        "spec": "盒",
        "unit": "盒",
        "price": 1.0,
    }
    r = client.post("/api/goods/", json=payload, headers=ctx["auth"](plain))
    assert r.status_code == 403, f"普通用户应 403，实际 {r.status_code}"

    r = client.post("/api/goods/", json=payload, headers=ctx["auth"](admin))
    assert r.status_code in (200, 201), f"admin 应成功，实际 {r.status_code}: {r.text[:120]}"


def test_goods_update_requires_admin(ctx):
    """P0-2：普通账号不得修改货物档案。"""
    client, plain, admin = ctx["client"], ctx["plain"], ctx["admin"]
    payload = {
        "barcode": f"P0-U-{uuid4().hex[:8]}",
        "name": "待改货物",
        "spec": "支",
        "unit": "支",
        "price": 2.0,
    }
    created = client.post("/api/goods/", json=payload, headers=ctx["auth"](admin))
    assert created.status_code in (200, 201)
    goods_id = created.json().get("id")
    assert goods_id

    r = client.put(f"/api/goods/{goods_id}", json={"name": "越权改名"},
                   headers=ctx["auth"](plain))
    assert r.status_code == 403, f"普通用户应 403，实际 {r.status_code}"

    r = client.put(f"/api/goods/{goods_id}", json={"name": "admin 改名"},
                   headers=ctx["auth"](admin))
    assert r.status_code in (200, 201), f"admin 应成功，实际 {r.status_code}"

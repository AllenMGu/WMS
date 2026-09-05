"""HTTP tests: business reports & controlled printing (P1)."""

import re
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.core.time import utc_now
from app.gsp.models import GspRoleAssignment
from app.gsp.procurement_receiving.models import GspControlledPrintRecord
from app.legacy import User, UserRole


@pytest.fixture()
def ctx(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import main  # noqa: F401
    from app.core.database import Base, get_db
    from app.legacy import get_current_user

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'r.db'}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    def user(label, role=None):
        u = User(username=f"rp-{label}-{uuid4().hex[:6]}", hashed_password="x",
                 full_name=label, role=UserRole.OPERATOR, is_active=True)
        db.add(u)
        db.flush()
        if role:
            db.add(GspRoleAssignment(user_id=u.id, role=role, granted_by=u.id,
                                     approval_ref=f"T{uuid4().hex[:6]}",
                                     review_due_at=utc_now() + __import__("datetime").timedelta(days=30),
                                     is_active=True))
        return u

    current = {}

    async def override_current_user():
        return current["user"]

    def override_db():
        yield db

    app = main.app
    app.dependency_overrides[get_current_user] = override_current_user
    app.dependency_overrides[get_db] = override_db
    state = {"db": db, "user": user, "current": current, "app": app}
    try:
        with TestClient(app) as tc:
            state["client"] = tc
            yield state
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db, None)
        db.close()
        engine.dispose()


def test_report_catalog_and_permission_gating(ctx):
    client = ctx["client"]
    ctx["current"]["user"] = ctx["user"]("审计", "AUDITOR")
    r = client.get("/api/gsp/reports")
    assert r.status_code == 200
    keys = [x["key"] for x in r.json()]
    for expected in ("batch_stock_ledger", "electronic_signature_ledger",
                     "environment_alarm_ledger", "quality_hold_ledger", "audit_event_ledger"):
        assert expected in keys
    outsider = ctx["user"]("无岗位")
    ctx["db"].commit()
    ctx["current"]["user"] = outsider
    assert client.get("/api/gsp/reports").status_code == 403
    assert client.get("/api/gsp/reports/batch_stock_ledger").status_code == 403


def test_report_query_empty_and_audit_rows(ctx):
    client = ctx["client"]
    ctx["current"]["user"] = ctx["user"]("审计", "AUDITOR")
    r = client.get("/api/gsp/reports/audit_event_ledger")
    assert r.status_code == 200
    body = r.json()
    assert body["key"] == "audit_event_ledger" and "rows" in body
    # generate an audit event through the API surface used by the app
    from app.gsp.audit import write_audit_event

    actor = ctx["user"]("事件源", "RECEIVER")
    write_audit_event(ctx["db"], actor_user_id=actor.id, action="REPORT_TEST_EVENT",
                      entity_type="GspControlledPrintRecord", entity_id="0", reason="测试生成")
    ctx["db"].commit()
    r = client.get("/api/gsp/reports/audit_event_ledger?action=REPORT_TEST_EVENT")
    assert r.status_code == 200
    assert len(r.json()["rows"]) >= 1
    assert client.get("/api/gsp/reports/not-a-report").status_code == 404


def test_controlled_print_records_snapshot_and_list(ctx):
    client = ctx["client"]
    user = ctx["user"]("质量经理", "QUALITY_MANAGER")
    ctx["db"].commit()
    ctx["current"]["user"] = user
    r = client.post("/api/gsp/reports/audit_event_ledger/print",
                    json={"reason": "审计事件台账受控打印测试", "limit": 50})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["copy_no"].startswith("RPT-")
    assert re.fullmatch(r"[0-9a-f]{64}", body["content_hash"])
    assert "<table>" in body["html"] and "受控打印" in body["html"]

    db = ctx["db"]
    record = db.query(GspControlledPrintRecord).filter(
        GspControlledPrintRecord.document_type == "REPORT:audit_event_ledger"
    ).first()
    assert record is not None
    assert record.content_hash == body["content_hash"]
    assert record.purpose == "审计事件台账受控打印测试"
    assert record.snapshot_data["report_key"] == "audit_event_ledger"

    r = client.get("/api/gsp/reports/prints/list")
    assert r.status_code == 200
    prints = r.json()
    assert any(p["copy_no"] == body["copy_no"] for p in prints)

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
    state = {"db": db, "user": user, "current": current}
    try:
        with TestClient(app) as tc:
            state["client"] = tc
            yield state
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db, None)
        db.close()
        engine.dispose()


def _login(ctx, label, role=None):
    u = ctx["user"](label, role)
    ctx["db"].commit()
    ctx["current"]["user"] = u
    return u


def test_catalog_role_matrix_and_gating(ctx):
    client = ctx["client"]
    _login(ctx, "审计", "AUDITOR")
    r = client.get("/api/gsp/reports")
    assert r.status_code == 200
    body = r.json()
    keys = [x["key"] for x in body]
    for expected in ("batch_stock_ledger", "electronic_signature_ledger",
                     "environment_alarm_ledger", "quality_hold_ledger", "audit_event_ledger"):
        assert expected in keys
    by_key = {x["key"]: x for x in body}
    assert by_key["electronic_signature_ledger"]["roles"]
    assert by_key["audit_event_ledger"]["roles"]
    assert not by_key["batch_stock_ledger"]["roles"]
    # no role at all
    _login(ctx, "无岗位")
    assert client.get("/api/gsp/reports/batch_stock_ledger").status_code == 403
    # ordinary GSP role may see open ledgers but not sensitive ones
    _login(ctx, "收货员", "RECEIVER")
    assert client.get("/api/gsp/reports/batch_stock_ledger").status_code == 200
    assert client.get("/api/gsp/reports/audit_event_ledger").status_code == 403
    assert client.get("/api/gsp/reports/electronic_signature_ledger").status_code == 403
    # quality roles can
    _login(ctx, "质量", "QUALITY_MANAGER")
    assert client.get("/api/gsp/reports/audit_event_ledger").status_code == 200


def test_query_pagination_unknown_filter_and_no_payload_leak(ctx):
    client = ctx["client"]
    _login(ctx, "审计", "AUDITOR")
    from app.gsp.audit import write_audit_event

    actor = ctx["user"]("源", "RECEIVER")
    for i in range(3):
        write_audit_event(ctx["db"], actor_user_id=actor.id, action=f"EVT_{i}",
                          entity_type="X", entity_id=str(i), reason="r" * 3)
    ctx["db"].commit()
    # pagination: limit=2 of 3 rows -> has_more
    r = client.get("/api/gsp/reports/audit_event_ledger?limit=2")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2 and body["total"] >= 3 and body["has_more"] is True
    r2 = client.get("/api/gsp/reports/audit_event_ledger?limit=2&offset=2")
    assert r2.json()["count"] >= 1
    # unknown filter -> 422 (not silently ignored)
    bad = client.get("/api/gsp/reports/audit_event_ledger?unknown_col=1")
    assert bad.status_code == 422
    # no raw sensitive columns (event_hash/payload/source_ip) in explicit output
    row_keys = set(body["row_keys"])
    assert not row_keys.intersection({"event_hash", "payload_snapshot", "source_ip", "previous_hash"})


def test_controlled_print_snapshot_immutable_and_verifiable(ctx):
    client = ctx["client"]
    _login(ctx, "审计", "AUDITOR")
    from app.gsp.audit import write_audit_event

    actor = ctx["user"]("源", "RECEIVER")
    write_audit_event(ctx["db"], actor_user_id=actor.id, action="PRINT_ME",
                      entity_type="X", entity_id="1", reason="rrr")
    ctx["db"].commit()

    r = client.post("/api/gsp/reports/audit_event_ledger/print",
                    json={"reason": "审计台账受控打印", "limit": 10, "filters": {"action": "PRINT_ME"}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["copy_no"].startswith("RPT-")
    assert re.fullmatch(r"[0-9a-f]{64}", body["content_hash"])
    assert "<table>" in body["html"]

    # change source data afterwards; the stored artifact must not change
    write_audit_event(ctx["db"], actor_user_id=actor.id, action="PRINT_ME",
                      entity_type="X", entity_id="2", reason="rrr")
    ctx["db"].commit()

    fetch = client.get(f"/api/gsp/reports/prints/{body['print_id']}")
    assert fetch.status_code == 200
    assert fetch.json()["content_hash"] == body["content_hash"]
    assert fetch.json()["html"] == body["html"]

    verify = client.post(f"/api/gsp/reports/prints/{body['print_id']}/verify")
    assert verify.status_code == 200
    assert verify.json()["valid"] is True

    # snapshot records range/total and truncation truthfully
    db = ctx["db"]
    record = db.get(GspControlledPrintRecord, body["print_id"])
    assert record is not None
    assert record.snapshot_data["html"] == body["html"]
    assert record.snapshot_data["rows"] is not None
    assert record.snapshot_data["total"] == 1
    assert record.snapshot_data["truncated"] is False


def test_cover_all_print_over_multiple_pages(ctx):
    client = ctx["client"]
    _login(ctx, "审计", "AUDITOR")
    from app.gsp.audit import write_audit_event

    actor = ctx["user"]("源", "RECEIVER")
    for i in range(3):
        write_audit_event(ctx["db"], actor_user_id=actor.id, action="ALL_COVER",
                          entity_type="X", entity_id=str(i), reason="rrr")
    ctx["db"].commit()
    r = client.post("/api/gsp/reports/audit_event_ledger/print",
                    json={"reason": "全量打印验证", "limit": 2, "cover_all": True,
                          "filters": {"action": "ALL_COVER"}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["html"].count("<tr>") >= 4  # 3 rows + header
    rec = client.get(f"/api/gsp/reports/prints/{body['print_id']}").json()
    assert "共 3 行" in rec["html"]

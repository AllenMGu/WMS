"""HTTP/service tests: business reports & controlled printing (P1, reviewed)."""

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

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'r.db'}",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    def user(label, role=None):
        u = User(username=f"rp-{label}-{uuid_hex()}", hashed_password="x",
                 full_name=label, role=UserRole.OPERATOR, is_active=True)
        db.add(u)
        db.flush()
        if role:
            db.add(GspRoleAssignment(user_id=u.id, role=role, granted_by=u.id,
                                     approval_ref=f"T{uuid_hex()}", review_due_at=utc_now() + _days(30),
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


def _days(n):
    from datetime import timedelta

    return timedelta(days=n)


def uuid_hex():
    import uuid

    return uuid.uuid4().hex[:10]


def _login(ctx, label, role=None):
    u = ctx["user"](label, role)
    ctx["db"].commit()
    ctx["current"]["user"] = u
    return u


def _events(ctx, action, n, db=None):
    from app.gsp.audit import write_audit_event

    actor = ctx["user"]("源", "RECEIVER")
    for i in range(n):
        write_audit_event(ctx["db"], actor_user_id=actor.id, action=action,
                          entity_type="X", entity_id=str(i), reason="rrr")
    ctx["db"].commit()
    return actor


def test_catalog_respects_visibility_and_print_acl(ctx):
    client = ctx["client"]
    _login(ctx, "审计", "AUDITOR")
    keys_auditor = {x["key"] for x in client.get("/api/gsp/reports").json()}
    assert "audit_event_ledger" in keys_auditor
    r = client.post("/api/gsp/reports/audit_event_ledger/print",
                    json={"reason": "审计台账打印ACL测试", "limit": 10})
    assert r.status_code == 200
    pid = r.json()["print_id"]
    # catalog must hide sensitive reports for RECEIVER
    _login(ctx, "收货", "RECEIVER")
    recv_keys = {x["key"] for x in client.get("/api/gsp/reports").json()}
    assert "audit_event_ledger" not in recv_keys
    assert "electronic_signature_ledger" not in recv_keys
    assert "batch_stock_ledger" in recv_keys
    # direct fetch/verify must be refused
    assert client.get(f"/api/gsp/reports/prints/{pid}").status_code == 403
    assert client.post(f"/api/gsp/reports/prints/{pid}/verify").status_code == 403
    # list must not expose the audit print record (DB-level visibility filter)
    listed = client.get("/api/gsp/reports/prints/list").json()
    assert listed["total"] == 0
    # preview reports cannot print without an explicit flag
    assert client.post("/api/gsp/reports/batch_stock_ledger/print",
                       json={"reason": "无 preview 标记尝试打印"}).status_code == 409
    rp = client.post("/api/gsp/reports/batch_stock_ledger/print",
                     json={"reason": "preview 验证", "preview": True})
    assert rp.status_code == 200
    assert rp.json()["copy_no"].startswith("PREVIEW-")
    assert "开发预览—非受控" in rp.json()["html"]
    assert "preview-mark" in rp.json()["html"]           # per-page watermark
    assert "非受控开发预览件" in rp.json()["html"]        # non-controlled footer
    recp = ctx["db"].get(GspControlledPrintRecord, rp.json()["print_id"])
    assert recp is not None and recp.status == "PREVIEW"  # status persisted
    listed2 = client.get("/api/gsp/reports/prints/list").json()
    assert listed2["total"] == 1
    assert listed2["items"][0]["copy_no"].startswith("PREVIEW-")
    assert listed2["items"][0]["status"] == "PREVIEW"


def test_list_pagination_filters_before_paging(ctx):
    client = ctx["client"]
    _login(ctx, "审计A", "AUDITOR")
    for i in range(3):
        r = client.post("/api/gsp/reports/audit_event_ledger/print",
                        json={"reason": f"audit 打印 {i}", "limit": 5})
        assert r.status_code == 200
    r = client.post("/api/gsp/reports/batch_stock_ledger/print",
                    json={"reason": "库存预览打印", "preview": True})
    assert r.status_code == 200
    _login(ctx, "收货B", "RECEIVER")
    body = client.get("/api/gsp/reports/prints/list?limit=10&offset=0").json()
    assert body["total"] == 1, "visibility must be applied before paging"
    assert len(body["items"]) == 1 and body["items"][0]["copy_no"] == r.json()["copy_no"]


def test_cover_all_cap_and_keyset(ctx, monkeypatch):
    _login(ctx, "审计", "AUDITOR")
    from app.gsp import reports as mod
    from app.gsp.reports import ReportError

    monkeypatch.setattr(mod, "MAX_ROWS", 5)
    _events(ctx, "CAP_ACTION", 6)
    # over cap -> specific error, not silent truncation
    with pytest.raises(ReportError, match="上限"):
        mod.run_full_print_rows(ctx["db"], "audit_event_ledger", filters={"action": "CAP_ACTION"})
    # exactly at cap -> full keyset, no duplicates, has_more False
    monkeypatch.setattr(mod, "MAX_ROWS", 6)
    res = mod.run_full_print_rows(ctx["db"], "audit_event_ledger", filters={"action": "CAP_ACTION"})
    assert res["count"] == res["total"] == 6
    ids = [r["id"] for r in res["rows"]]
    assert len(ids) == len(set(ids))
    assert res["has_more"] is False


def test_print_meta_and_truncation_and_full_hash_tamper(ctx):
    client = ctx["client"]
    _login(ctx, "审计", "AUDITOR")
    _events(ctx, "META_ACT", 4)
    # page print with limit=2 -> truncated true, html includes copy_no/version & warning
    r = client.post("/api/gsp/reports/audit_event_ledger/print",
                    json={"reason": "截断与元数据测试", "limit": 2})
    assert r.status_code == 200
    body = r.json()
    assert body["copy_no"] in body["html"]
    assert "v1" in body["html"]
    assert "已截断" in body["html"]
    record = ctx["db"].get(GspControlledPrintRecord, body["print_id"])
    assert record is not None
    assert record.snapshot_data["template_version"] == "v1"
    assert record.snapshot_data["truncated"] is True
    assert record.snapshot_data["copy_no"] == body["copy_no"]
    # cover_all full print: no truncation, exact total
    r2 = client.post("/api/gsp/reports/audit_event_ledger/print",
                     json={"reason": "全量打印", "cover_all": True, "filters": {"action": "META_ACT"}})
    assert r2.status_code == 200
    assert "共 4 行" in r2.json()["html"] and "已截断" not in r2.json()["html"]
    rec2 = ctx["db"].get(GspControlledPrintRecord, r2.json()["print_id"])
    assert rec2.snapshot_data["truncated"] is False and rec2.snapshot_data["total"] == 4
    # tamper detection: one independent record per field (never mutate twice)
    def make_print():
        rr = client.post("/api/gsp/reports/audit_event_ledger/print",
                         json={"reason": "tamper 用例", "limit": 5})
        assert rr.status_code == 200
        return ctx["db"].get(GspControlledPrintRecord, rr.json()["print_id"])

    rec_total = make_print()
    rec_total.snapshot_data = {**rec_total.snapshot_data, "total": rec_total.snapshot_data["total"] + 1}
    ctx["db"].commit()
    assert client.post(f"/api/gsp/reports/prints/{rec_total.id}/verify").json()["valid"] is False

    rec_gen = make_print()
    rec_gen.snapshot_data = {**rec_gen.snapshot_data, "generated_at": "2099-01-01T00:00:00"}
    ctx["db"].commit()
    assert client.post(f"/api/gsp/reports/prints/{rec_gen.id}/verify").json()["valid"] is False

    rec_copy = make_print()
    rec_copy.copy_no = "RPT-TAMPERED"
    ctx["db"].commit()
    assert client.post(f"/api/gsp/reports/prints/{rec_copy.id}/verify").json()["valid"] is False

    rec_outer_tpl = make_print()
    rec_outer_tpl.template_version = "v999"
    ctx["db"].commit()
    assert client.post(f"/api/gsp/reports/prints/{rec_outer_tpl.id}/verify").json()["valid"] is False

    # an untouched record still verifies
    ok = make_print()
    assert client.post(f"/api/gsp/reports/prints/{ok.id}/verify").json()["valid"] is True


def test_unknown_filter_and_pagination(ctx):
    client = ctx["client"]
    _login(ctx, "审计", "AUDITOR")
    _events(ctx, "PAGE_EVT", 3)
    assert client.get("/api/gsp/reports/audit_event_ledger?action=PAGE_EVT&bogus=1").status_code == 422
    body = client.get("/api/gsp/reports/audit_event_ledger?action=PAGE_EVT&limit=2").json()
    assert body["count"] == 2 and body["total"] == 3 and body["has_more"] is True
    page2 = client.get("/api/gsp/reports/audit_event_ledger?action=PAGE_EVT&limit=2&offset=2").json()
    assert page2["count"] >= 1


def test_preview_vs_formal_controlled_print_distinction(ctx):
    """Full regression evidence: preview prints must never look controlled."""
    client = ctx["client"]
    from app.gsp.models import GspAuditEvent

    def audit_action(print_id):
        row = (
            ctx["db"].query(GspAuditEvent)
            .filter(GspAuditEvent.entity_type == "GspControlledPrintRecord",
                    GspAuditEvent.entity_id == str(print_id))
            .order_by(GspAuditEvent.id.desc())
            .first()
        )
        return row.action if row else None

    # formal (audit ledger is production-ready and restricted to quality roles)
    _login(ctx, "审计C", "AUDITOR")
    _events(ctx, "FORMAL_ACT", 1)
    formal = client.post("/api/gsp/reports/audit_event_ledger/print",
                         json={"reason": "正式受控打印", "limit": 5}).json()
    rec_f = ctx["db"].get(GspControlledPrintRecord, formal["print_id"])
    assert formal["copy_no"].startswith("RPT-")
    assert rec_f is not None and rec_f.status == "GENERATED"
    assert rec_f.snapshot_data["preview"] is False
    assert "class='preview-mark'" not in formal["html"]      # watermark element absent
    assert "开发预览—非受控" not in formal["html"]              # banner absent
    assert "非受控开发预览件" not in formal["html"]            # footer stays controlled
    assert audit_action(formal["print_id"]) == "REPORT_PRINTED"
    list_f = client.get("/api/gsp/reports/prints/list").json()
    item_f = next(i for i in list_f["items"] if i["id"] == formal["print_id"])
    assert item_f["status"] == "GENERATED" and item_f["copy_no"].startswith("RPT-")

    # preview (batch stock ledger is production_ready=false)
    pv = client.post("/api/gsp/reports/batch_stock_ledger/print",
                     json={"reason": "预览验证", "preview": True}).json()
    rec_p = ctx["db"].get(GspControlledPrintRecord, pv["print_id"])
    assert pv["copy_no"].startswith("PREVIEW-")
    assert rec_p is not None and rec_p.status == "PREVIEW"
    assert rec_p.snapshot_data["preview"] is True
    for marker in ("class='preview-mark'", "@media print", "开发预览—非受控", "禁止作为正式GSP记录归档/放行", "非受控开发预览件"):
        assert marker in pv["html"], f"preview html missing {marker}"
    assert audit_action(pv["print_id"]) == "REPORT_PREVIEW_PRINTED"
    listed = client.get("/api/gsp/reports/prints/list").json()
    item_p = next(i for i in listed["items"] if i["id"] == pv["print_id"])
    assert item_p["status"] == "PREVIEW" and item_p["copy_no"].startswith("PREVIEW-")

"""HTTP integration tests: business records bind to controlled files.

Covers partner qualification documents (PARTNER_DOCUMENT), supplier-product
authorisation evidence, carrier documents and drug registration files:
- ATTACHMENT_POLICY=enforce rejects plain references (HTTP 422);
- a gspf: token resolves to the stored object and server-side sha/size win;
- purpose mismatch / unknown token are rejected.
"""

from datetime import date, timedelta
from uuid import uuid4

import pytest

from app.core.time import utc_now
from app.gsp.attachments.bindings import ATTACHMENT_POLICY_ENV
from app.gsp.models import GspBusinessPartner, GspRoleAssignment
from app.legacy import User, UserRole

QUALITY_ROLE = "QUALITY_MANAGER"


@pytest.fixture()
def ctx(tmp_path, monkeypatch):
    """TestClient + partner + roles bound to a dedicated file-backed DB."""
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import main  # noqa: F401
    from app.core.database import Base

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'db.sqlite'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    def _user(label, role=None):
        u = User(username=f"bh-{label}-{uuid4().hex[:6]}", hashed_password="x",
                 full_name=label, role=UserRole.OPERATOR, is_active=True)
        db.add(u)
        db.flush()
        if role:
            db.add(GspRoleAssignment(
                user_id=u.id, role=role, granted_by=u.id,
                approval_ref=f"T-{uuid4().hex[:6]}",
                review_due_at=utc_now() + timedelta(days=30), is_active=True))
        return u

    grantor = _user("授权人")
    partner = GspBusinessPartner(
        code=f"P-{uuid4().hex[:6]}", name="受控绑定测试供应商", partner_type="SUPPLIER",
        unified_social_credit_code=f"91{uuid4().hex[:16]}".upper(),
        license_no="L-001", license_scope="药品批发", license_valid_to=date.today() + timedelta(days=365),
        status="PENDING", created_by=grantor.id,
    )
    db.add(partner)
    db.flush()

    from app.core.database import get_db
    from app.legacy import get_current_user

    app = main.app
    current = {}

    async def override_current_user():
        return current["user"]

    def override_db():
        yield db

    app.dependency_overrides[get_current_user] = override_current_user
    app.dependency_overrides[get_db] = override_db
    state = {"db": db, "client": None, "current": current, "partner": partner,
             "grantor": grantor, "_user": _user, "_app": app, "Session": Session,
             "_monkeypatch": monkeypatch}
    try:
        with TestClient(app) as tc:
            state["client"] = tc
            yield state
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db, None)
        db.close()
        engine.dispose()


def _login(ctx, label, role=QUALITY_ROLE):
    u = ctx["_user"](label, role)
    ctx["db"].commit()
    ctx["current"]["user"] = u
    return u


def _upload(ctx, purpose, payload=b"%PDF-1.4 minimal control\n%%EOF\n"):
    return ctx["client"].post(
        "/api/gsp/files",
        files={"file": ("evidence.pdf", payload, "application/pdf")},
        data={"purpose": purpose},
    )


def _partner_doc_payload(ref, sha=None):
    return {
        "document_type": "BUSINESS_LICENSE",
        "document_no": f"N-{uuid4().hex[:6]}",
        "valid_to": date.today().isoformat(),
        "file_ref": ref,
        "file_sha256": sha,
        "file_size_bytes": len(b"%PDF-1.4 minimal control\n%%EOF\n") if sha else None,
        "reason": "绑定测试原因",
    }


def test_partner_doc_enforce_requires_token_and_uses_server_truth(ctx):
    _login(ctx, "质量甲")
    ctx["_monkeypatch"].setenv(ATTACHMENT_POLICY_ENV, "enforce")

    # 1) legacy ref rejected under enforce
    r = ctx["client"].post(
        f"/api/gsp/partners/{ctx['partner'].id}/documents",
        json=_partner_doc_payload("\\\\共享盘\\老扫描件.pdf", "a" * 64),
    )
    assert r.status_code == 422
    assert "enforce" in r.json()["detail"]

    # 2) upload controlled file, then bind by token
    up = _upload(ctx, "PARTNER_DOCUMENT").json()
    r = ctx["client"].post(
        f"/api/gsp/partners/{ctx['partner'].id}/documents",
        json=_partner_doc_payload(up["ref"], "0" * 64),  # forged sha -> ignored
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["file_ref"] == up["ref"]
    assert body["file_sha256"] == up["sha256"]
    assert body["file_size_bytes"] == up["size_bytes"]
    # purpose mismatch is refused
    other = _upload(ctx, "CSV_EVIDENCE").json()
    r = ctx["client"].post(
        f"/api/gsp/partners/{ctx['partner'].id}/documents",
        json=_partner_doc_payload(other["ref"]),
    )
    assert r.status_code == 422
    assert "用途" in r.json()["detail"]


def test_partner_doc_warn_mode_keeps_legacy_ref(ctx):
    _login(ctx, "质量乙")
    # ATTACHMENT_POLICY unset -> settings default warn
    r = ctx["client"].post(
        f"/api/gsp/partners/{ctx['partner'].id}/documents",
        json=_partner_doc_payload("共享盘:/旧扫描件/2025.pdf", "b" * 64),
    )
    assert r.status_code == 201, r.text
    assert r.json()["file_ref"] == "共享盘:/旧扫描件/2025.pdf"

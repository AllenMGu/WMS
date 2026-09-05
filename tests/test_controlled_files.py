"""HTTP + storage tests for the controlled (server-side) GSP file store.

Closes the P0 review finding: qualification/authorisation evidence used to be a
client-supplied ``file_ref`` + ``file_sha256`` pair with no server-side truth.
These tests prove the backend owns the hash, stores bytes immutably
(content-addressed), and gates downloads/verification/disable by role.
"""

import hashlib
import io
import os
from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_db
from app.core.time import utc_now
from app.gsp.attachments import storage
from app.gsp.attachments.models import GspControlledFile
from app.gsp.models import GspAuditEvent, GspRoleAssignment
from app.legacy import User, UserRole, get_current_user

PDF_BYTES = (
    b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
    b"trailer<</Root 1 0 R>>\n%%EOF\n"
)
PDF_SHA = hashlib.sha256(PDF_BYTES).hexdigest()


def _user(db, label: str) -> User:
    user = User(
        username=f"cf-{label}-{uuid4().hex[:8]}",
        hashed_password="test-only",
        full_name=label,
        role=UserRole.OPERATOR,
        is_active=True,
    )
    db.add(user)
    db.flush()
    return user


def _role(db, user: User, role: str, grantor: User) -> None:
    db.add(
        GspRoleAssignment(
            user_id=user.id,
            role=role,
            granted_by=grantor.id,
            approval_ref=f"TEST-{role}-{uuid4().hex[:8]}",
            review_due_at=utc_now() + timedelta(days=30),
            is_active=True,
        )
    )


@pytest.fixture()
def env_store(tmp_path, monkeypatch):
    """Point the immutable store at a throw-away directory for one test."""
    root = tmp_path / "store"
    monkeypatch.setenv("ATTACHMENT_DIR", str(root))
    return str(root)


@pytest.fixture()
def client(env_store, tmp_path):
    """TestClient bound to a dedicated per-test file-backed SQLite database.

    Uses its own engine + session so HTTP tests behave identically in every
    environment (in-memory SQLite cannot share one DB across threads).
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.core.database import Base
    from main import app

    db_file = tmp_path / "test.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestSession()
    current = {}

    async def override_current_user():
        return current["user"]

    def override_db():
        yield db

    app.dependency_overrides[get_current_user] = override_current_user
    app.dependency_overrides[get_db] = override_db
    grantor = _user(db, "授权人")
    db.flush()
    try:
        with TestClient(app) as test_client:
            state = {"client": test_client, "db": db, "current": current, "grantor": grantor}
            yield state
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db, None)
        db.close()
        engine.dispose()


def _login_as(state, db, label: str, role: str | None = None):
    user = _user(db, label)
    if role:
        _role(db, user, role, state["grantor"])
    db.commit()
    state["current"]["user"] = user
    return user


def _upload(state, payload=PDF_BYTES, *, content_type="application/pdf", expected=None, purpose="PARTNER_DOCUMENT"):
    data = {"purpose": purpose}
    if expected is not None:
        data["expected_sha256"] = expected
    return state["client"].post(
        "/api/gsp/files",
        files={"file": ("licence.pdf", payload, content_type)},
        data=data,
    )


def _audit_actions(db, entity_id: str) -> list[str]:
    rows = (
        db.query(GspAuditEvent.action)
        .filter(GspAuditEvent.entity_type == "GspControlledFile", GspAuditEvent.entity_id == entity_id)
        .all()
    )
    return [row[0] for row in rows]


def test_upload_stores_server_side_hash_and_audits(client):
    state = client
    db = state["db"]
    _login_as(state, db, "质量经理", "QUALITY_MANAGER")
    resp = _upload(state, expected=PDF_SHA)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["ref"].startswith("gspf:")
    assert body["sha256"] == PDF_SHA
    assert body["size_bytes"] == len(PDF_BYTES)
    assert body["purpose"] == "PARTNER_DOCUMENT"
    assert body["status"] == "ACTIVE"

    stored_path = storage.content_path(PDF_SHA)
    assert os.path.exists(stored_path)
    with open(stored_path, "rb") as fh:
        assert fh.read() == PDF_BYTES

    meta = state["client"].get(f"/api/gsp/files/{body['object_key']}")
    assert meta.status_code == 200
    assert meta.json()["ref"] == body["ref"]
    assert "FILE_UPLOADED" in _audit_actions(db, str(body["id"]))


def test_upload_rejects_client_hash_mismatch(client):
    _login_as(client, client["db"], "收货员", "RECEIVER")
    resp = _upload(client, expected="0" * 64)
    assert resp.status_code == 422
    assert "不一致" in resp.json()["detail"]


def test_upload_requires_gsp_role(client):
    db = client["db"]
    user = _user(db, "无岗位用户")
    db.commit()
    client["current"]["user"] = user
    resp = _upload(client)
    assert resp.status_code == 403


def test_upload_rejects_unsupported_content_type(client):
    _login_as(client, client["db"], "收货员", "RECEIVER")
    resp = _upload(client, payload=b"<html>x</html>", content_type="text/html")
    assert resp.status_code == 422


def test_download_returns_original_bytes_and_enforces_permission(client):
    db = client["db"]
    _login_as(client, db, "审计员", "AUDITOR")
    up = _upload(client).json()
    dl = client["client"].get(f"/api/gsp/files/{up['object_key']}/content")
    assert dl.status_code == 200
    assert dl.content == PDF_BYTES
    assert dl.headers.get("x-controlled-file-ref") == up["ref"]

    outsider = _user(db, "无岗位下载者")
    db.commit()
    client["current"]["user"] = outsider
    denied = client["client"].get(f"/api/gsp/files/{up['object_key']}/content")
    assert denied.status_code == 403


def test_verify_detects_tampered_stored_object(client):
    db = client["db"]
    _login_as(client, db, "审计员", "AUDITOR")
    up = _upload(client).json()
    stored_path = storage.content_path(up["sha256"])
    with open(stored_path, "wb") as fh:
        fh.write(b"tampered-bytes")
    result = client["client"].post(f"/api/gsp/files/{up['object_key']}/verify")
    assert result.status_code == 200
    body = result.json()
    assert body["valid"] is False
    assert body["sha256_matches"] is False
    assert "FILE_VERIFY_FAILED" in _audit_actions(db, str(up["id"]))


def test_disable_requires_quality_manager_then_blocks_download(client):
    db = client["db"]
    uploader = _login_as(client, db, "养护员", "MAINTENANCE")
    up = _upload(client).json()
    disable_url = f"/api/gsp/files/{up['object_key']}/disable"

    denied = client["client"].post(disable_url, json={"reason": "未经质量经理批准停用测试"})
    assert denied.status_code == 403

    quality = _user(db, "质量经理二号")
    _role(db, quality, "QUALITY_MANAGER", client["grantor"])
    db.commit()
    client["current"]["user"] = quality
    resp = client["client"].post(disable_url, json={"reason": "证照到期停用测试"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "DISABLED"
    assert "FILE_DISABLED" in _audit_actions(db, str(up["id"]))

    dl = client["client"].get(f"/api/gsp/files/{up['object_key']}/content")
    assert dl.status_code == 410
    assert uploader.id is not None  # silence unused


def test_unknown_file_returns_404(client):
    _login_as(client, client["db"], "审计员", "AUDITOR")
    assert client["client"].get("/api/gsp/files/" + "0" * 32).status_code == 404
    assert client["client"].get("/api/gsp/files/not-a-key").status_code == 404


def test_storage_rejects_empty_and_oversized_streams(env_store):
    with pytest.raises(ValueError, match="空文件"):
        storage.store_stream(io.BytesIO(b""), content_type="application/pdf")
    with pytest.raises(ValueError, match="大小限制"):
        storage.store_stream(io.BytesIO(b"x" * 64), content_type="application/pdf", max_bytes=16)
    # de-duplication: same bytes twice yield one object row path reuse
    first = storage.store_stream(io.BytesIO(PDF_BYTES), content_type="application/pdf")
    second = storage.store_stream(io.BytesIO(PDF_BYTES), content_type="application/pdf")
    assert first.sha256 == second.sha256 == PDF_SHA
    assert first.path == second.path
    row = GspControlledFile
    assert row is not None

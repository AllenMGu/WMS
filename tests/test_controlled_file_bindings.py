"""Unit tests for the business-record <-> controlled-file binding helper."""

from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.core.database import Base, get_db  # noqa: F401 (keeps import graph)
from app.core.time import utc_now
from app.gsp.attachments import bindings
from app.gsp.attachments.models import (
    PURPOSE_CSV_EVIDENCE,
    PURPOSE_OTHER,
    PURPOSE_PARTNER_DOCUMENT,
    STATUS_ACTIVE,
    GspControlledFile,
)
from app.legacy import User, UserRole


@pytest.fixture()
def store(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import main  # noqa: F401 - registers all tables on Base

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'b.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    user = User(username=f"bind-{uuid4().hex[:8]}", hashed_password="x",
                full_name="bind", role=UserRole.OPERATOR, is_active=True)
    db.add(user)
    db.flush()

    def make_file(purpose=PURPOSE_PARTNER_DOCUMENT, sha="a" * 64, status=STATUS_ACTIVE):
        obj = GspControlledFile(
            object_key=uuid4().hex,
            file_name="evidence.pdf",
            content_type="application/pdf",
            size_bytes=12,
            sha256=sha,
            purpose=purpose,
            status=status,
            uploaded_by=user.id,
            uploaded_at=utc_now(),
        )
        db.add(obj)
        db.flush()
        return obj

    yield db, make_file, user
    db.close()
    engine.dispose()


def _token(obj):
    from app.gsp.attachments.refs import build_ref

    return build_ref(obj.object_key)


def test_empty_value_returns_none(store):
    db, _, _ = store
    assert bindings.resolve_attachment(db, value=None, expected_purpose="PARTNER_DOCUMENT") == (None, None, None)
    assert bindings.resolve_attachment(db, value="", expected_purpose="PARTNER_DOCUMENT") == (None, None, None)


def test_legacy_ref_warn_mode_passthrough(store, monkeypatch):
    db, _, _ = store
    monkeypatch.setenv(bindings.ATTACHMENT_POLICY_ENV, "warn")
    value, sha, size = bindings.resolve_attachment(
        db, value="共享盘:/旧扫描件/2025.pdf", expected_purpose="PARTNER_DOCUMENT",
        declared_sha="c" * 64, declared_size=99,
    )
    assert value == "共享盘:/旧扫描件/2025.pdf"
    assert sha == "c" * 64
    assert size == 99


def test_legacy_ref_enforce_mode_rejected(store, monkeypatch):
    db, _, _ = store
    monkeypatch.setenv(bindings.ATTACHMENT_POLICY_ENV, "enforce")
    with pytest.raises(HTTPException) as exc:
        bindings.resolve_attachment(db, value="随手填的引用", expected_purpose="PARTNER_DOCUMENT")
    assert exc.value.status_code == 422
    assert "enforce" in exc.value.detail


def test_token_uses_server_truth_and_ignores_declared(store, monkeypatch):
    db, make_file, _ = store
    monkeypatch.setenv(bindings.ATTACHMENT_POLICY_ENV, "enforce")
    obj = make_file(purpose=PURPOSE_PARTNER_DOCUMENT, sha="f" * 64)
    value, sha, size = bindings.resolve_attachment(
        db, value=_token(obj), expected_purpose="PARTNER_DOCUMENT",
        declared_sha="9" * 64, declared_size=12345,  # forged -> must be ignored
    )
    assert value == _token(obj)
    assert sha == "f" * 64
    assert size == obj.size_bytes


def test_token_purpose_mismatch_rejected(store, monkeypatch):
    db, make_file, _ = store
    monkeypatch.setenv(bindings.ATTACHMENT_POLICY_ENV, "enforce")
    obj = make_file(purpose=PURPOSE_CSV_EVIDENCE)
    with pytest.raises(HTTPException) as exc:
        bindings.resolve_attachment(db, value=_token(obj), expected_purpose="PARTNER_DOCUMENT")
    assert exc.value.status_code == 422
    assert "用途" in exc.value.detail


def test_token_other_purpose_accepted_anywhere(store, monkeypatch):
    db, make_file, _ = store
    obj = make_file(purpose=PURPOSE_OTHER)
    value, sha, size = bindings.resolve_attachment(db, value=_token(obj), expected_purpose="PARTNER_DOCUMENT")
    assert value == _token(obj)


def test_unknown_or_disabled_token_rejected(store, monkeypatch):
    db, make_file, _ = store
    from app.gsp.attachments.models import STATUS_DISABLED

    obj = make_file(status=STATUS_DISABLED)
    with pytest.raises(HTTPException) as exc:
        bindings.resolve_attachment(db, value=_token(obj), expected_purpose="PARTNER_DOCUMENT")
    assert exc.value.status_code == 422
    with pytest.raises(HTTPException):
        bindings.resolve_attachment(db, value="gspf:" + "0" * 32, expected_purpose="PARTNER_DOCUMENT")


def test_purpose_mapping_and_policy_default():
    assert bindings.purpose_for("carrier_document") == "CARRIER_DOCUMENT"
    assert bindings.effective_policy() in {"warn", "enforce"}

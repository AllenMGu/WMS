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


def _make_supplier_goods(ctx, suffix):
    """Create supplier partner + goods + drug profile for SPA tests."""
    db = ctx["db"]
    supplier = GspBusinessPartner(
        code=f"S-{suffix}", name="受控供应商", partner_type="SUPPLIER",
        unified_social_credit_code=f"91{suffix}".ljust(18, "0"),
        license_no="L", license_scope="批发", license_valid_to=date.today() + timedelta(days=365),
        status="PENDING", created_by=ctx["grantor"].id,
    )
    db.add(supplier)
    from app.legacy import Goods

    goods = Goods(barcode=f"BC-{suffix}", name="测试药品", spec="10mg", unit="盒", price=1)
    db.add(goods)
    db.flush()
    from app.gsp.models import GspDrugProfile

    profile = GspDrugProfile(
        goods_id=goods.id, approval_no=f"AN-{suffix}", generic_name="测试药品",
        dosage_form="片剂", manufacturer="测试厂", storage_condition="NORMAL",
        created_by=ctx["grantor"].id, status="PENDING",
    )
    db.add(profile)
    db.commit()
    return supplier, goods


def test_supplier_authorization_single_and_bulk_bind(ctx):
    db = ctx["db"]
    _login(ctx, "质量丙")
    ctx["_monkeypatch"].setenv(ATTACHMENT_POLICY_ENV, "enforce")
    supplier, goods = _make_supplier_goods(ctx, "s1")
    up = _upload(ctx, "SUPPLIER_PRODUCT_AUTHORIZATION").json()
    body = {
        "goods_id": goods.id,
        "authorization_ref": up["ref"],
        "authorization_sha256": "0" * 64,   # forged -> replaced by server value
        "authorization_size_bytes": 1,
        "scope_description": "授权范围为该品种供货",
        "valid_from": date.today().isoformat(),
        "valid_to": (date.today() + timedelta(days=365)).isoformat(),
        "reason": "单条绑定测试",
    }
    r = ctx["client"].post(f"/api/gsp/partners/{supplier.id}/products", json=body)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["authorization_ref"] == up["ref"]
    assert out["authorization_sha256"] == up["sha256"]
    assert out["authorization_size_bytes"] == up["size_bytes"]

    # legacy ref under enforce is refused at route level
    bad = dict(body, authorization_ref="共享盘:/老授权书.pdf")
    r = ctx["client"].post(f"/api/gsp/partners/{supplier.id}/products", json=bad)
    assert r.status_code == 422

    # purpose mismatch refused
    other = _upload(ctx, "CSV_EVIDENCE").json()
    r = ctx["client"].post(
        f"/api/gsp/partners/{supplier.id}/products",
        json=dict(body, authorization_ref=other["ref"]),
    )
    assert r.status_code == 422
    assert "用途" in r.json()["detail"]

    # bulk import (second goods/profile)
    supplier2, goods2 = _make_supplier_goods(ctx, "s2")
    up2 = _upload(ctx, "SUPPLIER_PRODUCT_AUTHORIZATION").json()
    from app.gsp.models import GspDrugProfile

    approval_no2 = db.query(GspDrugProfile.approval_no).filter(GspDrugProfile.goods_id == goods2.id).scalar()
    r = ctx["client"].post(
        f"/api/gsp/partners/{supplier2.id}/products/bulk-import",
        json={
            "rows": [{
                "goods_barcode": goods2.barcode,
                "approval_no": approval_no2,
                "authorization_ref": up2["ref"],
                "authorization_sha256": up2["sha256"],
                "authorization_size_bytes": up2["size_bytes"],
                "scope_description": "批量绑定测试",
                "valid_from": date.today().isoformat(),
                "valid_to": (date.today() + timedelta(days=365)).isoformat(),
            }],
            "reason": "批量绑定测试原因",
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["created"] == 1
    from app.gsp.models import GspSupplierProductAuthorization

    stored = db.query(GspSupplierProductAuthorization).filter(
        GspSupplierProductAuthorization.supplier_id == supplier2.id,
        GspSupplierProductAuthorization.goods_id == goods2.id,
    ).first()
    assert stored.authorization_ref == up2["ref"]
    assert stored.authorization_sha256 == up2["sha256"]
    assert stored.authorization_size_bytes == up2["size_bytes"]


def test_drug_registration_binds_on_profile_upsert(ctx):
    db = ctx["db"]
    _login(ctx, "质量丁")
    ctx["_monkeypatch"].setenv(ATTACHMENT_POLICY_ENV, "enforce")
    from app.legacy import Goods

    goods = Goods(barcode=f"RD-{uuid4().hex[:8]}", name="注册药", spec="1g", unit="支", price=2)
    db.add(goods)
    db.flush()
    db.commit()
    up = _upload(ctx, "DRUG_REGISTRATION").json()
    body = {
        "approval_no": f"RAN-{uuid4().hex[:8]}",
        "generic_name": "注册用药品",
        "dosage_form": "注射剂",
        "manufacturer": "注册厂",
        "registration_document_ref": up["ref"],
        "registration_document_sha256": "0" * 64,
        "registration_document_size_bytes": 3,
        "nmpa_verification_ref": "NMPA-REG-1",
        "reason": "注册文件绑定测试",
    }
    r = ctx["client"].put(f"/api/gsp/products/{goods.id}/profile", json=body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["registration_document_ref"] == up["ref"]
    assert out["registration_document_sha256"] == up["sha256"]
    assert out["registration_document_size_bytes"] == up["size_bytes"]

    other = _upload(ctx, "CSV_EVIDENCE").json()
    r = ctx["client"].put(
        f"/api/gsp/products/{goods.id}/profile",
        json=dict(body, registration_document_ref=other["ref"]),
    )
    assert r.status_code == 422
    assert "用途" in r.json()["detail"]


def test_carrier_document_binds(ctx):
    db = ctx["db"]
    _login(ctx, "运输协调", role="TRANSPORT_COORDINATOR")
    ctx["_monkeypatch"].setenv(ATTACHMENT_POLICY_ENV, "enforce")
    from app.gsp.transport.models import GspCarrier

    carrier = GspCarrier(
        code=f"C-{uuid4().hex[:6]}", name="受控承运商",
        unified_social_credit_code=f"92{uuid4().hex[:16]}".upper(),
        license_no="TL-1", license_valid_to=date.today() + timedelta(days=365),
        service_modes=["NORMAL"], quality_agreement_valid_to=date.today() + timedelta(days=365),
        status="PENDING", created_by=ctx["grantor"].id,
    )
    db.add(carrier)
    db.commit()
    up = _upload(ctx, "CARRIER_DOCUMENT").json()
    r = ctx["client"].post(
        f"/api/gsp/transport/carriers/{carrier.id}/documents",
        json={
            "document_type": "BUSINESS_LICENSE",
            "document_no": f"DN-{uuid4().hex[:6]}",
            "valid_to": (date.today() + timedelta(days=365)).isoformat(),
            "file_ref": up["ref"],
            "reason": "承运商文件绑定测试",
        },
    )
    assert r.status_code == 201, r.text
    out = r.json()
    assert out.get("file_ref") == up["ref"]
    assert out.get("file_sha256") == up["sha256"]
    assert out.get("file_size_bytes") == up["size_bytes"]

    other = _upload(ctx, "CSV_EVIDENCE").json()
    r = ctx["client"].post(
        f"/api/gsp/transport/carriers/{carrier.id}/documents",
        json={
            "document_type": "BUSINESS_LICENSE",
            "document_no": f"DN-{uuid4().hex[:6]}",
            "valid_to": (date.today() + timedelta(days=365)).isoformat(),
            "file_ref": other["ref"],
            "reason": "用途不符测试",
        },
    )
    assert r.status_code == 422
    assert "用途" in r.json()["detail"]

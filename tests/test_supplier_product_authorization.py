from datetime import date, timedelta
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.core.database import SessionLocal
from app.gsp.models import GspBusinessPartner, GspDrugProfile, GspSupplierProductAuthorization
from app.gsp.qualification import evaluate_supplier_product_authorization
from app.gsp.router import (
    approve_supplier_product,
    bulk_import_supplier_products,
    compliance_summary,
    list_supplier_product_authorizations,
    list_supplier_products,
    suspend_supplier_product,
    upsert_supplier_product,
)
from app.gsp.schemas import (
    ChangeReason,
    SupplierProductAuthorizationBulkImport,
    SupplierProductAuthorizationBulkRow,
    SupplierProductAuthorizationCreate,
)
from app.legacy import Goods, User, UserRole
from tests.gsp_seed_helpers import add_verified_partner_evidence


def _request() -> Request:
    return Request({"type": "http", "client": ("127.0.0.1", 12345), "headers": []})


def test_supplier_product_scope_requires_independent_approval_and_can_be_suspended():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        suffix = uuid4().hex[:8]
        maintainer = User(
            username=f"scope-maintainer-{suffix}",
            hashed_password="test-only",
            full_name="供货目录维护人",
            role=UserRole.OPERATOR,
        )
        approver = User(
            username=f"scope-approver-{suffix}",
            hashed_password="test-only",
            full_name="供货目录批准人",
            role=UserRole.OPERATOR,
        )
        db.add_all([maintainer, approver])
        db.flush()
        goods = Goods(
            barcode=f"SCOPE-{suffix}",
            name="供货范围测试药品",
            spec="20mg*10片",
            unit="盒",
            price=10,
        )
        supplier = GspBusinessPartner(
            code=f"SCOPE-SUP-{suffix}",
            name="供货范围测试供应商",
            partner_type="SUPPLIER",
            license_no=f"SCOPE-LIC-{suffix}",
            license_scope="药品批发",
            license_valid_to=date.today() + timedelta(days=365),
            quality_agreement_valid_to=date.today() + timedelta(days=365),
            status="APPROVED",
            created_by=maintainer.id,
            approved_by=approver.id,
        )
        db.add_all([goods, supplier])
        db.flush()
        profile = GspDrugProfile(
            goods_id=goods.id,
            approval_no=f"SCOPE-APP-{suffix}",
            generic_name="供货范围测试药品",
            dosage_form="片剂",
            manufacturer="测试生产企业",
            storage_condition="NORMAL",
            traceability_required=True,
            registration_valid_to=date.today() + timedelta(days=365),
            registration_document_ref="test://scope/registration",
            nmpa_verification_ref="test://scope/nmpa",
            status="APPROVED",
            created_by=maintainer.id,
            approved_by=approver.id,
        )
        db.add(profile)
        db.flush()
        add_verified_partner_evidence(
            db,
            partner=supplier,
            verifier_id=approver.id,
            valid_to=date.today() + timedelta(days=365),
        )
        authorization = upsert_supplier_product(
                partner_id=supplier.id,
                payload=SupplierProductAuthorizationCreate(
                    goods_id=goods.id,
                    authorization_ref="test://scope/authorization",
                    authorization_sha256="b" * 64,
                    authorization_size_bytes=256,
                    scope_description="仅允许供应该批准文号和规格",
                    valid_from=date.today(),
                    valid_to=date.today() + timedelta(days=180),
                    reason="建立供应商固定供货品种目录",
                ),
                request=_request(),
                current_user=maintainer,
                db=db,
            )
        assert authorization.status == "PENDING"
        with pytest.raises(HTTPException, match="维护人与批准人必须分离"):
            approve_supplier_product(
                    partner_id=supplier.id,
                    authorization_id=authorization.id,
                    payload=ChangeReason(reason="错误同人批准"),
                    request=_request(),
                    current_user=maintainer,
                    db=db,
                )
        authorization = approve_supplier_product(
                partner_id=supplier.id,
                authorization_id=authorization.id,
                payload=ChangeReason(reason="质量复核供货范围及证据"),
                request=_request(),
                current_user=approver,
                db=db,
            )
        assert authorization.status == "APPROVED"
        assert evaluate_supplier_product_authorization(
            db, supplier_id=supplier.id, goods_id=goods.id
        ).qualified
        effective = list_supplier_products(
                partner_id=supplier.id,
                effective_only=True,
                current_user=maintainer,
                db=db,
            )
        assert [row.goods_id for row in effective] == [goods.id]
        authorization = suspend_supplier_product(
                partner_id=supplier.id,
                authorization_id=authorization.id,
                payload=ChangeReason(reason="暂停该品种供货授权"),
                request=_request(),
                current_user=approver,
                db=db,
            )
        assert authorization.status == "SUSPENDED"
        assert not evaluate_supplier_product_authorization(
            db, supplier_id=supplier.id, goods_id=goods.id
        ).qualified
        effective = list_supplier_products(
                partner_id=supplier.id,
                effective_only=True,
                current_user=maintainer,
                db=db,
            )
        assert effective == []
    finally:
        db.rollback()
        db.close()


def test_bulk_import_is_atomic_pending_and_visible_in_expiry_alerts():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        suffix = uuid4().hex[:8]
        maintainer = User(
            username=f"bulk-maintainer-{suffix}",
            hashed_password="test-only",
            full_name="批量目录维护人",
            role=UserRole.OPERATOR,
        )
        approver = User(
            username=f"bulk-approver-{suffix}",
            hashed_password="test-only",
            full_name="批量目录批准人",
            role=UserRole.OPERATOR,
        )
        db.add_all([maintainer, approver])
        db.flush()
        supplier = GspBusinessPartner(
            code=f"BULK-SUP-{suffix}",
            name="批量导入测试供应商",
            partner_type="SUPPLIER",
            license_no=f"BULK-LIC-{suffix}",
            license_scope="药品批发",
            license_valid_to=date.today() + timedelta(days=365),
            quality_agreement_valid_to=date.today() + timedelta(days=365),
            status="APPROVED",
            created_by=maintainer.id,
            approved_by=approver.id,
        )
        goods_rows = [
            Goods(
                barcode=f"BULK-{suffix}-{index}",
                name=f"批量导入测试药品{index}",
                spec="10mg*10片",
                unit="盒",
                price=10,
            )
            for index in range(2)
        ]
        db.add_all([supplier, *goods_rows])
        db.flush()
        profiles = []
        for index, goods in enumerate(goods_rows):
            profile = GspDrugProfile(
                goods_id=goods.id,
                approval_no=f"BULK-APP-{suffix}-{index}",
                generic_name=goods.name,
                dosage_form="片剂",
                manufacturer="测试生产企业",
                storage_condition="NORMAL",
                traceability_required=True,
                registration_valid_to=date.today() + timedelta(days=365),
                registration_document_ref=f"test://bulk/registration/{index}",
                nmpa_verification_ref=f"test://bulk/nmpa/{index}",
                status="APPROVED",
                created_by=maintainer.id,
                approved_by=approver.id,
            )
            profiles.append(profile)
        db.add_all(profiles)
        add_verified_partner_evidence(
            db,
            partner=supplier,
            verifier_id=approver.id,
            valid_to=date.today() + timedelta(days=365),
        )
        payload = SupplierProductAuthorizationBulkImport(
            rows=[
                SupplierProductAuthorizationBulkRow(
                    goods_barcode=goods.barcode,
                    approval_no=profile.approval_no,
                    authorization_ref=f"test://bulk/authorization/{index}",
                    authorization_sha256=str(index + 1) * 64,
                    authorization_size_bytes=256 + index,
                    scope_description="批量建立固定供货品种目录",
                    valid_from=date.today(),
                    valid_to=date.today() + timedelta(days=10 + index),
                )
                for index, (goods, profile) in enumerate(zip(goods_rows, profiles, strict=True))
            ],
            reason="批量回填供应商供货品种关系",
        )
        result = bulk_import_supplier_products(
                partner_id=supplier.id,
                payload=payload,
                request=_request(),
                current_user=maintainer,
                db=db,
            )
        assert result.created == 2
        assert result.updated == 0
        assert result.pending_approval == 2
        approve_supplier_product(
                partner_id=supplier.id,
                authorization_id=result.authorization_ids[0],
                payload=ChangeReason(reason="独立批准临期供货授权"),
                request=_request(),
                current_user=approver,
                db=db,
            )

        alerts = list_supplier_product_authorizations(
                supplier_id=supplier.id,
                alert_only=True,
                warning_days=30,
                current_user=maintainer,
                db=db,
            )
        assert {row.goods_id for row in alerts} == {goods.id for goods in goods_rows}
        summary = compliance_summary(current_user=maintainer, db=db)
        assert summary["pending_supplier_product_authorizations"] >= 1
        assert summary["near_expiry_supplier_product_authorizations"] >= 1

        duplicate_payload = payload.model_copy(update={"rows": [payload.rows[0], payload.rows[0]]})
        with pytest.raises(HTTPException, match="重复货物条码"):
            bulk_import_supplier_products(
                    partner_id=supplier.id,
                    payload=duplicate_payload,
                    request=_request(),
                    current_user=maintainer,
                    db=db,
                )
        approved = db.get(GspSupplierProductAuthorization, result.authorization_ids[0])
        assert approved.status == "APPROVED"

        result = bulk_import_supplier_products(
                partner_id=supplier.id,
                payload=payload,
                request=_request(),
                current_user=maintainer,
                db=db,
            )
        assert result.created == 0
        assert result.updated == 2
    finally:
        db.rollback()
        db.close()

from __future__ import annotations

from datetime import date, timedelta
from uuid import uuid4

from app.core.database import SessionLocal
from app.core.time import utc_now
from app.gsp.catalog_queries import (
    list_batch_stock,
    list_drug_batches,
    list_drug_profiles,
    list_effective_role_assignments,
    list_partner_documents,
    list_quality_holds,
)
from app.gsp.models import (
    GspBatchStock,
    GspBusinessPartner,
    GspDrugBatch,
    GspDrugProfile,
    GspPartnerDocument,
    GspQualityHold,
    GspRoleAssignment,
)
from app.gsp.schemas import (
    BatchResponse,
    BatchStockResponse,
    DrugProfileResponse,
    PartnerDocumentResponse,
    QualityHoldResponse,
)
from app.legacy import Goods, Location, User, UserRole, Warehouse


def test_catalog_queries_supply_frontend_read_models_and_filters():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        suffix = uuid4().hex[:10]
        actor = User(
            username=f"catalog-{suffix}",
            hashed_password="test-only",
            full_name="目录查询测试员",
            role=UserRole.OPERATOR,
            is_active=True,
        )
        goods = Goods(
            barcode=f"BAR-{suffix}",
            name=f"测试药品-{suffix}",
            spec="10mg",
            unit="盒",
            price=1,
        )
        warehouse = Warehouse(
            code=f"WH-{suffix}",
            name=f"测试仓库-{suffix}",
            is_active=True,
        )
        db.add_all([actor, goods, warehouse])
        db.flush()
        location = Location(
            warehouse_id=warehouse.id,
            location_code=f"LOC-{suffix}",
            name="合格品区",
            is_active=True,
        )
        partner = GspBusinessPartner(
            code=f"SUP-{suffix}",
            name=f"测试供货方-{suffix}",
            partner_type="SUPPLIER",
            license_no=f"LIC-{suffix}",
            license_scope="药品批发",
            license_valid_to=date.today() + timedelta(days=365),
            quality_agreement_valid_to=date.today() + timedelta(days=365),
            status="APPROVED",
            created_by=actor.id,
        )
        db.add_all([location, partner])
        db.flush()
        profile = GspDrugProfile(
            goods_id=goods.id,
            approval_no=f"APPROVAL-{suffix}",
            generic_name="测试通用名",
            dosage_form="片剂",
            manufacturer="测试生产企业",
            marketing_authorization_holder="测试持有人",
            storage_condition="NORMAL",
            min_temperature=10,
            max_temperature=30,
            is_prescription=True,
            is_special_controlled=False,
            traceability_required=True,
            registration_valid_to=date.today() + timedelta(days=365),
            registration_document_ref=f"internal://registration/{suffix}",
            nmpa_verification_ref=f"external-ref://nmpa/{suffix}",
            status="APPROVED",
            created_by=actor.id,
        )
        batch = GspDrugBatch(
            goods_id=goods.id,
            batch_no=f"BATCH-{suffix}",
            production_date=date.today() - timedelta(days=30),
            expiry_date=date.today() + timedelta(days=335),
            supplier_id=partner.id,
            receipt_document_no=f"RC-{suffix}",
            inspection_report_no=f"IR-{suffix}",
            traceability_code=f"TRACE-{suffix}",
            arrival_temperature=20,
            transport_temperature_min=10,
            transport_temperature_max=30,
            temperature_record_ref=f"internal://temperature/{suffix}",
            status="RELEASED",
            created_by=actor.id,
        )
        document = GspPartnerDocument(
            partner_id=partner.id,
            document_type="BUSINESS_LICENSE",
            document_no=f"DOC-{suffix}",
            valid_to=date.today() + timedelta(days=365),
            file_ref=f"internal://partner/{suffix}",
            status="VERIFIED",
        )
        db.add_all([profile, batch, document])
        db.flush()
        stock = GspBatchStock(
            batch_id=batch.id,
            warehouse_id=warehouse.id,
            location_id=location.id,
            quantity=100,
            reserved_quantity=12,
            stock_status="AVAILABLE",
        )
        hold = GspQualityHold(
            batch_id=batch.id,
            reason_code="OTHER",
            reason="目录查询测试锁定",
            status="ACTIVE",
            initiated_by=actor.id,
        )
        db.add_all([stock, hold])
        db.flush()

        profiles = list_drug_profiles(db, keyword=suffix)
        batches = list_drug_batches(db, batch_no=suffix)
        stocks = list_batch_stock(db, warehouse_id=warehouse.id)
        holds = list_quality_holds(db, status="ACTIVE", batch_id=batch.id)
        documents = list_partner_documents(
            db,
            partner_id=partner.id,
            document_type="BUSINESS_LICENSE",
        )

        assert profiles[0]["goods_name"] == goods.name
        assert profiles[0]["traceability_required"] is True
        assert batches[0]["goods_name"] == goods.name
        assert batches[0]["supplier_name"] == partner.name
        assert stocks[0]["batch_no"] == batch.batch_no
        assert stocks[0]["warehouse_name"] == warehouse.name
        assert stocks[0]["location_code"] == location.location_code
        assert holds[0]["batch_no"] == batch.batch_no
        assert documents[0]["file_ref"] == document.file_ref

        DrugProfileResponse.model_validate(profiles[0])
        BatchResponse.model_validate(batches[0])
        BatchStockResponse.model_validate(stocks[0])
        QualityHoldResponse.model_validate(holds[0])
        PartnerDocumentResponse.model_validate(documents[0])
    finally:
        db.rollback()
        db.close()


def test_effective_roles_only_returns_current_assignments():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        suffix = uuid4().hex[:10]
        user = User(
            username=f"roles-me-{suffix}",
            hashed_password="test-only",
            full_name="岗位查询测试员",
            role=UserRole.OPERATOR,
            is_active=True,
        )
        grantor = User(
            username=f"roles-grantor-{suffix}",
            hashed_password="test-only",
            full_name="岗位授权测试员",
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add_all([user, grantor])
        db.flush()
        db.add_all(
            [
                GspRoleAssignment(
                    user_id=user.id,
                    role="INSPECTOR",
                    granted_by=grantor.id,
                    approval_ref=f"OA-{suffix}-1",
                    review_due_at=utc_now() + timedelta(days=30),
                    is_active=True,
                ),
                GspRoleAssignment(
                    user_id=user.id,
                    role="SALES",
                    granted_by=grantor.id,
                    approval_ref=f"OA-{suffix}-2",
                    review_due_at=utc_now() - timedelta(days=1),
                    is_active=True,
                ),
            ]
        )
        db.flush()

        assignments = list_effective_role_assignments(db, user_id=user.id)
        assert [row.role for row in assignments] == ["INSPECTOR"]
    finally:
        db.rollback()
        db.close()

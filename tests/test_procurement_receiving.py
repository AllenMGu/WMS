from datetime import date, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.core.database import SessionLocal
from app.gsp.errors import WorkflowError
from app.gsp.models import (
    GspBatchStock,
    GspBusinessPartner,
    GspDrugBatch,
    GspDrugProfile,
    GspPartnerDocument,
    GspQualityHold,
)
from app.gsp.procurement_receiving.models import GspPurchaseOrderItem, GspReceiptItem
from app.gsp.procurement_receiving.schemas import (
    ControlledPrintCreate,
    PurchaseOrderCreate,
    PurchaseOrderLineCreate,
    ReceiptCreate,
    ReceiptInspection,
    ReceiptLineCreate,
    ReceiptSampling,
)
from app.gsp.procurement_receiving.service import (
    approve_purchase_order,
    create_purchase_order,
    create_receipt,
    create_receipt_print_record,
    inspect_receipt_item,
    record_receipt_sampling,
    submit_purchase_order,
)
from app.gsp.quality_disposition.models import GspNonconformingRecord
from app.legacy import Goods, Location, User, UserRole, Warehouse, ensure_not_gsp_managed_goods
from tests.gsp_seed_helpers import add_verified_partner_evidence


def _seed_qualified_purchase_data(db):
    suffix = uuid4().hex[:10]
    users = []
    for name in ("procurement", "quality", "receiver", "inspector"):
        user = User(
            username=f"{name}-{suffix}",
            hashed_password="test-only",
            full_name=name,
            role=UserRole.OPERATOR,
        )
        db.add(user)
        users.append(user)
    warehouse = Warehouse(code=f"WH-{suffix}", name="GSP测试仓", is_active=True)
    goods = Goods(
        barcode=f"BAR-{suffix}",
        name="测试药品",
        spec="10mg*10片",
        unit="盒",
        price=10,
    )
    db.add_all([warehouse, goods])
    db.flush()
    location = Location(
        warehouse_id=warehouse.id,
        location_code=f"LOC-{suffix}",
        name="验收合格区",
        is_active=True,
    )
    supplier = GspBusinessPartner(
        code=f"SUP-{suffix}",
        name="合格供货方",
        partner_type="SUPPLIER",
        license_no=f"LIC-{suffix}",
        license_scope="药品批发",
        license_valid_to=date.today() + timedelta(days=365),
        quality_agreement_valid_to=date.today() + timedelta(days=365),
        status="APPROVED",
        approved_by=users[1].id,
        created_by=users[1].id,
    )
    profile = GspDrugProfile(
        goods_id=goods.id,
        approval_no=f"APPROVAL-{suffix}",
        generic_name="测试药品",
        dosage_form="片剂",
        manufacturer="测试药企",
        storage_condition="NORMAL",
        traceability_required=True,
        registration_valid_to=date.today() + timedelta(days=365),
        registration_document_ref="test://registration/purchase",
        nmpa_verification_ref="test://nmpa/purchase",
        status="APPROVED",
        approved_by=users[1].id,
        created_by=users[1].id,
    )
    db.add_all([location, supplier, profile])
    db.flush()
    add_verified_partner_evidence(
        db,
        partner=supplier,
        verifier_id=users[1].id,
        valid_to=date.today() + timedelta(days=365),
    )
    return users, warehouse, location, goods, supplier


@pytest.mark.parametrize(
    ("accepted_quantity", "rejected_quantity", "inspection_status", "stock_status"),
    [
        (Decimal("12.000"), Decimal("0"), "ACCEPTED", "AVAILABLE"),
        (Decimal("10.000"), Decimal("2.000"), "PARTIALLY_ACCEPTED", "HOLD"),
    ],
)
def test_controlled_purchase_receipt_and_inspection_flow(
    accepted_quantity, rejected_quantity, inspection_status, stock_status
):
    # Importing the composition root registers and creates every table for the
    # in-memory test database.
    import main  # noqa: F401

    db = SessionLocal()
    try:
        users, warehouse, location, goods, supplier = _seed_qualified_purchase_data(db)
        procurement, quality, receiver, inspector = users
        order = create_purchase_order(
            db,
            payload=PurchaseOrderCreate(
                order_no=f"PO-{uuid4().hex[:10]}",
                supplier_id=supplier.id,
                warehouse_id=warehouse.id,
                ordered_on=date.today(),
                items=[
                    PurchaseOrderLineCreate(
                        goods_id=goods.id,
                        quantity=Decimal("12.000"),
                        unit="盒",
                    )
                ],
                reason="业务采购申请",
            ),
            actor_id=procurement.id,
            source_ip="127.0.0.1",
        )
        submit_purchase_order(
            db,
            order_id=order.id,
            actor_id=procurement.id,
            reason="提交质量审批",
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            approve_purchase_order(
                db,
                order_id=order.id,
                actor_id=procurement.id,
                reason="错误的同人审批",
                source_ip="127.0.0.1",
            )
        approve_purchase_order(
            db,
            order_id=order.id,
            actor_id=quality.id,
            reason="质量资质复核通过",
            source_ip="127.0.0.1",
        )
        db.flush()
        order_item = (
            db.query(GspPurchaseOrderItem)
            .filter(GspPurchaseOrderItem.purchase_order_id == order.id)
            .one()
        )

        receipt = create_receipt(
            db,
            payload=ReceiptCreate(
                receipt_no=f"RCV-{uuid4().hex[:10]}",
                purchase_order_id=order.id,
                delivery_document_no=f"DEL-{uuid4().hex[:10]}",
                arrived_at=datetime.now(),
                items=[
                    ReceiptLineCreate(
                        purchase_order_item_id=order_item.id,
                        batch_no=f"BATCH-{uuid4().hex[:8]}",
                        production_date=date.today() - timedelta(days=30),
                        expiry_date=date.today() + timedelta(days=700),
                        quantity=Decimal("12.000"),
                        location_id=location.id,
                        inspection_report_no="REPORT-001",
                        traceability_code="TRACE-001",
                    )
                ],
                reason="按批准采购订单收货",
            ),
            actor_id=receiver.id,
            source_ip="127.0.0.1",
        )
        db.flush()
        receipt_item = (
            db.query(GspReceiptItem).filter(GspReceiptItem.receipt_id == receipt.id).one()
        )
        record_receipt_sampling(
            db,
            receipt_id=receipt.id,
            item_id=receipt_item.id,
            payload=ReceiptSampling(
                sampling_plan_ref="SOP-SAMPLE-001",
                sampling_method="按批随机抽样",
                sample_quantity=Decimal("1.000"),
                sampling_record_no=f"SAMPLE-{uuid4().hex[:10]}",
                reason="按批准抽样方案完成抽样",
            ),
            actor_id=inspector.id,
            source_ip="127.0.0.1",
        )
        inspection = ReceiptInspection(
            accepted_quantity=accepted_quantity,
            rejected_quantity=rejected_quantity,
            conclusion="票账货相符，按检验结果分别入库和拒收",
            reason="按验收规程逐项检查",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            inspect_receipt_item(
                db,
                receipt_id=receipt.id,
                item_id=receipt_item.id,
                payload=inspection,
                actor_id=receiver.id,
                source_ip="127.0.0.1",
            )
        supplier.license_valid_to = date.today() - timedelta(days=1)
        with pytest.raises(WorkflowError, match="不满足 GSP"):
            inspect_receipt_item(
                db,
                receipt_id=receipt.id,
                item_id=receipt_item.id,
                payload=inspection,
                actor_id=inspector.id,
                source_ip="127.0.0.1",
            )
        supplier.license_valid_to = date.today() + timedelta(days=365)
        partner_document = (
            db.query(GspPartnerDocument)
            .filter(GspPartnerDocument.partner_id == supplier.id)
            .first()
        )
        partner_document.valid_to = date.today() - timedelta(days=1)
        with pytest.raises(WorkflowError, match="不满足 GSP"):
            inspect_receipt_item(
                db,
                receipt_id=receipt.id,
                item_id=receipt_item.id,
                payload=inspection,
                actor_id=inspector.id,
                source_ip="127.0.0.1",
            )
        partner_document.valid_to = date.today() + timedelta(days=365)
        inspect_receipt_item(
            db,
            receipt_id=receipt.id,
            item_id=receipt_item.id,
            payload=inspection,
            actor_id=inspector.id,
            source_ip="127.0.0.1",
        )
        print_record = create_receipt_print_record(
            db,
            receipt_id=receipt.id,
            payload=ControlledPrintCreate(
                template_version="RCV-1.0",
                copy_no=f"COPY-{uuid4().hex[:10]}",
                purpose="质量验收归档",
                reason="打印受控验收记录归档副本",
            ),
            actor_id=inspector.id,
            source_ip="127.0.0.1",
        )
        db.commit()

        db.refresh(order)
        db.refresh(receipt)
        db.refresh(receipt_item)
        batch = db.query(GspDrugBatch).filter(GspDrugBatch.id == receipt_item.batch_id).one()
        stock = db.query(GspBatchStock).filter(GspBatchStock.batch_id == batch.id).one()
        assert order.status == "COMPLETED"
        assert receipt.status == "COMPLETED"
        assert receipt_item.inspection_status == inspection_status
        assert batch.status == "RELEASED"
        assert stock.quantity == accepted_quantity
        assert stock.stock_status == stock_status
        assert print_record.document_type == "RECEIPT_INSPECTION"
        assert print_record.status == "GENERATED"
        assert print_record.snapshot_data["receipt_no"] == receipt.receipt_no
        assert print_record.snapshot_data["items"][0]["inspection_status"] == inspection_status
        assert len(print_record.content_hash) == 64
        if rejected_quantity:
            nonconforming = (
                db.query(GspNonconformingRecord)
                .filter(
                    GspNonconformingRecord.source_entity_type == "GspReceiptItem",
                    GspNonconformingRecord.source_entity_id == receipt_item.id,
                )
                .one()
            )
            assert nonconforming.quantity == rejected_quantity
            assert nonconforming.quality_hold_id is not None
            assert db.query(GspQualityHold).filter_by(id=nonconforming.quality_hold_id).one().status == "ACTIVE"
    finally:
        db.close()


def test_gsp_managed_product_cannot_use_legacy_stock_mutation():
    import main  # noqa: F401
    from app.legacy import Stock, gsp_managed_goods_query

    db = SessionLocal()
    try:
        _, warehouse, location, goods, _ = _seed_qualified_purchase_data(db)
        db.add(
            Stock(
                warehouse_id=warehouse.id,
                goods_id=goods.id,
                location_id=location.id,
                quantity=99,
            )
        )
        db.flush()
        with pytest.raises(HTTPException, match="旧版无批号") as error:
            ensure_not_gsp_managed_goods(db, [goods.id])
        assert error.value.status_code == 409
        visible_legacy_stock = db.query(Stock).filter(
            Stock.goods_id.notin_(gsp_managed_goods_query(db))
        )
        assert visible_legacy_stock.count() == 0
    finally:
        db.rollback()
        db.close()

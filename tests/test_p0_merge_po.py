from datetime import date, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest

from app.core.database import SessionLocal
from app.gsp.errors import WorkflowError
from app.gsp.models import (
    GspBatchStock,
    GspBusinessPartner,
    GspDrugBatch,
    GspDrugProfile,
    GspSupplierProductAuthorization,
)
from app.gsp.procurement_receiving.models import GspPurchaseOrderItem, GspReceiptItem
from app.gsp.procurement_receiving.schemas import (
    PurchaseOrderCreate,
    PurchaseOrderLineCreate,
    ReceiptCreate,
    ReceiptInspection,
    ReceiptLineCreate,
    ReceiptSampling,
)
from app.gsp.procurement_receiving.service import (
    approve_purchase_order,
    cancel_purchase_order,
    create_purchase_order,
    create_receipt,
    inspect_receipt_item,
    record_receipt_sampling,
    reject_purchase_order,
    submit_purchase_order,
)
from app.legacy import Goods, Location, User, UserRole, Warehouse
from tests.gsp_seed_helpers import add_verified_partner_evidence


def _seed(db):
    suffix = uuid4().hex[:10]
    users = []
    for name in ("procurement", "quality", "receiver", "inspector"):
        user = User(username=f"po{name}-{suffix}", hashed_password="x", full_name=name, role=UserRole.OPERATOR)
        db.add(user); users.append(user)
    wh = Warehouse(code=f"WH-{suffix}", name="GSP测试仓", is_active=True)
    goods = Goods(barcode=f"BAR-{suffix}", name="测试药品", spec="10mg*10片", unit="盒", price=10)
    db.add_all([wh, goods]); db.flush()
    loc = Location(warehouse_id=wh.id, location_code=f"LOC-{suffix}", name="验收合格区", is_active=True)
    supplier = GspBusinessPartner(
        code=f"SUP-{suffix}", name="合格供货方", partner_type="SUPPLIER", license_no=f"LIC-{suffix}",
        license_scope="药品批发", license_valid_to=date.today() + timedelta(days=365),
        quality_agreement_valid_to=date.today() + timedelta(days=365), status="APPROVED",
        approved_by=users[1].id, created_by=users[1].id,
    )
    profile = GspDrugProfile(
        goods_id=goods.id, approval_no=f"AP-{suffix}", generic_name="测试药品", dosage_form="片剂",
        manufacturer="测试药企", storage_condition="NORMAL", traceability_required=True,
        registration_valid_to=date.today() + timedelta(days=365),
        registration_document_ref="test://reg", nmpa_verification_ref="test://nmpa",
        status="APPROVED", approved_by=users[1].id, created_by=users[1].id,
    )
    db.add_all([loc, supplier, profile]); db.flush()
    db.add(GspSupplierProductAuthorization(
        supplier_id=supplier.id, goods_id=goods.id,
        authorization_ref="test://auth", authorization_sha256="a" * 64, authorization_size_bytes=1,
        scope_description="获准供应", valid_from=date.today() - timedelta(days=1),
        valid_to=date.today() + timedelta(days=365), status="APPROVED",
        created_by=users[0].id, updated_by=users[0].id, approved_by=users[1].id,
    ))
    add_verified_partner_evidence(db, partner=supplier, verifier_id=users[1].id,
                                  valid_to=date.today() + timedelta(days=365))
    db.flush()
    return users, wh, loc, goods, supplier


def _order(db, users, wh, goods, supplier, order_no):
    o = create_purchase_order(db, payload=PurchaseOrderCreate(
        order_no=order_no, supplier_id=supplier.id, warehouse_id=wh.id, ordered_on=date.today(),
        items=[PurchaseOrderLineCreate(goods_id=goods.id, quantity=Decimal("5.000"), unit="盒")],
        reason="业务采购申请"), actor_id=users[0].id, source_ip="127.0.0.1")
    return o


def test_po_draft_cancel_and_quality_reject():
    import main  # noqa: F401
    db = SessionLocal()
    try:
        users, wh, loc, goods, supplier = _seed(db)
        procurement, quality = users[0], users[1]
        o = _order(db, users, wh, goods, supplier, f"PO-C-{uuid4().hex[:6]}")
        c = cancel_purchase_order(db, order_id=o.id, actor_id=procurement.id,
                                  reason="录入有误作废重开", source_ip="127.0.0.1")
        assert c.status == "CANCELLED" and c.cancelled_by == procurement.id and c.cancellation_reason
        with pytest.raises(WorkflowError):
            submit_purchase_order(db, order_id=o.id, actor_id=procurement.id, reason="x", source_ip="127.0.0.1")

        o2 = _order(db, users, wh, goods, supplier, f"PO-R-{uuid4().hex[:6]}")
        submit_purchase_order(db, order_id=o2.id, actor_id=procurement.id, reason="提交审批", source_ip="127.0.0.1")
        with pytest.raises(WorkflowError, match="不能驳回"):
            reject_purchase_order(db, order_id=o2.id, actor_id=procurement.id, reason="自驳", source_ip="127.0.0.1")
        r = reject_purchase_order(db, order_id=o2.id, actor_id=quality.id,
                                  reason="供货范围不符，驳回重办", source_ip="127.0.0.1")
        assert r.status == "CANCELLED" and r.cancelled_by == quality.id
        with pytest.raises(WorkflowError):
            approve_purchase_order(db, order_id=o2.id, actor_id=quality.id, reason="x", source_ip="127.0.0.1")
    finally:
        db.rollback(); db.close()


def test_expired_batch_blocked_at_receipt_and_release():
    import main  # noqa: F401
    db = SessionLocal()
    try:
        users, wh, loc, goods, supplier = _seed(db)
        procurement, quality, receiver, inspector = users
        o = _order(db, users, wh, goods, supplier, f"PO-E-{uuid4().hex[:6]}")
        submit_purchase_order(db, order_id=o.id, actor_id=procurement.id, reason="提交质量审批", source_ip="127.0.0.1")
        approve_purchase_order(db, order_id=o.id, actor_id=quality.id, reason="质量批准通过", source_ip="127.0.0.1")
        db.flush()
        item = db.query(GspPurchaseOrderItem).filter_by(purchase_order_id=o.id).one()
        with pytest.raises(WorkflowError, match="已过有效期"):
            create_receipt(db, payload=ReceiptCreate(
                receipt_no=f"RCV-E-{uuid4().hex[:6]}", purchase_order_id=o.id,
                delivery_document_no="DEL-E", arrived_at=datetime.now(),
                items=[ReceiptLineCreate(purchase_order_item_id=item.id, batch_no=f"B-{uuid4().hex[:4]}",
                                         production_date=date.today() - timedelta(days=400),
                                         expiry_date=date.today() - timedelta(days=1),
                                         quantity=Decimal("5.000"), location_id=loc.id,
                                         inspection_report_no="R", traceability_code="T")],
                reason="过期收货测试"), actor_id=receiver.id, source_ip="127.0.0.1")

        rc = create_receipt(db, payload=ReceiptCreate(
            receipt_no=f"RCV-O-{uuid4().hex[:6]}", purchase_order_id=o.id,
            delivery_document_no="DEL-O", arrived_at=datetime.now(),
            items=[ReceiptLineCreate(purchase_order_item_id=item.id, batch_no=f"B2-{uuid4().hex[:4]}",
                                     production_date=date.today() - timedelta(days=30),
                                     expiry_date=date.today() + timedelta(days=700),
                                     quantity=Decimal("5.000"), location_id=loc.id,
                                     inspection_report_no="R2", traceability_code="T2")],
            reason="正常收货"), actor_id=receiver.id, source_ip="127.0.0.1")
        db.flush()
        ri = db.query(GspReceiptItem).filter_by(receipt_id=rc.id).one()
        record_receipt_sampling(db, receipt_id=rc.id, item_id=ri.id, payload=ReceiptSampling(
            sampling_plan_ref="SOP-001", sampling_method="随机", sample_quantity=Decimal("1"),
            sampling_record_no=f"SP-{uuid4().hex[:6]}", reason="完成抽样记录"), actor_id=inspector.id, source_ip="127.0.0.1")
        batch = db.query(GspDrugBatch).filter_by(id=ri.batch_id).one()
        batch.expiry_date = date.today() - timedelta(days=1)
        db.flush()
        with pytest.raises(WorkflowError, match="不能验收放行"):
            inspect_receipt_item(db, receipt_id=rc.id, item_id=ri.id, payload=ReceiptInspection(
                accepted_quantity=Decimal("5.000"), rejected_quantity=Decimal("0"),
                conclusion="过期仍验收", reason="过期放行测试"), actor_id=inspector.id, source_ip="127.0.0.1")
        assert batch.status == "PENDING_INSPECTION"
        assert db.query(GspBatchStock).filter_by(batch_id=batch.id).count() == 0
    finally:
        db.rollback(); db.close()

from datetime import date, timedelta
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
    GspQualityHold,
)
from app.gsp.quality_disposition.models import GspPurchaseReturnItem
from app.gsp.quality_disposition.schemas import (
    DispositionApproval,
    NonconformingStockCreate,
    PurchaseReturnCreate,
)
from app.gsp.quality_disposition.service import (
    approve_disposition,
    cancel_purchase_return,
    create_purchase_return,
    register_nonconforming_stock,
    reject_nonconforming_record,
    reject_purchase_return,
    submit_purchase_return,
)
from app.legacy import Goods, Location, User, UserRole, Warehouse


def _seed(db):
    suffix = uuid4().hex[:10]
    users = []
    for name in ("registrar", "approver", "executor", "witness", "procurement"):
        u = User(username=f"qd{name}-{suffix}", hashed_password="x", full_name=name, role=UserRole.OPERATOR)
        db.add(u)
        users.append(u)
    wh = Warehouse(code=f"QD-WH-{suffix}", name="不合格品测试仓", is_active=True)
    goods = Goods(barcode=f"QD-BAR-{suffix}", name="测试药品", spec="1", unit="盒", price=20)
    db.add_all([wh, goods])
    db.flush()
    loc = Location(warehouse_id=wh.id, location_code=f"QD-L-{suffix}", name="库位", is_active=True)
    supplier = GspBusinessPartner(
        code=f"QD-SUP-{suffix}",
        name="供货方",
        partner_type="SUPPLIER",
        license_no=f"L-{suffix}",
        license_scope="批发",
        license_valid_to=date.today() + timedelta(days=365),
        status="APPROVED",
        approved_by=users[1].id,
        created_by=users[0].id,
    )
    profile = GspDrugProfile(
        goods_id=goods.id,
        approval_no=f"A-{suffix}",
        generic_name="测试药品",
        dosage_form="片剂",
        manufacturer="药企",
        storage_condition="NORMAL",
        traceability_required=True,
        registration_valid_to=date.today() + timedelta(days=365),
        status="APPROVED",
        approved_by=users[1].id,
        created_by=users[0].id,
    )
    db.add_all([loc, supplier, profile])
    db.flush()
    batch = GspDrugBatch(
        goods_id=goods.id,
        batch_no=f"B-{suffix}",
        production_date=date.today() - timedelta(days=30),
        expiry_date=date.today() + timedelta(days=330),
        supplier_id=supplier.id,
        receipt_document_no="R",
        inspection_report_no="I",
        traceability_code="T",
        acceptance_conclusion="合格",
        status="RELEASED",
        accepted_by=users[1].id,
        created_by=users[0].id,
    )
    db.add(batch)
    db.flush()
    stock = GspBatchStock(
        batch_id=batch.id,
        warehouse_id=wh.id,
        location_id=loc.id,
        quantity=Decimal("10.000"),
        reserved_quantity=Decimal("0"),
        stock_status="AVAILABLE",
    )
    db.add(stock)
    db.flush()
    return users, batch, stock


def test_nc_misregistration_reject_and_purchase_return_cancel_reject():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        users, batch, stock = _seed(db)
        registrar, approver, _ex, _w, procurement = users
        rec = register_nonconforming_stock(
            db,
            payload=NonconformingStockCreate(
                record_no=f"NC-R-{uuid4().hex[:6]}",
                stock_id=stock.id,
                quantity=Decimal("1.000"),
                reason_code="QUALITY_DEFECT",
                description="疑似问题，待质量确认",
                proposed_disposition="QUARANTINE",
                reason="登记疑似不合格品",
            ),
            actor_id=registrar.id,
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="不能驳回"):
            reject_nonconforming_record(
                db, record_id=rec.id, actor_id=registrar.id, reason="登记人自行驳回", source_ip="127.0.0.1"
            )
        rejected = reject_nonconforming_record(
            db, record_id=rec.id, actor_id=approver.id, reason="复核确认误登记撤销", source_ip="127.0.0.1"
        )
        assert (
            rejected.status == "REJECTED"
            and rejected.rejected_by == approver.id
            and rejected.rejection_reason
        )
        hold = db.query(GspQualityHold).filter_by(id=rejected.quality_hold_id).one()
        assert hold.status == "ACTIVE"
        assert stock.stock_status == "HOLD"

        nc = register_nonconforming_stock(
            db,
            payload=NonconformingStockCreate(
                record_no=f"NC-PR-{uuid4().hex[:6]}",
                stock_id=stock.id,
                quantity=Decimal("1.000"),
                reason_code="QUALITY_DEFECT",
                description="拟退供",
                proposed_disposition="RETURN_TO_SUPPLIER",
                reason="登记不合格品",
            ),
            actor_id=registrar.id,
            source_ip="127.0.0.1",
        )
        approve_disposition(
            db,
            record_id=nc.id,
            payload=DispositionApproval(disposition="RETURN_TO_SUPPLIER", reason="批准退供"),
            actor_id=approver.id,
            source_ip="127.0.0.1",
        )
        pr = create_purchase_return(
            db,
            payload=PurchaseReturnCreate(
                return_no=f"PR-C-{uuid4().hex[:6]}", nonconforming_record_ids=[nc.id], reason="创建草稿退出单"
            ),
            actor_id=procurement.id,
            source_ip="127.0.0.1",
        )
        c = cancel_purchase_return(
            db, return_id=pr.id, actor_id=procurement.id, reason="业务取消不发运", source_ip="127.0.0.1"
        )
        assert c.status == "CANCELLED"
        assert db.query(GspPurchaseReturnItem).filter_by(purchase_return_id=c.id).count() == 1
        # 取消后同 NC 可再次组织退出
        pr2 = create_purchase_return(
            db,
            payload=PurchaseReturnCreate(
                return_no=f"PR-R-{uuid4().hex[:6]}", nonconforming_record_ids=[nc.id], reason="重新发起"
            ),
            actor_id=procurement.id,
            source_ip="127.0.0.1",
        )
        # 同一不合格品同一时刻只能关联一张未取消退出单。
        with pytest.raises(WorkflowError, match="已经关联其他进行中的"):
            create_purchase_return(
                db,
                payload=PurchaseReturnCreate(
                    return_no=f"PR-D-{uuid4().hex[:6]}",
                    nonconforming_record_ids=[nc.id],
                    reason="重复有效退出单应被拒绝",
                ),
                actor_id=procurement.id,
                source_ip="127.0.0.1",
            )
        with pytest.raises(WorkflowError, match="只有已提交"):
            reject_purchase_return(
                db, return_id=pr2.id, actor_id=approver.id, reason="草稿不能质量驳回", source_ip="127.0.0.1"
            )
        submit_purchase_return(
            db, return_id=pr2.id, actor_id=procurement.id, reason="提交", source_ip="127.0.0.1"
        )
        with pytest.raises(WorkflowError, match="不能驳回"):
            reject_purchase_return(
                db, return_id=pr2.id, actor_id=procurement.id, reason="提交人自行驳回", source_ip="127.0.0.1"
            )
        r = reject_purchase_return(
            db, return_id=pr2.id, actor_id=approver.id, reason="资料不全退回", source_ip="127.0.0.1"
        )
        assert r.status == "CANCELLED" and r.cancelled_by == approver.id
        # 已驳回单据占用释放，可再次引用该 NC
        pr3 = create_purchase_return(
            db,
            payload=PurchaseReturnCreate(
                return_no=f"PR-3-{uuid4().hex[:6]}", nonconforming_record_ids=[nc.id], reason="再次发起"
            ),
            actor_id=procurement.id,
            source_ip="127.0.0.1",
        )
        assert pr3.status == "DRAFT"
    finally:
        db.rollback()
        db.close()

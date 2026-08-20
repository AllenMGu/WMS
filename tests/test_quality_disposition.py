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
    GspIntegrationMessage,
    GspQualityHold,
)
from app.gsp.quality_disposition.schemas import (
    DestructionExecution,
    DispositionApproval,
    NonconformingStockCreate,
    PurchaseReturnCreate,
    PurchaseReturnDispatch,
)
from app.gsp.quality_disposition.service import (
    approve_disposition,
    approve_purchase_return,
    create_purchase_return,
    dispatch_purchase_return,
    execute_destruction,
    register_nonconforming_stock,
    submit_purchase_return,
)
from app.legacy import Goods, Location, User, UserRole, Warehouse


def _seed_stock(db):
    suffix = uuid4().hex[:10]
    users = []
    for name in ("registrar", "approver", "executor", "witness", "procurement"):
        user = User(
            username=f"qd-{name}-{suffix}",
            hashed_password="test-only",
            full_name=name,
            role=UserRole.OPERATOR,
        )
        db.add(user)
        users.append(user)
    warehouse = Warehouse(code=f"QD-WH-{suffix}", name="不合格品测试仓", is_active=True)
    goods = Goods(
        barcode=f"QD-BAR-{suffix}",
        name="不合格品测试药品",
        spec="10mg*10片",
        unit="盒",
        price=20,
    )
    db.add_all([warehouse, goods])
    db.flush()
    location = Location(
        warehouse_id=warehouse.id,
        location_code=f"QD-L-{suffix}",
        name="质量锁定库位",
        is_active=True,
    )
    supplier = GspBusinessPartner(
        code=f"QD-SUP-{suffix}",
        name="不合格品测试供货方",
        partner_type="SUPPLIER",
        license_no=f"QD-LIC-{suffix}",
        license_scope="药品批发",
        license_valid_to=date.today() + timedelta(days=365),
        status="APPROVED",
        approved_by=users[1].id,
        created_by=users[0].id,
    )
    profile = GspDrugProfile(
        goods_id=goods.id,
        approval_no=f"QD-APP-{suffix}",
        generic_name="不合格品测试药品",
        dosage_form="片剂",
        manufacturer="测试药企",
        storage_condition="NORMAL",
        traceability_required=True,
        registration_valid_to=date.today() + timedelta(days=365),
        status="APPROVED",
        approved_by=users[1].id,
        created_by=users[0].id,
    )
    db.add_all([location, supplier, profile])
    db.flush()
    batch = GspDrugBatch(
        goods_id=goods.id,
        batch_no=f"QD-BATCH-{suffix}",
        production_date=date.today() - timedelta(days=30),
        expiry_date=date.today() + timedelta(days=330),
        supplier_id=supplier.id,
        receipt_document_no=f"QD-RCV-{suffix}",
        inspection_report_no=f"QD-REPORT-{suffix}",
        traceability_code=f"QD-TRACE-{suffix}",
        acceptance_conclusion="合格",
        status="RELEASED",
        accepted_by=users[1].id,
        created_by=users[0].id,
    )
    db.add(batch)
    db.flush()
    stock = GspBatchStock(
        batch_id=batch.id,
        warehouse_id=warehouse.id,
        location_id=location.id,
        quantity=Decimal("10.000"),
        reserved_quantity=Decimal("0"),
        stock_status="AVAILABLE",
    )
    db.add(stock)
    db.flush()
    return users, stock


def test_nonconforming_destruction_requires_independent_approval_and_witness():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        users, stock = _seed_stock(db)
        registrar, approver, executor, witness, _procurement = users
        record = register_nonconforming_stock(
            db,
            payload=NonconformingStockCreate(
                record_no=f"NC-{uuid4().hex[:10]}",
                stock_id=stock.id,
                quantity=Decimal("2.000"),
                reason_code="PACKAGE_DAMAGE",
                description="养护检查发现包装破损",
                proposed_disposition="DESTROY",
                reason="登记不合格品并锁定批次",
            ),
            actor_id=registrar.id,
            source_ip="127.0.0.1",
        )
        db.flush()
        assert stock.stock_status == "HOLD"
        assert record.quality_hold_id is not None
        with pytest.raises(WorkflowError, match="必须分离"):
            approve_disposition(
                db,
                record_id=record.id,
                payload=DispositionApproval(
                    disposition="DESTROY",
                    reason="错误的同人批准",
                ),
                actor_id=registrar.id,
                source_ip="127.0.0.1",
            )
        approve_disposition(
            db,
            record_id=record.id,
            payload=DispositionApproval(
                disposition="DESTROY",
                reason="质量负责人批准监督销毁",
            ),
            actor_id=approver.id,
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="批准人与销毁执行人必须分离"):
            execute_destruction(
                db,
                record_id=record.id,
                payload=DestructionExecution(
                    witnessed_by=witness.id,
                    supervision_organization="属地药品监督管理部门",
                    execution_document_ref="DESTROY-EVIDENCE-INVALID",
                    reason="错误的同人执行",
                ),
                actor_id=approver.id,
                source_ip="127.0.0.1",
            )
        execute_destruction(
            db,
            record_id=record.id,
            payload=DestructionExecution(
                witnessed_by=witness.id,
                supervision_organization="属地药品监督管理部门",
                execution_document_ref="DESTROY-EVIDENCE-001",
                reason="监督销毁并上传证明",
            ),
            actor_id=executor.id,
            source_ip="127.0.0.1",
        )
        db.commit()
        db.refresh(record)
        db.refresh(stock)
        assert record.status == "EXECUTED"
        assert stock.quantity == Decimal("8.000")
        assert (
            db.query(GspQualityHold)
            .filter(GspQualityHold.id == record.quality_hold_id)
            .one()
            .status
            == "ACTIVE"
        )
        message_types = {
            row.message_type
            for row in db.query(GspIntegrationMessage)
            .filter(GspIntegrationMessage.aggregate_id == str(record.id))
            .all()
        }
        assert {
            "NONCONFORMING_DISPOSITION_APPROVED",
            "NONCONFORMING_DESTROYED",
        } <= message_types
    finally:
        db.close()


def test_purchase_return_uses_approved_nonconforming_record_and_decrements_stock():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        users, stock = _seed_stock(db)
        registrar, approver, dispatcher, _witness, procurement = users
        record = register_nonconforming_stock(
            db,
            payload=NonconformingStockCreate(
                record_no=f"NC-RETURN-{uuid4().hex[:8]}",
                stock_id=stock.id,
                quantity=Decimal("3.000"),
                reason_code="QUALITY_DEFECT",
                description="在库检查发现质量缺陷，拟退回原供货方",
                proposed_disposition="RETURN_TO_SUPPLIER",
                reason="登记退供不合格品",
            ),
            actor_id=registrar.id,
            source_ip="127.0.0.1",
        )
        approve_disposition(
            db,
            record_id=record.id,
            payload=DispositionApproval(
                disposition="RETURN_TO_SUPPLIER",
                reason="批准退回原供货方",
            ),
            actor_id=approver.id,
            source_ip="127.0.0.1",
        )
        purchase_return = create_purchase_return(
            db,
            payload=PurchaseReturnCreate(
                return_no=f"PR-{uuid4().hex[:10]}",
                nonconforming_record_ids=[record.id],
                reason="创建购进退出单",
            ),
            actor_id=procurement.id,
            source_ip="127.0.0.1",
        )
        submit_purchase_return(
            db,
            return_id=purchase_return.id,
            actor_id=procurement.id,
            reason="提交购进退出质量审批",
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            approve_purchase_return(
                db,
                return_id=purchase_return.id,
                actor_id=procurement.id,
                reason="错误的同人批准",
                source_ip="127.0.0.1",
            )
        approve_purchase_return(
            db,
            return_id=purchase_return.id,
            actor_id=approver.id,
            reason="质量批准购进退出",
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="批准人与发运执行人必须分离"):
            dispatch_purchase_return(
                db,
                return_id=purchase_return.id,
                payload=PurchaseReturnDispatch(
                    outbound_document_no="PR-OUT-INVALID",
                    carrier_name="测试承运商",
                    reason="错误的同人发运",
                ),
                actor_id=approver.id,
                source_ip="127.0.0.1",
            )
        dispatch_purchase_return(
            db,
            return_id=purchase_return.id,
            payload=PurchaseReturnDispatch(
                outbound_document_no="PR-OUT-001",
                carrier_name="测试承运商",
                reason="仓库复核后退供发运",
            ),
            actor_id=dispatcher.id,
            source_ip="127.0.0.1",
        )
        db.commit()
        db.refresh(record)
        db.refresh(purchase_return)
        db.refresh(stock)
        assert purchase_return.status == "DISPATCHED"
        assert record.status == "EXECUTED"
        assert stock.quantity == Decimal("7.000")
        message_types = {
            row.message_type
            for row in db.query(GspIntegrationMessage)
            .filter(GspIntegrationMessage.aggregate_id == str(purchase_return.id))
            .all()
        }
        assert {"PURCHASE_RETURN_APPROVED", "PURCHASE_RETURN_DISPATCHED"} <= message_types
    finally:
        db.close()


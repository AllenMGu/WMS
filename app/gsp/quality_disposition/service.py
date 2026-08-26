from __future__ import annotations

from decimal import Decimal

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.audit import write_audit_event
from app.gsp.errors import WorkflowError
from app.gsp.models import GspBatchStock, GspBusinessPartner, GspDrugBatch, GspQualityHold
from app.gsp.outbox import enqueue_integration_message
from app.gsp.quality_disposition.models import (
    GspNonconformingRecord,
    GspPurchaseReturn,
    GspPurchaseReturnItem,
)
from app.gsp.quality_disposition.schemas import (
    DestructionExecution,
    DispositionApproval,
    NonconformingStockCreate,
    PurchaseReturnCreate,
    PurchaseReturnDispatch,
)
from app.gsp.snapshots import model_snapshot
from app.gsp.stocktaking.service import ensure_stock_not_frozen
from app.legacy import User

FINAL_DISPOSITIONS = {"RETURN_TO_SUPPLIER", "DESTROY"}
PROPOSED_DISPOSITIONS = FINAL_DISPOSITIONS | {"QUARANTINE", "OTHER"}


def _purchase_return_items(db: Session, return_id: int) -> list[GspPurchaseReturnItem]:
    return (
        db.query(GspPurchaseReturnItem)
        .filter(GspPurchaseReturnItem.purchase_return_id == return_id)
        .order_by(GspPurchaseReturnItem.line_no)
        .all()
    )


def purchase_return_payload(db: Session, purchase_return: GspPurchaseReturn) -> dict:
    result = model_snapshot(purchase_return)
    result["items"] = [
        model_snapshot(item) for item in _purchase_return_items(db, purchase_return.id)
    ]
    return result


def _lock_batch_stock(
    db: Session, batch_id: int, actor_id: int, reason: str
) -> GspQualityHold:
    hold = GspQualityHold(
        batch_id=batch_id,
        reason_code="NONCONFORMING",
        reason=reason,
        status="ACTIVE",
        initiated_by=actor_id,
    )
    db.add(hold)
    db.flush()
    for stock in (
        db.query(GspBatchStock)
        .filter(GspBatchStock.batch_id == batch_id)
        .with_for_update()
    ):
        stock.stock_status = "HOLD"
        stock.lock_version += 1
    return hold


def register_rejected_material(
    db: Session,
    *,
    record_no: str,
    source_type: str,
    source_entity_type: str,
    source_entity_id: int,
    batch_id: int,
    warehouse_id: int,
    location_id: int | None,
    quantity: Decimal,
    reason_code: str,
    description: str,
    proposed_disposition: str | None,
    actor_id: int,
    source_ip: str | None,
) -> GspNonconformingRecord:
    existing_quantity = Decimal(
        db.query(func.coalesce(func.sum(GspNonconformingRecord.quantity), 0))
        .filter(
            GspNonconformingRecord.source_entity_type == source_entity_type,
            GspNonconformingRecord.source_entity_id == source_entity_id,
        )
        .scalar()
    )
    if existing_quantity:
        raise WorkflowError(409, "该拒收明细已经登记不合格品记录")
    normalized = proposed_disposition.upper() if proposed_disposition else None
    if normalized not in PROPOSED_DISPOSITIONS | {None}:
        raise WorkflowError(422, "不合格品拟处置方向无效")
    record = GspNonconformingRecord(
        record_no=record_no,
        source_type=source_type,
        source_entity_type=source_entity_type,
        source_entity_id=source_entity_id,
        stock_id=None,
        batch_id=batch_id,
        warehouse_id=warehouse_id,
        location_id=location_id,
        quantity=quantity,
        reason_code=reason_code,
        description=description,
        proposed_disposition=normalized,
        status="PENDING_APPROVAL",
        registered_by=actor_id,
    )
    db.add(record)
    db.flush()
    hold = _lock_batch_stock(
        db,
        batch_id,
        actor_id,
        f"不合格品 {record_no}：{description}",
    )
    record.quality_hold_id = hold.id
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="QUALITY_HOLD_CREATED_FOR_NONCONFORMING",
        entity_type="GspQualityHold",
        entity_id=str(hold.id),
        reason=description,
        after_data=model_snapshot(hold),
        source_ip=source_ip,
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="NONCONFORMING_RECORDED",
        entity_type="GspNonconformingRecord",
        entity_id=str(record.id),
        reason=description,
        after_data=model_snapshot(record),
        source_ip=source_ip,
    )
    return record


def register_nonconforming_stock(
    db: Session,
    *,
    payload: NonconformingStockCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspNonconformingRecord:
    stock = (
        db.query(GspBatchStock)
        .filter(GspBatchStock.id == payload.stock_id)
        .with_for_update()
        .first()
    )
    if not stock:
        raise WorkflowError(404, "批号库存不存在")
    already_controlled = Decimal(
        db.query(func.coalesce(func.sum(GspNonconformingRecord.quantity), 0))
        .filter(
            GspNonconformingRecord.stock_id == stock.id,
            GspNonconformingRecord.status.in_(["PENDING_APPROVAL", "APPROVED"]),
        )
        .scalar()
    )
    available = Decimal(stock.quantity) - Decimal(stock.reserved_quantity) - already_controlled
    if payload.quantity > available:
        raise WorkflowError(409, "不合格品数量超过该库位未预留且未处置的库存数量")
    normalized = payload.proposed_disposition.upper() if payload.proposed_disposition else None
    if normalized not in PROPOSED_DISPOSITIONS | {None}:
        raise WorkflowError(422, "不合格品拟处置方向无效")
    before_stock = model_snapshot(stock)
    record = GspNonconformingRecord(
        record_no=payload.record_no,
        source_type="STOCK_INSPECTION",
        source_entity_type="GspBatchStock",
        source_entity_id=stock.id,
        stock_id=stock.id,
        batch_id=stock.batch_id,
        warehouse_id=stock.warehouse_id,
        location_id=stock.location_id,
        quantity=payload.quantity,
        reason_code=payload.reason_code.upper(),
        description=payload.description,
        proposed_disposition=normalized,
        status="PENDING_APPROVAL",
        registered_by=actor_id,
    )
    db.add(record)
    hold = _lock_batch_stock(
        db,
        stock.batch_id,
        actor_id,
        f"不合格品 {payload.record_no}：{payload.description}",
    )
    record.quality_hold_id = hold.id
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="QUALITY_HOLD_CREATED_FOR_NONCONFORMING",
        entity_type="GspQualityHold",
        entity_id=str(hold.id),
        reason=payload.reason,
        after_data=model_snapshot(hold),
        source_ip=source_ip,
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="NONCONFORMING_RECORDED",
        entity_type="GspNonconformingRecord",
        entity_id=str(record.id),
        reason=payload.reason,
        before_data=before_stock,
        after_data=model_snapshot(record),
        source_ip=source_ip,
    )
    return record


def approve_disposition(
    db: Session,
    *,
    record_id: int,
    payload: DispositionApproval,
    actor_id: int,
    source_ip: str | None,
) -> GspNonconformingRecord:
    record = (
        db.query(GspNonconformingRecord)
        .filter(GspNonconformingRecord.id == record_id)
        .with_for_update()
        .first()
    )
    if not record:
        raise WorkflowError(404, "不合格品记录不存在")
    if record.status != "PENDING_APPROVAL":
        raise WorkflowError(409, "只有待审批的不合格品可以批准处置")
    if record.registered_by == actor_id:
        raise WorkflowError(409, "不合格品登记人与处置批准人必须分离")
    disposition = payload.disposition.upper()
    if disposition not in FINAL_DISPOSITIONS:
        raise WorkflowError(422, "最终处置只能是 RETURN_TO_SUPPLIER 或 DESTROY")
    before = model_snapshot(record)
    record.approved_disposition = disposition
    record.status = "APPROVED"
    record.approved_by = actor_id
    record.approved_at = utc_now()
    record.approval_reason = payload.reason
    db.flush()
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="NONCONFORMING_DISPOSITION_APPROVED",
        aggregate_type="GspNonconformingRecord",
        aggregate_id=str(record.id),
        payload=model_snapshot(record),
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="NONCONFORMING_DISPOSITION_APPROVED",
        entity_type="GspNonconformingRecord",
        entity_id=str(record.id),
        reason=payload.reason,
        before_data=before,
        after_data=model_snapshot(record),
        source_ip=source_ip,
    )
    return record


def execute_destruction(
    db: Session,
    *,
    record_id: int,
    payload: DestructionExecution,
    actor_id: int,
    source_ip: str | None,
) -> GspNonconformingRecord:
    record = (
        db.query(GspNonconformingRecord)
        .filter(GspNonconformingRecord.id == record_id)
        .with_for_update()
        .first()
    )
    if not record:
        raise WorkflowError(404, "不合格品记录不存在")
    if record.status != "APPROVED" or record.approved_disposition != "DESTROY":
        raise WorkflowError(409, "只有已批准销毁的不合格品可以执行销毁")
    if record.approved_by == actor_id:
        raise WorkflowError(409, "处置批准人与销毁执行人必须分离")
    if payload.witnessed_by in {actor_id, record.registered_by, record.approved_by}:
        raise WorkflowError(409, "销毁见证人必须独立于登记、批准和执行人员")
    if not db.query(User).filter(User.id == payload.witnessed_by).first():
        raise WorkflowError(404, "销毁见证人不存在")
    before = model_snapshot(record)
    if record.stock_id is not None:
        stock = (
            db.query(GspBatchStock)
            .filter(GspBatchStock.id == record.stock_id)
            .with_for_update()
            .first()
        )
        if not stock or Decimal(stock.quantity) - Decimal(stock.reserved_quantity) < record.quantity:
            raise WorkflowError(409, "待销毁库存数量不足或仍被销售订单预留")
        ensure_stock_not_frozen(db, [stock.id])
        stock.quantity -= record.quantity
        stock.lock_version += 1
    record.status = "EXECUTED"
    record.executed_by = actor_id
    record.executed_at = utc_now()
    record.witnessed_by = payload.witnessed_by
    record.supervision_organization = payload.supervision_organization
    record.execution_document_ref = payload.execution_document_ref
    db.flush()
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="NONCONFORMING_DESTROYED",
        aggregate_type="GspNonconformingRecord",
        aggregate_id=str(record.id),
        payload=model_snapshot(record),
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="NONCONFORMING_DESTROYED",
        entity_type="GspNonconformingRecord",
        entity_id=str(record.id),
        reason=payload.reason,
        before_data=before,
        after_data=model_snapshot(record),
        source_ip=source_ip,
    )
    return record


def create_purchase_return(
    db: Session,
    *,
    payload: PurchaseReturnCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspPurchaseReturn:
    if len(payload.nonconforming_record_ids) != len(set(payload.nonconforming_record_ids)):
        raise WorkflowError(422, "同一购进退出单不能重复选择不合格品记录")
    records = (
        db.query(GspNonconformingRecord)
        .filter(GspNonconformingRecord.id.in_(payload.nonconforming_record_ids))
        .order_by(GspNonconformingRecord.id)
        .with_for_update()
        .all()
    )
    if len(records) != len(payload.nonconforming_record_ids):
        raise WorkflowError(404, "一个或多个不合格品记录不存在")
    if any(
        record.status != "APPROVED"
        or record.approved_disposition != "RETURN_TO_SUPPLIER"
        for record in records
    ):
        raise WorkflowError(409, "购进退出只能关联已批准退回供货方的不合格品")
    if db.query(GspPurchaseReturnItem).filter(
        GspPurchaseReturnItem.nonconforming_record_id.in_(payload.nonconforming_record_ids)
    ).count():
        raise WorkflowError(409, "不合格品记录已经关联其他购进退出单")
    batches = {
        batch.id: batch
        for batch in db.query(GspDrugBatch)
        .filter(GspDrugBatch.id.in_({record.batch_id for record in records}))
        .all()
    }
    if len(batches) != len({record.batch_id for record in records}):
        raise WorkflowError(409, "不合格品关联的原始批次不存在")
    supplier_ids = {batches[record.batch_id].supplier_id for record in records}
    warehouse_ids = {record.warehouse_id for record in records}
    if len(supplier_ids) != 1 or len(warehouse_ids) != 1:
        raise WorkflowError(409, "同一购进退出单必须属于同一供货方和同一仓库")
    supplier_id = supplier_ids.pop()
    supplier = db.query(GspBusinessPartner).filter(GspBusinessPartner.id == supplier_id).first()
    if not supplier or supplier.partner_type not in {"SUPPLIER", "BOTH"}:
        raise WorkflowError(409, "原批次供货方主数据不存在或类型无效")
    purchase_return = GspPurchaseReturn(
        return_no=payload.return_no,
        supplier_id=supplier_id,
        warehouse_id=warehouse_ids.pop(),
        status="DRAFT",
        created_by=actor_id,
    )
    db.add(purchase_return)
    db.flush()
    for line_no, record in enumerate(records, start=1):
        db.add(
            GspPurchaseReturnItem(
                purchase_return_id=purchase_return.id,
                line_no=line_no,
                nonconforming_record_id=record.id,
                batch_id=record.batch_id,
                quantity=record.quantity,
            )
        )
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="PURCHASE_RETURN_CREATED",
        entity_type="GspPurchaseReturn",
        entity_id=str(purchase_return.id),
        reason=payload.reason,
        after_data=purchase_return_payload(db, purchase_return),
        source_ip=source_ip,
    )
    return purchase_return


def submit_purchase_return(
    db: Session,
    *,
    return_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspPurchaseReturn:
    purchase_return = (
        db.query(GspPurchaseReturn)
        .filter(GspPurchaseReturn.id == return_id)
        .with_for_update()
        .first()
    )
    if not purchase_return:
        raise WorkflowError(404, "购进退出单不存在")
    if purchase_return.status != "DRAFT":
        raise WorkflowError(409, "只有草稿购进退出单可以提交")
    before = purchase_return_payload(db, purchase_return)
    purchase_return.status = "SUBMITTED"
    purchase_return.submitted_by = actor_id
    purchase_return.submitted_at = utc_now()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="PURCHASE_RETURN_SUBMITTED",
        entity_type="GspPurchaseReturn",
        entity_id=str(purchase_return.id),
        reason=reason,
        before_data=before,
        after_data=purchase_return_payload(db, purchase_return),
        source_ip=source_ip,
    )
    return purchase_return


def approve_purchase_return(
    db: Session,
    *,
    return_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspPurchaseReturn:
    purchase_return = (
        db.query(GspPurchaseReturn)
        .filter(GspPurchaseReturn.id == return_id)
        .with_for_update()
        .first()
    )
    if not purchase_return:
        raise WorkflowError(404, "购进退出单不存在")
    if purchase_return.status != "SUBMITTED":
        raise WorkflowError(409, "只有已提交购进退出单可以质量批准")
    if actor_id in {purchase_return.created_by, purchase_return.submitted_by}:
        raise WorkflowError(409, "购进退出制单/提交人与质量批准人必须分离")
    record_ids = [item.nonconforming_record_id for item in _purchase_return_items(db, return_id)]
    records = db.query(GspNonconformingRecord).filter(
        GspNonconformingRecord.id.in_(record_ids)
    ).all()
    if any(
        record.status != "APPROVED"
        or record.approved_disposition != "RETURN_TO_SUPPLIER"
        for record in records
    ):
        raise WorkflowError(409, "购进退出关联的不合格品处置状态已经变化")
    before = purchase_return_payload(db, purchase_return)
    purchase_return.status = "APPROVED"
    purchase_return.quality_approved_by = actor_id
    purchase_return.quality_approved_at = utc_now()
    db.flush()
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="PURCHASE_RETURN_APPROVED",
        aggregate_type="GspPurchaseReturn",
        aggregate_id=str(purchase_return.id),
        payload=purchase_return_payload(db, purchase_return),
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="PURCHASE_RETURN_APPROVED",
        entity_type="GspPurchaseReturn",
        entity_id=str(purchase_return.id),
        reason=reason,
        before_data=before,
        after_data=purchase_return_payload(db, purchase_return),
        source_ip=source_ip,
    )
    return purchase_return


def dispatch_purchase_return(
    db: Session,
    *,
    return_id: int,
    payload: PurchaseReturnDispatch,
    actor_id: int,
    source_ip: str | None,
) -> GspPurchaseReturn:
    purchase_return = (
        db.query(GspPurchaseReturn)
        .filter(GspPurchaseReturn.id == return_id)
        .with_for_update()
        .first()
    )
    if not purchase_return:
        raise WorkflowError(404, "购进退出单不存在")
    if purchase_return.status != "APPROVED":
        raise WorkflowError(409, "只有质量批准的购进退出单可以发运")
    if purchase_return.quality_approved_by == actor_id:
        raise WorkflowError(409, "购进退出质量批准人与发运执行人必须分离")
    before = purchase_return_payload(db, purchase_return)
    for item in _purchase_return_items(db, return_id):
        record = (
            db.query(GspNonconformingRecord)
            .filter(GspNonconformingRecord.id == item.nonconforming_record_id)
            .with_for_update()
            .one()
        )
        if (
            record.status != "APPROVED"
            or record.approved_disposition != "RETURN_TO_SUPPLIER"
        ):
            raise WorkflowError(409, "购进退出关联的不合格品已经被其他流程处置")
        if record.stock_id is not None:
            stock = (
                db.query(GspBatchStock)
                .filter(GspBatchStock.id == record.stock_id)
                .with_for_update()
                .first()
            )
            if not stock or Decimal(stock.quantity) - Decimal(stock.reserved_quantity) < item.quantity:
                raise WorkflowError(409, "待退供库存数量不足或仍被销售订单预留")
            ensure_stock_not_frozen(db, [stock.id])
            stock.quantity -= item.quantity
            stock.lock_version += 1
        record.status = "EXECUTED"
        record.executed_by = actor_id
        record.executed_at = utc_now()
        record.execution_document_ref = payload.outbound_document_no
    purchase_return.status = "DISPATCHED"
    purchase_return.dispatched_by = actor_id
    purchase_return.dispatched_at = utc_now()
    purchase_return.outbound_document_no = payload.outbound_document_no
    purchase_return.carrier_name = payload.carrier_name
    db.flush()
    after = purchase_return_payload(db, purchase_return)
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="PURCHASE_RETURN_DISPATCHED",
        aggregate_type="GspPurchaseReturn",
        aggregate_id=str(purchase_return.id),
        payload=after,
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="PURCHASE_RETURN_DISPATCHED",
        entity_type="GspPurchaseReturn",
        entity_id=str(purchase_return.id),
        reason=payload.reason,
        before_data=before,
        after_data=after,
        source_ip=source_ip,
    )
    return purchase_return

from __future__ import annotations

from decimal import Decimal

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.audit import write_audit_event
from app.gsp.errors import WorkflowError
from app.gsp.models import (
    GspBatchStock,
    GspDrugBatch,
    GspDrugProfile,
    GspQualityHold,
)
from app.gsp.outbox import enqueue_integration_message
from app.gsp.returns_recalls.models import (
    GspRecall,
    GspRecallBatch,
    GspRecallTarget,
    GspSalesReturn,
    GspSalesReturnItem,
)
from app.gsp.returns_recalls.schemas import (
    RecallCreate,
    SalesReturnCreate,
    SalesReturnInspection,
)
from app.gsp.rules import evaluate_batch, evaluate_product
from app.gsp.sales_shipping.models import (
    GspSalesOrder,
    GspSalesOrderItem,
    GspShipment,
    GspStockAllocation,
)
from app.gsp.snapshots import model_snapshot
from app.legacy import Location

RECALL_LEVELS = {"I", "II", "III"}
RECALL_SOURCES = {"REGULATOR", "MANUFACTURER", "INTERNAL"}
NOTIFICATION_STATUSES = {"NOTIFIED", "ACKNOWLEDGED", "UNREACHABLE"}
REJECTION_DISPOSITIONS = {"RETURN_TO_SUPPLIER", "DESTROY", "QUARANTINE", "OTHER"}


def _finding_dicts(result) -> list[dict]:
    return [{"code": item.code, "message": item.message} for item in result.findings]


def _return_items(db: Session, return_id: int) -> list[GspSalesReturnItem]:
    return (
        db.query(GspSalesReturnItem)
        .filter(GspSalesReturnItem.sales_return_id == return_id)
        .order_by(GspSalesReturnItem.line_no)
        .all()
    )


def sales_return_payload(db: Session, sales_return: GspSalesReturn) -> dict:
    result = model_snapshot(sales_return)
    result["items"] = [model_snapshot(item) for item in _return_items(db, sales_return.id)]
    return result


def _recall_batches(db: Session, recall_id: int) -> list[GspRecallBatch]:
    return (
        db.query(GspRecallBatch)
        .filter(GspRecallBatch.recall_id == recall_id)
        .order_by(GspRecallBatch.id)
        .all()
    )


def _recall_targets(db: Session, recall_id: int) -> list[GspRecallTarget]:
    return (
        db.query(GspRecallTarget)
        .filter(GspRecallTarget.recall_id == recall_id)
        .order_by(GspRecallTarget.id)
        .all()
    )


def recall_payload(db: Session, recall: GspRecall) -> dict:
    result = model_snapshot(recall)
    result["batches"] = [model_snapshot(item) for item in _recall_batches(db, recall.id)]
    result["targets"] = [model_snapshot(item) for item in _recall_targets(db, recall.id)]
    return result


def _active_hold_exists(db: Session, batch_id: int) -> bool:
    return (
        db.query(GspQualityHold)
        .filter(
            GspQualityHold.batch_id == batch_id,
            GspQualityHold.status == "ACTIVE",
        )
        .count()
        > 0
    )


def _validate_return_batch_for_restock(
    db: Session,
    *,
    batch: GspDrugBatch,
    traceability_code: str | None,
) -> None:
    profile = (
        db.query(GspDrugProfile)
        .filter(GspDrugProfile.goods_id == batch.goods_id)
        .first()
    )
    if not profile:
        raise WorkflowError(409, "退回药品缺少质量主数据，不能重新入库")
    product_result = evaluate_product(
        status=profile.status,
        registration_valid_to=profile.registration_valid_to,
    )
    batch_result = evaluate_batch(
        status=batch.status,
        expiry_date=batch.expiry_date,
        has_active_hold=_active_hold_exists(db, batch.id),
        traceability_required=profile.traceability_required,
        traceability_code=traceability_code,
        minimum_remaining_days=0,
    )
    findings = _finding_dicts(product_result) + _finding_dicts(batch_result)
    if profile.traceability_required and traceability_code != batch.traceability_code:
        findings.append(
            {
                "code": "RETURN_TRACEABILITY_MISMATCH",
                "message": "退回追溯码与原发运批次不一致",
            }
        )
    if findings:
        raise WorkflowError(409, "退回药品不满足重新入库条件", findings)


def create_sales_return(
    db: Session,
    *,
    payload: SalesReturnCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspSalesReturn:
    shipment = (
        db.query(GspShipment)
        .filter(GspShipment.id == payload.shipment_id)
        .with_for_update()
        .first()
    )
    if not shipment:
        raise WorkflowError(404, "原发运单不存在")
    if shipment.status != "DISPATCHED":
        raise WorkflowError(409, "只有已实际发运的订单可以办理销后退回")
    order = db.query(GspSalesOrder).filter(GspSalesOrder.id == shipment.sales_order_id).first()
    if not order or order.status != "SHIPPED":
        raise WorkflowError(409, "原销售订单状态不允许退回")
    allocation_ids = [item.stock_allocation_id for item in payload.items]
    if len(allocation_ids) != len(set(allocation_ids)):
        raise WorkflowError(422, "同一退货单中同一原发运批次只能出现一次")

    sales_return = GspSalesReturn(
        return_no=payload.return_no,
        shipment_id=shipment.id,
        customer_id=order.customer_id,
        warehouse_id=order.warehouse_id,
        received_at=payload.received_at,
        status="PENDING_INSPECTION",
        received_by=actor_id,
    )
    db.add(sales_return)
    db.flush()

    for line_no, line in enumerate(payload.items, start=1):
        allocation = (
            db.query(GspStockAllocation)
            .filter(GspStockAllocation.id == line.stock_allocation_id)
            .with_for_update()
            .first()
        )
        if not allocation or allocation.status != "SHIPPED":
            raise WorkflowError(409, "退货明细必须关联已发运的批次分配记录")
        order_item = (
            db.query(GspSalesOrderItem)
            .filter(GspSalesOrderItem.id == allocation.sales_order_item_id)
            .first()
        )
        if not order_item or order_item.sales_order_id != order.id:
            raise WorkflowError(409, "退货批次不属于指定原发运单")
        already_returned = Decimal(
            db.query(
                func.coalesce(func.sum(GspSalesReturnItem.received_quantity), 0)
            )
            .filter(GspSalesReturnItem.stock_allocation_id == allocation.id)
            .scalar()
        )
        if already_returned + line.quantity > Decimal(allocation.quantity):
            raise WorkflowError(409, "累计退回数量不能超过原发运数量")
        batch = db.query(GspDrugBatch).filter(GspDrugBatch.id == allocation.batch_id).first()
        profile = (
            db.query(GspDrugProfile)
            .filter(GspDrugProfile.goods_id == order_item.goods_id)
            .first()
        )
        if not batch or not profile:
            raise WorkflowError(409, "原发运批次或质量主数据缺失")
        if profile.traceability_required and (
            not line.traceability_code or line.traceability_code != batch.traceability_code
        ):
            raise WorkflowError(409, "退回药品追溯码必须与原发运批次一致")
        if profile.storage_condition in {"COLD", "FROZEN"} and not line.temperature_record_ref:
            raise WorkflowError(409, "冷链退货必须提供退回运输温度记录")

        recall_target = None
        if line.recall_target_id is not None:
            recall_target = (
                db.query(GspRecallTarget)
                .filter(GspRecallTarget.id == line.recall_target_id)
                .with_for_update()
                .first()
            )
            if not recall_target or recall_target.stock_allocation_id != allocation.id:
                raise WorkflowError(409, "召回目标与原发运批次不匹配")
            recall = db.query(GspRecall).filter(GspRecall.id == recall_target.recall_id).first()
            if not recall or recall.status != "ACTIVE":
                raise WorkflowError(409, "只能针对执行中的召回登记回收数量")
            if recall_target.recovered_quantity + line.quantity > recall_target.shipped_quantity:
                raise WorkflowError(409, "累计召回回收数量不能超过目标发运数量")
            recall_batch = (
                db.query(GspRecallBatch)
                .filter(GspRecallBatch.id == recall_target.recall_batch_id)
                .with_for_update()
                .first()
            )
            recall_target.recovered_quantity += line.quantity
            recall_batch.recovered_quantity += line.quantity

        db.add(
            GspSalesReturnItem(
                sales_return_id=sales_return.id,
                line_no=line_no,
                stock_allocation_id=allocation.id,
                recall_target_id=recall_target.id if recall_target else None,
                batch_id=batch.id,
                goods_id=order_item.goods_id,
                received_quantity=line.quantity,
                accepted_quantity=Decimal("0"),
                rejected_quantity=Decimal("0"),
                reason_code=line.reason_code.upper(),
                condition_notes=line.condition_notes,
                traceability_code=line.traceability_code,
                temperature_record_ref=line.temperature_record_ref,
                inspection_status="PENDING",
            )
        )

    db.flush()
    snapshot = sales_return_payload(db, sales_return)
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="SALES_RETURN_RECEIVED",
        aggregate_type="GspSalesReturn",
        aggregate_id=str(sales_return.id),
        payload=snapshot,
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="SALES_RETURN_RECEIVED",
        entity_type="GspSalesReturn",
        entity_id=str(sales_return.id),
        reason=payload.reason,
        after_data=snapshot,
        source_ip=source_ip,
    )
    return sales_return


def inspect_sales_return_item(
    db: Session,
    *,
    return_id: int,
    item_id: int,
    payload: SalesReturnInspection,
    actor_id: int,
    source_ip: str | None,
) -> GspSalesReturn:
    sales_return = (
        db.query(GspSalesReturn)
        .filter(GspSalesReturn.id == return_id)
        .with_for_update()
        .first()
    )
    if not sales_return:
        raise WorkflowError(404, "销后退货单不存在")
    item = (
        db.query(GspSalesReturnItem)
        .filter(
            GspSalesReturnItem.id == item_id,
            GspSalesReturnItem.sales_return_id == sales_return.id,
        )
        .with_for_update()
        .first()
    )
    if not item:
        raise WorkflowError(404, "销后退货明细不存在")
    if item.inspection_status != "PENDING":
        raise WorkflowError(409, "该退货明细已经完成质量检验")
    if sales_return.received_by == actor_id:
        raise WorkflowError(409, "退货收货人与质量检验人必须分离")
    inspected_quantity = payload.accepted_quantity + payload.rejected_quantity
    if inspected_quantity != item.received_quantity:
        raise WorkflowError(422, "合格数量与拒收数量之和必须等于退回数量")
    if payload.rejected_quantity > 0 and (
        payload.rejection_disposition not in REJECTION_DISPOSITIONS
    ):
        raise WorkflowError(
            422,
            "拒收药品必须指定 RETURN_TO_SUPPLIER、DESTROY、QUARANTINE 或 OTHER 处置方式",
        )

    before = sales_return_payload(db, sales_return)
    if payload.accepted_quantity > 0:
        if not (
            payload.package_intact
            and payload.storage_conditions_confirmed
            and payload.traceability_verified
        ):
            raise WorkflowError(409, "重新入库前必须确认包装、储存条件和追溯信息全部合格")
        if payload.accepted_location_id is None:
            raise WorkflowError(422, "合格退货必须指定批准的回库库位")
        location = (
            db.query(Location)
            .filter(Location.id == payload.accepted_location_id)
            .first()
        )
        if (
            not location
            or not location.is_active
            or location.warehouse_id != sales_return.warehouse_id
        ):
            raise WorkflowError(422, "回库库位必须属于原销售仓库且处于启用状态")
        batch = db.query(GspDrugBatch).filter(GspDrugBatch.id == item.batch_id).first()
        if not batch:
            raise WorkflowError(409, "退回批次不存在")
        _validate_return_batch_for_restock(
            db,
            batch=batch,
            traceability_code=item.traceability_code,
        )
        stock = (
            db.query(GspBatchStock)
            .filter(
                GspBatchStock.batch_id == batch.id,
                GspBatchStock.warehouse_id == sales_return.warehouse_id,
                GspBatchStock.location_id == location.id,
            )
            .with_for_update()
            .first()
        )
        if stock and stock.stock_status != "AVAILABLE":
            raise WorkflowError(409, "目标批号库存当前不可回库")
        if stock:
            stock.quantity += payload.accepted_quantity
            stock.lock_version += 1
        else:
            stock = GspBatchStock(
                batch_id=batch.id,
                warehouse_id=sales_return.warehouse_id,
                location_id=location.id,
                quantity=payload.accepted_quantity,
                reserved_quantity=Decimal("0"),
                stock_status="AVAILABLE",
            )
            db.add(stock)

    item.accepted_quantity = payload.accepted_quantity
    item.rejected_quantity = payload.rejected_quantity
    item.inspection_conclusion = payload.conclusion
    item.accepted_location_id = payload.accepted_location_id
    item.rejection_disposition = payload.rejection_disposition
    item.package_intact = payload.package_intact
    item.storage_conditions_confirmed = payload.storage_conditions_confirmed
    item.traceability_verified = payload.traceability_verified
    item.inspected_by = actor_id
    item.inspected_at = utc_now()
    if payload.accepted_quantity > 0 and payload.rejected_quantity > 0:
        item.inspection_status = "PARTIALLY_ACCEPTED"
    elif payload.accepted_quantity > 0:
        item.inspection_status = "ACCEPTED"
    else:
        item.inspection_status = "REJECTED"
    db.flush()
    pending = any(row.inspection_status == "PENDING" for row in _return_items(db, return_id))
    sales_return.status = "PARTIALLY_INSPECTED" if pending else "COMPLETED"
    db.flush()
    after = sales_return_payload(db, sales_return)
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="SALES_RETURN_INSPECTED",
        aggregate_type="GspSalesReturn",
        aggregate_id=str(sales_return.id),
        payload=after,
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="SALES_RETURN_INSPECTED",
        entity_type="GspSalesReturnItem",
        entity_id=str(item.id),
        reason=payload.reason,
        before_data=before,
        after_data=after,
        source_ip=source_ip,
    )
    return sales_return


def create_recall(
    db: Session,
    *,
    payload: RecallCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspRecall:
    recall_level = payload.recall_level.upper()
    source = payload.source.upper()
    if recall_level not in RECALL_LEVELS:
        raise WorkflowError(422, "recall_level 只能是 I、II 或 III")
    if source not in RECALL_SOURCES:
        raise WorkflowError(422, "source 只能是 REGULATOR、MANUFACTURER 或 INTERNAL")
    if len(payload.batch_ids) != len(set(payload.batch_ids)):
        raise WorkflowError(422, "同一召回单不能重复选择批次")
    batches = (
        db.query(GspDrugBatch)
        .filter(GspDrugBatch.id.in_(payload.batch_ids))
        .order_by(GspDrugBatch.id)
        .all()
    )
    if len(batches) != len(payload.batch_ids):
        raise WorkflowError(404, "一个或多个召回批次不存在")
    recall = GspRecall(
        recall_no=payload.recall_no,
        recall_level=recall_level,
        source=source,
        regulatory_ref=payload.regulatory_ref,
        reason=payload.reason,
        status="DRAFT",
        created_by=actor_id,
    )
    db.add(recall)
    db.flush()
    for batch in batches:
        db.add(
            GspRecallBatch(
                recall_id=recall.id,
                batch_id=batch.id,
                target_shipped_quantity=Decimal("0"),
                recovered_quantity=Decimal("0"),
            )
        )
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="RECALL_CREATED",
        entity_type="GspRecall",
        entity_id=str(recall.id),
        reason=payload.reason,
        after_data=recall_payload(db, recall),
        source_ip=source_ip,
    )
    return recall


def activate_recall(
    db: Session,
    *,
    recall_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspRecall:
    recall = (
        db.query(GspRecall)
        .filter(GspRecall.id == recall_id)
        .with_for_update()
        .first()
    )
    if not recall:
        raise WorkflowError(404, "召回单不存在")
    if recall.status != "DRAFT":
        raise WorkflowError(409, "只有草稿召回单可以启动")
    if recall.created_by == actor_id:
        raise WorkflowError(409, "召回制单人与启动审批人必须分离")
    before = recall_payload(db, recall)

    for recall_batch in _recall_batches(db, recall.id):
        overlapping_recall = (
            db.query(GspRecallBatch)
            .join(GspRecall, GspRecall.id == GspRecallBatch.recall_id)
            .filter(
                GspRecallBatch.batch_id == recall_batch.batch_id,
                GspRecall.status == "ACTIVE",
            )
            .first()
        )
        if overlapping_recall:
            raise WorkflowError(409, "同一批次已经存在执行中的召回")
        rows = (
            db.query(
                GspStockAllocation,
                GspSalesOrderItem,
                GspSalesOrder,
                GspShipment,
            )
            .join(
                GspSalesOrderItem,
                GspSalesOrderItem.id == GspStockAllocation.sales_order_item_id,
            )
            .join(
                GspSalesOrder,
                GspSalesOrder.id == GspSalesOrderItem.sales_order_id,
            )
            .join(GspShipment, GspShipment.sales_order_id == GspSalesOrder.id)
            .filter(
                GspStockAllocation.batch_id == recall_batch.batch_id,
                GspStockAllocation.status == "SHIPPED",
                GspShipment.status == "DISPATCHED",
            )
            .all()
        )
        target_quantity = Decimal("0")
        for allocation, _order_item, order, shipment in rows:
            quantity = Decimal(allocation.quantity)
            target_quantity += quantity
            db.add(
                GspRecallTarget(
                    recall_id=recall.id,
                    recall_batch_id=recall_batch.id,
                    shipment_id=shipment.id,
                    customer_id=order.customer_id,
                    stock_allocation_id=allocation.id,
                    batch_id=recall_batch.batch_id,
                    shipped_quantity=quantity,
                    recovered_quantity=Decimal("0"),
                    notification_status="PENDING",
                )
            )
        recall_batch.target_shipped_quantity = target_quantity
        hold = GspQualityHold(
            batch_id=recall_batch.batch_id,
            reason_code="RECALL",
            reason=f"召回 {recall.recall_no}：{recall.reason}",
            status="ACTIVE",
            initiated_by=actor_id,
        )
        db.add(hold)
        db.flush()
        write_audit_event(
            db,
            actor_user_id=actor_id,
            action="QUALITY_HOLD_CREATED_BY_RECALL",
            entity_type="GspQualityHold",
            entity_id=str(hold.id),
            reason=reason,
            after_data=model_snapshot(hold),
            source_ip=source_ip,
        )
        for stock in (
            db.query(GspBatchStock)
            .filter(GspBatchStock.batch_id == recall_batch.batch_id)
            .with_for_update()
        ):
            stock.stock_status = "HOLD"
            stock.lock_version += 1

    recall.status = "ACTIVE"
    recall.activated_by = actor_id
    recall.activated_at = utc_now()
    db.flush()
    after = recall_payload(db, recall)
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="RECALL_ACTIVATED",
        aggregate_type="GspRecall",
        aggregate_id=str(recall.id),
        payload=after,
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="RECALL_ACTIVATED",
        entity_type="GspRecall",
        entity_id=str(recall.id),
        reason=reason,
        before_data=before,
        after_data=after,
        source_ip=source_ip,
    )
    return recall


def notify_recall_target(
    db: Session,
    *,
    recall_id: int,
    target_id: int,
    notification_status: str,
    notes: str,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspRecall:
    recall = db.query(GspRecall).filter(GspRecall.id == recall_id).first()
    if not recall:
        raise WorkflowError(404, "召回单不存在")
    if recall.status != "ACTIVE":
        raise WorkflowError(409, "只有执行中的召回可以登记通知结果")
    normalized_status = notification_status.upper()
    if normalized_status not in NOTIFICATION_STATUSES:
        raise WorkflowError(422, "通知状态只能是 NOTIFIED、ACKNOWLEDGED 或 UNREACHABLE")
    target = (
        db.query(GspRecallTarget)
        .filter(
            GspRecallTarget.id == target_id,
            GspRecallTarget.recall_id == recall.id,
        )
        .with_for_update()
        .first()
    )
    if not target:
        raise WorkflowError(404, "召回通知目标不存在")
    before = model_snapshot(target)
    target.notification_status = normalized_status
    target.notified_by = actor_id
    target.notified_at = utc_now()
    target.notification_notes = notes
    db.flush()
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="RECALL_TARGET_UPDATED",
        aggregate_type="GspRecallTarget",
        aggregate_id=str(target.id),
        payload=model_snapshot(target),
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="RECALL_TARGET_NOTIFIED",
        entity_type="GspRecallTarget",
        entity_id=str(target.id),
        reason=reason,
        before_data=before,
        after_data=model_snapshot(target),
        source_ip=source_ip,
    )
    return recall


def close_recall(
    db: Session,
    *,
    recall_id: int,
    conclusion: str,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspRecall:
    recall = (
        db.query(GspRecall)
        .filter(GspRecall.id == recall_id)
        .with_for_update()
        .first()
    )
    if not recall:
        raise WorkflowError(404, "召回单不存在")
    if recall.status != "ACTIVE":
        raise WorkflowError(409, "只有执行中的召回可以关闭")
    if recall.activated_by == actor_id:
        raise WorkflowError(409, "召回启动人与关闭复核人必须分离")
    pending_targets = (
        db.query(GspRecallTarget)
        .filter(
            GspRecallTarget.recall_id == recall.id,
            GspRecallTarget.notification_status == "PENDING",
        )
        .count()
    )
    if pending_targets:
        raise WorkflowError(409, "仍有购货方未登记召回通知结果，不能关闭召回")
    before = recall_payload(db, recall)
    recall.status = "CLOSED"
    recall.closed_by = actor_id
    recall.closed_at = utc_now()
    recall.closure_conclusion = conclusion
    db.flush()
    after = recall_payload(db, recall)
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="RECALL_CLOSED",
        aggregate_type="GspRecall",
        aggregate_id=str(recall.id),
        payload=after,
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="RECALL_CLOSED",
        entity_type="GspRecall",
        entity_id=str(recall.id),
        reason=reason,
        before_data=before,
        after_data=after,
        source_ip=source_ip,
    )
    return recall

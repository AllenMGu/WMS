from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.audit import write_audit_event, write_stock_audit_event
from app.gsp.errors import WorkflowError
from app.gsp.models import (
    GspBatchStock,
    GspDrugBatch,
    GspDrugProfile,
    GspQualityHold,
)
from app.gsp.outbox import enqueue_integration_message
from app.gsp.qualification import evaluate_product_evidence
from app.gsp.quality_disposition.service import register_rejected_material
from app.gsp.returns_recalls.models import (
    GspBusinessCalendarDay,
    GspRecall,
    GspRecallBatch,
    GspRecallCompletionReport,
    GspRecallDrill,
    GspRecallDrillBatch,
    GspRecallDrillTarget,
    GspRecallProgressReport,
    GspRecallTarget,
    GspSalesReturn,
    GspSalesReturnItem,
)
from app.gsp.returns_recalls.schemas import (
    BusinessCalendarDaySet,
    RecallCompletionReportCreate,
    RecallCreate,
    RecallDrillComplete,
    RecallDrillCreate,
    RecallDrillTargetVerification,
    SalesReturnCreate,
    SalesReturnInspection,
)
from app.gsp.rules import evaluate_batch
from app.gsp.sales_shipping.models import (
    GspSalesOrder,
    GspSalesOrderItem,
    GspShipment,
    GspStockAllocation,
)
from app.gsp.snapshots import model_snapshot
from app.gsp.stocktaking.service import ensure_stock_not_frozen
from app.legacy import Location

RECALL_LEVELS = {"I", "II", "III"}
RECALL_SOURCES = {"REGULATOR", "MANUFACTURER", "INTERNAL"}
NOTIFICATION_STATUSES = {"NOTIFIED", "ACKNOWLEDGED", "UNREACHABLE"}
REJECTION_DISPOSITIONS = {"RETURN_TO_SUPPLIER", "DESTROY", "QUARANTINE", "OTHER"}
RECALL_REPORT_INTERVAL_DAYS = {"I": 1, "II": 3, "III": 7}
DRILL_VERIFICATION_STATUSES = {"LOCATED", "MISSING"}


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
    result["progress_reports"] = [
        model_snapshot(item)
        for item in db.query(GspRecallProgressReport)
        .filter(GspRecallProgressReport.recall_id == recall.id)
        .order_by(GspRecallProgressReport.reported_at)
        .all()
    ]
    completion_report = (
        db.query(GspRecallCompletionReport)
        .filter(GspRecallCompletionReport.recall_id == recall.id)
        .first()
    )
    result["completion_report"] = (
        model_snapshot(completion_report) if completion_report else None
    )
    return result


def _drill_batches(db: Session, drill_id: int) -> list[GspRecallDrillBatch]:
    return (
        db.query(GspRecallDrillBatch)
        .filter(GspRecallDrillBatch.drill_id == drill_id)
        .order_by(GspRecallDrillBatch.id)
        .all()
    )


def _drill_targets(db: Session, drill_id: int) -> list[GspRecallDrillTarget]:
    return (
        db.query(GspRecallDrillTarget)
        .filter(GspRecallDrillTarget.drill_id == drill_id)
        .order_by(GspRecallDrillTarget.id)
        .all()
    )


def recall_drill_payload(db: Session, drill: GspRecallDrill) -> dict:
    result = model_snapshot(drill)
    result["batches"] = [model_snapshot(item) for item in _drill_batches(db, drill.id)]
    result["targets"] = [model_snapshot(item) for item in _drill_targets(db, drill.id)]
    return result


def _add_working_days(db: Session, start, working_days: int):
    """Apply approved calendar overrides with weekday behavior as the baseline."""
    result = start
    added = 0
    while added < working_days:
        result += timedelta(days=1)
        override = db.query(GspBusinessCalendarDay).filter(
            GspBusinessCalendarDay.calendar_date == result.date()
        ).first()
        is_working_day = override.is_working_day if override else result.weekday() < 5
        if is_working_day:
            added += 1
    return result


def set_business_calendar_day(
    db: Session,
    *,
    payload: BusinessCalendarDaySet,
    actor_id: int,
    source_ip: str | None,
) -> GspBusinessCalendarDay:
    day = db.query(GspBusinessCalendarDay).filter(
        GspBusinessCalendarDay.calendar_date == payload.calendar_date
    ).with_for_update().first()
    before = model_snapshot(day) if day else None
    if day is None:
        day = GspBusinessCalendarDay(calendar_date=payload.calendar_date)
        db.add(day)
    day.is_working_day = payload.is_working_day
    day.approval_ref = payload.approval_ref
    day.reason = payload.reason
    day.approved_by = actor_id
    day.approved_at = utc_now()
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="BUSINESS_CALENDAR_DAY_APPROVED",
        entity_type="GspBusinessCalendarDay",
        entity_id=str(day.id),
        reason=payload.reason,
        before_data=before,
        after_data=model_snapshot(day),
        source_ip=source_ip,
    )
    return day


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
    product_result = evaluate_product_evidence(db, profile)
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
    if shipment.status not in {"DISPATCHED", "DELIVERED", "CLOSED"}:
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
            stock_before = model_snapshot(stock)
            ensure_stock_not_frozen(db, [stock.id])
            stock.quantity += payload.accepted_quantity
            stock.lock_version += 1
            stock_after = model_snapshot(stock)
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
            db.flush()
            stock_before = None
            stock_after = model_snapshot(stock)
        write_stock_audit_event(
            db,
            actor_user_id=actor_id,
            action="RETURN_RESTOCKED_AS_AVAILABLE",
            stock=stock,
            reason=payload.reason,
            source_ip=source_ip,
            before_data=stock_before,
            after_data=stock_after,
        )

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
    if payload.rejected_quantity > 0:
        register_rejected_material(
            db,
            record_no=f"NC-SRET-{item.id}",
            source_type="SALES_RETURN_REJECTION",
            source_entity_type="GspSalesReturnItem",
            source_entity_id=item.id,
            batch_id=item.batch_id,
            warehouse_id=sales_return.warehouse_id,
            location_id=None,
            quantity=payload.rejected_quantity,
            reason_code="SALES_RETURN_REJECTED",
            description=payload.conclusion,
            proposed_disposition=payload.rejection_disposition,
            actor_id=actor_id,
            source_ip=source_ip,
        )
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
                GspShipment.status.in_(["DISPATCHED", "DELIVERED", "CLOSED"]),
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

    activated_at = utc_now()
    interval = timedelta(days=RECALL_REPORT_INTERVAL_DAYS[recall.recall_level])
    recall.status = "ACTIVE"
    recall.activated_by = actor_id
    recall.activated_at = activated_at
    recall.notification_due_at = activated_at + interval
    recall.next_progress_report_due_at = activated_at + interval
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


def record_recall_progress(
    db: Session,
    *,
    recall_id: int,
    report_ref: str,
    summary: str,
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
        raise WorkflowError(409, "只有执行中的召回可以登记进展报告")
    before = recall_payload(db, recall)
    reported_at = utc_now()
    report = GspRecallProgressReport(
        recall_id=recall.id,
        report_ref=report_ref,
        summary=summary,
        reported_by=actor_id,
        reported_at=reported_at,
    )
    db.add(report)
    recall.last_progress_reported_at = reported_at
    recall.next_progress_report_due_at = reported_at + timedelta(
        days=RECALL_REPORT_INTERVAL_DAYS[recall.recall_level]
    )
    db.flush()
    after = recall_payload(db, recall)
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="RECALL_PROGRESS_REPORTED",
        aggregate_type="GspRecall",
        aggregate_id=str(recall.id),
        payload=after,
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="RECALL_PROGRESS_REPORTED",
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
    recall.completion_report_due_at = _add_working_days(db, recall.closed_at, 10)
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


def submit_recall_completion_report(
    db: Session,
    *,
    recall_id: int,
    payload: RecallCompletionReportCreate,
    actor_id: int,
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
    if recall.status != "CLOSED":
        raise WorkflowError(409, "只有已完成的召回可以提交完成报告")
    if recall.closed_by == actor_id:
        raise WorkflowError(409, "召回关闭复核人与完成报告提交人必须分离")
    if (
        db.query(GspRecallCompletionReport)
        .filter(GspRecallCompletionReport.recall_id == recall.id)
        .first()
    ):
        raise WorkflowError(409, "该召回已经提交完成报告")
    before = recall_payload(db, recall)
    report = GspRecallCompletionReport(
        recall_id=recall.id,
        report_ref=payload.report_ref,
        treatment_summary=payload.treatment_summary,
        effectiveness_evaluation=payload.effectiveness_evaluation,
        regulatory_submission_ref=payload.regulatory_submission_ref,
        reported_by=actor_id,
        reported_at=utc_now(),
    )
    db.add(report)
    db.flush()
    after = recall_payload(db, recall)
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="RECALL_COMPLETION_REPORTED",
        aggregate_type="GspRecall",
        aggregate_id=str(recall.id),
        payload=after,
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="RECALL_COMPLETION_REPORTED",
        entity_type="GspRecall",
        entity_id=str(recall.id),
        reason=payload.reason,
        before_data=before,
        after_data=after,
        source_ip=source_ip,
    )
    return recall


def create_recall_drill(
    db: Session,
    *,
    payload: RecallDrillCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspRecallDrill:
    recall_level = payload.recall_level.upper()
    if recall_level not in RECALL_LEVELS:
        raise WorkflowError(422, "recall_level 只能是 I、II 或 III")
    if len(payload.batch_ids) != len(set(payload.batch_ids)):
        raise WorkflowError(422, "同一召回演练不能重复选择批次")
    batches = (
        db.query(GspDrugBatch)
        .filter(GspDrugBatch.id.in_(payload.batch_ids))
        .order_by(GspDrugBatch.id)
        .all()
    )
    if len(batches) != len(payload.batch_ids):
        raise WorkflowError(404, "一个或多个演练批次不存在")
    drill = GspRecallDrill(
        drill_no=payload.drill_no,
        recall_level=recall_level,
        scenario=payload.scenario,
        objective=payload.objective,
        max_allowed_minutes=payload.max_allowed_minutes,
        status="DRAFT",
        created_by=actor_id,
    )
    db.add(drill)
    db.flush()
    for batch in batches:
        db.add(
            GspRecallDrillBatch(
                drill_id=drill.id,
                batch_id=batch.id,
                target_shipped_quantity=Decimal("0"),
            )
        )
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="RECALL_DRILL_CREATED",
        entity_type="GspRecallDrill",
        entity_id=str(drill.id),
        reason=payload.reason,
        after_data=recall_drill_payload(db, drill),
        source_ip=source_ip,
    )
    return drill


def activate_recall_drill(
    db: Session,
    *,
    drill_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspRecallDrill:
    drill = (
        db.query(GspRecallDrill)
        .filter(GspRecallDrill.id == drill_id)
        .with_for_update()
        .first()
    )
    if not drill:
        raise WorkflowError(404, "召回演练不存在")
    if drill.status != "DRAFT":
        raise WorkflowError(409, "只有草稿召回演练可以启动")
    if drill.created_by == actor_id:
        raise WorkflowError(409, "召回演练制单人与启动审批人必须分离")
    before = recall_drill_payload(db, drill)
    for drill_batch in _drill_batches(db, drill.id):
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
                GspStockAllocation.batch_id == drill_batch.batch_id,
                GspStockAllocation.status == "SHIPPED",
                GspShipment.status.in_(["DISPATCHED", "DELIVERED", "CLOSED"]),
            )
            .all()
        )
        target_quantity = Decimal("0")
        for allocation, _order_item, order, shipment in rows:
            quantity = Decimal(allocation.quantity)
            target_quantity += quantity
            db.add(
                GspRecallDrillTarget(
                    drill_id=drill.id,
                    drill_batch_id=drill_batch.id,
                    shipment_id=shipment.id,
                    customer_id=order.customer_id,
                    stock_allocation_id=allocation.id,
                    batch_id=drill_batch.batch_id,
                    shipped_quantity=quantity,
                    verification_status="PENDING",
                )
            )
        drill_batch.target_shipped_quantity = target_quantity
    drill.status = "ACTIVE"
    drill.activated_by = actor_id
    drill.activated_at = utc_now()
    db.flush()
    after = recall_drill_payload(db, drill)
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="RECALL_DRILL_ACTIVATED",
        entity_type="GspRecallDrill",
        entity_id=str(drill.id),
        reason=reason,
        before_data=before,
        after_data=after,
        source_ip=source_ip,
    )
    return drill


def verify_recall_drill_target(
    db: Session,
    *,
    drill_id: int,
    target_id: int,
    payload: RecallDrillTargetVerification,
    actor_id: int,
    source_ip: str | None,
) -> GspRecallDrill:
    drill = db.query(GspRecallDrill).filter(GspRecallDrill.id == drill_id).first()
    if not drill:
        raise WorkflowError(404, "召回演练不存在")
    if drill.status != "ACTIVE":
        raise WorkflowError(409, "只有执行中的召回演练可以登记追溯核验")
    status = payload.verification_status.upper()
    if status not in DRILL_VERIFICATION_STATUSES:
        raise WorkflowError(422, "verification_status 只能是 LOCATED 或 MISSING")
    target = (
        db.query(GspRecallDrillTarget)
        .filter(
            GspRecallDrillTarget.id == target_id,
            GspRecallDrillTarget.drill_id == drill.id,
        )
        .with_for_update()
        .first()
    )
    if not target:
        raise WorkflowError(404, "召回演练追溯目标不存在")
    before = model_snapshot(target)
    target.verification_status = status
    target.verified_by = actor_id
    target.verified_at = utc_now()
    target.verification_notes = payload.notes
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="RECALL_DRILL_TARGET_VERIFIED",
        entity_type="GspRecallDrillTarget",
        entity_id=str(target.id),
        reason=payload.reason,
        before_data=before,
        after_data=model_snapshot(target),
        source_ip=source_ip,
    )
    return drill


def complete_recall_drill(
    db: Session,
    *,
    drill_id: int,
    payload: RecallDrillComplete,
    actor_id: int,
    source_ip: str | None,
) -> GspRecallDrill:
    drill = (
        db.query(GspRecallDrill)
        .filter(GspRecallDrill.id == drill_id)
        .with_for_update()
        .first()
    )
    if not drill:
        raise WorkflowError(404, "召回演练不存在")
    if drill.status != "ACTIVE":
        raise WorkflowError(409, "只有执行中的召回演练可以完成")
    if drill.activated_by == actor_id:
        raise WorkflowError(409, "召回演练启动人与完成复核人必须分离")
    targets = _drill_targets(db, drill.id)
    if not targets:
        raise WorkflowError(409, "召回演练未生成任何已发运追溯目标")
    if any(target.verification_status == "PENDING" for target in targets):
        raise WorkflowError(409, "仍有召回演练追溯目标未完成核验")
    has_missing = any(target.verification_status == "MISSING" for target in targets)
    completed_at = utc_now()
    elapsed_seconds = (completed_at - drill.activated_at).total_seconds()
    exceeded_time = elapsed_seconds > drill.max_allowed_minutes * 60
    if (has_missing or exceeded_time) and not (
        payload.deviation_notes and payload.capa_ref
    ):
        raise WorkflowError(422, "演练存在未定位目标或超时，必须记录偏差和 CAPA 引用")
    before = recall_drill_payload(db, drill)
    drill.status = "COMPLETED"
    drill.completed_by = actor_id
    drill.completed_at = completed_at
    drill.result = "FAILED" if has_missing or exceeded_time else "PASSED"
    drill.completion_summary = payload.completion_summary
    drill.deviation_notes = payload.deviation_notes
    drill.capa_ref = payload.capa_ref
    db.flush()
    after = recall_drill_payload(db, drill)
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="RECALL_DRILL_COMPLETED",
        entity_type="GspRecallDrill",
        entity_id=str(drill.id),
        reason=payload.reason,
        before_data=before,
        after_data=after,
        source_ip=source_ip,
    )
    return drill


def cancel_sales_return(
    db: Session,
    *,
    return_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspSalesReturn:
    """取消尚未开始质量检验的销后退回单（退货收货有误/客户撤销）。

    一旦任一行进入质量检验（不再为 PENDING），必须走完检验与后续处置，
    不允许整单取消，保证退回货物流向可追溯。
    """
    sales_return = (
        db.query(GspSalesReturn)
        .filter(GspSalesReturn.id == return_id)
        .with_for_update()
        .first()
    )
    if not sales_return:
        raise WorkflowError(404, "销后退回单不存在")
    if sales_return.status != "PENDING_INSPECTION":
        raise WorkflowError(409, "只有待检验的销后退回单可以取消")
    items = _return_items(db, return_id)
    if any(item.inspection_status != "PENDING" for item in items):
        raise WorkflowError(409, "退货明细已开始质量检验，不能取消整单；请完成检验与处置")
    before = sales_return_payload(db, sales_return)
    sales_return.status = "CANCELLED"
    sales_return.cancelled_by = actor_id
    sales_return.cancelled_at = utc_now()
    sales_return.cancellation_reason = reason
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="SALES_RETURN_CANCELLED",
        entity_type="GspSalesReturn",
        entity_id=str(sales_return.id),
        reason=reason,
        before_data=before,
        after_data=sales_return_payload(db, sales_return),
        source_ip=source_ip,
    )
    return sales_return

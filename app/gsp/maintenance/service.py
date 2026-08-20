from __future__ import annotations

from datetime import date

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.audit import write_audit_event
from app.gsp.errors import WorkflowError
from app.gsp.maintenance.models import GspMaintenancePlan, GspMaintenancePlanItem
from app.gsp.maintenance.schemas import MaintenanceInspection, MaintenancePlanCreate
from app.gsp.models import GspBatchStock, GspDrugBatch, GspQualityHold
from app.gsp.outbox import enqueue_integration_message
from app.gsp.snapshots import model_snapshot
from app.legacy import Warehouse

PLAN_TYPES = {"ROUTINE", "KEY"}
INSPECTION_RESULTS = {"NORMAL", "ABNORMAL"}


def _plan_items(db: Session, plan_id: int) -> list[GspMaintenancePlanItem]:
    return (
        db.query(GspMaintenancePlanItem)
        .filter(GspMaintenancePlanItem.plan_id == plan_id)
        .order_by(GspMaintenancePlanItem.line_no)
        .all()
    )


def maintenance_plan_payload(db: Session, plan: GspMaintenancePlan) -> dict:
    result = model_snapshot(plan)
    result["items"] = [model_snapshot(item) for item in _plan_items(db, plan.id)]
    return result


def create_maintenance_plan(
    db: Session,
    *,
    payload: MaintenancePlanCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspMaintenancePlan:
    plan_type = payload.plan_type.upper()
    if plan_type not in PLAN_TYPES:
        raise WorkflowError(422, "plan_type 只能是 ROUTINE 或 KEY")
    if payload.scheduled_to < payload.scheduled_from:
        raise WorkflowError(422, "养护计划结束日期不能早于开始日期")
    warehouse = db.query(Warehouse).filter(Warehouse.id == payload.warehouse_id).first()
    if not warehouse or not warehouse.is_active:
        raise WorkflowError(422, "养护计划仓库不存在或未启用")
    stock_ids = [item.stock_id for item in payload.items]
    if len(stock_ids) != len(set(stock_ids)):
        raise WorkflowError(422, "同一养护计划不能重复选择库存记录")
    stocks = (
        db.query(GspBatchStock)
        .filter(GspBatchStock.id.in_(stock_ids))
        .order_by(GspBatchStock.id)
        .all()
    )
    if len(stocks) != len(stock_ids):
        raise WorkflowError(404, "一个或多个批号库存记录不存在")
    stocks_by_id = {stock.id: stock for stock in stocks}
    for stock in stocks:
        if stock.warehouse_id != warehouse.id or stock.quantity <= 0:
            raise WorkflowError(409, "养护对象必须是指定仓库内现存量大于零的批号库存")
        if not db.query(GspDrugBatch).filter(GspDrugBatch.id == stock.batch_id).first():
            raise WorkflowError(409, "养护对象关联的药品批次不存在")

    plan = GspMaintenancePlan(
        plan_no=payload.plan_no,
        warehouse_id=warehouse.id,
        plan_type=plan_type,
        scheduled_from=payload.scheduled_from,
        scheduled_to=payload.scheduled_to,
        scope_summary=payload.scope_summary,
        status="DRAFT",
        created_by=actor_id,
    )
    db.add(plan)
    db.flush()
    for line_no, item in enumerate(payload.items, start=1):
        stock = stocks_by_id[item.stock_id]
        db.add(
            GspMaintenancePlanItem(
                plan_id=plan.id,
                line_no=line_no,
                stock_id=stock.id,
                batch_id=stock.batch_id,
                planned_quantity=stock.quantity,
                priority_reason=item.priority_reason,
                status="PENDING",
            )
        )
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="MAINTENANCE_PLAN_CREATED",
        entity_type="GspMaintenancePlan",
        entity_id=str(plan.id),
        reason=payload.reason,
        after_data=maintenance_plan_payload(db, plan),
        source_ip=source_ip,
    )
    return plan


def submit_maintenance_plan(
    db: Session,
    *,
    plan_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspMaintenancePlan:
    plan = (
        db.query(GspMaintenancePlan)
        .filter(GspMaintenancePlan.id == plan_id)
        .with_for_update()
        .first()
    )
    if not plan:
        raise WorkflowError(404, "养护计划不存在")
    if plan.status != "DRAFT":
        raise WorkflowError(409, "只有草稿养护计划可以提交")
    before = maintenance_plan_payload(db, plan)
    plan.status = "SUBMITTED"
    plan.submitted_by = actor_id
    plan.submitted_at = utc_now()
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="MAINTENANCE_PLAN_SUBMITTED",
        entity_type="GspMaintenancePlan",
        entity_id=str(plan.id),
        reason=reason,
        before_data=before,
        after_data=maintenance_plan_payload(db, plan),
        source_ip=source_ip,
    )
    return plan


def approve_maintenance_plan(
    db: Session,
    *,
    plan_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspMaintenancePlan:
    plan = (
        db.query(GspMaintenancePlan)
        .filter(GspMaintenancePlan.id == plan_id)
        .with_for_update()
        .first()
    )
    if not plan:
        raise WorkflowError(404, "养护计划不存在")
    if plan.status != "SUBMITTED":
        raise WorkflowError(409, "只有已提交养护计划可以审批")
    if plan.submitted_by == actor_id:
        raise WorkflowError(409, "养护计划提交人与质量审批人必须分离")
    before = maintenance_plan_payload(db, plan)
    plan.status = "APPROVED"
    plan.approved_by = actor_id
    plan.approved_at = utc_now()
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="MAINTENANCE_PLAN_APPROVED",
        entity_type="GspMaintenancePlan",
        entity_id=str(plan.id),
        reason=reason,
        before_data=before,
        after_data=maintenance_plan_payload(db, plan),
        source_ip=source_ip,
    )
    return plan


def inspect_maintenance_item(
    db: Session,
    *,
    plan_id: int,
    item_id: int,
    payload: MaintenanceInspection,
    actor_id: int,
    source_ip: str | None,
) -> GspMaintenancePlan:
    plan = (
        db.query(GspMaintenancePlan)
        .filter(GspMaintenancePlan.id == plan_id)
        .with_for_update()
        .first()
    )
    if not plan:
        raise WorkflowError(404, "养护计划不存在")
    if plan.status not in {"APPROVED", "IN_PROGRESS"}:
        raise WorkflowError(409, "只有已批准或执行中的养护计划可以登记检查")
    item = (
        db.query(GspMaintenancePlanItem)
        .filter(
            GspMaintenancePlanItem.id == item_id,
            GspMaintenancePlanItem.plan_id == plan.id,
        )
        .with_for_update()
        .first()
    )
    if not item:
        raise WorkflowError(404, "养护计划明细不存在")
    if item.status != "PENDING":
        raise WorkflowError(409, "该养护计划明细已经完成检查")
    result = payload.result.upper()
    if result not in INSPECTION_RESULTS:
        raise WorkflowError(422, "result 只能是 NORMAL 或 ABNORMAL")
    checks = (
        payload.appearance_ok,
        payload.package_ok,
        payload.storage_condition_ok,
        payload.temperature_humidity_ok,
    )
    if result == "NORMAL" and not all(checks):
        raise WorkflowError(422, "检查项存在异常时结果不能登记为 NORMAL")
    if result == "ABNORMAL" and all(checks):
        raise WorkflowError(422, "ABNORMAL 结果至少需要一个异常检查项")
    if payload.next_due_on <= date.today():
        raise WorkflowError(422, "下次养护日期必须晚于当前日期")

    before = maintenance_plan_payload(db, plan)
    item.status = result
    item.appearance_ok = payload.appearance_ok
    item.package_ok = payload.package_ok
    item.storage_condition_ok = payload.storage_condition_ok
    item.temperature_humidity_ok = payload.temperature_humidity_ok
    item.finding = payload.finding
    item.next_due_on = payload.next_due_on
    item.checked_by = actor_id
    item.checked_at = utc_now()
    if result == "ABNORMAL":
        hold = GspQualityHold(
            batch_id=item.batch_id,
            reason_code="MAINTENANCE_ABNORMAL",
            reason=f"养护计划 {plan.plan_no} 发现异常：{payload.finding}",
            status="ACTIVE",
            initiated_by=actor_id,
        )
        db.add(hold)
        db.flush()
        item.quality_hold_id = hold.id
        for stock in (
            db.query(GspBatchStock)
            .filter(GspBatchStock.batch_id == item.batch_id)
            .with_for_update()
        ):
            stock.stock_status = "HOLD"
            stock.lock_version += 1
        write_audit_event(
            db,
            actor_user_id=actor_id,
            action="QUALITY_HOLD_CREATED_BY_MAINTENANCE",
            entity_type="GspQualityHold",
            entity_id=str(hold.id),
            reason=payload.reason,
            after_data=model_snapshot(hold),
            source_ip=source_ip,
        )
    plan.status = "IN_PROGRESS"
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="MAINTENANCE_ITEM_INSPECTED",
        entity_type="GspMaintenancePlanItem",
        entity_id=str(item.id),
        reason=payload.reason,
        before_data=before,
        after_data=maintenance_plan_payload(db, plan),
        source_ip=source_ip,
    )
    return plan


def complete_maintenance_plan(
    db: Session,
    *,
    plan_id: int,
    conclusion: str,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspMaintenancePlan:
    plan = (
        db.query(GspMaintenancePlan)
        .filter(GspMaintenancePlan.id == plan_id)
        .with_for_update()
        .first()
    )
    if not plan:
        raise WorkflowError(404, "养护计划不存在")
    if plan.status not in {"APPROVED", "IN_PROGRESS"}:
        raise WorkflowError(409, "养护计划当前状态不能完成复核")
    items = _plan_items(db, plan.id)
    if any(item.status == "PENDING" for item in items):
        raise WorkflowError(409, "仍有未完成的养护检查明细")
    if actor_id in {item.checked_by for item in items}:
        raise WorkflowError(409, "养护检查人与完成复核人必须分离")
    before = maintenance_plan_payload(db, plan)
    plan.status = "COMPLETED"
    plan.completed_by = actor_id
    plan.completed_at = utc_now()
    plan.completion_conclusion = conclusion
    db.flush()
    after = maintenance_plan_payload(db, plan)
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="MAINTENANCE_PLAN_COMPLETED",
        aggregate_type="GspMaintenancePlan",
        aggregate_id=str(plan.id),
        payload=after,
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="MAINTENANCE_PLAN_COMPLETED",
        entity_type="GspMaintenancePlan",
        entity_id=str(plan.id),
        reason=reason,
        before_data=before,
        after_data=after,
        source_ip=source_ip,
    )
    return plan

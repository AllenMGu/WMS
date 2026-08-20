from __future__ import annotations

from decimal import Decimal

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.audit import write_audit_event
from app.gsp.errors import WorkflowError
from app.gsp.models import GspBatchStock, GspDrugBatch
from app.gsp.outbox import enqueue_integration_message
from app.gsp.snapshots import model_snapshot
from app.gsp.stocktaking.models import GspStocktakeItem, GspStocktakePlan
from app.gsp.stocktaking.schemas import StocktakeCount, StocktakePlanCreate, StocktakeReview
from app.legacy import Location, Warehouse

SCOPE_TYPES = {"FULL", "CYCLE", "SAMPLE"}
REVIEW_DECISIONS = {"APPROVE", "RECOUNT"}
BOOK_VISIBLE_STATUSES = {"COUNTED", "ADJUSTMENT_APPROVED", "COMPLETED"}


def _plan_items(db: Session, plan_id: int) -> list[GspStocktakeItem]:
    return (
        db.query(GspStocktakeItem)
        .filter(GspStocktakeItem.plan_id == plan_id)
        .order_by(GspStocktakeItem.line_no)
        .all()
    )


def stocktake_plan_payload(
    db: Session,
    plan: GspStocktakePlan,
    *,
    expose_book: bool | None = None,
) -> dict:
    result = model_snapshot(plan)
    if expose_book is None:
        expose_book = plan.status in BOOK_VISIBLE_STATUSES
    items = []
    for item in _plan_items(db, plan.id):
        snapshot = model_snapshot(item)
        snapshot.pop("book_lock_version", None)
        if not expose_book:
            snapshot["book_quantity"] = None
            snapshot["book_reserved_quantity"] = None
            snapshot["difference_quantity"] = None
        items.append(snapshot)
    result["items"] = items
    return result


def create_stocktake_plan(
    db: Session,
    *,
    payload: StocktakePlanCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspStocktakePlan:
    scope_type = payload.scope_type.upper()
    if scope_type not in SCOPE_TYPES:
        raise WorkflowError(422, "scope_type 只能是 FULL、CYCLE 或 SAMPLE")
    if len(payload.stock_ids) != len(set(payload.stock_ids)):
        raise WorkflowError(422, "同一盘点计划不能重复选择批号库存")
    warehouse = db.query(Warehouse).filter(Warehouse.id == payload.warehouse_id).first()
    if not warehouse or not warehouse.is_active:
        raise WorkflowError(422, "盘点仓库不存在或未启用")
    stocks = (
        db.query(GspBatchStock)
        .filter(GspBatchStock.id.in_(payload.stock_ids))
        .order_by(GspBatchStock.id)
        .all()
    )
    if len(stocks) != len(payload.stock_ids):
        raise WorkflowError(404, "一个或多个批号库存记录不存在")
    stocks_by_id = {stock.id: stock for stock in stocks}
    for stock in stocks:
        location = db.query(Location).filter(Location.id == stock.location_id).first()
        batch = db.query(GspDrugBatch).filter(GspDrugBatch.id == stock.batch_id).first()
        if stock.warehouse_id != warehouse.id or not location or location.warehouse_id != warehouse.id:
            raise WorkflowError(409, "盘点对象必须属于指定仓库及其库位")
        if not batch:
            raise WorkflowError(409, "盘点对象关联的药品批次不存在")

    plan = GspStocktakePlan(
        plan_no=payload.plan_no,
        warehouse_id=warehouse.id,
        scope_type=scope_type,
        scope_summary=payload.scope_summary,
        status="DRAFT",
        created_by=actor_id,
    )
    db.add(plan)
    db.flush()
    for line_no, stock_id in enumerate(payload.stock_ids, start=1):
        stock = stocks_by_id[stock_id]
        db.add(
            GspStocktakeItem(
                plan_id=plan.id,
                line_no=line_no,
                stock_id=stock.id,
                batch_id=stock.batch_id,
                location_id=stock.location_id,
                status="PENDING",
            )
        )
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="STOCKTAKE_PLAN_CREATED",
        entity_type="GspStocktakePlan",
        entity_id=str(plan.id),
        reason=payload.reason,
        after_data=stocktake_plan_payload(db, plan, expose_book=True),
        source_ip=source_ip,
    )
    return plan


def submit_stocktake_plan(
    db: Session,
    *,
    plan_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspStocktakePlan:
    plan = db.query(GspStocktakePlan).filter(GspStocktakePlan.id == plan_id).with_for_update().first()
    if not plan:
        raise WorkflowError(404, "盘点计划不存在")
    if plan.status != "DRAFT":
        raise WorkflowError(409, "只有草稿盘点计划可以提交")
    before = stocktake_plan_payload(db, plan, expose_book=True)
    plan.status = "SUBMITTED"
    plan.submitted_by = actor_id
    plan.submitted_at = utc_now()
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="STOCKTAKE_PLAN_SUBMITTED",
        entity_type="GspStocktakePlan",
        entity_id=str(plan.id),
        reason=reason,
        before_data=before,
        after_data=stocktake_plan_payload(db, plan, expose_book=True),
        source_ip=source_ip,
    )
    return plan


def approve_stocktake_plan(
    db: Session,
    *,
    plan_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspStocktakePlan:
    plan = db.query(GspStocktakePlan).filter(GspStocktakePlan.id == plan_id).with_for_update().first()
    if not plan:
        raise WorkflowError(404, "盘点计划不存在")
    if plan.status != "SUBMITTED":
        raise WorkflowError(409, "只有已提交盘点计划可以批准")
    if actor_id in {plan.created_by, plan.submitted_by}:
        raise WorkflowError(409, "盘点计划制单/提交与质量批准必须分离")
    before = stocktake_plan_payload(db, plan, expose_book=True)
    items = _plan_items(db, plan.id)
    for item in items:
        stock = (
            db.query(GspBatchStock)
            .filter(GspBatchStock.id == item.stock_id)
            .with_for_update()
            .first()
        )
        if not stock or stock.warehouse_id != plan.warehouse_id:
            raise WorkflowError(409, "盘点对象已不存在或已移出计划仓库")
        item.book_quantity = stock.quantity
        item.book_reserved_quantity = stock.reserved_quantity
        item.book_lock_version = stock.lock_version
        item.status = "PENDING"
    plan.status = "COUNTING"
    plan.approved_by = actor_id
    plan.approved_at = utc_now()
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="STOCKTAKE_PLAN_APPROVED",
        entity_type="GspStocktakePlan",
        entity_id=str(plan.id),
        reason=reason,
        before_data=before,
        after_data=stocktake_plan_payload(db, plan, expose_book=True),
        source_ip=source_ip,
    )
    return plan


def record_stocktake_count(
    db: Session,
    *,
    plan_id: int,
    item_id: int,
    payload: StocktakeCount,
    actor_id: int,
    source_ip: str | None,
) -> GspStocktakePlan:
    plan = db.query(GspStocktakePlan).filter(GspStocktakePlan.id == plan_id).with_for_update().first()
    if not plan:
        raise WorkflowError(404, "盘点计划不存在")
    if plan.status != "COUNTING":
        raise WorkflowError(409, "盘点计划当前不允许录入数量")
    if actor_id == plan.approved_by:
        raise WorkflowError(409, "盘点计划批准人与实盘人员必须分离")
    item = (
        db.query(GspStocktakeItem)
        .filter(GspStocktakeItem.id == item_id, GspStocktakeItem.plan_id == plan.id)
        .with_for_update()
        .first()
    )
    if not item:
        raise WorkflowError(404, "盘点明细不存在")
    stock = db.query(GspBatchStock).filter(GspBatchStock.id == item.stock_id).with_for_update().first()
    if not stock or stock.lock_version != item.book_lock_version or stock.quantity != item.book_quantity:
        raise WorkflowError(409, "盘点期间库存已发生交易，必须调查并重新建立盘点基线")
    counted = Decimal(payload.counted_quantity)
    difference = counted - Decimal(item.book_quantity)
    if difference != 0 and not payload.discrepancy_reason:
        raise WorkflowError(422, "存在盘点差异时必须填写差异原因")
    before = model_snapshot(item)
    item.counted_quantity = counted
    item.difference_quantity = difference
    item.discrepancy_reason = payload.discrepancy_reason if difference != 0 else None
    item.count_round += 1
    item.counted_by = actor_id
    item.counted_at = utc_now()
    item.status = "COUNTED"
    db.flush()
    if all(row.status == "COUNTED" for row in _plan_items(db, plan.id)):
        plan.status = "COUNTED"
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="STOCKTAKE_COUNT_RECORDED",
        entity_type="GspStocktakeItem",
        entity_id=str(item.id),
        reason=payload.reason,
        before_data=before,
        after_data=model_snapshot(item),
        source_ip=source_ip,
    )
    return plan


def review_stocktake_results(
    db: Session,
    *,
    plan_id: int,
    payload: StocktakeReview,
    actor_id: int,
    source_ip: str | None,
) -> GspStocktakePlan:
    decision = payload.decision.upper()
    if decision not in REVIEW_DECISIONS:
        raise WorkflowError(422, "decision 只能是 APPROVE 或 RECOUNT")
    plan = db.query(GspStocktakePlan).filter(GspStocktakePlan.id == plan_id).with_for_update().first()
    if not plan:
        raise WorkflowError(404, "盘点计划不存在")
    if plan.status != "COUNTED":
        raise WorkflowError(409, "只有已完成实盘的计划可以复核")
    items = _plan_items(db, plan.id)
    counters = {item.counted_by for item in items if item.counted_by is not None}
    if actor_id in counters:
        raise WorkflowError(409, "实盘人员与质量复核人员必须分离")
    before = stocktake_plan_payload(db, plan, expose_book=True)
    difference_items = [item for item in items if item.difference_quantity != 0]
    plan.reviewed_by = actor_id
    plan.reviewed_at = utc_now()
    plan.review_conclusion = payload.conclusion
    if decision == "RECOUNT":
        if not difference_items:
            raise WorkflowError(409, "无差异盘点不需要重新实盘")
        for item in difference_items:
            item.status = "PENDING"
            item.counted_quantity = None
            item.difference_quantity = None
            item.discrepancy_reason = None
            item.counted_by = None
            item.counted_at = None
        plan.status = "COUNTING"
        action = "STOCKTAKE_RECOUNT_REQUIRED"
    elif difference_items:
        plan.status = "ADJUSTMENT_APPROVED"
        action = "STOCKTAKE_ADJUSTMENT_APPROVED"
    else:
        plan.status = "COMPLETED"
        plan.completed_by = actor_id
        plan.completed_at = utc_now()
        action = "STOCKTAKE_RESULTS_APPROVED"
        enqueue_integration_message(
            db,
            destination="JZT",
            message_type="STOCKTAKE_COMPLETED",
            aggregate_type="GspStocktakePlan",
            aggregate_id=str(plan.id),
            payload=stocktake_plan_payload(db, plan, expose_book=True),
        )
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action=action,
        entity_type="GspStocktakePlan",
        entity_id=str(plan.id),
        reason=payload.reason,
        before_data=before,
        after_data=stocktake_plan_payload(db, plan, expose_book=True),
        source_ip=source_ip,
    )
    return plan


def apply_stocktake_adjustments(
    db: Session,
    *,
    plan_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspStocktakePlan:
    plan = db.query(GspStocktakePlan).filter(GspStocktakePlan.id == plan_id).with_for_update().first()
    if not plan:
        raise WorkflowError(404, "盘点计划不存在")
    if plan.status != "ADJUSTMENT_APPROVED":
        raise WorkflowError(409, "盘点差异尚未批准或已经处理")
    items = _plan_items(db, plan.id)
    counters = {item.counted_by for item in items if item.counted_by is not None}
    if actor_id == plan.reviewed_by or actor_id in counters:
        raise WorkflowError(409, "实盘、差异批准与库存调整执行必须分离")
    before_plan = stocktake_plan_payload(db, plan, expose_book=True)
    for item in items:
        if item.difference_quantity == 0:
            continue
        stock = db.query(GspBatchStock).filter(GspBatchStock.id == item.stock_id).with_for_update().first()
        if not stock or stock.lock_version != item.book_lock_version or stock.quantity != item.book_quantity:
            raise WorkflowError(409, "盘点基线后库存已变化，禁止自动调整并需启动偏差调查")
        if Decimal(item.counted_quantity) < Decimal(stock.reserved_quantity):
            raise WorkflowError(409, "实盘数量低于已预留数量，必须先处理销售预留和偏差")
        before_stock = model_snapshot(stock)
        stock.quantity = item.counted_quantity
        stock.lock_version += 1
        item.status = "ADJUSTED"
        item.adjusted_by = actor_id
        item.adjusted_at = utc_now()
        db.flush()
        write_audit_event(
            db,
            actor_user_id=actor_id,
            action="STOCKTAKE_STOCK_ADJUSTED",
            entity_type="GspBatchStock",
            entity_id=str(stock.id),
            reason=reason,
            before_data=before_stock,
            after_data=model_snapshot(stock),
            source_ip=source_ip,
        )
    plan.status = "COMPLETED"
    plan.completed_by = actor_id
    plan.completed_at = utc_now()
    db.flush()
    final_payload = stocktake_plan_payload(db, plan, expose_book=True)
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="STOCKTAKE_COMPLETED",
        aggregate_type="GspStocktakePlan",
        aggregate_id=str(plan.id),
        payload=final_payload,
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="STOCKTAKE_COMPLETED",
        entity_type="GspStocktakePlan",
        entity_id=str(plan.id),
        reason=reason,
        before_data=before_plan,
        after_data=final_payload,
        source_ip=source_ip,
    )
    return plan

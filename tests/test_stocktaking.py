from datetime import date, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.core.database import SessionLocal
from app.gsp.errors import WorkflowError
from app.gsp.models import (
    GspBatchStock,
    GspBusinessPartner,
    GspDrugBatch,
    GspIntegrationMessage,
)
from app.gsp.router import receive_batch_stock
from app.gsp.schemas import BatchStockReceipt
from app.gsp.stocktaking.models import GspStocktakeItem
from app.gsp.stocktaking.schemas import StocktakeCount, StocktakePlanCreate, StocktakeReview
from app.gsp.stocktaking.service import (
    apply_stocktake_adjustments,
    approve_stocktake_plan,
    create_stocktake_plan,
    ensure_stock_not_frozen,
    record_stocktake_count,
    review_stocktake_results,
    stocktake_plan_payload,
    submit_stocktake_plan,
)
from app.legacy import Goods, Location, User, UserRole, Warehouse


def _stocktake_context(db):
    suffix = uuid4().hex[:10]
    planner = User(
        username=f"stocktake-planner-{suffix}", hashed_password="test-only",
        full_name="盘点计划员", role=UserRole.OPERATOR,
    )
    approver = User(
        username=f"stocktake-approver-{suffix}", hashed_password="test-only",
        full_name="质量批准员", role=UserRole.OPERATOR,
    )
    counter = User(
        username=f"stocktake-counter-{suffix}", hashed_password="test-only",
        full_name="实盘人员", role=UserRole.OPERATOR,
    )
    reviewer = User(
        username=f"stocktake-reviewer-{suffix}", hashed_password="test-only",
        full_name="质量复核员", role=UserRole.OPERATOR,
    )
    executor = User(
        username=f"stocktake-executor-{suffix}", hashed_password="test-only",
        full_name="调整执行员", role=UserRole.OPERATOR,
    )
    warehouse = Warehouse(code=f"COUNT-WH-{suffix}", name="批号盘点测试仓", is_active=True)
    goods = Goods(
        barcode=f"COUNT-BAR-{suffix}", name="批号盘点测试药品",
        spec="10mg*10片", unit="盒", price=10,
    )
    db.add_all([planner, approver, counter, reviewer, executor, warehouse, goods])
    db.flush()
    location = Location(
        warehouse_id=warehouse.id, location_code=f"COUNT-L-{suffix}",
        name="盘点库位", is_active=True,
    )
    supplier = GspBusinessPartner(
        code=f"COUNT-SUP-{suffix}", name="盘点测试供货方", partner_type="SUPPLIER",
        license_no=f"COUNT-LIC-{suffix}", license_scope="药品批发",
        license_valid_to=date.today() + timedelta(days=365), status="APPROVED",
        approved_by=approver.id, created_by=planner.id,
    )
    db.add_all([location, supplier])
    db.flush()
    batch = GspDrugBatch(
        goods_id=goods.id, batch_no=f"COUNT-BATCH-{suffix}",
        production_date=date.today() - timedelta(days=30),
        expiry_date=date.today() + timedelta(days=365), supplier_id=supplier.id,
        receipt_document_no=f"COUNT-RCV-{suffix}",
        traceability_code=f"COUNT-TRACE-{suffix}", status="RELEASED",
        accepted_by=approver.id, created_by=planner.id,
    )
    db.add(batch)
    db.flush()
    stock = GspBatchStock(
        batch_id=batch.id, warehouse_id=warehouse.id, location_id=location.id,
        quantity=Decimal("10.000"), reserved_quantity=Decimal("2.000"),
        stock_status="AVAILABLE", lock_version=3,
    )
    db.add(stock)
    db.flush()
    return {
        "suffix": suffix, "planner": planner, "approver": approver,
        "counter": counter, "reviewer": reviewer, "executor": executor,
        "warehouse": warehouse, "stock": stock,
    }


def _approved_plan(db, context):
    plan = create_stocktake_plan(
        db,
        payload=StocktakePlanCreate(
            plan_no=f"COUNT-PLAN-{context['suffix']}", warehouse_id=context["warehouse"].id,
            scope_type="CYCLE", scope_summary="对指定库位药品批号库存执行受控循环盘点。",
            stock_ids=[context["stock"].id], reason="依据批准的月度循环盘点计划建立任务",
        ),
        actor_id=context["planner"].id, source_ip="127.0.0.1",
    )
    submit_stocktake_plan(
        db, plan_id=plan.id, actor_id=context["planner"].id,
        reason="提交质量部门批准盘点范围", source_ip="127.0.0.1",
    )
    with pytest.raises(WorkflowError, match="必须分离"):
        approve_stocktake_plan(
            db, plan_id=plan.id, actor_id=context["planner"].id,
            reason="错误的同人批准", source_ip="127.0.0.1",
        )
    approve_stocktake_plan(
        db, plan_id=plan.id, actor_id=context["approver"].id,
        reason="质量部门独立批准盘点范围并生成账面基线", source_ip="127.0.0.1",
    )
    assert plan.transactions_frozen is True
    with pytest.raises(WorkflowError, match="盘点冻结"):
        ensure_stock_not_frozen(db, [context["stock"].id])
    return plan


def test_direct_stock_receipt_route_is_disabled_even_for_frozen_stock():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        context = _stocktake_context(db)
        _approved_plan(db, context)
        request = Request({"type": "http", "client": ("127.0.0.1", 12345)})
        with pytest.raises(HTTPException, match="直接增加批号库存入口已停用") as error:
            receive_batch_stock(
                    payload=BatchStockReceipt(
                        batch_id=context["stock"].batch_id,
                        warehouse_id=context["warehouse"].id,
                        location_id=context["stock"].location_id,
                        quantity=Decimal("1.000"),
                        reason="验证冻结库存不能通过直接收货入口增加",
                    ),
                    request=request,
                    current_user=context["planner"],
                    db=db,
                )
        assert error.value.status_code == 409
    finally:
        db.rollback()
        db.close()


def test_stocktake_difference_requires_independent_approval_and_execution():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        context = _stocktake_context(db)
        plan = _approved_plan(db, context)
        item = db.query(GspStocktakeItem).filter(GspStocktakeItem.plan_id == plan.id).one()
        assert stocktake_plan_payload(db, plan)["items"][0]["book_quantity"] is None
        assert item.book_quantity == Decimal("10.000")

        record_stocktake_count(
            db, plan_id=plan.id, item_id=item.id,
            payload=StocktakeCount(
                counted_quantity=Decimal("8.000"),
                discrepancy_reason="现场发现两盒破损并已隔离，实盘数量少于账面。",
                reason="录入首次盲盘结果",
            ),
            actor_id=context["counter"].id, source_ip="127.0.0.1",
        )
        assert plan.status == "COUNTED"
        assert stocktake_plan_payload(db, plan)["items"][0]["difference_quantity"] == Decimal("-2.000")

        with pytest.raises(WorkflowError, match="必须分离"):
            review_stocktake_results(
                db, plan_id=plan.id,
                payload=StocktakeReview(
                    decision="APPROVE", conclusion="错误的实盘人员自行批准差异调整。",
                    reason="错误的同人复核",
                ),
                actor_id=context["counter"].id, source_ip="127.0.0.1",
            )
        review_stocktake_results(
            db, plan_id=plan.id,
            payload=StocktakeReview(
                decision="APPROVE",
                conclusion="已核对破损隔离记录，同意按实盘数量执行受控库存调整。",
                capa_ref="CAPA-STOCKTAKE-001",
                reason="质量部门独立批准盘点差异",
            ),
            actor_id=context["reviewer"].id, source_ip="127.0.0.1",
        )
        assert plan.status == "ADJUSTMENT_APPROVED"
        assert context["stock"].quantity == Decimal("10.000")

        with pytest.raises(WorkflowError, match="必须分离"):
            apply_stocktake_adjustments(
                db, plan_id=plan.id, actor_id=context["reviewer"].id,
                reason="错误的批准人自行调账", source_ip="127.0.0.1",
            )
        apply_stocktake_adjustments(
            db, plan_id=plan.id, actor_id=context["executor"].id,
            reason="依据已批准盘点差异执行库存调整", source_ip="127.0.0.1",
        )
        db.commit()
        db.refresh(context["stock"])
        assert plan.status == "COMPLETED"
        assert plan.transactions_frozen is False
        assert plan.capa_ref == "CAPA-STOCKTAKE-001"
        assert context["stock"].quantity == Decimal("8.000")
        assert context["stock"].lock_version == 4
        assert item.status == "ADJUSTED"
        assert db.query(GspIntegrationMessage).filter(
            GspIntegrationMessage.message_type == "STOCKTAKE_COMPLETED"
        ).count() >= 1
    finally:
        db.close()


def test_stocktake_blocks_adjustment_when_inventory_changed_after_baseline():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        context = _stocktake_context(db)
        plan = _approved_plan(db, context)
        item = db.query(GspStocktakeItem).filter(GspStocktakeItem.plan_id == plan.id).one()
        record_stocktake_count(
            db, plan_id=plan.id, item_id=item.id,
            payload=StocktakeCount(
                counted_quantity=Decimal("9.000"),
                discrepancy_reason="复核发现一盒账实差异，等待质量批准。",
                reason="录入盲盘差异",
            ),
            actor_id=context["counter"].id, source_ip="127.0.0.1",
        )
        review_stocktake_results(
            db, plan_id=plan.id,
            payload=StocktakeReview(
                decision="APPROVE", conclusion="差异原因已经核实，同意进入调整执行阶段。",
                capa_ref="CAPA-STOCKTAKE-002",
                reason="质量复核批准差异",
            ),
            actor_id=context["reviewer"].id, source_ip="127.0.0.1",
        )
        context["stock"].quantity = Decimal("9.500")
        context["stock"].lock_version += 1
        db.flush()
        with pytest.raises(WorkflowError, match="库存已变化"):
            apply_stocktake_adjustments(
                db, plan_id=plan.id, actor_id=context["executor"].id,
                reason="尝试使用过期盘点基线调账", source_ip="127.0.0.1",
            )
    finally:
        db.rollback()
        db.close()

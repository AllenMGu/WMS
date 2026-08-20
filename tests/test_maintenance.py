from datetime import date, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest

from app.core.database import SessionLocal
from app.gsp.errors import WorkflowError
from app.gsp.maintenance.models import GspMaintenancePlanItem
from app.gsp.maintenance.schemas import (
    MaintenanceInspection,
    MaintenancePlanCreate,
    MaintenancePlanItemCreate,
)
from app.gsp.maintenance.service import (
    approve_maintenance_plan,
    complete_maintenance_plan,
    create_maintenance_plan,
    inspect_maintenance_item,
    submit_maintenance_plan,
)
from app.gsp.models import (
    GspBatchStock,
    GspBusinessPartner,
    GspDrugBatch,
    GspIntegrationMessage,
    GspQualityHold,
)
from app.legacy import Goods, Location, User, UserRole, Warehouse


def test_maintenance_plan_locks_abnormal_batch_and_requires_independent_review():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        suffix = uuid4().hex[:10]
        planner = User(
            username=f"maint-planner-{suffix}",
            hashed_password="test-only",
            full_name="养护计划员",
            role=UserRole.OPERATOR,
        )
        approver = User(
            username=f"maint-approver-{suffix}",
            hashed_password="test-only",
            full_name="质量审批员",
            role=UserRole.OPERATOR,
        )
        inspector = User(
            username=f"maint-inspector-{suffix}",
            hashed_password="test-only",
            full_name="养护检查员",
            role=UserRole.OPERATOR,
        )
        reviewer = User(
            username=f"maint-reviewer-{suffix}",
            hashed_password="test-only",
            full_name="质量复核员",
            role=UserRole.OPERATOR,
        )
        warehouse = Warehouse(
            code=f"MAINT-WH-{suffix}",
            name="养护测试仓",
            is_active=True,
        )
        goods = Goods(
            barcode=f"MAINT-BAR-{suffix}",
            name="养护测试药品",
            spec="20mg*10片",
            unit="盒",
            price=20,
        )
        db.add_all([planner, approver, inspector, reviewer, warehouse, goods])
        db.flush()
        location = Location(
            warehouse_id=warehouse.id,
            location_code=f"MAINT-L-{suffix}",
            name="养护库位",
            is_active=True,
        )
        supplier = GspBusinessPartner(
            code=f"MAINT-SUP-{suffix}",
            name="养护测试供货方",
            partner_type="SUPPLIER",
            license_no=f"MAINT-LIC-{suffix}",
            license_scope="药品批发",
            license_valid_to=date.today() + timedelta(days=365),
            status="APPROVED",
            approved_by=approver.id,
            created_by=planner.id,
        )
        db.add_all([location, supplier])
        db.flush()
        batch = GspDrugBatch(
            goods_id=goods.id,
            batch_no=f"MAINT-BATCH-{suffix}",
            production_date=date.today() - timedelta(days=100),
            expiry_date=date.today() + timedelta(days=90),
            supplier_id=supplier.id,
            receipt_document_no=f"MAINT-RCV-{suffix}",
            traceability_code=f"MAINT-TRACE-{suffix}",
            status="RELEASED",
            accepted_by=approver.id,
            created_by=planner.id,
        )
        db.add(batch)
        db.flush()
        stock = GspBatchStock(
            batch_id=batch.id,
            warehouse_id=warehouse.id,
            location_id=location.id,
            quantity=Decimal("12.000"),
            reserved_quantity=Decimal("0"),
            stock_status="AVAILABLE",
        )
        db.add(stock)
        db.flush()

        plan = create_maintenance_plan(
            db,
            payload=MaintenancePlanCreate(
                plan_no=f"MAINT-PLAN-{suffix}",
                warehouse_id=warehouse.id,
                plan_type="KEY",
                scheduled_from=date.today(),
                scheduled_to=date.today() + timedelta(days=2),
                scope_summary="近效期重点品种的外观、包装、储存环境和温湿度检查。",
                items=[
                    MaintenancePlanItemCreate(
                        stock_id=stock.id,
                        priority_reason="距有效期不足九十天，列入重点养护",
                    )
                ],
                reason="依据企业养护 SOP 建立重点养护计划",
            ),
            actor_id=planner.id,
            source_ip="127.0.0.1",
        )
        submit_maintenance_plan(
            db,
            plan_id=plan.id,
            actor_id=planner.id,
            reason="提交质量部门审批",
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            approve_maintenance_plan(
                db,
                plan_id=plan.id,
                actor_id=planner.id,
                reason="错误的同人审批",
                source_ip="127.0.0.1",
            )
        approve_maintenance_plan(
            db,
            plan_id=plan.id,
            actor_id=approver.id,
            reason="质量部门独立批准养护计划",
            source_ip="127.0.0.1",
        )
        item = (
            db.query(GspMaintenancePlanItem)
            .filter(GspMaintenancePlanItem.plan_id == plan.id)
            .one()
        )
        inspect_maintenance_item(
            db,
            plan_id=plan.id,
            item_id=item.id,
            payload=MaintenanceInspection(
                result="ABNORMAL",
                appearance_ok=False,
                package_ok=True,
                storage_condition_ok=True,
                temperature_humidity_ok=True,
                finding="抽查发现一盒外观颜色异常，立即停止销售并通知质量部门。",
                next_due_on=date.today() + timedelta(days=30),
                reason="登记养护异常并锁定批次",
            ),
            actor_id=inspector.id,
            source_ip="127.0.0.1",
        )
        db.flush()
        assert stock.stock_status == "HOLD"
        assert item.quality_hold_id is not None
        assert (
            db.query(GspQualityHold)
            .filter(
                GspQualityHold.id == item.quality_hold_id,
                GspQualityHold.reason_code == "MAINTENANCE_ABNORMAL",
            )
            .count()
            == 1
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            complete_maintenance_plan(
                db,
                plan_id=plan.id,
                conclusion="异常品种已经锁定，等待质量部门进一步调查和处置。",
                actor_id=inspector.id,
                reason="错误的同人复核",
                source_ip="127.0.0.1",
            )
        complete_maintenance_plan(
            db,
            plan_id=plan.id,
            conclusion="异常品种已经锁定，养护记录完整，转质量部门进一步调查。",
            actor_id=reviewer.id,
            reason="独立复核并完成养护计划",
            source_ip="127.0.0.1",
        )
        db.commit()
        db.refresh(plan)
        assert plan.status == "COMPLETED"
        assert (
            db.query(GspIntegrationMessage)
            .filter(GspIntegrationMessage.message_type == "MAINTENANCE_PLAN_COMPLETED")
            .count()
            >= 1
        )
    finally:
        db.close()

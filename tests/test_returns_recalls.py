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
    GspIntegrationMessage,
    GspQualityHold,
)
from app.gsp.returns_recalls.models import (
    GspRecallBatch,
    GspRecallTarget,
    GspSalesReturnItem,
)
from app.gsp.returns_recalls.schemas import (
    RecallCreate,
    SalesReturnCreate,
    SalesReturnInspection,
    SalesReturnLineCreate,
)
from app.gsp.returns_recalls.service import (
    activate_recall,
    close_recall,
    create_recall,
    create_sales_return,
    inspect_sales_return_item,
    notify_recall_target,
)
from app.gsp.sales_shipping.models import GspStockAllocation
from app.gsp.sales_shipping.schemas import (
    SalesOrderCreate,
    SalesOrderLineCreate,
    ShipmentPrepare,
)
from app.gsp.sales_shipping.service import (
    allocate_sales_order,
    approve_sales_order,
    create_sales_order,
    dispatch_shipment,
    mark_sales_order_picked,
    prepare_shipment,
    review_shipment,
    submit_sales_order,
)
from app.legacy import Goods, Location, User, UserRole, Warehouse


def _seed_dispatched_batch(db):
    suffix = uuid4().hex[:10]
    user_names = (
        "sales",
        "quality-creator",
        "quality-activator",
        "quality-closer",
        "allocator",
        "picker",
        "preparer",
        "reviewer",
        "dispatcher",
        "returns-receiver",
    )
    users = []
    for name in user_names:
        user = User(
            username=f"rr-{name}-{suffix}",
            hashed_password="test-only",
            full_name=name,
            role=UserRole.OPERATOR,
        )
        db.add(user)
        users.append(user)
    warehouse = Warehouse(code=f"RR-WH-{suffix}", name="退货召回测试仓", is_active=True)
    goods = Goods(
        barcode=f"RR-BAR-{suffix}",
        name="退货召回测试药品",
        spec="10mg*20片",
        unit="盒",
        price=30,
    )
    db.add_all([warehouse, goods])
    db.flush()
    location = Location(
        warehouse_id=warehouse.id,
        location_code=f"RR-L-{suffix}",
        name="合格品库位",
        is_active=True,
    )
    supplier = GspBusinessPartner(
        code=f"RR-SUP-{suffix}",
        name="退货召回测试供货方",
        partner_type="SUPPLIER",
        license_no=f"RR-SUP-LIC-{suffix}",
        license_scope="药品批发",
        license_valid_to=date.today() + timedelta(days=365),
        status="APPROVED",
        approved_by=users[1].id,
        created_by=users[1].id,
    )
    customer = GspBusinessPartner(
        code=f"RR-CUS-{suffix}",
        name="退货召回测试购货方",
        partner_type="CUSTOMER",
        license_no=f"RR-CUS-LIC-{suffix}",
        license_scope="医疗机构采购",
        license_valid_to=date.today() + timedelta(days=365),
        quality_agreement_valid_to=date.today() + timedelta(days=365),
        status="APPROVED",
        approved_by=users[1].id,
        created_by=users[1].id,
    )
    profile = GspDrugProfile(
        goods_id=goods.id,
        approval_no=f"RR-APPROVAL-{suffix}",
        generic_name="退货召回测试药品",
        dosage_form="片剂",
        manufacturer="测试药企",
        storage_condition="NORMAL",
        traceability_required=True,
        registration_valid_to=date.today() + timedelta(days=365),
        status="APPROVED",
        approved_by=users[1].id,
        created_by=users[1].id,
    )
    db.add_all([location, supplier, customer, profile])
    db.flush()
    batch = GspDrugBatch(
        goods_id=goods.id,
        batch_no=f"RR-BATCH-{suffix}",
        production_date=date.today() - timedelta(days=60),
        expiry_date=date.today() + timedelta(days=300),
        supplier_id=supplier.id,
        receipt_document_no=f"RR-RCV-{suffix}",
        inspection_report_no=f"RR-REPORT-{suffix}",
        traceability_code=f"RR-TRACE-{suffix}",
        acceptance_conclusion="合格",
        status="RELEASED",
        accepted_by=users[1].id,
        created_by=users[1].id,
    )
    db.add(batch)
    db.flush()
    stock = GspBatchStock(
        batch_id=batch.id,
        warehouse_id=warehouse.id,
        location_id=location.id,
        quantity=Decimal("5.000"),
        reserved_quantity=Decimal("0"),
        stock_status="AVAILABLE",
    )
    db.add(stock)
    db.flush()

    order = create_sales_order(
        db,
        payload=SalesOrderCreate(
            order_no=f"RR-SO-{suffix}",
            customer_id=customer.id,
            warehouse_id=warehouse.id,
            ordered_on=date.today(),
            items=[
                SalesOrderLineCreate(
                    goods_id=goods.id,
                    quantity=Decimal("4.000"),
                    unit="盒",
                    minimum_remaining_days=30,
                )
            ],
            reason="创建退货召回测试销售订单",
        ),
        actor_id=users[0].id,
        source_ip="127.0.0.1",
    )
    submit_sales_order(
        db,
        order_id=order.id,
        actor_id=users[0].id,
        reason="提交测试销售订单",
        source_ip="127.0.0.1",
    )
    approve_sales_order(
        db,
        order_id=order.id,
        actor_id=users[1].id,
        reason="批准测试销售订单",
        source_ip="127.0.0.1",
    )
    allocate_sales_order(
        db,
        order_id=order.id,
        actor_id=users[4].id,
        reason="分配测试批次",
        source_ip="127.0.0.1",
    )
    mark_sales_order_picked(
        db,
        order_id=order.id,
        actor_id=users[5].id,
        reason="完成测试拣货",
        source_ip="127.0.0.1",
    )
    shipment = prepare_shipment(
        db,
        order_id=order.id,
        payload=ShipmentPrepare(
            shipment_no=f"RR-SHIP-{suffix}",
            carrier_name="测试承运商",
            vehicle_no="苏B00001",
            driver_name="测试司机",
            transport_mode="NORMAL",
            reason="准备测试发运",
        ),
        actor_id=users[6].id,
        source_ip="127.0.0.1",
    )
    review_shipment(
        db,
        shipment_id=shipment.id,
        actor_id=users[7].id,
        reason="复核测试发运",
        source_ip="127.0.0.1",
    )
    dispatch_shipment(
        db,
        shipment_id=shipment.id,
        actor_id=users[8].id,
        reason="确认测试发运",
        source_ip="127.0.0.1",
    )
    db.flush()
    allocation = (
        db.query(GspStockAllocation)
        .filter(GspStockAllocation.batch_id == batch.id)
        .order_by(GspStockAllocation.id.desc())
        .first()
    )
    return users, warehouse, location, batch, stock, shipment, allocation


def test_sales_return_is_quarantined_until_independent_inspection():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        users, _warehouse, location, batch, stock, shipment, allocation = (
            _seed_dispatched_batch(db)
        )
        receiver = users[9]
        quality = users[1]
        assert stock.quantity == Decimal("1.000")
        sales_return = create_sales_return(
            db,
            payload=SalesReturnCreate(
                return_no=f"RETURN-{uuid4().hex[:10]}",
                shipment_id=shipment.id,
                received_at=datetime.now(),
                items=[
                    SalesReturnLineCreate(
                        stock_allocation_id=allocation.id,
                        quantity=Decimal("2.000"),
                        reason_code="CUSTOMER_RETURN",
                        condition_notes="外包装完整，等待质量检验",
                        traceability_code=batch.traceability_code,
                    )
                ],
                reason="登记客户销后退回",
            ),
            actor_id=receiver.id,
            source_ip="127.0.0.1",
        )
        db.flush()
        assert stock.quantity == Decimal("1.000")
        return_item = (
            db.query(GspSalesReturnItem)
            .filter(GspSalesReturnItem.sales_return_id == sales_return.id)
            .one()
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            inspect_sales_return_item(
                db,
                return_id=sales_return.id,
                item_id=return_item.id,
                payload=SalesReturnInspection(
                    accepted_quantity=Decimal("2.000"),
                    rejected_quantity=Decimal("0"),
                    conclusion="符合重新入库条件",
                    accepted_location_id=location.id,
                    package_intact=True,
                    storage_conditions_confirmed=True,
                    traceability_verified=True,
                    reason="错误的同人检验",
                ),
                actor_id=receiver.id,
                source_ip="127.0.0.1",
            )
        inspect_sales_return_item(
            db,
            return_id=sales_return.id,
            item_id=return_item.id,
            payload=SalesReturnInspection(
                accepted_quantity=Decimal("2.000"),
                rejected_quantity=Decimal("0"),
                conclusion="包装、储存和追溯信息复核合格",
                accepted_location_id=location.id,
                package_intact=True,
                storage_conditions_confirmed=True,
                traceability_verified=True,
                reason="独立质量检验合格后回库",
            ),
            actor_id=quality.id,
            source_ip="127.0.0.1",
        )
        db.commit()
        db.refresh(stock)
        db.refresh(sales_return)
        assert sales_return.status == "COMPLETED"
        assert stock.quantity == Decimal("3.000")
        message_types = {
            row.message_type
            for row in db.query(GspIntegrationMessage)
            .filter(GspIntegrationMessage.aggregate_id == str(sales_return.id))
            .all()
        }
        assert {"SALES_RETURN_RECEIVED", "SALES_RETURN_INSPECTED"} <= message_types
    finally:
        db.close()


def test_recall_locks_batch_tracks_recovery_and_requires_notification():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        users, _warehouse, _location, batch, stock, shipment, allocation = (
            _seed_dispatched_batch(db)
        )
        creator, activator, closer = users[1], users[2], users[3]
        receiver, sales = users[9], users[0]
        recall = create_recall(
            db,
            payload=RecallCreate(
                recall_no=f"RECALL-{uuid4().hex[:10]}",
                recall_level="II",
                source="INTERNAL",
                regulatory_ref="DEV-TEST-001",
                batch_ids=[batch.id],
                reason="内部质量偏差触发召回",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            activate_recall(
                db,
                recall_id=recall.id,
                actor_id=creator.id,
                reason="错误的同人启动",
                source_ip="127.0.0.1",
            )
        activate_recall(
            db,
            recall_id=recall.id,
            actor_id=activator.id,
            reason="独立质量审批后启动召回",
            source_ip="127.0.0.1",
        )
        db.flush()
        target = (
            db.query(GspRecallTarget)
            .filter(GspRecallTarget.recall_id == recall.id)
            .one()
        )
        recall_batch = (
            db.query(GspRecallBatch)
            .filter(GspRecallBatch.recall_id == recall.id)
            .one()
        )
        assert recall_batch.target_shipped_quantity == Decimal("4.000")
        assert stock.stock_status == "HOLD"

        sales_return = create_sales_return(
            db,
            payload=SalesReturnCreate(
                return_no=f"RECALL-RETURN-{uuid4().hex[:8]}",
                shipment_id=shipment.id,
                received_at=datetime.now(),
                items=[
                    SalesReturnLineCreate(
                        stock_allocation_id=allocation.id,
                        recall_target_id=target.id,
                        quantity=Decimal("1.000"),
                        reason_code="RECALL",
                        condition_notes="召回药品已隔离",
                        traceability_code=batch.traceability_code,
                    )
                ],
                reason="登记召回回收药品",
            ),
            actor_id=receiver.id,
            source_ip="127.0.0.1",
        )
        db.flush()
        db.refresh(target)
        db.refresh(recall_batch)
        assert target.recovered_quantity == Decimal("1.000")
        assert recall_batch.recovered_quantity == Decimal("1.000")

        return_item = (
            db.query(GspSalesReturnItem)
            .filter(GspSalesReturnItem.sales_return_id == sales_return.id)
            .one()
        )
        with pytest.raises(WorkflowError, match="不满足重新入库条件"):
            inspect_sales_return_item(
                db,
                return_id=sales_return.id,
                item_id=return_item.id,
                payload=SalesReturnInspection(
                    accepted_quantity=Decimal("1.000"),
                    rejected_quantity=Decimal("0"),
                    conclusion="召回锁定期间不得回库",
                    accepted_location_id=stock.location_id,
                    package_intact=True,
                    storage_conditions_confirmed=True,
                    traceability_verified=True,
                    reason="验证召回锁定阻断",
                ),
                actor_id=creator.id,
                source_ip="127.0.0.1",
            )
        inspect_sales_return_item(
            db,
            return_id=sales_return.id,
            item_id=return_item.id,
            payload=SalesReturnInspection(
                accepted_quantity=Decimal("0"),
                rejected_quantity=Decimal("1.000"),
                conclusion="召回药品继续隔离等待后续处置",
                rejection_disposition="QUARANTINE",
                reason="质量检验判定不得回库",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="未登记召回通知"):
            close_recall(
                db,
                recall_id=recall.id,
                conclusion="错误的提前关闭",
                actor_id=closer.id,
                reason="尝试提前关闭",
                source_ip="127.0.0.1",
            )
        notify_recall_target(
            db,
            recall_id=recall.id,
            target_id=target.id,
            notification_status="ACKNOWLEDGED",
            notes="购货方确认收到召回通知并退回一盒",
            actor_id=sales.id,
            reason="登记购货方通知结果",
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            close_recall(
                db,
                recall_id=recall.id,
                conclusion="错误的同人关闭",
                actor_id=activator.id,
                reason="错误的同人关闭",
                source_ip="127.0.0.1",
            )
        close_recall(
            db,
            recall_id=recall.id,
            conclusion="已完成通知、数量核对，未回收数量记录在结论中",
            actor_id=closer.id,
            reason="独立复核召回记录后关闭",
            source_ip="127.0.0.1",
        )
        db.commit()
        db.refresh(recall)
        db.refresh(stock)
        assert recall.status == "CLOSED"
        assert stock.stock_status == "HOLD"
        assert (
            db.query(GspQualityHold)
            .filter(
                GspQualityHold.batch_id == batch.id,
                GspQualityHold.reason_code == "RECALL",
                GspQualityHold.status == "ACTIVE",
            )
            .count()
            == 1
        )
        recall_messages = {
            row.message_type
            for row in db.query(GspIntegrationMessage)
            .filter(GspIntegrationMessage.aggregate_type.like("GspRecall%"))
            .all()
        }
        assert {"RECALL_ACTIVATED", "RECALL_TARGET_UPDATED", "RECALL_CLOSED"} <= recall_messages
    finally:
        db.close()

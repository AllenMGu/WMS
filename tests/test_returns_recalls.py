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
from app.gsp.quality_disposition.models import GspNonconformingRecord
from app.gsp.returns_recalls.models import (
    GspRecallBatch,
    GspRecallCompletionReport,
    GspRecallDrillTarget,
    GspRecallTarget,
    GspSalesReturnItem,
)
from app.gsp.returns_recalls.schemas import (
    RecallCompletionReportCreate,
    RecallCreate,
    RecallDrillComplete,
    RecallDrillCreate,
    RecallDrillTargetVerification,
    SalesReturnCreate,
    SalesReturnInspection,
    SalesReturnLineCreate,
)
from app.gsp.returns_recalls.service import (
    activate_recall,
    activate_recall_drill,
    close_recall,
    complete_recall_drill,
    create_recall,
    create_recall_drill,
    create_sales_return,
    inspect_sales_return_item,
    notify_recall_target,
    record_recall_progress,
    submit_recall_completion_report,
    verify_recall_drill_target,
)
from app.gsp.sales_shipping.models import GspStockAllocation
from app.gsp.sales_shipping.schemas import (
    SalesOrderCreate,
    SalesOrderLineCreate,
    ShipmentPackageCreate,
    ShipmentPackageLineCreate,
    ShipmentPrepare,
)
from app.gsp.sales_shipping.service import (
    add_shipment_package,
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
from tests.gsp_seed_helpers import (
    add_approved_transport_resources,
    add_verified_partner_evidence,
)


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
        registration_document_ref="test://registration/returns",
        nmpa_verification_ref="test://nmpa/returns",
        status="APPROVED",
        approved_by=users[1].id,
        created_by=users[1].id,
    )
    db.add_all([location, supplier, customer, profile])
    db.flush()
    add_verified_partner_evidence(
        db,
        partner=customer,
        verifier_id=users[1].id,
        valid_to=date.today() + timedelta(days=365),
    )
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
    carrier, vehicle, driver = add_approved_transport_resources(
        db,
        creator_id=users[6].id,
        approver_id=users[1].id,
        suffix=suffix,
    )
    shipment = prepare_shipment(
        db,
        order_id=order.id,
        payload=ShipmentPrepare(
            shipment_no=f"RR-SHIP-{suffix}",
            carrier_id=carrier.id,
            vehicle_id=vehicle.id,
            driver_id=driver.id,
            transport_mode="NORMAL",
            route_plan_ref="test://route/returns-recalls",
            handover_document_no=f"RR-HO-{suffix}",
            expected_arrival_at=datetime.now() + timedelta(days=1),
            reason="准备测试发运",
        ),
        actor_id=users[6].id,
        source_ip="127.0.0.1",
    )
    allocation = db.query(GspStockAllocation).filter(
        GspStockAllocation.batch_id == batch.id
    ).one()
    add_shipment_package(
        db,
        shipment_id=shipment.id,
        payload=ShipmentPackageCreate(
            package_no=f"RR-PKG-{suffix}",
            package_type="CARTON",
            seal_no=f"RR-SEAL-{suffix}",
            packing_condition="包装完整并已封签",
            delivery_note_no=f"RR-DN-{suffix}",
            packing_record_ref=f"test://packing/{suffix}",
            items=[ShipmentPackageLineCreate(
                allocation_id=allocation.id,
                quantity=allocation.quantity,
                traceability_code=batch.traceability_code,
            )],
            reason="登记逐箱包装和追溯码",
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


@pytest.mark.parametrize(
    ("accepted_quantity", "rejected_quantity", "expected_stock", "expected_status"),
    [
        (Decimal("2.000"), Decimal("0"), Decimal("3.000"), "AVAILABLE"),
        (Decimal("1.000"), Decimal("1.000"), Decimal("2.000"), "HOLD"),
    ],
)
def test_sales_return_is_quarantined_until_independent_inspection(
    accepted_quantity, rejected_quantity, expected_stock, expected_status
):
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
                accepted_quantity=accepted_quantity,
                rejected_quantity=rejected_quantity,
                conclusion="包装、储存和追溯信息已复核，按结论分别回库和隔离",
                accepted_location_id=location.id,
                rejection_disposition="QUARANTINE" if rejected_quantity else None,
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
        assert stock.quantity == expected_stock
        assert stock.stock_status == expected_status
        if rejected_quantity:
            nonconforming = (
                db.query(GspNonconformingRecord)
                .filter(
                    GspNonconformingRecord.source_entity_type == "GspSalesReturnItem",
                    GspNonconformingRecord.source_entity_id == return_item.id,
                )
                .one()
            )
            assert nonconforming.quantity == rejected_quantity
            assert nonconforming.quality_hold_id is not None
            assert db.query(GspQualityHold).filter_by(id=nonconforming.quality_hold_id).one().status == "ACTIVE"
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
        assert recall.notification_due_at - recall.activated_at == timedelta(days=3)
        assert recall.next_progress_report_due_at - recall.activated_at == timedelta(days=3)
        record_recall_progress(
            db,
            recall_id=recall.id,
            report_ref="RECALL-PROGRESS-001",
            summary="已完成目标识别并开始通知购货方",
            actor_id=creator.id,
            reason="按二级召回频次登记进展",
            source_ip="127.0.0.1",
        )
        assert recall.next_progress_report_due_at - recall.last_progress_reported_at == timedelta(
            days=3
        )

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
        nonconforming = (
            db.query(GspNonconformingRecord)
            .filter(
                GspNonconformingRecord.source_entity_type == "GspSalesReturnItem",
                GspNonconformingRecord.source_entity_id == return_item.id,
            )
            .one()
        )
        assert nonconforming.quantity == Decimal("1.000")
        assert nonconforming.proposed_disposition == "QUARANTINE"
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
        assert recall.completion_report_due_at > recall.closed_at
        cursor = recall.closed_at
        counted_working_days = 0
        while cursor < recall.completion_report_due_at:
            cursor += timedelta(days=1)
            if cursor.weekday() < 5:
                counted_working_days += 1
        assert counted_working_days == 10
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
        assert {
            "RECALL_ACTIVATED",
            "RECALL_PROGRESS_REPORTED",
            "RECALL_TARGET_UPDATED",
            "RECALL_CLOSED",
        } <= recall_messages
        with pytest.raises(WorkflowError, match="必须分离"):
            submit_recall_completion_report(
                db,
                recall_id=recall.id,
                payload=RecallCompletionReportCreate(
                    report_ref="RECALL-COMPLETE-INVALID",
                    treatment_summary="召回范围、通知、回收和处置记录已经完成汇总。",
                    effectiveness_evaluation="召回过程达到计划目标，未发现新的风险扩散。",
                    regulatory_submission_ref="REG-SUBMISSION-INVALID",
                    reason="错误的同人提交完成报告",
                ),
                actor_id=closer.id,
                source_ip="127.0.0.1",
            )
        submit_recall_completion_report(
            db,
            recall_id=recall.id,
            payload=RecallCompletionReportCreate(
                report_ref="RECALL-COMPLETE-001",
                treatment_summary="召回范围、通知、回收和处置记录已经完成汇总。",
                effectiveness_evaluation="召回过程达到计划目标，未发现新的风险扩散。",
                regulatory_submission_ref="REG-SUBMISSION-001",
                reason="在法定期限内提交召回完成报告",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        db.commit()
        report = (
            db.query(GspRecallCompletionReport)
            .filter(GspRecallCompletionReport.recall_id == recall.id)
            .one()
        )
        assert report.regulatory_submission_ref == "REG-SUBMISSION-001"
        assert (
            db.query(GspIntegrationMessage)
            .filter(GspIntegrationMessage.message_type == "RECALL_COMPLETION_REPORTED")
            .count()
            >= 1
        )
    finally:
        db.close()


def test_recall_drill_uses_real_trace_targets_without_locking_inventory():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        users, _warehouse, _location, batch, stock, _shipment, _allocation = (
            _seed_dispatched_batch(db)
        )
        creator, activator, completer = users[1], users[2], users[3]
        drill = create_recall_drill(
            db,
            payload=RecallDrillCreate(
                drill_no=f"DRILL-{uuid4().hex[:10]}",
                recall_level="I",
                scenario="模拟已发运批次出现严重质量风险，需要快速定位全部购货方。",
                objective="验证批号到发运单和购货方的正向追溯完整性。",
                max_allowed_minutes=60,
                batch_ids=[batch.id],
                reason="建立年度召回演练",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        activate_recall_drill(
            db,
            drill_id=drill.id,
            actor_id=activator.id,
            reason="独立批准并启动召回演练",
            source_ip="127.0.0.1",
        )
        db.flush()
        target = (
            db.query(GspRecallDrillTarget)
            .filter(GspRecallDrillTarget.drill_id == drill.id)
            .one()
        )
        assert target.shipped_quantity == Decimal("4.000")
        assert stock.stock_status == "AVAILABLE"
        verify_recall_drill_target(
            db,
            drill_id=drill.id,
            target_id=target.id,
            payload=RecallDrillTargetVerification(
                verification_status="LOCATED",
                notes="已从批号追溯到原发运单与购货方",
                reason="登记演练追溯结果",
            ),
            actor_id=users[0].id,
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            complete_recall_drill(
                db,
                drill_id=drill.id,
                payload=RecallDrillComplete(
                    completion_summary="演练完成且所有目标均已定位。",
                    reason="错误的同人完成演练",
                ),
                actor_id=activator.id,
                source_ip="127.0.0.1",
            )
        complete_recall_drill(
            db,
            drill_id=drill.id,
            payload=RecallDrillComplete(
                completion_summary="演练在目标时限内完成，所有发运目标均已定位。",
                reason="独立复核演练完成记录",
            ),
            actor_id=completer.id,
            source_ip="127.0.0.1",
        )
        db.commit()
        db.refresh(drill)
        db.refresh(stock)
        assert drill.status == "COMPLETED"
        assert drill.result == "PASSED"
        assert stock.stock_status == "AVAILABLE"
    finally:
        db.close()

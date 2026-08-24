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
from app.gsp.sales_shipping.models import GspSalesOrderItem, GspStockAllocation
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


def _seed_sales_data(db):
    suffix = uuid4().hex[:10]
    users = []
    for name in (
        "sales",
        "quality",
        "allocator",
        "picker",
        "preparer",
        "reviewer",
        "dispatcher",
    ):
        user = User(
            username=f"ship-{name}-{suffix}",
            hashed_password="test-only",
            full_name=name,
            role=UserRole.OPERATOR,
        )
        db.add(user)
        users.append(user)
    warehouse = Warehouse(code=f"SHIP-WH-{suffix}", name="销售测试仓", is_active=True)
    goods = Goods(
        barcode=f"SHIP-BAR-{suffix}",
        name="销售测试药品",
        spec="20mg*10片",
        unit="盒",
        price=20,
    )
    db.add_all([warehouse, goods])
    db.flush()
    early_location = Location(
        warehouse_id=warehouse.id,
        location_code=f"SHIP-L1-{suffix}",
        name="近效期库位",
        is_active=True,
    )
    later_location = Location(
        warehouse_id=warehouse.id,
        location_code=f"SHIP-L2-{suffix}",
        name="远效期库位",
        is_active=True,
    )
    supplier = GspBusinessPartner(
        code=f"SHIP-SUP-{suffix}",
        name="销售测试供货方",
        partner_type="SUPPLIER",
        license_no=f"SHIP-SUP-LIC-{suffix}",
        license_scope="药品批发",
        license_valid_to=date.today() + timedelta(days=365),
        status="APPROVED",
        approved_by=users[1].id,
        created_by=users[1].id,
    )
    customer = GspBusinessPartner(
        code=f"SHIP-CUS-{suffix}",
        name="合格购货方",
        partner_type="CUSTOMER",
        license_no=f"SHIP-CUS-LIC-{suffix}",
        license_scope="医疗机构采购",
        license_valid_to=date.today() + timedelta(days=365),
        quality_agreement_valid_to=date.today() + timedelta(days=365),
        status="APPROVED",
        approved_by=users[1].id,
        created_by=users[1].id,
    )
    profile = GspDrugProfile(
        goods_id=goods.id,
        approval_no=f"SHIP-APPROVAL-{suffix}",
        generic_name="销售测试药品",
        dosage_form="片剂",
        manufacturer="测试药企",
        storage_condition="NORMAL",
        traceability_required=True,
        registration_valid_to=date.today() + timedelta(days=365),
        registration_document_ref="test://registration/sales",
        nmpa_verification_ref="test://nmpa/sales",
        status="APPROVED",
        approved_by=users[1].id,
        created_by=users[1].id,
    )
    db.add_all([early_location, later_location, supplier, customer, profile])
    db.flush()
    add_verified_partner_evidence(
        db,
        partner=customer,
        verifier_id=users[1].id,
        valid_to=date.today() + timedelta(days=365),
    )
    early_batch = GspDrugBatch(
        goods_id=goods.id,
        batch_no=f"EARLY-{suffix}",
        production_date=date.today() - timedelta(days=100),
        expiry_date=date.today() + timedelta(days=180),
        supplier_id=supplier.id,
        receipt_document_no=f"EARLY-RCV-{suffix}",
        inspection_report_no=f"EARLY-REPORT-{suffix}",
        traceability_code=f"EARLY-TRACE-{suffix}",
        acceptance_conclusion="合格",
        status="RELEASED",
        accepted_by=users[1].id,
        created_by=users[1].id,
    )
    later_batch = GspDrugBatch(
        goods_id=goods.id,
        batch_no=f"LATER-{suffix}",
        production_date=date.today() - timedelta(days=30),
        expiry_date=date.today() + timedelta(days=360),
        supplier_id=supplier.id,
        receipt_document_no=f"LATER-RCV-{suffix}",
        inspection_report_no=f"LATER-REPORT-{suffix}",
        traceability_code=f"LATER-TRACE-{suffix}",
        acceptance_conclusion="合格",
        status="RELEASED",
        accepted_by=users[1].id,
        created_by=users[1].id,
    )
    db.add_all([early_batch, later_batch])
    db.flush()
    early_stock = GspBatchStock(
        batch_id=early_batch.id,
        warehouse_id=warehouse.id,
        location_id=early_location.id,
        quantity=Decimal("5.000"),
        reserved_quantity=Decimal("0"),
        stock_status="AVAILABLE",
    )
    later_stock = GspBatchStock(
        batch_id=later_batch.id,
        warehouse_id=warehouse.id,
        location_id=later_location.id,
        quantity=Decimal("10.000"),
        reserved_quantity=Decimal("0"),
        stock_status="AVAILABLE",
    )
    db.add_all([early_stock, later_stock])
    db.flush()
    return users, warehouse, goods, customer, early_batch, early_stock, later_stock


def test_fefo_sales_allocation_review_and_dispatch():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        users, warehouse, goods, customer, early_batch, early_stock, later_stock = (
            _seed_sales_data(db)
        )
        sales, quality, allocator, picker, preparer, reviewer, dispatcher = users
        order = create_sales_order(
            db,
            payload=SalesOrderCreate(
                order_no=f"SO-{uuid4().hex[:10]}",
                customer_id=customer.id,
                warehouse_id=warehouse.id,
                ordered_on=date.today(),
                items=[
                    SalesOrderLineCreate(
                        goods_id=goods.id,
                        quantity=Decimal("8.000"),
                        unit="盒",
                        minimum_remaining_days=60,
                    )
                ],
                reason="客户销售申请",
            ),
            actor_id=sales.id,
            source_ip="127.0.0.1",
        )
        submit_sales_order(
            db,
            order_id=order.id,
            actor_id=sales.id,
            reason="提交质量审核",
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            approve_sales_order(
                db,
                order_id=order.id,
                actor_id=sales.id,
                reason="错误的同人审批",
                source_ip="127.0.0.1",
            )
        approve_sales_order(
            db,
            order_id=order.id,
            actor_id=quality.id,
            reason="购货方和品种资质复核通过",
            source_ip="127.0.0.1",
        )
        allocate_sales_order(
            db,
            order_id=order.id,
            actor_id=allocator.id,
            reason="按近效期先出原则分配",
            source_ip="127.0.0.1",
        )
        db.flush()
        item = (
            db.query(GspSalesOrderItem)
            .filter(GspSalesOrderItem.sales_order_id == order.id)
            .one()
        )
        allocations = (
            db.query(GspStockAllocation)
            .filter(GspStockAllocation.sales_order_item_id == item.id)
            .order_by(GspStockAllocation.id)
            .all()
        )
        assert [allocation.quantity for allocation in allocations] == [
            Decimal("5.000"),
            Decimal("3.000"),
        ]
        assert early_stock.reserved_quantity == Decimal("5.000")
        assert later_stock.reserved_quantity == Decimal("3.000")

        picking_hold = GspQualityHold(
            batch_id=early_batch.id,
            reason_code="PICKING_HOLD",
            reason="拣货前质量锁定测试",
            status="ACTIVE",
            initiated_by=quality.id,
        )
        db.add(picking_hold)
        db.flush()
        with pytest.raises(WorkflowError, match="不满足出库条件"):
            mark_sales_order_picked(
                db,
                order_id=order.id,
                actor_id=picker.id,
                reason="锁定批次不得拣货",
                source_ip="127.0.0.1",
            )
        picking_hold.status = "RELEASED"
        db.flush()
        mark_sales_order_picked(
            db,
            order_id=order.id,
            actor_id=picker.id,
            reason="按分配批号完成拣货",
            source_ip="127.0.0.1",
        )
        carrier, vehicle, driver = add_approved_transport_resources(
            db,
            creator_id=preparer.id,
            approver_id=quality.id,
            suffix=uuid4().hex[:10],
        )
        shipment = prepare_shipment(
            db,
            order_id=order.id,
            payload=ShipmentPrepare(
                shipment_no=f"SHIP-{uuid4().hex[:10]}",
                carrier_id=carrier.id,
                vehicle_id=vehicle.id,
                driver_id=driver.id,
                transport_mode="NORMAL",
                route_plan_ref="test://route/standard",
                handover_document_no=f"HO-{uuid4().hex[:10]}",
                expected_arrival_at=datetime.now() + timedelta(days=1),
                reason="准备发运",
            ),
            actor_id=preparer.id,
            source_ip="127.0.0.1",
        )
        add_shipment_package(
            db,
            shipment_id=shipment.id,
            payload=ShipmentPackageCreate(
                package_no=f"PKG-{uuid4().hex[:10]}",
                package_type="CARTON",
                seal_no=f"SEAL-{uuid4().hex[:10]}",
                packing_condition="外包装完整并已封签",
                delivery_note_no=f"DN-{uuid4().hex[:10]}",
                packing_record_ref="test://packing/sales-shipping",
                items=[
                    ShipmentPackageLineCreate(
                        allocation_id=allocation.id,
                        quantity=allocation.quantity,
                        traceability_code=db.query(GspDrugBatch).filter(
                            GspDrugBatch.id == allocation.batch_id
                        ).one().traceability_code,
                    )
                    for allocation in allocations
                ],
                reason="逐箱扫描批号与追溯码",
            ),
            actor_id=preparer.id,
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            review_shipment(
                db,
                shipment_id=shipment.id,
                actor_id=picker.id,
                reason="错误的拣货人复核",
                source_ip="127.0.0.1",
            )
        hold = GspQualityHold(
            batch_id=early_batch.id,
            reason_code="TEST_HOLD",
            reason="复核前质量锁定测试",
            status="ACTIVE",
            initiated_by=quality.id,
        )
        db.add(hold)
        db.flush()
        with pytest.raises(WorkflowError, match="不满足出库条件"):
            review_shipment(
                db,
                shipment_id=shipment.id,
                actor_id=reviewer.id,
                reason="锁定状态不得复核",
                source_ip="127.0.0.1",
            )
        hold.status = "RELEASED"
        db.flush()
        review_shipment(
            db,
            shipment_id=shipment.id,
            actor_id=reviewer.id,
            reason="批号数量客户信息复核一致",
            source_ip="127.0.0.1",
        )
        dispatch_shipment(
            db,
            shipment_id=shipment.id,
            actor_id=dispatcher.id,
            reason="复核通过后交接发运",
            source_ip="127.0.0.1",
        )
        db.commit()

        db.refresh(order)
        db.refresh(shipment)
        db.refresh(early_stock)
        db.refresh(later_stock)
        assert order.status == "SHIPPED"
        assert shipment.status == "DISPATCHED"
        assert item.shipped_quantity == Decimal("8.000")
        assert early_stock.quantity == Decimal("0.000")
        assert later_stock.quantity == Decimal("7.000")
        assert early_stock.reserved_quantity == Decimal("0.000")
        assert later_stock.reserved_quantity == Decimal("0.000")
        assert (
            db.query(GspIntegrationMessage)
            .filter(
                GspIntegrationMessage.message_type == "SHIPMENT_CONFIRMED",
                GspIntegrationMessage.aggregate_id == str(shipment.id),
            )
            .count()
            == 1
        )
    finally:
        db.close()


def test_allocation_shortage_does_not_leave_partial_reservation():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        users, warehouse, goods, customer, _, early_stock, later_stock = _seed_sales_data(db)
        sales, quality, allocator, *_ = users
        order = create_sales_order(
            db,
            payload=SalesOrderCreate(
                order_no=f"SO-SHORT-{uuid4().hex[:8]}",
                customer_id=customer.id,
                warehouse_id=warehouse.id,
                ordered_on=date.today(),
                items=[
                    SalesOrderLineCreate(
                        goods_id=goods.id,
                        quantity=Decimal("20.000"),
                        unit="盒",
                    )
                ],
                reason="库存不足原子性测试",
            ),
            actor_id=sales.id,
            source_ip="127.0.0.1",
        )
        submit_sales_order(
            db,
            order_id=order.id,
            actor_id=sales.id,
            reason="提交测试订单",
            source_ip="127.0.0.1",
        )
        approve_sales_order(
            db,
            order_id=order.id,
            actor_id=quality.id,
            reason="测试审批通过",
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="没有足够"):
            allocate_sales_order(
                db,
                order_id=order.id,
                actor_id=allocator.id,
                reason="尝试分配不足库存",
                source_ip="127.0.0.1",
            )
        assert early_stock.reserved_quantity == Decimal("0")
        assert later_stock.reserved_quantity == Decimal("0")
        assert (
            db.query(GspStockAllocation)
            .join(
                GspSalesOrderItem,
                GspSalesOrderItem.id == GspStockAllocation.sales_order_item_id,
            )
            .filter(GspSalesOrderItem.sales_order_id == order.id)
            .count()
            == 0
        )
    finally:
        db.rollback()
        db.close()

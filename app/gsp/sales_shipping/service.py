"""Transactional service for qualified sales, FEFO allocation and dispatch."""

from __future__ import annotations

from decimal import Decimal

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.audit import write_audit_event
from app.gsp.errors import WorkflowError
from app.gsp.models import (
    GspBatchStock,
    GspBusinessPartner,
    GspDrugBatch,
    GspDrugProfile,
    GspQualityHold,
)
from app.gsp.outbox import enqueue_integration_message
from app.gsp.qualification import evaluate_partner_evidence
from app.gsp.rules import evaluate_batch, evaluate_product
from app.gsp.sales_shipping.models import (
    GspSalesOrder,
    GspSalesOrderItem,
    GspShipment,
    GspShipmentPackage,
    GspShipmentPackageItem,
    GspStockAllocation,
)
from app.gsp.sales_shipping.schemas import SalesOrderCreate, ShipmentPackageCreate, ShipmentPrepare
from app.gsp.snapshots import model_snapshot
from app.gsp.stocktaking.service import ensure_stock_not_frozen
from app.gsp.transport.service import (
    create_transport_task,
    start_transport_task,
    validate_transport_resources,
)
from app.legacy import Warehouse


def _finding_dicts(result) -> list[dict]:
    return [{"code": item.code, "message": item.message} for item in result.findings]


def _order_items(db: Session, order_id: int) -> list[GspSalesOrderItem]:
    return (
        db.query(GspSalesOrderItem)
        .filter(GspSalesOrderItem.sales_order_id == order_id)
        .order_by(GspSalesOrderItem.line_no)
        .all()
    )


def _allocations(db: Session, order_id: int) -> list[GspStockAllocation]:
    return (
        db.query(GspStockAllocation)
        .join(
            GspSalesOrderItem,
            GspSalesOrderItem.id == GspStockAllocation.sales_order_item_id,
        )
        .filter(GspSalesOrderItem.sales_order_id == order_id)
        .order_by(GspSalesOrderItem.line_no, GspStockAllocation.id)
        .all()
    )


def sales_order_payload(db: Session, order: GspSalesOrder) -> dict:
    result = model_snapshot(order)
    result["items"] = [model_snapshot(item) for item in _order_items(db, order.id)]
    result["allocations"] = [model_snapshot(item) for item in _allocations(db, order.id)]
    return result


def shipment_payload(shipment: GspShipment) -> dict:
    return model_snapshot(shipment)


def shipment_package_payload(db: Session, package: GspShipmentPackage) -> dict:
    result = model_snapshot(package)
    result["items"] = [
        model_snapshot(item)
        for item in db.query(GspShipmentPackageItem)
        .filter(GspShipmentPackageItem.package_id == package.id)
        .order_by(GspShipmentPackageItem.id)
    ]
    return result


def add_shipment_package(
    db: Session,
    *,
    shipment_id: int,
    payload: ShipmentPackageCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspShipmentPackage:
    shipment = db.query(GspShipment).filter(GspShipment.id == shipment_id).with_for_update().first()
    if not shipment:
        raise WorkflowError(404, "发运单不存在")
    if shipment.status != "PREPARED":
        raise WorkflowError(409, "只有待复核发运单可以登记包装")
    order = db.query(GspSalesOrder).filter(GspSalesOrder.id == shipment.sales_order_id).first()
    allocations = {item.id: item for item in _allocations(db, order.id)}
    if len({item.allocation_id for item in payload.items}) != len(payload.items):
        raise WorkflowError(422, "同一包装内不能重复登记批次分配")
    package = GspShipmentPackage(
        shipment_id=shipment.id,
        package_no=payload.package_no,
        package_type=payload.package_type,
        seal_no=payload.seal_no,
        packing_condition=payload.packing_condition,
        delivery_note_no=payload.delivery_note_no,
        packing_record_ref=payload.packing_record_ref,
        created_by=actor_id,
    )
    db.add(package)
    db.flush()
    for line in payload.items:
        allocation = allocations.get(line.allocation_id)
        if not allocation or allocation.status != "PICKED":
            raise WorkflowError(409, "包装明细未关联当前发运单的已拣批次")
        batch = db.query(GspDrugBatch).filter(GspDrugBatch.id == allocation.batch_id).first()
        item = db.query(GspSalesOrderItem).filter(
            GspSalesOrderItem.id == allocation.sales_order_item_id
        ).first()
        profile = db.query(GspDrugProfile).filter(GspDrugProfile.goods_id == item.goods_id).first()
        if profile.traceability_required and (
            not line.traceability_code or line.traceability_code != batch.traceability_code
        ):
            raise WorkflowError(409, "追溯码未扫描或与批准批次不一致")
        already_packed = db.query(GspShipmentPackageItem).filter(
            GspShipmentPackageItem.allocation_id == allocation.id
        ).with_entities(GspShipmentPackageItem.quantity).all()
        packed_quantity = sum((Decimal(row[0]) for row in already_packed), Decimal("0"))
        if packed_quantity + Decimal(line.quantity) > Decimal(allocation.quantity):
            raise WorkflowError(409, "包装数量超过批次分配数量")
        db.add(GspShipmentPackageItem(
            package_id=package.id,
            allocation_id=allocation.id,
            quantity=line.quantity,
            traceability_code=line.traceability_code,
        ))
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="SHIPMENT_PACKAGE_RECORDED",
        entity_type="GspShipmentPackage",
        entity_id=str(package.id),
        reason=payload.reason,
        after_data=shipment_package_payload(db, package),
        source_ip=source_ip,
    )
    return package


def _validate_shipment_packages(db: Session, shipment: GspShipment, order: GspSalesOrder, reviewer_id: int) -> None:
    packages = db.query(GspShipmentPackage).filter(
        GspShipmentPackage.shipment_id == shipment.id
    ).all()
    if not packages:
        raise WorkflowError(409, "出库复核前必须完成逐箱包装登记")
    if any(package.created_by == reviewer_id for package in packages):
        raise WorkflowError(409, "包装登记人与出库复核人必须分离")
    package_ids = [package.id for package in packages]
    packed = {}
    for item in db.query(GspShipmentPackageItem).filter(
        GspShipmentPackageItem.package_id.in_(package_ids)
    ):
        packed[item.allocation_id] = packed.get(item.allocation_id, Decimal("0")) + Decimal(item.quantity)
    for allocation in _allocations(db, order.id):
        if packed.get(allocation.id, Decimal("0")) != Decimal(allocation.quantity):
            raise WorkflowError(409, "逐箱包装数量与批次分配数量不一致")


def _qualified_customer_and_products(
    db: Session,
    *,
    customer_id: int,
    goods_ids: set[int],
) -> tuple[GspBusinessPartner, dict[int, GspDrugProfile]]:
    customer = (
        db.query(GspBusinessPartner)
        .filter(GspBusinessPartner.id == customer_id)
        .first()
    )
    if not customer or customer.partner_type not in {"CUSTOMER", "BOTH"}:
        raise WorkflowError(409, "销售订单必须关联已建档的购货方")
    customer_result = evaluate_partner_evidence(db, customer)
    profiles = {
        profile.goods_id: profile
        for profile in db.query(GspDrugProfile)
        .filter(GspDrugProfile.goods_id.in_(goods_ids))
        .all()
    }
    findings = _finding_dicts(customer_result)
    for goods_id in sorted(goods_ids):
        profile = profiles.get(goods_id)
        if not profile:
            findings.append(
                {
                    "code": "PRODUCT_PROFILE_MISSING",
                    "message": f"货物 {goods_id} 缺少药品质量主数据",
                }
            )
            continue
        findings.extend(
            _finding_dicts(
                evaluate_product(
                    status=profile.status,
                    registration_valid_to=profile.registration_valid_to,
                    registration_document_ref=profile.registration_document_ref,
                    nmpa_verification_ref=profile.nmpa_verification_ref,
                )
            )
        )
    if findings:
        raise WorkflowError(409, "购货方或经营品种不满足 GSP 销售条件", findings)
    return customer, profiles


def _revalidate_order(
    db: Session,
    order: GspSalesOrder,
) -> tuple[GspBusinessPartner, dict[int, GspDrugProfile]]:
    items = _order_items(db, order.id)
    if not items:
        raise WorkflowError(409, "销售订单没有明细")
    return _qualified_customer_and_products(
        db,
        customer_id=order.customer_id,
        goods_ids={item.goods_id for item in items},
    )


def create_sales_order(
    db: Session,
    *,
    payload: SalesOrderCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspSalesOrder:
    warehouse = db.query(Warehouse).filter(Warehouse.id == payload.warehouse_id).first()
    if not warehouse or not warehouse.is_active:
        raise WorkflowError(422, "销售订单必须指定启用的仓库")
    goods_ids = [item.goods_id for item in payload.items]
    if len(goods_ids) != len(set(goods_ids)):
        raise WorkflowError(422, "同一销售订单中同一品种只能出现一次")
    _qualified_customer_and_products(
        db,
        customer_id=payload.customer_id,
        goods_ids=set(goods_ids),
    )
    order = GspSalesOrder(
        order_no=payload.order_no,
        customer_id=payload.customer_id,
        warehouse_id=payload.warehouse_id,
        ordered_on=payload.ordered_on,
        status="DRAFT",
        created_by=actor_id,
    )
    db.add(order)
    db.flush()
    for line_no, line in enumerate(payload.items, start=1):
        db.add(
            GspSalesOrderItem(
                sales_order_id=order.id,
                line_no=line_no,
                goods_id=line.goods_id,
                ordered_quantity=line.quantity,
                allocated_quantity=Decimal("0"),
                shipped_quantity=Decimal("0"),
                unit=line.unit,
                minimum_remaining_days=line.minimum_remaining_days,
            )
        )
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="SALES_ORDER_CREATED",
        entity_type="GspSalesOrder",
        entity_id=str(order.id),
        reason=payload.reason,
        after_data=sales_order_payload(db, order),
        source_ip=source_ip,
    )
    return order


def submit_sales_order(
    db: Session,
    *,
    order_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspSalesOrder:
    order = db.query(GspSalesOrder).filter(GspSalesOrder.id == order_id).first()
    if not order:
        raise WorkflowError(404, "销售订单不存在")
    if order.status != "DRAFT":
        raise WorkflowError(409, "只有草稿销售订单可以提交")
    _revalidate_order(db, order)
    before = sales_order_payload(db, order)
    order.status = "SUBMITTED"
    order.submitted_by = actor_id
    order.submitted_at = utc_now()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="SALES_ORDER_SUBMITTED",
        entity_type="GspSalesOrder",
        entity_id=str(order.id),
        reason=reason,
        before_data=before,
        after_data=sales_order_payload(db, order),
        source_ip=source_ip,
    )
    return order


def approve_sales_order(
    db: Session,
    *,
    order_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspSalesOrder:
    order = db.query(GspSalesOrder).filter(GspSalesOrder.id == order_id).first()
    if not order:
        raise WorkflowError(404, "销售订单不存在")
    if order.status != "SUBMITTED":
        raise WorkflowError(409, "只有已提交销售订单可以质量审批")
    if actor_id in {order.created_by, order.submitted_by}:
        raise WorkflowError(409, "销售制单/提交人与质量审批人必须分离")
    _revalidate_order(db, order)
    before = sales_order_payload(db, order)
    order.status = "APPROVED"
    order.quality_approved_by = actor_id
    order.quality_approved_at = utc_now()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="SALES_ORDER_APPROVED",
        entity_type="GspSalesOrder",
        entity_id=str(order.id),
        reason=reason,
        before_data=before,
        after_data=sales_order_payload(db, order),
        source_ip=source_ip,
    )
    return order


def allocate_sales_order(
    db: Session,
    *,
    order_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspSalesOrder:
    order = (
        db.query(GspSalesOrder)
        .filter(GspSalesOrder.id == order_id)
        .with_for_update()
        .first()
    )
    if not order:
        raise WorkflowError(404, "销售订单不存在")
    if order.status != "APPROVED":
        raise WorkflowError(409, "只有质量批准的销售订单可以分配批号")
    _, profiles = _revalidate_order(db, order)
    before = sales_order_payload(db, order)
    complete_plan: list[tuple[GspSalesOrderItem, GspBatchStock, GspDrugBatch, Decimal]] = []

    for item in _order_items(db, order.id):
        candidates = (
            db.query(GspBatchStock, GspDrugBatch)
            .join(GspDrugBatch, GspDrugBatch.id == GspBatchStock.batch_id)
            .filter(
                GspBatchStock.warehouse_id == order.warehouse_id,
                GspBatchStock.stock_status == "AVAILABLE",
                GspDrugBatch.goods_id == item.goods_id,
            )
            .order_by(GspDrugBatch.expiry_date, GspDrugBatch.id, GspBatchStock.location_id)
            .with_for_update()
            .all()
        )
        remaining = Decimal(item.ordered_quantity)
        line_plan: list[tuple[GspSalesOrderItem, GspBatchStock, GspDrugBatch, Decimal]] = []
        profile = profiles[item.goods_id]
        for stock, batch in candidates:
            active_hold = (
                db.query(GspQualityHold)
                .filter(
                    GspQualityHold.batch_id == batch.id,
                    GspQualityHold.status == "ACTIVE",
                )
                .count()
                > 0
            )
            result = evaluate_batch(
                status=batch.status,
                expiry_date=batch.expiry_date,
                has_active_hold=active_hold,
                traceability_required=profile.traceability_required,
                traceability_code=batch.traceability_code,
                minimum_remaining_days=item.minimum_remaining_days,
            )
            if not result.qualified:
                continue
            available = Decimal(stock.quantity) - Decimal(stock.reserved_quantity or 0)
            if available <= 0:
                continue
            quantity = min(available, remaining)
            line_plan.append((item, stock, batch, quantity))
            remaining -= quantity
            if remaining == 0:
                break
        if remaining > 0:
            raise WorkflowError(
                409,
                f"销售订单第 {item.line_no} 行没有足够的合格批次库存",
                [
                    {
                        "code": "INSUFFICIENT_ELIGIBLE_BATCH_STOCK",
                        "message": f"缺少数量 {remaining}",
                    }
                ],
            )
        complete_plan.extend(line_plan)

    for item, stock, batch, quantity in complete_plan:
        ensure_stock_not_frozen(db, [stock.id])
        stock.reserved_quantity = Decimal(stock.reserved_quantity or 0) + quantity
        stock.lock_version += 1
        db.add(
            GspStockAllocation(
                sales_order_item_id=item.id,
                batch_stock_id=stock.id,
                batch_id=batch.id,
                location_id=stock.location_id,
                quantity=quantity,
                status="ALLOCATED",
            )
        )
        item.allocated_quantity += quantity
    order.status = "ALLOCATED"
    order.allocated_by = actor_id
    order.allocated_at = utc_now()
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="SALES_ORDER_FEFO_ALLOCATED",
        entity_type="GspSalesOrder",
        entity_id=str(order.id),
        reason=reason,
        before_data=before,
        after_data=sales_order_payload(db, order),
        source_ip=source_ip,
    )
    return order


def mark_sales_order_picked(
    db: Session,
    *,
    order_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspSalesOrder:
    order = db.query(GspSalesOrder).filter(GspSalesOrder.id == order_id).first()
    if not order:
        raise WorkflowError(404, "销售订单不存在")
    if order.status != "ALLOCATED":
        raise WorkflowError(409, "只有完成批号分配的销售订单可以确认拣货")
    allocations = _allocations(db, order.id)
    if not allocations:
        raise WorkflowError(409, "销售订单没有批次分配记录")
    _validate_allocations(
        db,
        order=order,
        lock_stock=False,
        expected_status="ALLOCATED",
    )
    before = sales_order_payload(db, order)
    picked_at = utc_now()
    for allocation in allocations:
        allocation.status = "PICKED"
        allocation.picked_by = actor_id
        allocation.picked_at = picked_at
    order.status = "PICKED"
    order.picked_by = actor_id
    order.picked_at = picked_at
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="SALES_ORDER_PICKED",
        entity_type="GspSalesOrder",
        entity_id=str(order.id),
        reason=reason,
        before_data=before,
        after_data=sales_order_payload(db, order),
        source_ip=source_ip,
    )
    return order


def prepare_shipment(
    db: Session,
    *,
    order_id: int,
    payload: ShipmentPrepare,
    actor_id: int,
    source_ip: str | None,
) -> GspShipment:
    order = db.query(GspSalesOrder).filter(GspSalesOrder.id == order_id).first()
    if not order:
        raise WorkflowError(404, "销售订单不存在")
    if order.status != "PICKED":
        raise WorkflowError(409, "只有完成拣货的销售订单可以准备发运")
    _validate_allocations(
        db,
        order=order,
        lock_stock=False,
        expected_status="PICKED",
    )
    if payload.transport_mode not in {"NORMAL", "COLD", "FROZEN"}:
        raise WorkflowError(422, "transport_mode 只能是 NORMAL、COLD 或 FROZEN")
    carrier, vehicle, driver = validate_transport_resources(
        db,
        carrier_id=payload.carrier_id,
        vehicle_id=payload.vehicle_id,
        driver_id=payload.driver_id,
        transport_mode=payload.transport_mode,
    )
    _, profiles = _revalidate_order(db, order)
    requires_cold_chain = any(
        profile.storage_condition in {"COLD", "FROZEN"} for profile in profiles.values()
    )
    if requires_cold_chain and (
        payload.transport_mode not in {"COLD", "FROZEN"}
        or not payload.temperature_record_ref
    ):
        raise WorkflowError(409, "冷链药品必须配置冷链运输方式、车辆和温度记录")
    shipment = GspShipment(
        shipment_no=payload.shipment_no,
        sales_order_id=order.id,
        carrier_id=carrier.id,
        vehicle_id=vehicle.id,
        driver_id=driver.id,
        carrier_name=carrier.name,
        vehicle_no=vehicle.vehicle_no,
        driver_name=driver.name,
        transport_mode=payload.transport_mode,
        temperature_record_ref=payload.temperature_record_ref,
        status="PREPARED",
        prepared_by=actor_id,
    )
    db.add(shipment)
    order.status = "PREPARED"
    db.flush()
    create_transport_task(
        db,
        shipment=shipment,
        carrier=carrier,
        vehicle=vehicle,
        driver=driver,
        route_plan_ref=payload.route_plan_ref,
        handover_document_no=payload.handover_document_no,
        expected_arrival_at=payload.expected_arrival_at,
        actor_id=actor_id,
        reason=payload.reason,
        source_ip=source_ip,
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="SHIPMENT_PREPARED",
        entity_type="GspShipment",
        entity_id=str(shipment.id),
        reason=payload.reason,
        after_data=shipment_payload(shipment),
        source_ip=source_ip,
    )
    return shipment


def _validate_allocations(
    db: Session,
    *,
    order: GspSalesOrder,
    lock_stock: bool,
    expected_status: str,
) -> list[tuple[GspStockAllocation, GspBatchStock, GspDrugBatch, GspSalesOrderItem]]:
    _, profiles = _revalidate_order(db, order)
    item_map = {item.id: item for item in _order_items(db, order.id)}
    validated = []
    for allocation in _allocations(db, order.id):
        if allocation.status != expected_status:
            raise WorkflowError(409, "批次分配状态与当前出库步骤不一致")
        stock_query = db.query(GspBatchStock).filter(
            GspBatchStock.id == allocation.batch_stock_id
        )
        if lock_stock:
            stock_query = stock_query.with_for_update()
        stock = stock_query.first()
        batch = db.query(GspDrugBatch).filter(GspDrugBatch.id == allocation.batch_id).first()
        item = item_map[allocation.sales_order_item_id]
        if not stock or not batch:
            raise WorkflowError(409, "批次库存或批次主数据缺失")
        active_hold = (
            db.query(GspQualityHold)
            .filter(
                GspQualityHold.batch_id == batch.id,
                GspQualityHold.status == "ACTIVE",
            )
            .count()
            > 0
        )
        result = evaluate_batch(
            status=batch.status,
            expiry_date=batch.expiry_date,
            has_active_hold=active_hold,
            traceability_required=profiles[item.goods_id].traceability_required,
            traceability_code=batch.traceability_code,
            minimum_remaining_days=item.minimum_remaining_days,
        )
        if not result.qualified:
            raise WorkflowError(
                409,
                f"批次 {batch.batch_no} 不满足出库条件",
                _finding_dicts(result),
            )
        if stock.stock_status != "AVAILABLE":
            raise WorkflowError(409, f"批次 {batch.batch_no} 库存当前不可用")
        if (
            Decimal(stock.quantity) < Decimal(allocation.quantity)
            or Decimal(stock.reserved_quantity or 0) < Decimal(allocation.quantity)
        ):
            raise WorkflowError(409, f"批次 {batch.batch_no} 的库存或预留数量不足")
        validated.append((allocation, stock, batch, item))
    return validated


def review_shipment(
    db: Session,
    *,
    shipment_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspShipment:
    shipment = db.query(GspShipment).filter(GspShipment.id == shipment_id).first()
    if not shipment:
        raise WorkflowError(404, "发运单不存在")
    order = (
        db.query(GspSalesOrder)
        .filter(GspSalesOrder.id == shipment.sales_order_id)
        .first()
    )
    if shipment.status != "PREPARED" or order.status != "PREPARED":
        raise WorkflowError(409, "只有已准备的发运单可以出库复核")
    if order.picked_by == actor_id or shipment.prepared_by == actor_id:
        raise WorkflowError(409, "拣货/发运准备人与出库复核人必须分离")
    _validate_allocations(
        db,
        order=order,
        lock_stock=False,
        expected_status="PICKED",
    )
    _validate_shipment_packages(db, shipment, order, actor_id)
    before = shipment_payload(shipment)
    reviewed_at = utc_now()
    for allocation in _allocations(db, order.id):
        allocation.status = "REVIEWED"
        allocation.reviewed_by = actor_id
        allocation.reviewed_at = reviewed_at
    shipment.status = "REVIEWED"
    shipment.reviewed_by = actor_id
    shipment.reviewed_at = reviewed_at
    order.status = "REVIEWED"
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="SHIPMENT_OUTBOUND_REVIEWED",
        entity_type="GspShipment",
        entity_id=str(shipment.id),
        reason=reason,
        before_data=before,
        after_data=shipment_payload(shipment),
        source_ip=source_ip,
    )
    return shipment


def dispatch_shipment(
    db: Session,
    *,
    shipment_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspShipment:
    shipment = (
        db.query(GspShipment)
        .filter(GspShipment.id == shipment_id)
        .with_for_update()
        .first()
    )
    if not shipment:
        raise WorkflowError(404, "发运单不存在")
    order = (
        db.query(GspSalesOrder)
        .filter(GspSalesOrder.id == shipment.sales_order_id)
        .with_for_update()
        .first()
    )
    if shipment.status != "REVIEWED" or order.status != "REVIEWED":
        raise WorkflowError(409, "只有通过出库复核的发运单可以发运")
    start_transport_task(
        db,
        shipment=shipment,
        actor_id=actor_id,
        reason=reason,
        source_ip=source_ip,
    )
    validated = _validate_allocations(
        db,
        order=order,
        lock_stock=True,
        expected_status="REVIEWED",
    )
    before = shipment_payload(shipment)
    dispatched_at = utc_now()
    for allocation, stock, _batch, item in validated:
        quantity = Decimal(allocation.quantity)
        ensure_stock_not_frozen(db, [stock.id])
        stock.quantity -= quantity
        stock.reserved_quantity -= quantity
        stock.lock_version += 1
        allocation.status = "SHIPPED"
        allocation.shipped_at = dispatched_at
        item.shipped_quantity += quantity
    shipment.status = "DISPATCHED"
    shipment.dispatched_by = actor_id
    shipment.dispatched_at = dispatched_at
    order.status = "SHIPPED"
    db.flush()
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="SHIPMENT_CONFIRMED",
        aggregate_type="GspShipment",
        aggregate_id=str(shipment.id),
        payload={
            "shipment": shipment_payload(shipment),
            "sales_order": sales_order_payload(db, order),
        },
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="SHIPMENT_DISPATCHED",
        entity_type="GspShipment",
        entity_id=str(shipment.id),
        reason=reason,
        before_data=before,
        after_data=shipment_payload(shipment),
        source_ip=source_ip,
    )
    return shipment


def cancel_sales_order(
    db: Session,
    *,
    order_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspSalesOrder:
    order = (
        db.query(GspSalesOrder)
        .filter(GspSalesOrder.id == order_id)
        .with_for_update()
        .first()
    )
    if not order:
        raise WorkflowError(404, "销售订单不存在")
    if order.status in {"SHIPPED", "CANCELLED"}:
        raise WorkflowError(409, "已发运或已取消的销售订单不能再次取消")
    before = sales_order_payload(db, order)
    for allocation in _allocations(db, order.id):
        if allocation.status == "SHIPPED":
            raise WorkflowError(409, "存在已发运分配，不能取消销售订单")
        stock = (
            db.query(GspBatchStock)
            .filter(GspBatchStock.id == allocation.batch_stock_id)
            .with_for_update()
            .first()
        )
        if allocation.status != "RELEASED":
            ensure_stock_not_frozen(db, [stock.id])
            stock.reserved_quantity = max(
                Decimal("0"),
                Decimal(stock.reserved_quantity or 0) - Decimal(allocation.quantity),
            )
            stock.lock_version += 1
            allocation.status = "RELEASED"
    shipment = db.query(GspShipment).filter(GspShipment.sales_order_id == order.id).first()
    if shipment:
        shipment.status = "CANCELLED"
    order.status = "CANCELLED"
    order.cancelled_by = actor_id
    order.cancelled_at = utc_now()
    order.cancellation_reason = reason
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="SALES_ORDER_CANCELLED",
        entity_type="GspSalesOrder",
        entity_id=str(order.id),
        reason=reason,
        before_data=before,
        after_data=sales_order_payload(db, order),
        source_ip=source_ip,
    )
    return order

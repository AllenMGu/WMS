"""Transactional application service for controlled procurement and receipt."""

from __future__ import annotations

import hashlib
import json
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
from app.gsp.procurement_receiving.models import (
    GspControlledPrintRecord,
    GspPurchaseOrder,
    GspPurchaseOrderItem,
    GspReceipt,
    GspReceiptItem,
)
from app.gsp.procurement_receiving.schemas import (
    ControlledPrintCreate,
    PurchaseOrderCreate,
    ReceiptCreate,
    ReceiptInspection,
    ReceiptSampling,
)
from app.gsp.qualification import evaluate_partner_evidence
from app.gsp.quality_disposition.service import register_rejected_material
from app.gsp.rules import evaluate_product
from app.gsp.snapshots import model_snapshot
from app.gsp.stocktaking.service import ensure_stock_not_frozen
from app.legacy import Location, Warehouse


def _finding_dicts(result) -> list[dict]:
    return [{"code": item.code, "message": item.message} for item in result.findings]


def _order_items(db: Session, order_id: int) -> list[GspPurchaseOrderItem]:
    return (
        db.query(GspPurchaseOrderItem)
        .filter(GspPurchaseOrderItem.purchase_order_id == order_id)
        .order_by(GspPurchaseOrderItem.line_no)
        .all()
    )


def _receipt_items(db: Session, receipt_id: int) -> list[GspReceiptItem]:
    return (
        db.query(GspReceiptItem)
        .filter(GspReceiptItem.receipt_id == receipt_id)
        .order_by(GspReceiptItem.id)
        .all()
    )


def order_payload(db: Session, order: GspPurchaseOrder) -> dict:
    result = model_snapshot(order)
    result["items"] = [model_snapshot(item) for item in _order_items(db, order.id)]
    return result


def receipt_payload(db: Session, receipt: GspReceipt) -> dict:
    result = model_snapshot(receipt)
    result["items"] = [model_snapshot(item) for item in _receipt_items(db, receipt.id)]
    return result


def _qualified_master_data(
    db: Session,
    *,
    supplier_id: int,
    goods_ids: set[int],
) -> tuple[GspBusinessPartner, dict[int, GspDrugProfile]]:
    supplier = (
        db.query(GspBusinessPartner)
        .filter(GspBusinessPartner.id == supplier_id)
        .first()
    )
    if not supplier or supplier.partner_type not in {"SUPPLIER", "BOTH"}:
        raise WorkflowError(409, "采购订单必须关联已建档的供货方")

    supplier_result = evaluate_partner_evidence(db, supplier)
    profiles = {
        profile.goods_id: profile
        for profile in db.query(GspDrugProfile)
        .filter(GspDrugProfile.goods_id.in_(goods_ids))
        .all()
    }
    findings = _finding_dicts(supplier_result)
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
        result = evaluate_product(
            status=profile.status,
            registration_valid_to=profile.registration_valid_to,
            registration_document_ref=profile.registration_document_ref,
            nmpa_verification_ref=profile.nmpa_verification_ref,
        )
        findings.extend(_finding_dicts(result))
    if findings:
        raise WorkflowError(409, "供货方或经营品种不满足 GSP 采购条件", findings)
    return supplier, profiles


def create_purchase_order(
    db: Session,
    *,
    payload: PurchaseOrderCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspPurchaseOrder:
    warehouse = db.query(Warehouse).filter(Warehouse.id == payload.warehouse_id).first()
    if not warehouse or not warehouse.is_active:
        raise WorkflowError(422, "采购订单必须指定启用的仓库")
    goods_ids = [item.goods_id for item in payload.items]
    if len(goods_ids) != len(set(goods_ids)):
        raise WorkflowError(422, "同一采购订单中同一品种只能出现一次")
    _qualified_master_data(db, supplier_id=payload.supplier_id, goods_ids=set(goods_ids))

    order = GspPurchaseOrder(
        order_no=payload.order_no,
        supplier_id=payload.supplier_id,
        warehouse_id=payload.warehouse_id,
        ordered_on=payload.ordered_on,
        status="DRAFT",
        created_by=actor_id,
    )
    db.add(order)
    db.flush()
    for line_no, item in enumerate(payload.items, start=1):
        db.add(
            GspPurchaseOrderItem(
                purchase_order_id=order.id,
                line_no=line_no,
                goods_id=item.goods_id,
                ordered_quantity=item.quantity,
                received_quantity=Decimal("0"),
                unit=item.unit,
            )
        )
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="PURCHASE_ORDER_CREATED",
        entity_type="GspPurchaseOrder",
        entity_id=str(order.id),
        reason=payload.reason,
        after_data=order_payload(db, order),
        source_ip=source_ip,
    )
    return order


def submit_purchase_order(
    db: Session,
    *,
    order_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspPurchaseOrder:
    order = db.query(GspPurchaseOrder).filter(GspPurchaseOrder.id == order_id).first()
    if not order:
        raise WorkflowError(404, "采购订单不存在")
    if order.status != "DRAFT":
        raise WorkflowError(409, "只有草稿采购订单可以提交")
    items = _order_items(db, order.id)
    _qualified_master_data(
        db,
        supplier_id=order.supplier_id,
        goods_ids={item.goods_id for item in items},
    )
    before = order_payload(db, order)
    order.status = "SUBMITTED"
    order.submitted_by = actor_id
    order.submitted_at = utc_now()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="PURCHASE_ORDER_SUBMITTED",
        entity_type="GspPurchaseOrder",
        entity_id=str(order.id),
        reason=reason,
        before_data=before,
        after_data=order_payload(db, order),
        source_ip=source_ip,
    )
    return order


def approve_purchase_order(
    db: Session,
    *,
    order_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None,
) -> GspPurchaseOrder:
    order = db.query(GspPurchaseOrder).filter(GspPurchaseOrder.id == order_id).first()
    if not order:
        raise WorkflowError(404, "采购订单不存在")
    if order.status != "SUBMITTED":
        raise WorkflowError(409, "只有已提交采购订单可以质量审批")
    if order.created_by == actor_id or order.submitted_by == actor_id:
        raise WorkflowError(409, "采购订单制单/提交人与质量审批人必须分离")
    items = _order_items(db, order.id)
    _qualified_master_data(
        db,
        supplier_id=order.supplier_id,
        goods_ids={item.goods_id for item in items},
    )
    before = order_payload(db, order)
    order.status = "APPROVED"
    order.quality_approved_by = actor_id
    order.quality_approved_at = utc_now()
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="PURCHASE_ORDER_APPROVED",
        aggregate_type="GspPurchaseOrder",
        aggregate_id=str(order.id),
        payload=order_payload(db, order),
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="PURCHASE_ORDER_APPROVED",
        entity_type="GspPurchaseOrder",
        entity_id=str(order.id),
        reason=reason,
        before_data=before,
        after_data=order_payload(db, order),
        source_ip=source_ip,
    )
    return order


def create_receipt(
    db: Session,
    *,
    payload: ReceiptCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspReceipt:
    order = (
        db.query(GspPurchaseOrder)
        .filter(GspPurchaseOrder.id == payload.purchase_order_id)
        .with_for_update()
        .first()
    )
    if not order:
        raise WorkflowError(404, "采购订单不存在")
    if order.status not in {"APPROVED", "PARTIALLY_RECEIVED"}:
        raise WorkflowError(409, "只有质量批准且未收完的采购订单可以收货")
    requested_item_ids = [item.purchase_order_item_id for item in payload.items]
    if len(requested_item_ids) != len(set(requested_item_ids)):
        raise WorkflowError(422, "同一收货单不能重复引用采购订单明细")

    order_items = {item.id: item for item in _order_items(db, order.id)}
    _qualified_master_data(
        db,
        supplier_id=order.supplier_id,
        goods_ids={item.goods_id for item in order_items.values()},
    )
    receipt = GspReceipt(
        receipt_no=payload.receipt_no,
        purchase_order_id=order.id,
        delivery_document_no=payload.delivery_document_no,
        arrived_at=payload.arrived_at,
        status="PENDING_INSPECTION",
        received_by=actor_id,
    )
    db.add(receipt)
    db.flush()

    for line in payload.items:
        order_item = order_items.get(line.purchase_order_item_id)
        if not order_item:
            raise WorkflowError(422, "收货明细不属于指定采购订单")
        remaining = order_item.ordered_quantity - order_item.received_quantity
        if line.quantity > remaining:
            raise WorkflowError(409, f"采购订单第 {order_item.line_no} 行收货数量超过未收数量")
        if line.expiry_date <= line.production_date:
            raise WorkflowError(422, "有效期必须晚于生产日期")
        location = db.query(Location).filter(Location.id == line.location_id).first()
        if not location or not location.is_active or location.warehouse_id != order.warehouse_id:
            raise WorkflowError(422, "待验库位必须属于采购订单指定的启用仓库")

        profile = db.query(GspDrugProfile).filter(GspDrugProfile.goods_id == order_item.goods_id).first()
        if profile.traceability_required and not line.traceability_code:
            raise WorkflowError(409, "该品种收货时必须采集药品追溯信息")
        if profile.storage_condition in {"COLD", "FROZEN"} and not line.temperature_record_ref:
            raise WorkflowError(409, "冷藏/冷冻药品收货时必须关联运输温度记录")

        batch = (
            db.query(GspDrugBatch)
            .filter(
                GspDrugBatch.goods_id == order_item.goods_id,
                GspDrugBatch.batch_no == line.batch_no,
            )
            .first()
        )
        if batch:
            if (
                batch.supplier_id != order.supplier_id
                or batch.production_date != line.production_date
                or batch.expiry_date != line.expiry_date
            ):
                raise WorkflowError(409, "同品种同批号的供货方或生产/有效期信息不一致")
            if not batch.traceability_code:
                batch.traceability_code = line.traceability_code
        else:
            batch = GspDrugBatch(
                goods_id=order_item.goods_id,
                batch_no=line.batch_no,
                production_date=line.production_date,
                expiry_date=line.expiry_date,
                supplier_id=order.supplier_id,
                receipt_document_no=payload.delivery_document_no,
                inspection_report_no=line.inspection_report_no,
                traceability_code=line.traceability_code,
                arrival_temperature=float(line.arrival_temperature)
                if line.arrival_temperature is not None
                else None,
                transport_temperature_min=float(line.transport_temperature_min)
                if line.transport_temperature_min is not None
                else None,
                transport_temperature_max=float(line.transport_temperature_max)
                if line.transport_temperature_max is not None
                else None,
                temperature_record_ref=line.temperature_record_ref,
                status="PENDING_INSPECTION",
                created_by=actor_id,
            )
            db.add(batch)
            db.flush()

        db.add(
            GspReceiptItem(
                receipt_id=receipt.id,
                purchase_order_item_id=order_item.id,
                batch_id=batch.id,
                location_id=line.location_id,
                received_quantity=line.quantity,
                accepted_quantity=Decimal("0"),
                rejected_quantity=Decimal("0"),
                inspection_status="PENDING",
                inspection_report_no=line.inspection_report_no,
                traceability_code=line.traceability_code,
                arrival_temperature=line.arrival_temperature,
                transport_temperature_min=line.transport_temperature_min,
                transport_temperature_max=line.transport_temperature_max,
                temperature_record_ref=line.temperature_record_ref,
            )
        )
        order_item.received_quantity += line.quantity

    db.flush()
    all_received = all(
        item.received_quantity == item.ordered_quantity for item in order_items.values()
    )
    order.status = "RECEIVED" if all_received else "PARTIALLY_RECEIVED"
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="PURCHASE_RECEIPT_RECORDED",
        aggregate_type="GspReceipt",
        aggregate_id=str(receipt.id),
        payload=receipt_payload(db, receipt),
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="PURCHASE_RECEIPT_RECORDED",
        entity_type="GspReceipt",
        entity_id=str(receipt.id),
        reason=payload.reason,
        after_data=receipt_payload(db, receipt),
        source_ip=source_ip,
    )
    return receipt


def inspect_receipt_item(
    db: Session,
    *,
    receipt_id: int,
    item_id: int,
    payload: ReceiptInspection,
    actor_id: int,
    source_ip: str | None,
) -> GspReceipt:
    receipt = db.query(GspReceipt).filter(GspReceipt.id == receipt_id).first()
    if not receipt:
        raise WorkflowError(404, "收货单不存在")
    if receipt.received_by == actor_id:
        raise WorkflowError(409, "收货人与验收人必须分离")
    item = (
        db.query(GspReceiptItem)
        .filter(GspReceiptItem.id == item_id, GspReceiptItem.receipt_id == receipt.id)
        .with_for_update()
        .first()
    )
    if not item:
        raise WorkflowError(404, "收货明细不存在")
    if item.inspection_status != "PENDING":
        raise WorkflowError(409, "该收货明细已经完成验收")
    if (
        not item.sampling_plan_ref
        or not item.sampling_method
        or not item.sampling_record_no
        or item.sample_quantity is None
        or item.sampled_by is None
    ):
        raise WorkflowError(409, "必须先按批准的抽样方案完成抽样记录")
    if payload.accepted_quantity + payload.rejected_quantity != item.received_quantity:
        raise WorkflowError(422, "合格数量与拒收数量之和必须等于收货数量")

    batch = db.query(GspDrugBatch).filter(GspDrugBatch.id == item.batch_id).first()
    order_item = (
        db.query(GspPurchaseOrderItem)
        .filter(GspPurchaseOrderItem.id == item.purchase_order_item_id)
        .first()
    )
    order = (
        db.query(GspPurchaseOrder)
        .filter(GspPurchaseOrder.id == order_item.purchase_order_id)
        .first()
    )
    profile = (
        db.query(GspDrugProfile)
        .filter(GspDrugProfile.goods_id == order_item.goods_id)
        .first()
    )
    _qualified_master_data(
        db,
        supplier_id=order.supplier_id,
        goods_ids={order_item.goods_id},
    )
    if payload.accepted_quantity > 0 and not item.inspection_report_no:
        raise WorkflowError(409, "缺少检验报告书编号，不能判定合格")
    if profile.traceability_required and not item.traceability_code:
        raise WorkflowError(409, "缺少法规要求的药品追溯信息")
    if profile.storage_condition in {"COLD", "FROZEN"}:
        if (
            item.transport_temperature_min is None
            or item.transport_temperature_max is None
            or not item.temperature_record_ref
        ):
            raise WorkflowError(409, "冷藏/冷冻药品缺少完整运输温度证据")
        if (
            profile.min_temperature is not None
            and item.transport_temperature_min < Decimal(str(profile.min_temperature))
        ):
            raise WorkflowError(409, "运输最低温度超出品种允许范围")
        if (
            profile.max_temperature is not None
            and item.transport_temperature_max > Decimal(str(profile.max_temperature))
        ):
            raise WorkflowError(409, "运输最高温度超出品种允许范围")

    before = model_snapshot(item)
    item.accepted_quantity = payload.accepted_quantity
    item.rejected_quantity = payload.rejected_quantity
    item.inspection_conclusion = payload.conclusion
    item.inspected_by = actor_id
    item.inspected_at = utc_now()
    if payload.accepted_quantity == item.received_quantity:
        item.inspection_status = "ACCEPTED"
    elif payload.rejected_quantity == item.received_quantity:
        item.inspection_status = "REJECTED"
    else:
        item.inspection_status = "PARTIALLY_ACCEPTED"

    if payload.rejected_quantity > 0:
        register_rejected_material(
            db,
            record_no=f"NC-RCV-{item.id}",
            source_type="RECEIPT_REJECTION",
            source_entity_type="GspReceiptItem",
            source_entity_id=item.id,
            batch_id=item.batch_id,
            warehouse_id=order.warehouse_id,
            location_id=item.location_id,
            quantity=payload.rejected_quantity,
            reason_code="RECEIPT_REJECTED",
            description=payload.conclusion,
            proposed_disposition=None,
            actor_id=actor_id,
            source_ip=source_ip,
        )

    if payload.accepted_quantity > 0:
        active_hold = (
            db.query(GspQualityHold)
            .filter(
                GspQualityHold.batch_id == batch.id,
                GspQualityHold.status == "ACTIVE",
            )
            .count()
            > 0
        )
        stock = (
            db.query(GspBatchStock)
            .filter(
                GspBatchStock.batch_id == batch.id,
                GspBatchStock.warehouse_id == order.warehouse_id,
                GspBatchStock.location_id == item.location_id,
            )
            .with_for_update()
            .first()
        )
        if stock:
            ensure_stock_not_frozen(db, [stock.id])
            stock.quantity += payload.accepted_quantity
            stock.stock_status = "HOLD" if active_hold else "AVAILABLE"
            stock.lock_version += 1
        else:
            stock = GspBatchStock(
                batch_id=batch.id,
                warehouse_id=order.warehouse_id,
                location_id=item.location_id,
                quantity=payload.accepted_quantity,
                stock_status="HOLD" if active_hold else "AVAILABLE",
            )
            db.add(stock)
        batch.status = "RELEASED"
        batch.accepted_by = actor_id
        batch.accepted_at = item.inspected_at
        batch.acceptance_conclusion = payload.conclusion
    elif db.query(GspBatchStock).filter(GspBatchStock.batch_id == batch.id).count() == 0:
        batch.status = "REJECTED"

    db.flush()
    pending_items = (
        db.query(GspReceiptItem)
        .filter(
            GspReceiptItem.receipt_id == receipt.id,
            GspReceiptItem.inspection_status == "PENDING",
        )
        .count()
    )
    receipt.status = "COMPLETED" if pending_items == 0 else "INSPECTION_IN_PROGRESS"
    db.flush()
    if order.status == "RECEIVED":
        unfinished_receipts = (
            db.query(GspReceipt)
            .filter(
                GspReceipt.purchase_order_id == order.id,
                GspReceipt.status != "COMPLETED",
            )
            .count()
        )
        if unfinished_receipts == 0:
            order.status = "COMPLETED"

    event_type = (
        "RECEIPT_ITEM_ACCEPTED"
        if payload.rejected_quantity == 0
        else "RECEIPT_ITEM_INSPECTED_WITH_REJECTION"
    )
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type=event_type,
        aggregate_type="GspReceiptItem",
        aggregate_id=str(item.id),
        payload=model_snapshot(item),
    )
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action=event_type,
        entity_type="GspReceiptItem",
        entity_id=str(item.id),
        reason=payload.reason,
        before_data=before,
        after_data=model_snapshot(item),
        source_ip=source_ip,
    )
    return receipt


def record_receipt_sampling(
    db: Session,
    *,
    receipt_id: int,
    item_id: int,
    payload: ReceiptSampling,
    actor_id: int,
    source_ip: str | None,
) -> GspReceipt:
    receipt = db.query(GspReceipt).filter(GspReceipt.id == receipt_id).first()
    if receipt is None:
        raise WorkflowError(404, "收货单不存在")
    if receipt.received_by == actor_id:
        raise WorkflowError(409, "收货人与抽样人员必须分离")
    item = (
        db.query(GspReceiptItem)
        .filter(GspReceiptItem.id == item_id, GspReceiptItem.receipt_id == receipt.id)
        .with_for_update()
        .first()
    )
    if item is None:
        raise WorkflowError(404, "收货明细不存在")
    if item.inspection_status != "PENDING":
        raise WorkflowError(409, "已完成验收的明细不能补录抽样")
    if payload.sample_quantity > item.received_quantity:
        raise WorkflowError(422, "抽样数量不能超过收货数量")
    before = model_snapshot(item)
    item.sampling_plan_ref = payload.sampling_plan_ref
    item.sampling_method = payload.sampling_method
    item.sample_quantity = payload.sample_quantity
    item.sampling_record_no = payload.sampling_record_no
    item.sampled_by = actor_id
    item.sampled_at = utc_now()
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="RECEIPT_ITEM_SAMPLED",
        entity_type="GspReceiptItem",
        entity_id=str(item.id),
        reason=payload.reason,
        before_data=before,
        after_data=model_snapshot(item),
        source_ip=source_ip,
    )
    return receipt


def create_receipt_print_record(
    db: Session,
    *,
    receipt_id: int,
    payload: ControlledPrintCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspControlledPrintRecord:
    receipt = db.query(GspReceipt).filter(GspReceipt.id == receipt_id).first()
    if receipt is None:
        raise WorkflowError(404, "收货单不存在")
    snapshot = receipt_payload(db, receipt)
    order = (
        db.query(GspPurchaseOrder)
        .filter(GspPurchaseOrder.id == receipt.purchase_order_id)
        .first()
    )
    snapshot["purchase_order_no"] = order.order_no if order else None
    snapshot["template_version"] = payload.template_version
    snapshot["copy_no"] = payload.copy_no
    canonical = json.dumps(
        snapshot,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    record = GspControlledPrintRecord(
        document_type="RECEIPT_INSPECTION",
        entity_id=receipt.id,
        template_version=payload.template_version,
        copy_no=payload.copy_no,
        purpose=payload.purpose,
        status="GENERATED",
        snapshot_data=snapshot,
        content_hash=hashlib.sha256(canonical).hexdigest(),
        printed_by=actor_id,
    )
    db.add(record)
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="CONTROLLED_COPY_GENERATED",
        entity_type="GspControlledPrintRecord",
        entity_id=str(record.id),
        reason=payload.reason,
        after_data=model_snapshot(record),
        source_ip=source_ip,
    )
    return record

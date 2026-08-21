"""Controlled carrier qualification, in-transit events and custody handover."""

from __future__ import annotations

from datetime import UTC, date, datetime

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.audit import write_audit_event
from app.gsp.errors import WorkflowError
from app.gsp.models import GspQualityHold
from app.gsp.outbox import enqueue_integration_message
from app.gsp.sales_shipping.models import (
    GspSalesOrderItem,
    GspShipment,
    GspStockAllocation,
)
from app.gsp.snapshots import model_snapshot
from app.gsp.transport.models import (
    GspCarrier,
    GspCarrierDocument,
    GspCarrierDriver,
    GspCarrierVehicle,
    GspTransportEvent,
    GspTransportException,
    GspTransportTask,
)
from app.gsp.transport.schemas import (
    ApprovalDecision,
    CarrierCreate,
    CarrierDocumentCreate,
    CarrierDriverCreate,
    CarrierVehicleCreate,
    DeliveryCreate,
    TransportClose,
    TransportEventCreate,
    TransportExceptionCreate,
    TransportExceptionDecision,
)

BASE_DOCUMENTS = {"BUSINESS_LICENSE", "ROAD_TRANSPORT_LICENSE", "QUALITY_AGREEMENT"}
COLD_DOCUMENTS = {"COLD_CHAIN_QUALIFICATION"}


def _utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _audit(
    db: Session,
    *,
    actor_id: int,
    action: str,
    entity,
    reason: str,
    before: dict | None = None,
    source_ip: str | None = None,
) -> None:
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action=action,
        entity_type=type(entity).__name__,
        entity_id=str(entity.id),
        reason=reason,
        before_data=before,
        after_data=model_snapshot(entity),
        source_ip=source_ip,
    )


def create_carrier(
    db: Session,
    *,
    payload: CarrierCreate,
    actor_id: int,
    source_ip: str | None = None,
) -> GspCarrier:
    if payload.license_valid_to < date.today() or payload.quality_agreement_valid_to < date.today():
        raise WorkflowError(422, "承运商许可证和质量协议必须在有效期内")
    carrier = GspCarrier(
        **payload.model_dump(exclude={"reason"}),
        status="PENDING",
        created_by=actor_id,
    )
    db.add(carrier)
    _audit(
        db,
        actor_id=actor_id,
        action="CARRIER_CREATED",
        entity=carrier,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return carrier


def add_carrier_document(
    db: Session,
    *,
    carrier: GspCarrier,
    payload: CarrierDocumentCreate,
    actor_id: int,
    source_ip: str | None = None,
) -> GspCarrierDocument:
    if payload.valid_to < date.today():
        raise WorkflowError(422, "承运商文件已过期")
    if payload.document_type not in BASE_DOCUMENTS | COLD_DOCUMENTS | {
        "INSURANCE",
        "DRIVER_MANAGEMENT_PROCEDURE",
        "VEHICLE_MANAGEMENT_PROCEDURE",
    }:
        raise WorkflowError(422, "承运商文件类型不在受控清单中")
    before = model_snapshot(carrier)
    if carrier.status == "APPROVED":
        carrier.status = "PENDING"
        carrier.approved_by = None
        carrier.approved_at = None
    document = GspCarrierDocument(
        carrier_id=carrier.id,
        document_type=payload.document_type,
        document_no=payload.document_no,
        valid_to=payload.valid_to,
        file_ref=payload.file_ref,
        status="PENDING",
        created_by=actor_id,
    )
    db.add(document)
    db.flush()
    _audit(
        db,
        actor_id=actor_id,
        action="CARRIER_DOCUMENT_ADDED",
        entity=document,
        reason=payload.reason,
        source_ip=source_ip,
    )
    if before != model_snapshot(carrier):
        _audit(
            db,
            actor_id=actor_id,
            action="CARRIER_REQUALIFICATION_REQUIRED",
            entity=carrier,
            reason="承运商资质文件变更，撤销原批准并要求重新审核",
            before=before,
            source_ip=source_ip,
        )
    return document


def verify_carrier_document(
    db: Session,
    *,
    document: GspCarrierDocument,
    payload: ApprovalDecision,
    actor_id: int,
    source_ip: str | None = None,
) -> GspCarrierDocument:
    if document.status != "PENDING":
        raise WorkflowError(409, "承运商文件不在待核验状态")
    if document.created_by == actor_id:
        raise WorkflowError(409, "文件登记人与核验人必须分离")
    before = model_snapshot(document)
    document.status = "VERIFIED" if payload.decision == "APPROVE" else "REJECTED"
    document.verified_by = actor_id
    document.verified_at = utc_now()
    _audit(
        db,
        actor_id=actor_id,
        action=f"CARRIER_DOCUMENT_{document.status}",
        entity=document,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    return document


def carrier_findings(db: Session, carrier: GspCarrier, transport_mode: str) -> list[str]:
    today = date.today()
    findings = []
    if carrier.status != "APPROVED":
        findings.append("承运商未批准")
    if carrier.license_valid_to < today:
        findings.append("承运商许可证已过期")
    if carrier.quality_agreement_valid_to < today:
        findings.append("承运商质量协议已过期")
    if transport_mode not in (carrier.service_modes or []):
        findings.append("承运商服务范围不覆盖本次运输方式")
    required = set(BASE_DOCUMENTS)
    if transport_mode in {"COLD", "FROZEN"}:
        required |= COLD_DOCUMENTS
    verified_types = {
        row.document_type
        for row in db.query(GspCarrierDocument).filter(
            GspCarrierDocument.carrier_id == carrier.id,
            GspCarrierDocument.status == "VERIFIED",
            GspCarrierDocument.valid_to >= today,
        )
    }
    missing = sorted(required - verified_types)
    if missing:
        findings.append(f"承运商缺少有效核验文件：{', '.join(missing)}")
    return findings


def decide_carrier(
    db: Session,
    *,
    carrier: GspCarrier,
    payload: ApprovalDecision,
    actor_id: int,
    source_ip: str | None = None,
) -> GspCarrier:
    if carrier.status != "PENDING":
        raise WorkflowError(409, "承运商不在待审批状态")
    if carrier.created_by == actor_id:
        raise WorkflowError(409, "承运商建档人与质量审批人必须分离")
    before = model_snapshot(carrier)
    if payload.decision == "APPROVE":
        modes = carrier.service_modes or []
        findings = []
        for mode in modes:
            findings.extend(carrier_findings(db, carrier, mode))
        findings = [item for item in findings if item != "承运商未批准"]
        if findings:
            raise WorkflowError(409, "承运商资质证据不完整", [{"message": item} for item in findings])
        carrier.status = "APPROVED"
    else:
        carrier.status = "SUSPENDED"
        carrier.suspension_reason = payload.reason
    carrier.approved_by = actor_id
    carrier.approved_at = utc_now()
    _audit(
        db,
        actor_id=actor_id,
        action=f"CARRIER_{carrier.status}",
        entity=carrier,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    return carrier


def suspend_carrier(
    db: Session,
    *,
    carrier: GspCarrier,
    reason: str,
    actor_id: int,
    source_ip: str | None = None,
) -> GspCarrier:
    if carrier.status == "SUSPENDED":
        raise WorkflowError(409, "承运商已暂停")
    before = model_snapshot(carrier)
    carrier.status = "SUSPENDED"
    carrier.suspension_reason = reason
    _audit(
        db,
        actor_id=actor_id,
        action="CARRIER_SUSPENDED",
        entity=carrier,
        reason=reason,
        before=before,
        source_ip=source_ip,
    )
    return carrier


def create_vehicle(
    db: Session,
    *,
    carrier: GspCarrier,
    payload: CarrierVehicleCreate,
    actor_id: int,
    source_ip: str | None = None,
) -> GspCarrierVehicle:
    if payload.qualification_valid_to < date.today():
        raise WorkflowError(422, "车辆资质已过期")
    if payload.vehicle_type in {"REFRIGERATED", "FROZEN"} and (
        not payload.calibration_ref
        or payload.calibration_valid_to is None
        or payload.calibration_valid_to < date.today()
    ):
        raise WorkflowError(422, "冷链车辆必须提供有效校准证据")
    vehicle = GspCarrierVehicle(
        carrier_id=carrier.id,
        **payload.model_dump(exclude={"reason"}),
        status="PENDING",
        created_by=actor_id,
    )
    db.add(vehicle)
    _audit(
        db,
        actor_id=actor_id,
        action="CARRIER_VEHICLE_CREATED",
        entity=vehicle,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return vehicle


def decide_vehicle(
    db: Session,
    *,
    vehicle: GspCarrierVehicle,
    payload: ApprovalDecision,
    actor_id: int,
    source_ip: str | None = None,
) -> GspCarrierVehicle:
    if vehicle.status != "PENDING":
        raise WorkflowError(409, "车辆不在待审批状态")
    if vehicle.created_by == actor_id:
        raise WorkflowError(409, "车辆登记人与审批人必须分离")
    before = model_snapshot(vehicle)
    vehicle.status = "APPROVED" if payload.decision == "APPROVE" else "SUSPENDED"
    vehicle.approved_by = actor_id
    vehicle.approved_at = utc_now()
    _audit(
        db,
        actor_id=actor_id,
        action=f"CARRIER_VEHICLE_{vehicle.status}",
        entity=vehicle,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    return vehicle


def create_driver(
    db: Session,
    *,
    carrier: GspCarrier,
    payload: CarrierDriverCreate,
    actor_id: int,
    source_ip: str | None = None,
) -> GspCarrierDriver:
    if payload.authorization_valid_to < date.today():
        raise WorkflowError(422, "驾驶员授权已过期")
    driver = GspCarrierDriver(
        carrier_id=carrier.id,
        **payload.model_dump(exclude={"reason"}),
        status="PENDING",
        created_by=actor_id,
    )
    db.add(driver)
    _audit(
        db,
        actor_id=actor_id,
        action="CARRIER_DRIVER_CREATED",
        entity=driver,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return driver


def decide_driver(
    db: Session,
    *,
    driver: GspCarrierDriver,
    payload: ApprovalDecision,
    actor_id: int,
    source_ip: str | None = None,
) -> GspCarrierDriver:
    if driver.status != "PENDING":
        raise WorkflowError(409, "驾驶员不在待审批状态")
    if driver.created_by == actor_id:
        raise WorkflowError(409, "驾驶员登记人与审批人必须分离")
    before = model_snapshot(driver)
    driver.status = "APPROVED" if payload.decision == "APPROVE" else "SUSPENDED"
    driver.approved_by = actor_id
    driver.approved_at = utc_now()
    _audit(
        db,
        actor_id=actor_id,
        action=f"CARRIER_DRIVER_{driver.status}",
        entity=driver,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    return driver


def validate_transport_resources(
    db: Session,
    *,
    carrier_id: int,
    vehicle_id: int,
    driver_id: int,
    transport_mode: str,
) -> tuple[GspCarrier, GspCarrierVehicle, GspCarrierDriver]:
    if transport_mode not in {"NORMAL", "COLD", "FROZEN"}:
        raise WorkflowError(422, "transport_mode 只能是 NORMAL、COLD 或 FROZEN")
    carrier = db.query(GspCarrier).filter(GspCarrier.id == carrier_id).first()
    vehicle = db.query(GspCarrierVehicle).filter(GspCarrierVehicle.id == vehicle_id).first()
    driver = db.query(GspCarrierDriver).filter(GspCarrierDriver.id == driver_id).first()
    if not carrier or not vehicle or not driver:
        raise WorkflowError(409, "承运商、车辆或驾驶员受控主数据不存在")
    findings = carrier_findings(db, carrier, transport_mode)
    today = date.today()
    if vehicle.carrier_id != carrier.id or driver.carrier_id != carrier.id:
        findings.append("车辆或驾驶员不属于所选承运商")
    if vehicle.status != "APPROVED" or vehicle.qualification_valid_to < today:
        findings.append("车辆未批准或资质已过期")
    if driver.status != "APPROVED" or driver.authorization_valid_to < today:
        findings.append("驾驶员未批准或授权已过期")
    required_vehicle_types = {
        "NORMAL": {"NORMAL", "REFRIGERATED", "FROZEN"},
        "COLD": {"REFRIGERATED", "FROZEN"},
        "FROZEN": {"FROZEN"},
    }
    if vehicle.vehicle_type not in required_vehicle_types[transport_mode]:
        findings.append("车辆类型不满足运输方式")
    if transport_mode in {"COLD", "FROZEN"} and (
        not vehicle.calibration_ref
        or not vehicle.calibration_valid_to
        or vehicle.calibration_valid_to < today
    ):
        findings.append("冷链车辆缺少有效校准证据")
    if findings:
        raise WorkflowError(409, "运输资源不满足 GSP 发运条件", [{"message": x} for x in findings])
    return carrier, vehicle, driver


def create_transport_task(
    db: Session,
    *,
    shipment: GspShipment,
    carrier: GspCarrier,
    vehicle: GspCarrierVehicle,
    driver: GspCarrierDriver,
    route_plan_ref: str,
    handover_document_no: str,
    expected_arrival_at: datetime,
    actor_id: int,
    reason: str,
    source_ip: str | None = None,
) -> GspTransportTask:
    arrival = _utc_naive(expected_arrival_at)
    if arrival <= utc_now():
        raise WorkflowError(422, "预计到达时间必须晚于当前时间")
    task = GspTransportTask(
        task_no=f"TR-{shipment.shipment_no}",
        shipment_id=shipment.id,
        carrier_id=carrier.id,
        vehicle_id=vehicle.id,
        driver_id=driver.id,
        transport_mode=shipment.transport_mode,
        route_plan_ref=route_plan_ref,
        handover_document_no=handover_document_no,
        expected_arrival_at=arrival,
        status="PREPARED",
        created_by=actor_id,
    )
    db.add(task)
    _audit(
        db,
        actor_id=actor_id,
        action="TRANSPORT_TASK_PREPARED",
        entity=task,
        reason=reason,
        source_ip=source_ip,
    )
    return task


def start_transport_task(
    db: Session,
    *,
    shipment: GspShipment,
    actor_id: int,
    reason: str,
    source_ip: str | None = None,
) -> GspTransportTask:
    task = db.query(GspTransportTask).filter(GspTransportTask.shipment_id == shipment.id).first()
    if not task or task.status != "PREPARED":
        raise WorkflowError(409, "发运单缺少已准备的受控运输任务")
    validate_transport_resources(
        db,
        carrier_id=task.carrier_id,
        vehicle_id=task.vehicle_id,
        driver_id=task.driver_id,
        transport_mode=task.transport_mode,
    )
    before = model_snapshot(task)
    task.status = "IN_TRANSIT"
    task.actual_departure_at = utc_now()
    event = GspTransportEvent(
        task_id=task.id,
        event_type="DEPARTED",
        occurred_at=task.actual_departure_at,
        location="发运仓交接点",
        detail=f"按交接单 {task.handover_document_no} 完成承运交接",
        evidence_ref=task.handover_document_no,
        reported_by=actor_id,
    )
    db.add(event)
    _audit(
        db,
        actor_id=actor_id,
        action="TRANSPORT_STARTED",
        entity=task,
        reason=reason,
        before=before,
        source_ip=source_ip,
    )
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="TRANSPORT_STARTED",
        aggregate_type="GspTransportTask",
        aggregate_id=str(task.id),
        payload={"transport_task": model_snapshot(task), "shipment": model_snapshot(shipment)},
    )
    return task


def record_transport_event(
    db: Session,
    *,
    task: GspTransportTask,
    payload: TransportEventCreate,
    actor_id: int,
    source_ip: str | None = None,
) -> GspTransportEvent:
    if task.status not in {"IN_TRANSIT", "EXCEPTION"}:
        raise WorkflowError(409, "当前运输任务状态不能登记在途事件")
    occurred_at = _utc_naive(payload.occurred_at)
    if task.actual_departure_at and occurred_at < task.actual_departure_at:
        raise WorkflowError(422, "在途事件不能早于实际发运时间")
    if occurred_at > utc_now():
        raise WorkflowError(422, "在途事件时间不能晚于当前时间")
    event = GspTransportEvent(
        task_id=task.id,
        event_type=payload.event_type,
        occurred_at=occurred_at,
        location=payload.location,
        detail=payload.detail,
        evidence_ref=payload.evidence_ref,
        reported_by=actor_id,
    )
    db.add(event)
    _audit(
        db,
        actor_id=actor_id,
        action="TRANSPORT_EVENT_RECORDED",
        entity=event,
        reason=payload.detail,
        source_ip=source_ip,
    )
    return event


def _shipment_batch_ids(db: Session, shipment_id: int) -> set[int]:
    shipment = db.query(GspShipment).filter(GspShipment.id == shipment_id).first()
    return {
        row[0]
        for row in db.query(GspStockAllocation.batch_id)
        .join(
            GspSalesOrderItem,
            GspSalesOrderItem.id == GspStockAllocation.sales_order_item_id,
        )
        .filter(GspSalesOrderItem.sales_order_id == shipment.sales_order_id)
        .all()
    }


def create_transport_exception(
    db: Session,
    *,
    task: GspTransportTask,
    payload: TransportExceptionCreate,
    actor_id: int,
    source_ip: str | None = None,
) -> GspTransportException:
    if task.status != "IN_TRANSIT":
        raise WorkflowError(409, "只有在途任务可以报告运输异常")
    occurred_at = _utc_naive(payload.occurred_at)
    if task.actual_departure_at and occurred_at < task.actual_departure_at:
        raise WorkflowError(422, "运输异常不能早于实际发运时间")
    if occurred_at > utc_now():
        raise WorkflowError(422, "运输异常时间不能晚于当前时间")
    before = model_snapshot(task)
    event = GspTransportEvent(
        task_id=task.id,
        event_type=f"EXCEPTION_{payload.category}",
        occurred_at=occurred_at,
        location=payload.location,
        detail=payload.description,
        evidence_ref=payload.evidence_ref,
        reported_by=actor_id,
    )
    db.add(event)
    db.flush()
    exception = GspTransportException(
        task_id=task.id,
        event_id=event.id,
        category=payload.category,
        severity=payload.severity,
        quality_impact=payload.quality_impact,
        description=payload.description,
        status="PENDING_QUALITY",
        reported_by=actor_id,
    )
    db.add(exception)
    task.status = "EXCEPTION"
    db.flush()
    if payload.quality_impact and payload.severity in {"HIGH", "CRITICAL"}:
        for batch_id in _shipment_batch_ids(db, task.shipment_id):
            existing = db.query(GspQualityHold).filter(
                GspQualityHold.batch_id == batch_id,
                GspQualityHold.status == "ACTIVE",
                GspQualityHold.reason_code == "TRANSPORT_EXCEPTION",
            ).first()
            if not existing:
                hold = GspQualityHold(
                    batch_id=batch_id,
                    reason_code="TRANSPORT_EXCEPTION",
                    reason=f"运输任务 {task.task_no}：{payload.description}",
                    status="ACTIVE",
                    initiated_by=actor_id,
                )
                db.add(hold)
                _audit(
                    db,
                    actor_id=actor_id,
                    action="TRANSPORT_EXCEPTION_BATCH_HELD",
                    entity=hold,
                    reason=payload.description,
                    source_ip=source_ip,
                )
    _audit(
        db,
        actor_id=actor_id,
        action="TRANSPORT_EXCEPTION_REPORTED",
        entity=exception,
        reason=payload.description,
        source_ip=source_ip,
    )
    _audit(
        db,
        actor_id=actor_id,
        action="TRANSPORT_TASK_EXCEPTION_BLOCKED",
        entity=task,
        reason=payload.description,
        before=before,
        source_ip=source_ip,
    )
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="TRANSPORT_EXCEPTION",
        aggregate_type="GspTransportException",
        aggregate_id=str(exception.id),
        payload={"transport_task": model_snapshot(task), "exception": model_snapshot(exception)},
    )
    return exception


def decide_transport_exception(
    db: Session,
    *,
    exception: GspTransportException,
    payload: TransportExceptionDecision,
    actor_id: int,
    source_ip: str | None = None,
) -> GspTransportException:
    if exception.status != "PENDING_QUALITY":
        raise WorkflowError(409, "运输异常已完成质量决定")
    if exception.reported_by == actor_id:
        raise WorkflowError(409, "异常报告人与质量决定人必须分离")
    if exception.severity in {"HIGH", "CRITICAL"} and not payload.capa_ref:
        raise WorkflowError(422, "高风险运输异常必须关联 CAPA")
    task = db.query(GspTransportTask).filter(GspTransportTask.id == exception.task_id).first()
    before = model_snapshot(exception)
    task_before = model_snapshot(task)
    exception.decision = payload.decision
    exception.deviation_ref = payload.deviation_ref
    exception.capa_ref = payload.capa_ref
    exception.decided_by = actor_id
    exception.decided_at = utc_now()
    if payload.decision == "CONTINUE":
        exception.status = "RESOLVED"
        task.status = "IN_TRANSIT"
    elif payload.decision == "RETURN":
        exception.status = "RETURN_REQUIRED"
        task.status = "RETURN_REQUIRED"
    else:
        exception.status = "REJECTED_DELIVERY"
        task.status = "REJECTED_DELIVERY"
    _audit(
        db,
        actor_id=actor_id,
        action=f"TRANSPORT_EXCEPTION_{exception.decision}",
        entity=exception,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    _audit(
        db,
        actor_id=actor_id,
        action=f"TRANSPORT_TASK_{task.status}",
        entity=task,
        reason=payload.reason,
        before=task_before,
        source_ip=source_ip,
    )
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="TRANSPORT_EXCEPTION_DECIDED",
        aggregate_type="GspTransportException",
        aggregate_id=str(exception.id),
        payload={"transport_task": model_snapshot(task), "exception": model_snapshot(exception)},
    )
    return exception


def record_delivery(
    db: Session,
    *,
    task: GspTransportTask,
    payload: DeliveryCreate,
    actor_id: int,
    source_ip: str | None = None,
) -> GspTransportTask:
    if task.status != "IN_TRANSIT":
        raise WorkflowError(409, "运输任务存在未解决异常或不在可签收状态")
    required_decisions = []
    if payload.package_condition != "INTACT":
        required_decisions.append("PACKAGE_DAMAGE")
    if payload.quantity_conclusion != "MATCHED":
        required_decisions.append("QUANTITY_MISMATCH")
    for category in required_decisions:
        resolved = db.query(GspTransportException).filter(
            GspTransportException.task_id == task.id,
            GspTransportException.category == category,
            GspTransportException.status == "RESOLVED",
            GspTransportException.decision == "CONTINUE",
        ).first()
        if not resolved:
            raise WorkflowError(409, "包装或数量异常必须先登记运输异常并取得质量决定")
    received_at = _utc_naive(payload.received_at)
    if task.actual_departure_at and received_at < task.actual_departure_at:
        raise WorkflowError(422, "签收时间不能早于发运时间")
    if received_at > utc_now():
        raise WorkflowError(422, "签收时间不能晚于当前时间")
    if received_at > task.expected_arrival_at:
        delay_resolved = db.query(GspTransportException).filter(
            GspTransportException.task_id == task.id,
            GspTransportException.category == "DELAY",
            GspTransportException.status == "RESOLVED",
            GspTransportException.decision == "CONTINUE",
        ).first()
        if not delay_resolved:
            raise WorkflowError(409, "超出预计到达时间时必须先登记延误偏差并取得质量决定")
    before = model_snapshot(task)
    task.status = "DELIVERED"
    task.delivery_recorded_by = actor_id
    task.delivered_at = received_at
    task.delivery_location = payload.delivery_location
    task.recipient_name = payload.recipient_name
    task.recipient_organization = payload.recipient_organization
    task.delivery_proof_ref = payload.delivery_proof_ref
    task.package_condition = payload.package_condition
    task.quantity_conclusion = payload.quantity_conclusion
    shipment = db.query(GspShipment).filter(GspShipment.id == task.shipment_id).first()
    shipment.status = "DELIVERED"
    event = GspTransportEvent(
        task_id=task.id,
        event_type="DELIVERED",
        occurred_at=received_at,
        location=payload.delivery_location,
        detail=f"由 {payload.recipient_organization} 的 {payload.recipient_name} 完成签收",
        evidence_ref=payload.delivery_proof_ref,
        reported_by=actor_id,
    )
    db.add(event)
    _audit(
        db,
        actor_id=actor_id,
        action="TRANSPORT_DELIVERY_RECORDED",
        entity=task,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="SHIPMENT_DELIVERED",
        aggregate_type="GspTransportTask",
        aggregate_id=str(task.id),
        payload={"transport_task": model_snapshot(task), "shipment": model_snapshot(shipment)},
    )
    return task


def close_transport_task(
    db: Session,
    *,
    task: GspTransportTask,
    payload: TransportClose,
    actor_id: int,
    source_ip: str | None = None,
) -> GspTransportTask:
    if task.status != "DELIVERED":
        raise WorkflowError(409, "只有已签收运输任务可以关闭")
    if task.delivery_recorded_by == actor_id:
        raise WorkflowError(409, "签收登记人与运输关闭复核人必须分离")
    unresolved = db.query(GspTransportException).filter(
        GspTransportException.task_id == task.id,
        GspTransportException.status == "PENDING_QUALITY",
    ).count()
    if unresolved:
        raise WorkflowError(409, "运输任务仍有未完成质量决定的异常")
    before = model_snapshot(task)
    task.status = "CLOSED"
    task.closed_by = actor_id
    task.closed_at = utc_now()
    task.close_evidence_ref = payload.evidence_ref
    shipment = db.query(GspShipment).filter(GspShipment.id == task.shipment_id).first()
    shipment.status = "CLOSED"
    _audit(
        db,
        actor_id=actor_id,
        action="TRANSPORT_CUSTODY_CLOSED",
        entity=task,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="TRANSPORT_CLOSED",
        aggregate_type="GspTransportTask",
        aggregate_id=str(task.id),
        payload={"transport_task": model_snapshot(task), "shipment": model_snapshot(shipment)},
    )
    return task

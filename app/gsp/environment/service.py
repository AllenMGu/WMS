"""Services for calibrated environment monitoring and excursion handling."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, date, datetime
from decimal import Decimal
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.audit import write_audit_event
from app.gsp.chain_lock import lock_chain_append
from app.gsp.environment.models import (
    GspEnvironmentAlarm,
    GspEnvironmentAssignment,
    GspEnvironmentDevice,
    GspEnvironmentReading,
)
from app.gsp.environment.schemas import (
    AlarmDecision,
    DeviceRecalibration,
    EnvironmentAssignmentCreate,
    EnvironmentDecision,
    EnvironmentDeviceCreate,
    EnvironmentReadingCreate,
)
from app.gsp.errors import WorkflowError
from app.gsp.models import GspBatchStock, GspQualityHold
from app.gsp.outbox import enqueue_integration_message
from app.gsp.sales_shipping.models import GspSalesOrderItem, GspShipment, GspStockAllocation
from app.gsp.snapshots import model_snapshot
from app.gsp.transport.models import GspTransportTask
from app.legacy import Location, Warehouse


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


def _canonical(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _decimal_text(value: Decimal | None, places: int = 3) -> str | None:
    if value is None:
        return None
    return f"{Decimal(value):.{places}f}"


def create_device(
    db: Session,
    *,
    payload: EnvironmentDeviceCreate,
    actor_id: int,
    source_ip: str | None = None,
) -> GspEnvironmentDevice:
    if payload.calibration_valid_to < date.today():
        raise WorkflowError(422, "监测设备校准已过期")
    if payload.measurement_scope == "TEMPERATURE_HUMIDITY" and payload.humidity_accuracy is None:
        raise WorkflowError(422, "温湿度设备必须提供湿度测量精度")
    device = GspEnvironmentDevice(
        **payload.model_dump(exclude={"reason"}),
        status="PENDING",
        created_by=actor_id,
    )
    db.add(device)
    _audit(
        db,
        actor_id=actor_id,
        action="ENVIRONMENT_DEVICE_CREATED",
        entity=device,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return device


def decide_device(
    db: Session,
    *,
    device: GspEnvironmentDevice,
    payload: EnvironmentDecision,
    actor_id: int,
    source_ip: str | None = None,
) -> GspEnvironmentDevice:
    if device.status != "PENDING":
        raise WorkflowError(409, "监测设备不在待审批状态")
    if device.created_by == actor_id:
        raise WorkflowError(409, "设备登记人与质量审批人必须分离")
    if payload.decision == "APPROVE" and device.calibration_valid_to < date.today():
        raise WorkflowError(409, "设备校准已过期，不能批准")
    before = model_snapshot(device)
    device.status = "APPROVED" if payload.decision == "APPROVE" else "SUSPENDED"
    device.approved_by = actor_id
    device.approved_at = utc_now()
    if payload.decision == "REJECT":
        device.suspension_reason = payload.reason
    _audit(
        db,
        actor_id=actor_id,
        action=f"ENVIRONMENT_DEVICE_{device.status}",
        entity=device,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    return device


def recalibrate_device(
    db: Session,
    *,
    device: GspEnvironmentDevice,
    payload: DeviceRecalibration,
    actor_id: int,
    source_ip: str | None = None,
) -> GspEnvironmentDevice:
    if payload.calibration_valid_to < date.today():
        raise WorkflowError(422, "新校准有效期已过期")
    if device.measurement_scope == "TEMPERATURE_HUMIDITY" and payload.humidity_accuracy is None:
        raise WorkflowError(422, "温湿度设备必须提供湿度测量精度")
    before = model_snapshot(device)
    device.calibration_ref = payload.calibration_ref
    device.calibration_valid_to = payload.calibration_valid_to
    device.temperature_accuracy = payload.temperature_accuracy
    device.humidity_accuracy = payload.humidity_accuracy
    device.status = "PENDING"
    device.approved_by = None
    device.approved_at = None
    device.suspension_reason = None
    _audit(
        db,
        actor_id=actor_id,
        action="ENVIRONMENT_DEVICE_RECALIBRATION_REVIEW_REQUIRED",
        entity=device,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    return device


def suspend_device(
    db: Session,
    *,
    device: GspEnvironmentDevice,
    reason: str,
    actor_id: int,
    source_ip: str | None = None,
) -> GspEnvironmentDevice:
    if device.status == "SUSPENDED":
        raise WorkflowError(409, "监测设备已暂停")
    before = model_snapshot(device)
    device.status = "SUSPENDED"
    device.suspension_reason = reason
    _audit(
        db,
        actor_id=actor_id,
        action="ENVIRONMENT_DEVICE_SUSPENDED",
        entity=device,
        reason=reason,
        before=before,
        source_ip=source_ip,
    )
    return device


def _validate_ranges(payload: EnvironmentAssignmentCreate, device: GspEnvironmentDevice) -> None:
    if not (
        payload.critical_temperature_min <= payload.temperature_min
        < payload.temperature_max <= payload.critical_temperature_max
    ):
        raise WorkflowError(422, "温度告警与严重告警阈值顺序无效")
    humidity_values = (
        payload.humidity_min,
        payload.humidity_max,
        payload.critical_humidity_min,
        payload.critical_humidity_max,
    )
    if any(value is not None for value in humidity_values):
        if device.measurement_scope != "TEMPERATURE_HUMIDITY" or any(
            value is None for value in humidity_values
        ):
            raise WorkflowError(422, "湿度监测必须使用温湿度设备并完整配置四个阈值")
        if not (
            payload.critical_humidity_min <= payload.humidity_min
            < payload.humidity_max <= payload.critical_humidity_max
        ):
            raise WorkflowError(422, "湿度告警与严重告警阈值顺序无效")
    if payload.offline_after_seconds < payload.sampling_interval_seconds:
        raise WorkflowError(422, "离线判定时间不得短于采样周期")


def create_assignment(
    db: Session,
    *,
    payload: EnvironmentAssignmentCreate,
    actor_id: int,
    source_ip: str | None = None,
) -> GspEnvironmentAssignment:
    device = db.query(GspEnvironmentDevice).filter(GspEnvironmentDevice.id == payload.device_id).first()
    if not device or device.status != "APPROVED" or device.calibration_valid_to < date.today():
        raise WorkflowError(409, "监测设备未批准或校准已过期")
    _validate_ranges(payload, device)
    if payload.context_type == "WAREHOUSE":
        warehouse = db.query(Warehouse).filter(Warehouse.id == payload.warehouse_id).first()
        location = db.query(Location).filter(Location.id == payload.location_id).first()
        if (
            not warehouse
            or not location
            or location.warehouse_id != warehouse.id
            or not warehouse.is_active
            or not location.is_active
            or payload.transport_task_id is not None
        ):
            raise WorkflowError(409, "仓库监测分配目标无效")
    else:
        task = db.query(GspTransportTask).filter(
            GspTransportTask.id == payload.transport_task_id
        ).first()
        if (
            not task
            or task.status not in {"PREPARED", "IN_TRANSIT", "EXCEPTION"}
            or payload.warehouse_id is not None
            or payload.location_id is not None
        ):
            raise WorkflowError(409, "运输监测分配目标无效")
    existing = db.query(GspEnvironmentAssignment).filter(
        GspEnvironmentAssignment.device_id == device.id,
        GspEnvironmentAssignment.status.in_(["PENDING", "ACTIVE"]),
    ).first()
    if existing:
        raise WorkflowError(409, "设备已有待审批或生效中的监测分配")
    assignment = GspEnvironmentAssignment(
        **payload.model_dump(exclude={"reason"}),
        status="PENDING",
        created_by=actor_id,
    )
    db.add(assignment)
    _audit(
        db,
        actor_id=actor_id,
        action="ENVIRONMENT_ASSIGNMENT_CREATED",
        entity=assignment,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return assignment


def decide_assignment(
    db: Session,
    *,
    assignment: GspEnvironmentAssignment,
    payload: EnvironmentDecision,
    actor_id: int,
    source_ip: str | None = None,
) -> GspEnvironmentAssignment:
    if assignment.status != "PENDING":
        raise WorkflowError(409, "监测分配不在待审批状态")
    if assignment.created_by == actor_id:
        raise WorkflowError(409, "监测分配人与质量审批人必须分离")
    device = db.query(GspEnvironmentDevice).filter(
        GspEnvironmentDevice.id == assignment.device_id
    ).first()
    if payload.decision == "APPROVE" and (
        not device or device.status != "APPROVED" or device.calibration_valid_to < date.today()
    ):
        raise WorkflowError(409, "监测设备当前不可用")
    before = model_snapshot(assignment)
    assignment.status = "ACTIVE" if payload.decision == "APPROVE" else "SUSPENDED"
    assignment.approved_by = actor_id
    assignment.approved_at = utc_now()
    _audit(
        db,
        actor_id=actor_id,
        action=f"ENVIRONMENT_ASSIGNMENT_{assignment.status}",
        entity=assignment,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    return assignment


def _reading_source_payload(
    assignment_id: int, payload: EnvironmentReadingCreate, observed_at: datetime
) -> dict:
    return {
        "assignment_id": assignment_id,
        "external_reading_id": payload.external_reading_id,
        "observed_at": observed_at.isoformat(timespec="microseconds"),
        "temperature": _decimal_text(payload.temperature),
        "humidity": _decimal_text(payload.humidity),
        "battery_percent": _decimal_text(payload.battery_percent, 2),
        "signal_strength": payload.signal_strength,
        "source_payload": payload.source_payload,
    }


def _record_hash_payload(reading: GspEnvironmentReading) -> dict:
    return {
        "assignment_id": reading.assignment_id,
        "external_reading_id": reading.external_reading_id,
        "observed_at": reading.observed_at.isoformat(timespec="microseconds"),
        "received_at": reading.received_at.isoformat(timespec="microseconds"),
        "temperature": _decimal_text(reading.temperature),
        "humidity": _decimal_text(reading.humidity),
        "battery_percent": _decimal_text(reading.battery_percent, 2),
        "signal_strength": reading.signal_strength,
        "source_payload_hash": reading.source_payload_hash,
        "previous_hash": reading.previous_hash,
        "evaluation": reading.evaluation,
        "reported_by": reading.reported_by,
    }


def _stored_source_payload(reading: GspEnvironmentReading) -> dict:
    return {
        "assignment_id": reading.assignment_id,
        "external_reading_id": reading.external_reading_id,
        "observed_at": reading.observed_at.isoformat(timespec="microseconds"),
        "temperature": _decimal_text(reading.temperature),
        "humidity": _decimal_text(reading.humidity),
        "battery_percent": _decimal_text(reading.battery_percent, 2),
        "signal_strength": reading.signal_strength,
        "source_payload": reading.source_payload,
    }


def _alarm_specs(
    assignment: GspEnvironmentAssignment,
    temperature: Decimal,
    humidity: Decimal | None,
) -> list[tuple[str, str, Decimal, Decimal, str]]:
    specs = []
    if temperature < assignment.temperature_min:
        severity = "CRITICAL" if temperature < assignment.critical_temperature_min else "WARNING"
        specs.append(
            ("TEMPERATURE_LOW", severity, temperature, assignment.temperature_min, "温度低于批准下限")
        )
    elif temperature > assignment.temperature_max:
        severity = "CRITICAL" if temperature > assignment.critical_temperature_max else "WARNING"
        specs.append(
            ("TEMPERATURE_HIGH", severity, temperature, assignment.temperature_max, "温度高于批准上限")
        )
    if assignment.humidity_min is not None:
        if humidity is None:
            raise WorkflowError(422, "当前监测分配要求湿度读数")
        if humidity < assignment.humidity_min:
            severity = "CRITICAL" if humidity < assignment.critical_humidity_min else "WARNING"
            specs.append(
                ("HUMIDITY_LOW", severity, humidity, assignment.humidity_min, "湿度低于批准下限")
            )
        elif humidity > assignment.humidity_max:
            severity = "CRITICAL" if humidity > assignment.critical_humidity_max else "WARNING"
            specs.append(
                ("HUMIDITY_HIGH", severity, humidity, assignment.humidity_max, "湿度高于批准上限")
            )
    return specs


def _target_batch_ids(db: Session, assignment: GspEnvironmentAssignment) -> set[int]:
    if assignment.context_type == "WAREHOUSE":
        return {
            row[0]
            for row in db.query(GspBatchStock.batch_id).filter(
                GspBatchStock.warehouse_id == assignment.warehouse_id,
                GspBatchStock.location_id == assignment.location_id,
                GspBatchStock.quantity > 0,
            )
        }
    task = db.query(GspTransportTask).filter(
        GspTransportTask.id == assignment.transport_task_id
    ).first()
    if not task:
        return set()
    shipment = db.query(GspShipment).filter(GspShipment.id == task.shipment_id).first()
    if not shipment:
        return set()
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


def _hold_batches(
    db: Session,
    *,
    assignment: GspEnvironmentAssignment,
    alarm: GspEnvironmentAlarm,
    actor_id: int,
    source_ip: str | None,
) -> None:
    for batch_id in _target_batch_ids(db, assignment):
        existing = db.query(GspQualityHold).filter(
            GspQualityHold.batch_id == batch_id,
            GspQualityHold.reason_code == "ENVIRONMENT_EXCURSION",
            GspQualityHold.status == "ACTIVE",
        ).first()
        if existing:
            continue
        hold = GspQualityHold(
            batch_id=batch_id,
            reason_code="ENVIRONMENT_EXCURSION",
            reason=f"环境告警 {alarm.alarm_no}：{alarm.detail}",
            status="ACTIVE",
            initiated_by=actor_id,
        )
        db.add(hold)
        for stock in db.query(GspBatchStock).filter(GspBatchStock.batch_id == batch_id):
            stock.stock_status = "HOLD"
            stock.lock_version += 1
        _audit(
            db,
            actor_id=actor_id,
            action="ENVIRONMENT_EXCURSION_BATCH_HELD",
            entity=hold,
            reason=alarm.detail,
            source_ip=source_ip,
        )


def _raise_alarm(
    db: Session,
    *,
    assignment: GspEnvironmentAssignment,
    reading: GspEnvironmentReading | None,
    alarm_type: str,
    severity: str,
    observed_value: Decimal,
    threshold_value: Decimal,
    detail: str,
    actor_id: int,
    source_ip: str | None,
) -> GspEnvironmentAlarm:
    suffix = reading.id if reading else uuid4().hex[:12]
    alarm = GspEnvironmentAlarm(
        alarm_no=f"AL-{assignment.id}-{suffix}-{alarm_type}",
        assignment_id=assignment.id,
        reading_id=reading.id if reading else None,
        alarm_type=alarm_type,
        severity=severity,
        status="OPEN",
        observed_value=observed_value,
        threshold_value=threshold_value,
        detail=detail,
        created_by=actor_id,
    )
    db.add(alarm)
    _audit(
        db,
        actor_id=actor_id,
        action="ENVIRONMENT_ALARM_RAISED",
        entity=alarm,
        reason=detail,
        source_ip=source_ip,
    )
    if severity == "CRITICAL":
        _hold_batches(
            db,
            assignment=assignment,
            alarm=alarm,
            actor_id=actor_id,
            source_ip=source_ip,
        )
    enqueue_integration_message(
        db,
        destination="ENVIRONMENT_MONITORING",
        message_type="ENVIRONMENT_ALARM_RAISED",
        aggregate_type="GspEnvironmentAlarm",
        aggregate_id=str(alarm.id),
        payload={"alarm": model_snapshot(alarm), "assignment": model_snapshot(assignment)},
    )
    return alarm


def ingest_reading(
    db: Session,
    *,
    assignment: GspEnvironmentAssignment,
    payload: EnvironmentReadingCreate,
    actor_id: int,
    source_ip: str | None = None,
) -> GspEnvironmentReading:
    lock_chain_append(db, f"environment-reading:{assignment.id}")
    if assignment.status != "ACTIVE":
        raise WorkflowError(409, "监测分配未生效")
    device = db.query(GspEnvironmentDevice).filter(
        GspEnvironmentDevice.id == assignment.device_id
    ).first()
    if not device or device.status != "APPROVED" or device.calibration_valid_to < date.today():
        raise WorkflowError(409, "监测设备未批准或校准已过期")
    observed_at = _utc_naive(payload.observed_at)
    if observed_at > utc_now():
        raise WorkflowError(422, "读数时间不能晚于当前时间")
    if assignment.approved_at and observed_at < assignment.approved_at:
        raise WorkflowError(422, "读数时间不能早于监测分配生效时间")
    source_payload = _reading_source_payload(assignment.id, payload, observed_at)
    source_payload_hash = _sha256(_canonical(source_payload))
    existing = db.query(GspEnvironmentReading).filter(
        GspEnvironmentReading.assignment_id == assignment.id,
        GspEnvironmentReading.external_reading_id == payload.external_reading_id,
    ).first()
    if existing:
        if existing.source_payload_hash == source_payload_hash:
            return existing
        raise WorkflowError(409, "相同外部读数编号的内容不一致")
    specs = _alarm_specs(assignment, payload.temperature, payload.humidity)
    evaluation = "CRITICAL" if any(row[1] == "CRITICAL" for row in specs) else (
        "WARNING" if specs else "NORMAL"
    )
    previous = db.query(GspEnvironmentReading).filter(
        GspEnvironmentReading.assignment_id == assignment.id
    ).order_by(GspEnvironmentReading.id.desc()).first()
    reading = GspEnvironmentReading(
        assignment_id=assignment.id,
        external_reading_id=payload.external_reading_id,
        observed_at=observed_at,
        received_at=utc_now(),
        temperature=payload.temperature,
        humidity=payload.humidity,
        battery_percent=payload.battery_percent,
        signal_strength=payload.signal_strength,
        source_payload=payload.source_payload,
        source_payload_hash=source_payload_hash,
        previous_hash=previous.record_hash if previous else None,
        evaluation=evaluation,
        reported_by=actor_id,
        record_hash="pending",
    )
    reading.record_hash = _sha256(_canonical(_record_hash_payload(reading)))
    db.add(reading)
    db.flush()
    assignment.last_reading_at = reading.received_at
    for alarm_type, severity, observed, threshold, detail in specs:
        _raise_alarm(
            db,
            assignment=assignment,
            reading=reading,
            alarm_type=alarm_type,
            severity=severity,
            observed_value=observed,
            threshold_value=threshold,
            detail=detail,
            actor_id=actor_id,
            source_ip=source_ip,
        )
    return reading


def verify_reading_chain(
    db: Session, assignment_id: int
) -> tuple[bool, int | None]:
    previous_hash = None
    for reading in db.query(GspEnvironmentReading).filter(
        GspEnvironmentReading.assignment_id == assignment_id
    ).order_by(GspEnvironmentReading.id):
        if reading.previous_hash != previous_hash:
            return False, reading.id
        if _sha256(_canonical(_stored_source_payload(reading))) != reading.source_payload_hash:
            return False, reading.id
        expected = _sha256(_canonical(_record_hash_payload(reading)))
        if expected != reading.record_hash:
            return False, reading.id
        previous_hash = reading.record_hash
    return True, None


def acknowledge_alarm(
    db: Session,
    *,
    alarm: GspEnvironmentAlarm,
    reason: str,
    actor_id: int,
    source_ip: str | None = None,
) -> GspEnvironmentAlarm:
    if alarm.status != "OPEN":
        raise WorkflowError(409, "环境告警不在待确认状态")
    before = model_snapshot(alarm)
    alarm.status = "ACKNOWLEDGED"
    alarm.acknowledged_by = actor_id
    alarm.acknowledged_at = utc_now()
    alarm.acknowledgment_note = reason
    _audit(
        db,
        actor_id=actor_id,
        action="ENVIRONMENT_ALARM_ACKNOWLEDGED",
        entity=alarm,
        reason=reason,
        before=before,
        source_ip=source_ip,
    )
    return alarm


def decide_alarm(
    db: Session,
    *,
    alarm: GspEnvironmentAlarm,
    payload: AlarmDecision,
    actor_id: int,
    source_ip: str | None = None,
) -> GspEnvironmentAlarm:
    if alarm.status not in {"OPEN", "ACKNOWLEDGED"}:
        raise WorkflowError(409, "环境告警已完成质量决定")
    if alarm.created_by == actor_id or alarm.acknowledged_by == actor_id:
        raise WorkflowError(409, "告警上报/确认人与质量决定人必须分离")
    if alarm.severity == "CRITICAL" and not payload.capa_ref:
        raise WorkflowError(422, "严重环境告警必须关联 CAPA")
    before = model_snapshot(alarm)
    alarm.status = "RESOLVED"
    alarm.decision = payload.decision
    alarm.deviation_ref = payload.deviation_ref
    alarm.capa_ref = payload.capa_ref
    alarm.resolution_evidence_ref = payload.resolution_evidence_ref
    alarm.decided_by = actor_id
    alarm.decided_at = utc_now()
    _audit(
        db,
        actor_id=actor_id,
        action=f"ENVIRONMENT_ALARM_{payload.decision}",
        entity=alarm,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    enqueue_integration_message(
        db,
        destination="ENVIRONMENT_MONITORING",
        message_type="ENVIRONMENT_ALARM_DECIDED",
        aggregate_type="GspEnvironmentAlarm",
        aggregate_id=str(alarm.id),
        payload={"alarm": model_snapshot(alarm)},
    )
    return alarm


def scan_offline_assignments(
    db: Session,
    *,
    actor_id: int,
    source_ip: str | None = None,
) -> list[GspEnvironmentAlarm]:
    now = utc_now()
    alarms = []
    assignments = db.query(GspEnvironmentAssignment).filter(
        GspEnvironmentAssignment.status == "ACTIVE"
    ).with_for_update().all()
    for assignment in assignments:
        baseline = assignment.last_reading_at or assignment.approved_at
        if not baseline or (now - baseline).total_seconds() <= assignment.offline_after_seconds:
            continue
        existing = db.query(GspEnvironmentAlarm).filter(
            GspEnvironmentAlarm.assignment_id == assignment.id,
            GspEnvironmentAlarm.alarm_type == "DEVICE_OFFLINE",
            GspEnvironmentAlarm.status.in_(["OPEN", "ACKNOWLEDGED"]),
        ).first()
        if existing:
            continue
        elapsed = Decimal(str(round((now - baseline).total_seconds(), 3)))
        alarms.append(
            _raise_alarm(
                db,
                assignment=assignment,
                reading=None,
                alarm_type="DEVICE_OFFLINE",
                severity="CRITICAL",
                observed_value=elapsed,
                threshold_value=Decimal(assignment.offline_after_seconds),
                detail="设备超过批准离线判定时间未收到读数",
                actor_id=actor_id,
                source_ip=source_ip,
            )
        )
    return alarms


def close_assignment(
    db: Session,
    *,
    assignment: GspEnvironmentAssignment,
    reason: str,
    actor_id: int,
    source_ip: str | None = None,
) -> GspEnvironmentAssignment:
    if assignment.status != "ACTIVE":
        raise WorkflowError(409, "只有生效中的监测分配可以关闭")
    unresolved = db.query(GspEnvironmentAlarm).filter(
        GspEnvironmentAlarm.assignment_id == assignment.id,
        GspEnvironmentAlarm.status.in_(["OPEN", "ACKNOWLEDGED"]),
    ).count()
    if unresolved:
        raise WorkflowError(409, "监测分配仍有未完成质量决定的告警")
    before = model_snapshot(assignment)
    assignment.status = "CLOSED"
    assignment.closed_by = actor_id
    assignment.closed_at = utc_now()
    assignment.close_reason = reason
    _audit(
        db,
        actor_id=actor_id,
        action="ENVIRONMENT_ASSIGNMENT_CLOSED",
        entity=assignment,
        reason=reason,
        before=before,
        source_ip=source_ip,
    )
    return assignment

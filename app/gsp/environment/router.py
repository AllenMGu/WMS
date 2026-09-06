from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.dependencies import require_gsp_roles
from app.gsp.electronic_signature.dependencies import require_electronic_signature
from app.gsp.environment.models import (
    GspEnvironmentAlarm,
    GspEnvironmentAssignment,
    GspEnvironmentDevice,
    GspEnvironmentReading,
)
from app.gsp.environment.schemas import (
    AlarmAcknowledge,
    AlarmDecision,
    AssignmentClose,
    DeviceRecalibration,
    EnvironmentAlarmResponse,
    EnvironmentAssignmentCreate,
    EnvironmentAssignmentResponse,
    EnvironmentDecision,
    EnvironmentDeviceCreate,
    EnvironmentDeviceResponse,
    EnvironmentReadingCreate,
    EnvironmentReadingResponse,
)
from app.gsp.environment.service import (
    acknowledge_alarm,
    close_assignment,
    create_assignment,
    create_device,
    decide_alarm,
    decide_assignment,
    decide_device,
    ingest_reading,
    recalibrate_device,
    scan_offline_assignments,
    suspend_device,
    verify_reading_chain,
)
from app.gsp.errors import WorkflowError
from app.legacy import User

router = APIRouter(prefix="/gsp/environment", tags=["GSP温湿度监测"])
QUALITY_ROLES = ("QUALITY_MANAGER", "QUALITY_REVIEWER")
READ_ROLES = ("ENVIRONMENT_MONITOR", "AUDITOR", *QUALITY_ROLES)


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _get(db: Session, model, entity_id: int, detail: str, *, lock: bool = False):
    query = db.query(model).filter(model.id == entity_id)
    if lock:
        query = query.with_for_update()
    entity = query.first()
    if entity is None:
        raise HTTPException(404, detail)
    return entity


def _rollback_and_raise(db: Session, error: Exception):
    db.rollback()
    if isinstance(error, WorkflowError):
        raise HTTPException(error.status_code, error.detail) from error
    if isinstance(error, IntegrityError):
        raise HTTPException(409, "设备、分配、读数或告警业务编号重复") from error
    raise error


@router.post("/devices", response_model=EnvironmentDeviceResponse, status_code=201)
def add_device(
    payload: EnvironmentDeviceCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("ENVIRONMENT_MONITOR")),
    db: Session = Depends(get_db),
):
    try:
        device = create_device(
            db,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        db.refresh(device)
        return device
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.get("/devices", response_model=list[EnvironmentDeviceResponse])
def list_devices(
    status: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_gsp_roles(*READ_ROLES)),
    db: Session = Depends(get_db),
):
    query = db.query(GspEnvironmentDevice)
    if status:
        query = query.filter(GspEnvironmentDevice.status == status)
    return query.order_by(GspEnvironmentDevice.id.desc()).offset(offset).limit(limit).all()


@router.post(
    "/devices/{device_id}/decision",
    response_model=EnvironmentDeviceResponse,
    dependencies=[Depends(require_electronic_signature(
        "ENVIRONMENT_DEVICE_DECISION", "GspEnvironmentDevice",
        entity_id_param="device_id", meaning="APPROVAL",
    ))],
)
def approve_device(
    device_id: int,
    payload: EnvironmentDecision,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    device = _get(db, GspEnvironmentDevice, device_id, "监测设备不存在", lock=True)
    try:
        decide_device(
            db,
            device=device,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return device
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.post("/devices/{device_id}/recalibrate", response_model=EnvironmentDeviceResponse)
def recalibrate(
    device_id: int,
    payload: DeviceRecalibration,
    request: Request,
    current_user: User = Depends(require_gsp_roles("ENVIRONMENT_MONITOR")),
    db: Session = Depends(get_db),
):
    device = _get(db, GspEnvironmentDevice, device_id, "监测设备不存在", lock=True)
    try:
        recalibrate_device(
            db,
            device=device,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return device
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.post(
    "/devices/{device_id}/suspend",
    response_model=EnvironmentDeviceResponse,
    dependencies=[Depends(require_electronic_signature(
        "ENVIRONMENT_DEVICE_SUSPEND", "GspEnvironmentDevice",
        entity_id_param="device_id", meaning="RESPONSIBILITY",
    ))],
)
def suspend(
    device_id: int,
    payload: AssignmentClose,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    device = _get(db, GspEnvironmentDevice, device_id, "监测设备不存在", lock=True)
    try:
        suspend_device(
            db,
            device=device,
            reason=payload.reason,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return device
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.post("/assignments", response_model=EnvironmentAssignmentResponse, status_code=201)
def add_assignment(
    payload: EnvironmentAssignmentCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("ENVIRONMENT_MONITOR")),
    db: Session = Depends(get_db),
):
    try:
        assignment = create_assignment(
            db,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        db.refresh(assignment)
        return assignment
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.get("/assignments", response_model=list[EnvironmentAssignmentResponse])
def list_assignments(
    status: str | None = None,
    context_type: str | None = None,
    transport_task_id: int | None = Query(None, gt=0),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_gsp_roles(*READ_ROLES)),
    db: Session = Depends(get_db),
):
    query = db.query(GspEnvironmentAssignment)
    if status:
        query = query.filter(GspEnvironmentAssignment.status == status)
    if context_type:
        query = query.filter(GspEnvironmentAssignment.context_type == context_type)
    if transport_task_id:
        query = query.filter(GspEnvironmentAssignment.transport_task_id == transport_task_id)
    return query.order_by(GspEnvironmentAssignment.id.desc()).offset(offset).limit(limit).all()


@router.post(
    "/assignments/{assignment_id}/decision",
    response_model=EnvironmentAssignmentResponse,
    dependencies=[Depends(require_electronic_signature(
        "ENVIRONMENT_ASSIGNMENT_DECISION", "GspEnvironmentAssignment",
        entity_id_param="assignment_id", meaning="APPROVAL",
    ))],
)
def approve_assignment(
    assignment_id: int,
    payload: EnvironmentDecision,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    assignment = _get(
        db,
        GspEnvironmentAssignment,
        assignment_id,
        "监测分配不存在",
        lock=True,
    )
    try:
        decide_assignment(
            db,
            assignment=assignment,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return assignment
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.post(
    "/assignments/{assignment_id}/readings",
    response_model=EnvironmentReadingResponse,
    status_code=201,
)
def add_reading(
    assignment_id: int,
    payload: EnvironmentReadingCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("ENVIRONMENT_MONITOR")),
    db: Session = Depends(get_db),
):
    assignment = _get(
        db,
        GspEnvironmentAssignment,
        assignment_id,
        "监测分配不存在",
        lock=True,
    )
    try:
        reading = ingest_reading(
            db,
            assignment=assignment,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        db.refresh(reading)
        return reading
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/assignments/{assignment_id}/close",
    response_model=EnvironmentAssignmentResponse,
    dependencies=[Depends(require_electronic_signature(
        "ENVIRONMENT_ASSIGNMENT_CLOSE", "GspEnvironmentAssignment",
        entity_id_param="assignment_id", meaning="RESPONSIBILITY",
    ))],
)
def close_monitoring_assignment(
    assignment_id: int,
    payload: AssignmentClose,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    assignment = _get(
        db,
        GspEnvironmentAssignment,
        assignment_id,
        "监测分配不存在",
        lock=True,
    )
    try:
        close_assignment(
            db,
            assignment=assignment,
            reason=payload.reason,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return assignment
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.get(
    "/assignments/{assignment_id}/readings",
    response_model=list[EnvironmentReadingResponse],
)
def list_readings(
    assignment_id: int,
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_gsp_roles(*READ_ROLES)),
    db: Session = Depends(get_db),
):
    _get(db, GspEnvironmentAssignment, assignment_id, "监测分配不存在")
    return (
        db.query(GspEnvironmentReading)
        .filter(GspEnvironmentReading.assignment_id == assignment_id)
        .order_by(GspEnvironmentReading.observed_at.desc(), GspEnvironmentReading.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/assignments/{assignment_id}/verify-chain")
def verify_chain(
    assignment_id: int,
    current_user: User = Depends(require_gsp_roles("AUDITOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    _get(db, GspEnvironmentAssignment, assignment_id, "监测分配不存在")
    valid, broken_reading_id = verify_reading_chain(db, assignment_id)
    return {"assignment_id": assignment_id, "valid": valid, "broken_reading_id": broken_reading_id}


@router.get("/alarms", response_model=list[EnvironmentAlarmResponse])
def list_alarms(
    status: str | None = None,
    severity: str | None = None,
    assignment_id: int | None = Query(None, gt=0),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_gsp_roles(*READ_ROLES)),
    db: Session = Depends(get_db),
):
    query = db.query(GspEnvironmentAlarm)
    if status:
        query = query.filter(GspEnvironmentAlarm.status == status)
    if severity:
        query = query.filter(GspEnvironmentAlarm.severity == severity)
    if assignment_id:
        query = query.filter(GspEnvironmentAlarm.assignment_id == assignment_id)
    return query.order_by(GspEnvironmentAlarm.id.desc()).offset(offset).limit(limit).all()


@router.post("/alarms/{alarm_id}/acknowledge", response_model=EnvironmentAlarmResponse)
def acknowledge(
    alarm_id: int,
    payload: AlarmAcknowledge,
    request: Request,
    current_user: User = Depends(require_gsp_roles("ENVIRONMENT_MONITOR")),
    db: Session = Depends(get_db),
):
    alarm = _get(db, GspEnvironmentAlarm, alarm_id, "环境告警不存在", lock=True)
    try:
        acknowledge_alarm(
            db,
            alarm=alarm,
            reason=payload.reason,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return alarm
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.post(
    "/alarms/{alarm_id}/decision",
    response_model=EnvironmentAlarmResponse,
    dependencies=[Depends(require_electronic_signature(
        "ENVIRONMENT_ALARM_DECISION", "GspEnvironmentAlarm",
        entity_id_param="alarm_id", meaning="APPROVAL",
    ))],
)
def quality_decision(
    alarm_id: int,
    payload: AlarmDecision,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    alarm = _get(db, GspEnvironmentAlarm, alarm_id, "环境告警不存在", lock=True)
    try:
        decide_alarm(
            db,
            alarm=alarm,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return alarm
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.post("/alarms/scan-offline", response_model=list[EnvironmentAlarmResponse])
def scan_offline(
    request: Request,
    current_user: User = Depends(require_gsp_roles("ENVIRONMENT_MONITOR")),
    db: Session = Depends(get_db),
):
    try:
        alarms = scan_offline_assignments(
            db,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return alarms
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)

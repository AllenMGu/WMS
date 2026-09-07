from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.dependencies import require_gsp_roles
from app.gsp.electronic_signature.dependencies import require_electronic_signature
from app.gsp.errors import WorkflowError
from app.gsp.schemas import ChangeReason
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
    CarrierDocumentResponse,
    CarrierDriverCreate,
    CarrierDriverResponse,
    CarrierResponse,
    CarrierVehicleCreate,
    CarrierVehicleResponse,
    DeliveryCreate,
    TransportClose,
    TransportEventCreate,
    TransportEventResponse,
    TransportExceptionCreate,
    TransportExceptionDecision,
    TransportExceptionResponse,
    TransportTaskResponse,
)
from app.gsp.transport.service import (
    add_carrier_document,
    close_transport_task,
    create_carrier,
    create_driver,
    create_transport_exception,
    create_vehicle,
    decide_carrier,
    decide_driver,
    decide_transport_exception,
    decide_vehicle,
    record_delivery,
    record_transport_event,
    suspend_carrier,
    verify_carrier_document,
)
from app.legacy import User

router = APIRouter(prefix="/gsp/transport", tags=["GSP运输与签收"])
QUALITY_ROLES = ("QUALITY_MANAGER", "QUALITY_REVIEWER")


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
        raise HTTPException(409, "承运商、车辆、驾驶员或运输业务编号重复") from error
    raise error


@router.post("/carriers", response_model=CarrierResponse, status_code=201)
def create_carrier_record(
    payload: CarrierCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("TRANSPORT_COORDINATOR")),
    db: Session = Depends(get_db),
):
    try:
        carrier = create_carrier(
            db, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
        )
        db.commit()
        db.refresh(carrier)
        return carrier
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.get("/carriers", response_model=list[CarrierResponse])
def list_carriers(
    status: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(
        require_gsp_roles("TRANSPORT_COORDINATOR", "AUDITOR", *QUALITY_ROLES)
    ),
    db: Session = Depends(get_db),
):
    query = db.query(GspCarrier)
    if status:
        query = query.filter(GspCarrier.status == status)
    return query.order_by(GspCarrier.id.desc()).offset(offset).limit(limit).all()


@router.get(
    "/carriers/{carrier_id}/documents",
    response_model=list[CarrierDocumentResponse],
)
def list_carrier_documents(
    carrier_id: int,
    current_user: User = Depends(
        require_gsp_roles("TRANSPORT_COORDINATOR", "AUDITOR", *QUALITY_ROLES)
    ),
    db: Session = Depends(get_db),
):
    _get(db, GspCarrier, carrier_id, "承运商不存在")
    return (
        db.query(GspCarrierDocument)
        .filter(GspCarrierDocument.carrier_id == carrier_id)
        .order_by(GspCarrierDocument.id)
        .all()
    )


@router.get(
    "/carriers/{carrier_id}/vehicles",
    response_model=list[CarrierVehicleResponse],
)
def list_carrier_vehicles(
    carrier_id: int,
    current_user: User = Depends(
        require_gsp_roles("TRANSPORT_COORDINATOR", "AUDITOR", *QUALITY_ROLES)
    ),
    db: Session = Depends(get_db),
):
    _get(db, GspCarrier, carrier_id, "承运商不存在")
    return (
        db.query(GspCarrierVehicle)
        .filter(GspCarrierVehicle.carrier_id == carrier_id)
        .order_by(GspCarrierVehicle.id)
        .all()
    )


@router.get(
    "/carriers/{carrier_id}/drivers",
    response_model=list[CarrierDriverResponse],
)
def list_carrier_drivers(
    carrier_id: int,
    current_user: User = Depends(
        require_gsp_roles("TRANSPORT_COORDINATOR", "AUDITOR", *QUALITY_ROLES)
    ),
    db: Session = Depends(get_db),
):
    _get(db, GspCarrier, carrier_id, "承运商不存在")
    return (
        db.query(GspCarrierDriver)
        .filter(GspCarrierDriver.carrier_id == carrier_id)
        .order_by(GspCarrierDriver.id)
        .all()
    )


@router.post(
    "/carriers/{carrier_id}/documents",
    response_model=CarrierDocumentResponse,
    status_code=201,
)
def add_document(
    carrier_id: int,
    payload: CarrierDocumentCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("TRANSPORT_COORDINATOR")),
    db: Session = Depends(get_db),
):
    carrier = _get(db, GspCarrier, carrier_id, "承运商不存在", lock=True)
    try:
        document = add_carrier_document(
            db,
            carrier=carrier,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        db.refresh(document)
        return document
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/documents/{document_id}/decision",
    response_model=CarrierDocumentResponse,
    dependencies=[Depends(require_electronic_signature(
        "CARRIER_DOCUMENT_DECISION", "GspCarrierDocument",
        entity_id_param="document_id", meaning="REVIEW",
    ))],
)
def decide_document(
    document_id: int,
    payload: ApprovalDecision,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    document = _get(db, GspCarrierDocument, document_id, "承运商文件不存在", lock=True)
    try:
        verify_carrier_document(
            db,
            document=document,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return document
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.post(
    "/carriers/{carrier_id}/decision",
    response_model=CarrierResponse,
    dependencies=[Depends(require_electronic_signature(
        "CARRIER_DECISION", "GspCarrier",
        entity_id_param="carrier_id", meaning="APPROVAL",
    ))],
)
def approve_carrier_record(
    carrier_id: int,
    payload: ApprovalDecision,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    carrier = _get(db, GspCarrier, carrier_id, "承运商不存在", lock=True)
    try:
        decide_carrier(
            db,
            carrier=carrier,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return carrier
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.post("/carriers/{carrier_id}/suspend", response_model=CarrierResponse)
def suspend_carrier_record(
    carrier_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    carrier = _get(db, GspCarrier, carrier_id, "承运商不存在", lock=True)
    try:
        suspend_carrier(
            db,
            carrier=carrier,
            reason=payload.reason,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return carrier
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.post(
    "/carriers/{carrier_id}/vehicles",
    response_model=CarrierVehicleResponse,
    status_code=201,
)
def create_carrier_vehicle(
    carrier_id: int,
    payload: CarrierVehicleCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("TRANSPORT_COORDINATOR")),
    db: Session = Depends(get_db),
):
    carrier = _get(db, GspCarrier, carrier_id, "承运商不存在", lock=True)
    try:
        vehicle = create_vehicle(
            db,
            carrier=carrier,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        db.refresh(vehicle)
        return vehicle
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/vehicles/{vehicle_id}/decision",
    response_model=CarrierVehicleResponse,
    dependencies=[Depends(require_electronic_signature(
        "CARRIER_VEHICLE_DECISION", "GspCarrierVehicle",
        entity_id_param="vehicle_id", meaning="APPROVAL",
    ))],
)
def approve_vehicle(
    vehicle_id: int,
    payload: ApprovalDecision,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    vehicle = _get(db, GspCarrierVehicle, vehicle_id, "承运车辆不存在", lock=True)
    try:
        decide_vehicle(
            db,
            vehicle=vehicle,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return vehicle
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.post(
    "/carriers/{carrier_id}/drivers",
    response_model=CarrierDriverResponse,
    status_code=201,
)
def create_carrier_driver(
    carrier_id: int,
    payload: CarrierDriverCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("TRANSPORT_COORDINATOR")),
    db: Session = Depends(get_db),
):
    carrier = _get(db, GspCarrier, carrier_id, "承运商不存在", lock=True)
    try:
        driver = create_driver(
            db,
            carrier=carrier,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        db.refresh(driver)
        return driver
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/drivers/{driver_id}/decision",
    response_model=CarrierDriverResponse,
    dependencies=[Depends(require_electronic_signature(
        "CARRIER_DRIVER_DECISION", "GspCarrierDriver",
        entity_id_param="driver_id", meaning="APPROVAL",
    ))],
)
def approve_driver(
    driver_id: int,
    payload: ApprovalDecision,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    driver = _get(db, GspCarrierDriver, driver_id, "承运驾驶员不存在", lock=True)
    try:
        decide_driver(
            db,
            driver=driver,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return driver
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.get("/tasks", response_model=list[TransportTaskResponse])
def list_tasks(
    status: str | None = None,
    shipment_id: int | None = Query(None, gt=0),
    carrier_id: int | None = Query(None, gt=0),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(
        require_gsp_roles("TRANSPORT_COORDINATOR", "AUDITOR", *QUALITY_ROLES)
    ),
    db: Session = Depends(get_db),
):
    query = db.query(GspTransportTask)
    if status:
        query = query.filter(GspTransportTask.status == status)
    if shipment_id:
        query = query.filter(GspTransportTask.shipment_id == shipment_id)
    if carrier_id:
        query = query.filter(GspTransportTask.carrier_id == carrier_id)
    return query.order_by(GspTransportTask.id.desc()).offset(offset).limit(limit).all()


@router.get("/tasks/{task_id}", response_model=TransportTaskResponse)
def get_task(
    task_id: int,
    current_user: User = Depends(
        require_gsp_roles("TRANSPORT_COORDINATOR", "AUDITOR", *QUALITY_ROLES)
    ),
    db: Session = Depends(get_db),
):
    return _get(db, GspTransportTask, task_id, "运输任务不存在")


@router.get("/tasks/{task_id}/events", response_model=list[TransportEventResponse])
def list_task_events(
    task_id: int,
    current_user: User = Depends(
        require_gsp_roles("TRANSPORT_COORDINATOR", "AUDITOR", *QUALITY_ROLES)
    ),
    db: Session = Depends(get_db),
):
    _get(db, GspTransportTask, task_id, "运输任务不存在")
    return (
        db.query(GspTransportEvent)
        .filter(GspTransportEvent.task_id == task_id)
        .order_by(GspTransportEvent.occurred_at, GspTransportEvent.id)
        .all()
    )


@router.post("/tasks/{task_id}/events", response_model=TransportEventResponse, status_code=201)
def add_task_event(
    task_id: int,
    payload: TransportEventCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("TRANSPORT_COORDINATOR")),
    db: Session = Depends(get_db),
):
    task = _get(db, GspTransportTask, task_id, "运输任务不存在", lock=True)
    try:
        event = record_transport_event(
            db,
            task=task,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        db.refresh(event)
        return event
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.post(
    "/tasks/{task_id}/exceptions",
    response_model=TransportExceptionResponse,
    status_code=201,
)
def add_task_exception(
    task_id: int,
    payload: TransportExceptionCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("TRANSPORT_COORDINATOR")),
    db: Session = Depends(get_db),
):
    task = _get(db, GspTransportTask, task_id, "运输任务不存在", lock=True)
    try:
        exception = create_transport_exception(
            db,
            task=task,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        db.refresh(exception)
        return exception
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.get(
    "/tasks/{task_id}/exceptions",
    response_model=list[TransportExceptionResponse],
)
def list_task_exceptions(
    task_id: int,
    current_user: User = Depends(
        require_gsp_roles("TRANSPORT_COORDINATOR", "AUDITOR", *QUALITY_ROLES)
    ),
    db: Session = Depends(get_db),
):
    _get(db, GspTransportTask, task_id, "运输任务不存在")
    return (
        db.query(GspTransportException)
        .filter(GspTransportException.task_id == task_id)
        .order_by(GspTransportException.id)
        .all()
    )


@router.post(
    "/exceptions/{exception_id}/decision",
    response_model=TransportExceptionResponse,
    dependencies=[Depends(require_electronic_signature(
        "TRANSPORT_EXCEPTION_DECISION", "GspTransportException",
        entity_id_param="exception_id", meaning="APPROVAL",
    ))],
)
def decide_exception(
    exception_id: int,
    payload: TransportExceptionDecision,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    exception = _get(
        db, GspTransportException, exception_id, "运输异常不存在", lock=True
    )
    try:
        decide_transport_exception(
            db,
            exception=exception,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return exception
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.post(
    "/tasks/{task_id}/delivery",
    response_model=TransportTaskResponse,
    dependencies=[Depends(require_electronic_signature(
        "TRANSPORT_DELIVERY", "GspTransportTask",
        entity_id_param="task_id", meaning="CONFIRMATION",
    ))],
)
def deliver_task(
    task_id: int,
    payload: DeliveryCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("TRANSPORT_COORDINATOR")),
    db: Session = Depends(get_db),
):
    task = _get(db, GspTransportTask, task_id, "运输任务不存在", lock=True)
    try:
        record_delivery(
            db,
            task=task,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return task
    except WorkflowError as error:
        _rollback_and_raise(db, error)


@router.post(
    "/tasks/{task_id}/close",
    response_model=TransportTaskResponse,
    dependencies=[Depends(require_electronic_signature(
        "TRANSPORT_CLOSE", "GspTransportTask",
        entity_id_param="task_id", meaning="REVIEW",
    ))],
)
def close_task(
    task_id: int,
    payload: TransportClose,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    task = _get(db, GspTransportTask, task_id, "运输任务不存在", lock=True)
    try:
        close_transport_task(
            db,
            task=task,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return task
    except WorkflowError as error:
        _rollback_and_raise(db, error)

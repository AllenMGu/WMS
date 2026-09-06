from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.dependencies import require_gsp_roles
from app.gsp.electronic_signature.dependencies import require_electronic_signature
from app.gsp.errors import WorkflowError
from app.gsp.maintenance.models import GspExpiryAlert, GspMaintenancePlan
from app.gsp.maintenance.schemas import (
    ExpiryAlertDecision,
    ExpiryAlertResponse,
    MaintenanceCompletion,
    MaintenanceInspection,
    MaintenancePlanCreate,
    MaintenancePlanResponse,
)
from app.gsp.maintenance.service import (
    approve_maintenance_plan,
    complete_maintenance_plan,
    create_maintenance_plan,
    inspect_maintenance_item,
    maintenance_plan_payload,
    resolve_expiry_alert,
    submit_maintenance_plan,
)
from app.gsp.schemas import ChangeReason
from app.legacy import User, get_current_user

router = APIRouter(prefix="/gsp/maintenance", tags=["GSP药品养护"])
QUALITY_ROLES = ("QUALITY_MANAGER", "QUALITY_REVIEWER")


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _rollback_and_raise(db: Session, error: Exception):
    db.rollback()
    if isinstance(error, WorkflowError):
        raise HTTPException(error.status_code, error.detail) from error
    if isinstance(error, IntegrityError):
        raise HTTPException(409, "养护计划编号或明细重复") from error
    raise error


@router.get("/expiry-alerts", response_model=list[ExpiryAlertResponse])
def list_expiry_alerts(
    status: str | None = None,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(GspExpiryAlert)
    if status:
        query = query.filter(GspExpiryAlert.status == status.upper())
    return query.order_by(GspExpiryAlert.id.desc()).all()


@router.post(
    "/expiry-alerts/{alert_id}/resolve",
    response_model=ExpiryAlertResponse,
    dependencies=[Depends(require_electronic_signature(
        "EXPIRY_ALERT_RESOLVE", "GspExpiryAlert",
        entity_id_param="alert_id", meaning="REVIEW",
    ))],
)
def close_expiry_alert(
    alert_id: int,
    payload: ExpiryAlertDecision,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        alert = resolve_expiry_alert(
            db,
            alert_id=alert_id,
            resolution=payload.resolution,
            evidence_ref=payload.evidence_ref,
            review_due_on=payload.review_due_on,
            reason=payload.reason,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return alert
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post("/plans", response_model=MaintenancePlanResponse, status_code=201)
def create_plan(
    payload: MaintenancePlanCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("MAINTENANCE", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        plan = create_maintenance_plan(
            db,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return maintenance_plan_payload(db, plan)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.get("/plans", response_model=list[MaintenancePlanResponse])
def list_plans(
    status: str | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(GspMaintenancePlan)
    if status:
        query = query.filter(GspMaintenancePlan.status == status.upper())
    return [
        maintenance_plan_payload(db, plan)
        for plan in query.order_by(GspMaintenancePlan.id.desc()).all()
    ]


@router.post("/plans/{plan_id}/submit", response_model=MaintenancePlanResponse)
def submit_plan(
    plan_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles("MAINTENANCE", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        plan = submit_maintenance_plan(
            db,
            plan_id=plan_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return maintenance_plan_payload(db, plan)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/plans/{plan_id}/approve",
    response_model=MaintenancePlanResponse,
    dependencies=[Depends(require_electronic_signature(
        "MAINTENANCE_PLAN_APPROVE", "GspMaintenancePlan",
        entity_id_param="plan_id", meaning="APPROVAL",
    ))],
)
def approve_plan(
    plan_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        plan = approve_maintenance_plan(
            db,
            plan_id=plan_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return maintenance_plan_payload(db, plan)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/plans/{plan_id}/items/{item_id}/inspect",
    response_model=MaintenancePlanResponse,
)
def inspect_item(
    plan_id: int,
    item_id: int,
    payload: MaintenanceInspection,
    request: Request,
    current_user: User = Depends(require_gsp_roles("MAINTENANCE")),
    db: Session = Depends(get_db),
):
    try:
        plan = inspect_maintenance_item(
            db,
            plan_id=plan_id,
            item_id=item_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return maintenance_plan_payload(db, plan)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/plans/{plan_id}/complete",
    response_model=MaintenancePlanResponse,
    dependencies=[Depends(require_electronic_signature(
        "MAINTENANCE_PLAN_COMPLETE", "GspMaintenancePlan",
        entity_id_param="plan_id", meaning="REVIEW",
    ))],
)
def complete_plan(
    plan_id: int,
    payload: MaintenanceCompletion,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        plan = complete_maintenance_plan(
            db,
            plan_id=plan_id,
            conclusion=payload.conclusion,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return maintenance_plan_payload(db, plan)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)

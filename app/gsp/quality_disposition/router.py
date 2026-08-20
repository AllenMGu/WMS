from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.dependencies import require_gsp_roles
from app.gsp.errors import WorkflowError
from app.gsp.quality_disposition.models import GspNonconformingRecord, GspPurchaseReturn
from app.gsp.quality_disposition.schemas import (
    DestructionExecution,
    DispositionApproval,
    NonconformingResponse,
    NonconformingStockCreate,
    PurchaseReturnCreate,
    PurchaseReturnDispatch,
    PurchaseReturnResponse,
)
from app.gsp.quality_disposition.service import (
    approve_disposition,
    approve_purchase_return,
    create_purchase_return,
    dispatch_purchase_return,
    execute_destruction,
    purchase_return_payload,
    register_nonconforming_stock,
    submit_purchase_return,
)
from app.gsp.schemas import ChangeReason
from app.legacy import User, get_current_user

router = APIRouter(prefix="/gsp", tags=["GSP不合格品与购进退出"])
QUALITY_ROLES = ("QUALITY_MANAGER", "QUALITY_REVIEWER")


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _rollback_and_raise(db: Session, error: Exception):
    db.rollback()
    if isinstance(error, WorkflowError):
        raise HTTPException(error.status_code, error.detail) from error
    if isinstance(error, IntegrityError):
        raise HTTPException(409, "不合格品记录号、购进退出单号或业务明细重复") from error
    raise error


@router.post(
    "/quality/nonconforming",
    response_model=NonconformingResponse,
    status_code=201,
)
async def create_nonconforming_record(
    payload: NonconformingStockCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES, "MAINTENANCE")),
    db: Session = Depends(get_db),
):
    try:
        record = register_nonconforming_stock(
            db,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        db.refresh(record)
        return record
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.get("/quality/nonconforming", response_model=list[NonconformingResponse])
async def list_nonconforming_records(
    status: str | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(GspNonconformingRecord)
    if status:
        query = query.filter(GspNonconformingRecord.status == status)
    return query.order_by(GspNonconformingRecord.id.desc()).all()


@router.post(
    "/quality/nonconforming/{record_id}/approve",
    response_model=NonconformingResponse,
)
async def approve_nonconforming_disposition(
    record_id: int,
    payload: DispositionApproval,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        record = approve_disposition(
            db,
            record_id=record_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        db.refresh(record)
        return record
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/quality/nonconforming/{record_id}/destroy",
    response_model=NonconformingResponse,
)
async def destroy_nonconforming_product(
    record_id: int,
    payload: DestructionExecution,
    request: Request,
    current_user: User = Depends(require_gsp_roles("WAREHOUSE_CUSTODIAN")),
    db: Session = Depends(get_db),
):
    try:
        record = execute_destruction(
            db,
            record_id=record_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        db.refresh(record)
        return record
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/procurement/returns",
    response_model=PurchaseReturnResponse,
    status_code=201,
)
async def create_supplier_return(
    payload: PurchaseReturnCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("PROCUREMENT")),
    db: Session = Depends(get_db),
):
    try:
        purchase_return = create_purchase_return(
            db,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return purchase_return_payload(db, purchase_return)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.get("/procurement/returns", response_model=list[PurchaseReturnResponse])
async def list_supplier_returns(
    status: str | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(GspPurchaseReturn)
    if status:
        query = query.filter(GspPurchaseReturn.status == status)
    return [
        purchase_return_payload(db, item)
        for item in query.order_by(GspPurchaseReturn.id.desc()).all()
    ]


@router.post(
    "/procurement/returns/{return_id}/submit",
    response_model=PurchaseReturnResponse,
)
async def submit_supplier_return(
    return_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles("PROCUREMENT")),
    db: Session = Depends(get_db),
):
    try:
        purchase_return = submit_purchase_return(
            db,
            return_id=return_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return purchase_return_payload(db, purchase_return)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/procurement/returns/{return_id}/approve",
    response_model=PurchaseReturnResponse,
)
async def approve_supplier_return(
    return_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        purchase_return = approve_purchase_return(
            db,
            return_id=return_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return purchase_return_payload(db, purchase_return)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/procurement/returns/{return_id}/dispatch",
    response_model=PurchaseReturnResponse,
)
async def dispatch_supplier_return(
    return_id: int,
    payload: PurchaseReturnDispatch,
    request: Request,
    current_user: User = Depends(require_gsp_roles("WAREHOUSE_CUSTODIAN")),
    db: Session = Depends(get_db),
):
    try:
        purchase_return = dispatch_purchase_return(
            db,
            return_id=return_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return purchase_return_payload(db, purchase_return)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


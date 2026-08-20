from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.dependencies import require_gsp_roles
from app.gsp.errors import WorkflowError
from app.gsp.returns_recalls.models import GspRecall, GspRecallDrill, GspSalesReturn
from app.gsp.returns_recalls.schemas import (
    RecallClose,
    RecallCompletionReportCreate,
    RecallCreate,
    RecallDrillComplete,
    RecallDrillCreate,
    RecallDrillResponse,
    RecallDrillTargetVerification,
    RecallProgressCreate,
    RecallResponse,
    RecallTargetNotification,
    SalesReturnCreate,
    SalesReturnInspection,
    SalesReturnResponse,
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
    recall_drill_payload,
    recall_payload,
    record_recall_progress,
    sales_return_payload,
    submit_recall_completion_report,
    verify_recall_drill_target,
)
from app.gsp.schemas import ChangeReason
from app.legacy import User, get_current_user

router = APIRouter(prefix="/gsp", tags=["GSP退货召回"])
QUALITY_ROLES = ("QUALITY_MANAGER", "QUALITY_REVIEWER")


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _rollback_and_raise(db: Session, error: Exception):
    db.rollback()
    if isinstance(error, WorkflowError):
        raise HTTPException(error.status_code, error.detail) from error
    if isinstance(error, IntegrityError):
        raise HTTPException(409, "退货单号、召回单号或业务明细重复") from error
    raise error


@router.post("/returns/sales", response_model=SalesReturnResponse, status_code=201)
async def receive_sales_return(
    payload: SalesReturnCreate,
    request: Request,
    current_user: User = Depends(
        require_gsp_roles("RETURNS_RECEIVER", "WAREHOUSE_CUSTODIAN")
    ),
    db: Session = Depends(get_db),
):
    try:
        sales_return = create_sales_return(
            db,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return sales_return_payload(db, sales_return)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.get("/returns/sales", response_model=list[SalesReturnResponse])
async def list_sales_returns(
    status: str | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(GspSalesReturn)
    if status:
        query = query.filter(GspSalesReturn.status == status)
    return [
        sales_return_payload(db, item)
        for item in query.order_by(GspSalesReturn.id.desc()).all()
    ]


@router.post(
    "/returns/sales/{return_id}/items/{item_id}/inspect",
    response_model=SalesReturnResponse,
)
async def inspect_sales_return(
    return_id: int,
    item_id: int,
    payload: SalesReturnInspection,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        sales_return = inspect_sales_return_item(
            db,
            return_id=return_id,
            item_id=item_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return sales_return_payload(db, sales_return)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post("/recalls/{recall_id}/progress", response_model=RecallResponse)
async def report_recall_progress(
    recall_id: int,
    payload: RecallProgressCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        recall = record_recall_progress(
            db,
            recall_id=recall_id,
            report_ref=payload.report_ref,
            summary=payload.summary,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return recall_payload(db, recall)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post("/recalls", response_model=RecallResponse, status_code=201)
async def create_product_recall(
    payload: RecallCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        recall = create_recall(
            db,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return recall_payload(db, recall)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.get("/recalls", response_model=list[RecallResponse])
async def list_product_recalls(
    status: str | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(GspRecall)
    if status:
        query = query.filter(GspRecall.status == status)
    return [recall_payload(db, item) for item in query.order_by(GspRecall.id.desc()).all()]


@router.post("/recalls/{recall_id}/activate", response_model=RecallResponse)
async def activate_product_recall(
    recall_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        recall = activate_recall(
            db,
            recall_id=recall_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return recall_payload(db, recall)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/recalls/{recall_id}/targets/{target_id}/notify",
    response_model=RecallResponse,
)
async def update_recall_target(
    recall_id: int,
    target_id: int,
    payload: RecallTargetNotification,
    request: Request,
    current_user: User = Depends(require_gsp_roles("SALES", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        recall = notify_recall_target(
            db,
            recall_id=recall_id,
            target_id=target_id,
            notification_status=payload.notification_status,
            notes=payload.notes,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return recall_payload(db, recall)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post("/recalls/{recall_id}/close", response_model=RecallResponse)
async def close_product_recall(
    recall_id: int,
    payload: RecallClose,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        recall = close_recall(
            db,
            recall_id=recall_id,
            conclusion=payload.conclusion,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return recall_payload(db, recall)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post("/recalls/{recall_id}/completion-report", response_model=RecallResponse)
async def report_recall_completion(
    recall_id: int,
    payload: RecallCompletionReportCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        recall = submit_recall_completion_report(
            db,
            recall_id=recall_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return recall_payload(db, recall)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post("/recall-drills", response_model=RecallDrillResponse, status_code=201)
async def create_product_recall_drill(
    payload: RecallDrillCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        drill = create_recall_drill(
            db,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return recall_drill_payload(db, drill)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.get("/recall-drills", response_model=list[RecallDrillResponse])
async def list_product_recall_drills(
    status: str | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(GspRecallDrill)
    if status:
        query = query.filter(GspRecallDrill.status == status.upper())
    return [
        recall_drill_payload(db, drill)
        for drill in query.order_by(GspRecallDrill.id.desc()).all()
    ]


@router.post("/recall-drills/{drill_id}/activate", response_model=RecallDrillResponse)
async def activate_product_recall_drill(
    drill_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        drill = activate_recall_drill(
            db,
            drill_id=drill_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return recall_drill_payload(db, drill)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/recall-drills/{drill_id}/targets/{target_id}/verify",
    response_model=RecallDrillResponse,
)
async def verify_product_recall_drill_target(
    drill_id: int,
    target_id: int,
    payload: RecallDrillTargetVerification,
    request: Request,
    current_user: User = Depends(require_gsp_roles("SALES", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        drill = verify_recall_drill_target(
            db,
            drill_id=drill_id,
            target_id=target_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return recall_drill_payload(db, drill)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post("/recall-drills/{drill_id}/complete", response_model=RecallDrillResponse)
async def complete_product_recall_drill(
    drill_id: int,
    payload: RecallDrillComplete,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        drill = complete_recall_drill(
            db,
            drill_id=drill_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return recall_drill_payload(db, drill)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)

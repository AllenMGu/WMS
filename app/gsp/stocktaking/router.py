from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.dependencies import require_gsp_roles
from app.gsp.errors import WorkflowError
from app.gsp.schemas import ChangeReason
from app.gsp.stocktaking.models import GspStocktakePlan
from app.gsp.stocktaking.schemas import (
    StocktakeCount,
    StocktakePlanCreate,
    StocktakePlanResponse,
    StocktakeReview,
)
from app.gsp.stocktaking.service import (
    apply_stocktake_adjustments,
    approve_stocktake_plan,
    create_stocktake_plan,
    record_stocktake_count,
    review_stocktake_results,
    stocktake_plan_payload,
    submit_stocktake_plan,
)
from app.legacy import User, get_current_user

router = APIRouter(prefix="/gsp/stocktaking", tags=["GSP批号库存盘点"])
QUALITY_ROLES = ("QUALITY_MANAGER", "QUALITY_REVIEWER")
STOCKTAKE_ROLES = ("STOCKTAKE", "WAREHOUSE_MANAGER")


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _rollback_and_raise(db: Session, error: Exception):
    db.rollback()
    if isinstance(error, WorkflowError):
        raise HTTPException(error.status_code, error.detail) from error
    if isinstance(error, IntegrityError):
        raise HTTPException(409, "盘点计划编号或明细重复") from error
    raise error


@router.post("/plans", response_model=StocktakePlanResponse, status_code=201)
async def create_plan(
    payload: StocktakePlanCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*STOCKTAKE_ROLES, *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        plan = create_stocktake_plan(
            db,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return stocktake_plan_payload(db, plan)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.get("/plans", response_model=list[StocktakePlanResponse])
async def list_plans(
    status: str | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(GspStocktakePlan)
    if status:
        query = query.filter(GspStocktakePlan.status == status.upper())
    return [stocktake_plan_payload(db, plan) for plan in query.order_by(GspStocktakePlan.id.desc())]


@router.get("/plans/{plan_id}", response_model=StocktakePlanResponse)
async def get_plan(
    plan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    plan = db.query(GspStocktakePlan).filter(GspStocktakePlan.id == plan_id).first()
    if not plan:
        raise HTTPException(404, "盘点计划不存在")
    return stocktake_plan_payload(db, plan)


@router.post("/plans/{plan_id}/submit", response_model=StocktakePlanResponse)
async def submit_plan(
    plan_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*STOCKTAKE_ROLES, *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        plan = submit_stocktake_plan(
            db,
            plan_id=plan_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return stocktake_plan_payload(db, plan)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post("/plans/{plan_id}/approve", response_model=StocktakePlanResponse)
async def approve_plan(
    plan_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        plan = approve_stocktake_plan(
            db,
            plan_id=plan_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return stocktake_plan_payload(db, plan)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post("/plans/{plan_id}/items/{item_id}/count", response_model=StocktakePlanResponse)
async def count_item(
    plan_id: int,
    item_id: int,
    payload: StocktakeCount,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*STOCKTAKE_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        plan = record_stocktake_count(
            db,
            plan_id=plan_id,
            item_id=item_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return stocktake_plan_payload(db, plan)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post("/plans/{plan_id}/review", response_model=StocktakePlanResponse)
async def review_plan(
    plan_id: int,
    payload: StocktakeReview,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        plan = review_stocktake_results(
            db,
            plan_id=plan_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return stocktake_plan_payload(db, plan)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post("/plans/{plan_id}/apply-adjustments", response_model=StocktakePlanResponse)
async def apply_adjustments(
    plan_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*STOCKTAKE_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        plan = apply_stocktake_adjustments(
            db,
            plan_id=plan_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return stocktake_plan_payload(db, plan)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)

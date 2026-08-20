from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.dependencies import require_gsp_roles
from app.gsp.procurement_receiving.models import GspPurchaseOrder, GspReceipt
from app.gsp.procurement_receiving.schemas import (
    PurchaseOrderCreate,
    PurchaseOrderResponse,
    ReceiptCreate,
    ReceiptInspection,
    ReceiptResponse,
)
from app.gsp.procurement_receiving.service import (
    WorkflowError,
    approve_purchase_order,
    create_purchase_order,
    create_receipt,
    inspect_receipt_item,
    order_payload,
    receipt_payload,
    submit_purchase_order,
)
from app.gsp.schemas import ChangeReason
from app.legacy import User, get_current_user

router = APIRouter(prefix="/gsp", tags=["GSP采购收货"])
QUALITY_ROLES = ("QUALITY_MANAGER", "QUALITY_REVIEWER")


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _rollback_and_raise(db: Session, error: Exception):
    db.rollback()
    if isinstance(error, WorkflowError):
        raise HTTPException(error.status_code, error.detail) from error
    if isinstance(error, IntegrityError):
        raise HTTPException(409, "订单号、收货单号或业务明细重复") from error
    raise error


@router.post(
    "/procurement/orders",
    response_model=PurchaseOrderResponse,
    status_code=201,
)
async def create_order(
    payload: PurchaseOrderCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("PROCUREMENT")),
    db: Session = Depends(get_db),
):
    try:
        order = create_purchase_order(
            db,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return order_payload(db, order)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.get("/procurement/orders", response_model=list[PurchaseOrderResponse])
async def list_orders(
    status: str | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(GspPurchaseOrder)
    if status:
        query = query.filter(GspPurchaseOrder.status == status)
    return [order_payload(db, order) for order in query.order_by(GspPurchaseOrder.id.desc()).all()]


@router.post(
    "/procurement/orders/{order_id}/submit",
    response_model=PurchaseOrderResponse,
)
async def submit_order(
    order_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles("PROCUREMENT")),
    db: Session = Depends(get_db),
):
    try:
        order = submit_purchase_order(
            db,
            order_id=order_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return order_payload(db, order)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/procurement/orders/{order_id}/approve",
    response_model=PurchaseOrderResponse,
)
async def approve_order(
    order_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        order = approve_purchase_order(
            db,
            order_id=order_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return order_payload(db, order)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post("/receiving/receipts", response_model=ReceiptResponse, status_code=201)
async def receive_order(
    payload: ReceiptCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("RECEIVER")),
    db: Session = Depends(get_db),
):
    try:
        receipt = create_receipt(
            db,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return receipt_payload(db, receipt)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.get("/receiving/receipts", response_model=list[ReceiptResponse])
async def list_receipts(
    status: str | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(GspReceipt)
    if status:
        query = query.filter(GspReceipt.status == status)
    return [receipt_payload(db, receipt) for receipt in query.order_by(GspReceipt.id.desc()).all()]


@router.post(
    "/receiving/receipts/{receipt_id}/items/{item_id}/inspect",
    response_model=ReceiptResponse,
)
async def inspect_item(
    receipt_id: int,
    item_id: int,
    payload: ReceiptInspection,
    request: Request,
    current_user: User = Depends(require_gsp_roles("INSPECTOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        receipt = inspect_receipt_item(
            db,
            receipt_id=receipt_id,
            item_id=item_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return receipt_payload(db, receipt)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)

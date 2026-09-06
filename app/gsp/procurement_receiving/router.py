from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.dependencies import require_gsp_roles
from app.gsp.electronic_signature.dependencies import require_electronic_signature
from app.gsp.errors import WorkflowError
from app.gsp.procurement_receiving.models import GspPurchaseOrder, GspReceipt
from app.gsp.procurement_receiving.schemas import (
    ControlledPrintCreate,
    ControlledPrintResponse,
    PurchaseOrderCreate,
    PurchaseOrderResponse,
    ReceiptCreate,
    ReceiptInspection,
    ReceiptResponse,
    ReceiptSampling,
)
from app.gsp.procurement_receiving.service import (
    approve_purchase_order,
    cancel_purchase_order,
    create_purchase_order,
    create_receipt,
    create_receipt_print_record,
    inspect_receipt_item,
    order_payload,
    receipt_payload,
    record_receipt_sampling,
    reject_purchase_order,
    submit_purchase_order,
)
from app.gsp.schemas import ChangeReason
from app.legacy import User

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
def create_order(
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
def list_orders(
    status: str | None = None,
    current_user: User = Depends(require_gsp_roles("PROCUREMENT", *QUALITY_ROLES)),
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
def submit_order(
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
    dependencies=[Depends(require_electronic_signature(
        "PURCHASE_ORDER_APPROVE", "GspPurchaseOrder",
        entity_id_param="order_id", meaning="APPROVAL",
    ))],
)
def approve_order(
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


@router.post(
    "/procurement/orders/{order_id}/cancel",
    response_model=PurchaseOrderResponse,
)
def cancel_order(
    order_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles("PROCUREMENT")),
    db: Session = Depends(get_db),
):
    try:
        order = cancel_purchase_order(
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
    "/procurement/orders/{order_id}/reject",
    response_model=PurchaseOrderResponse,
    dependencies=[Depends(require_electronic_signature(
        "PURCHASE_ORDER_REJECT", "GspPurchaseOrder",
        entity_id_param="order_id", meaning="REJECTION",
    ))],
)
def reject_order(
    order_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        order = reject_purchase_order(
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
def receive_order(
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
def list_receipts(
    status: str | None = None,
    current_user: User = Depends(require_gsp_roles("RECEIVER", "INSPECTOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    query = db.query(GspReceipt)
    if status:
        query = query.filter(GspReceipt.status == status)
    return [receipt_payload(db, receipt) for receipt in query.order_by(GspReceipt.id.desc()).all()]


@router.post(
    "/receiving/receipts/{receipt_id}/items/{item_id}/inspect",
    response_model=ReceiptResponse,
    dependencies=[Depends(require_electronic_signature(
        "RECEIPT_ITEM_INSPECT", "GspReceiptItem",
        entity_id_param="item_id", meaning="CONFIRMATION",
    ))],
)
def inspect_item(
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


@router.post(
    "/receiving/receipts/{receipt_id}/items/{item_id}/sample",
    response_model=ReceiptResponse,
)
def sample_item(
    receipt_id: int,
    item_id: int,
    payload: ReceiptSampling,
    request: Request,
    current_user: User = Depends(require_gsp_roles("INSPECTOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        receipt = record_receipt_sampling(
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


@router.post(
    "/receiving/receipts/{receipt_id}/print-records",
    response_model=ControlledPrintResponse,
    status_code=201,
)
def record_controlled_print(
    receipt_id: int,
    payload: ControlledPrintCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("INSPECTOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        record = create_receipt_print_record(
            db,
            receipt_id=receipt_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return record
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)

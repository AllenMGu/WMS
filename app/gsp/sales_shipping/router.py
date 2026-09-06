from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.dependencies import require_gsp_roles
from app.gsp.electronic_signature.dependencies import require_electronic_signature
from app.gsp.errors import WorkflowError
from app.gsp.sales_shipping.models import GspSalesOrder, GspShipment, GspShipmentPackage
from app.gsp.sales_shipping.schemas import (
    SalesOrderCreate,
    SalesOrderResponse,
    ShipmentPackageCreate,
    ShipmentPackageResponse,
    ShipmentPrepare,
    ShipmentResponse,
)
from app.gsp.sales_shipping.service import (
    add_shipment_package,
    allocate_sales_order,
    approve_sales_order,
    cancel_sales_order,
    create_sales_order,
    dispatch_shipment,
    mark_sales_order_picked,
    prepare_shipment,
    review_shipment,
    sales_order_payload,
    shipment_package_payload,
    shipment_payload,
    submit_sales_order,
)
from app.gsp.schemas import ChangeReason
from app.legacy import User

router = APIRouter(prefix="/gsp", tags=["GSP销售出库"])
QUALITY_ROLES = ("QUALITY_MANAGER", "QUALITY_REVIEWER")


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _rollback_and_raise(db: Session, error: Exception):
    db.rollback()
    if isinstance(error, WorkflowError):
        raise HTTPException(error.status_code, error.detail) from error
    if isinstance(error, IntegrityError):
        raise HTTPException(409, "订单号、发运单号或业务明细重复") from error
    raise error


@router.post("/sales/orders", response_model=SalesOrderResponse, status_code=201)
def create_order(
    payload: SalesOrderCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("SALES")),
    db: Session = Depends(get_db),
):
    try:
        order = create_sales_order(
            db,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return sales_order_payload(db, order)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.get("/sales/orders", response_model=list[SalesOrderResponse])
def list_orders(
    status: str | None = None,
    current_user: User = Depends(require_gsp_roles("SALES", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    query = db.query(GspSalesOrder)
    if status:
        query = query.filter(GspSalesOrder.status == status)
    return [
        sales_order_payload(db, order)
        for order in query.order_by(GspSalesOrder.id.desc()).all()
    ]


@router.post("/sales/orders/{order_id}/submit", response_model=SalesOrderResponse)
def submit_order(
    order_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles("SALES")),
    db: Session = Depends(get_db),
):
    try:
        order = submit_sales_order(
            db,
            order_id=order_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return sales_order_payload(db, order)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/sales/orders/{order_id}/approve",
    response_model=SalesOrderResponse,
    dependencies=[Depends(require_electronic_signature(
        "SALES_ORDER_APPROVE", "GspSalesOrder",
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
        order = approve_sales_order(
            db,
            order_id=order_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return sales_order_payload(db, order)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post("/sales/orders/{order_id}/allocate", response_model=SalesOrderResponse)
def allocate_order(
    order_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles("WAREHOUSE_CUSTODIAN")),
    db: Session = Depends(get_db),
):
    try:
        order = allocate_sales_order(
            db,
            order_id=order_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return sales_order_payload(db, order)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post("/sales/orders/{order_id}/pick", response_model=SalesOrderResponse)
def pick_order(
    order_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles("PICKER", "WAREHOUSE_CUSTODIAN")),
    db: Session = Depends(get_db),
):
    try:
        order = mark_sales_order_picked(
            db,
            order_id=order_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return sales_order_payload(db, order)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post("/sales/orders/{order_id}/cancel", response_model=SalesOrderResponse)
def cancel_order(
    order_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles("SALES", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        order = cancel_sales_order(
            db,
            order_id=order_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return sales_order_payload(db, order)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/shipping/orders/{order_id}/prepare",
    response_model=ShipmentResponse,
    status_code=201,
)
def prepare_order_shipment(
    order_id: int,
    payload: ShipmentPrepare,
    request: Request,
    current_user: User = Depends(
        require_gsp_roles("DISPATCHER", "WAREHOUSE_CUSTODIAN")
    ),
    db: Session = Depends(get_db),
):
    try:
        shipment = prepare_shipment(
            db,
            order_id=order_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return shipment_payload(shipment)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.get("/shipping/shipments", response_model=list[ShipmentResponse])
def list_shipments(
    status: str | None = None,
    current_user: User = Depends(require_gsp_roles("DISPATCHER", "WAREHOUSE_CUSTODIAN", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    query = db.query(GspShipment)
    if status:
        query = query.filter(GspShipment.status == status)
    return [shipment_payload(item) for item in query.order_by(GspShipment.id.desc()).all()]


@router.post(
    "/shipping/shipments/{shipment_id}/packages",
    response_model=ShipmentPackageResponse,
    status_code=201,
)
def create_shipment_package(
    shipment_id: int,
    payload: ShipmentPackageCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("WAREHOUSE_CUSTODIAN")),
    db: Session = Depends(get_db),
):
    try:
        package = add_shipment_package(
            db,
            shipment_id=shipment_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        )
        db.commit()
        return shipment_package_payload(db, package)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.get(
    "/shipping/shipments/{shipment_id}/packages",
    response_model=list[ShipmentPackageResponse],
)
def list_shipment_packages(
    shipment_id: int,
    _: User = Depends(require_gsp_roles("WAREHOUSE_CUSTODIAN", "OUTBOUND_REVIEWER", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return [
        shipment_package_payload(db, package)
        for package in db.query(GspShipmentPackage)
        .filter(GspShipmentPackage.shipment_id == shipment_id)
        .order_by(GspShipmentPackage.id)
    ]


@router.post(
    "/shipping/shipments/{shipment_id}/review",
    response_model=ShipmentResponse,
    dependencies=[Depends(require_electronic_signature(
        "SHIPMENT_REVIEW", "GspShipment",
        entity_id_param="shipment_id", meaning="REVIEW",
    ))],
)
def review_order_shipment(
    shipment_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles("OUTBOUND_REVIEWER", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    try:
        shipment = review_shipment(
            db,
            shipment_id=shipment_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return shipment_payload(shipment)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)


@router.post(
    "/shipping/shipments/{shipment_id}/dispatch",
    response_model=ShipmentResponse,
    dependencies=[Depends(require_electronic_signature(
        "SHIPMENT_DISPATCH", "GspShipment",
        entity_id_param="shipment_id", meaning="RESPONSIBILITY",
    ))],
)
def dispatch_order_shipment(
    shipment_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(
        require_gsp_roles("DISPATCHER", "WAREHOUSE_CUSTODIAN")
    ),
    db: Session = Depends(get_db),
):
    try:
        shipment = dispatch_shipment(
            db,
            shipment_id=shipment_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        )
        db.commit()
        return shipment_payload(shipment)
    except (WorkflowError, IntegrityError) as error:
        _rollback_and_raise(db, error)

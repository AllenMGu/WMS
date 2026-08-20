from datetime import date, datetime
from decimal import Decimal

from pydantic import BaseModel, Field

from app.gsp.schemas import ChangeReason, OrmModel


class PurchaseOrderLineCreate(BaseModel):
    goods_id: int
    quantity: Decimal = Field(..., gt=0, decimal_places=3)
    unit: str = Field(..., min_length=1, max_length=30)


class PurchaseOrderCreate(ChangeReason):
    order_no: str = Field(..., min_length=3, max_length=100)
    supplier_id: int
    warehouse_id: int
    ordered_on: date
    items: list[PurchaseOrderLineCreate] = Field(..., min_length=1)


class PurchaseOrderLineResponse(OrmModel):
    id: int
    line_no: int
    goods_id: int
    ordered_quantity: Decimal
    received_quantity: Decimal
    unit: str


class PurchaseOrderResponse(OrmModel):
    id: int
    order_no: str
    supplier_id: int
    warehouse_id: int
    ordered_on: date
    status: str
    created_by: int
    submitted_by: int | None
    quality_approved_by: int | None
    created_at: datetime
    items: list[PurchaseOrderLineResponse]


class ReceiptLineCreate(BaseModel):
    purchase_order_item_id: int
    batch_no: str = Field(..., min_length=1, max_length=100)
    production_date: date
    expiry_date: date
    quantity: Decimal = Field(..., gt=0, decimal_places=3)
    location_id: int
    inspection_report_no: str | None = None
    traceability_code: str | None = None
    arrival_temperature: Decimal | None = None
    transport_temperature_min: Decimal | None = None
    transport_temperature_max: Decimal | None = None
    temperature_record_ref: str | None = None


class ReceiptCreate(ChangeReason):
    receipt_no: str = Field(..., min_length=3, max_length=100)
    purchase_order_id: int
    delivery_document_no: str = Field(..., min_length=1, max_length=100)
    arrived_at: datetime
    items: list[ReceiptLineCreate] = Field(..., min_length=1)


class ReceiptInspection(ChangeReason):
    accepted_quantity: Decimal = Field(..., ge=0, decimal_places=3)
    rejected_quantity: Decimal = Field(..., ge=0, decimal_places=3)
    conclusion: str = Field(..., min_length=2, max_length=500)


class ReceiptItemResponse(OrmModel):
    id: int
    purchase_order_item_id: int
    batch_id: int
    location_id: int
    received_quantity: Decimal
    accepted_quantity: Decimal
    rejected_quantity: Decimal
    inspection_status: str
    inspection_conclusion: str | None
    inspected_by: int | None
    inspected_at: datetime | None


class ReceiptResponse(OrmModel):
    id: int
    receipt_no: str
    purchase_order_id: int
    delivery_document_no: str
    arrived_at: datetime
    status: str
    received_by: int
    created_at: datetime
    items: list[ReceiptItemResponse]

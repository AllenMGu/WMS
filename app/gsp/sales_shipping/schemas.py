from datetime import date, datetime
from decimal import Decimal

from pydantic import BaseModel, Field

from app.gsp.schemas import ChangeReason, OrmModel


class SalesOrderLineCreate(BaseModel):
    goods_id: int
    quantity: Decimal = Field(..., gt=0, decimal_places=3)
    unit: str = Field(..., min_length=1, max_length=30)
    minimum_remaining_days: int = Field(0, ge=0, le=3650)


class SalesOrderCreate(ChangeReason):
    order_no: str = Field(..., min_length=3, max_length=100)
    customer_id: int
    warehouse_id: int
    ordered_on: date
    items: list[SalesOrderLineCreate] = Field(..., min_length=1)


class SalesOrderItemResponse(OrmModel):
    id: int
    line_no: int
    goods_id: int
    ordered_quantity: Decimal
    allocated_quantity: Decimal
    shipped_quantity: Decimal
    unit: str
    minimum_remaining_days: int


class AllocationResponse(OrmModel):
    id: int
    sales_order_item_id: int
    batch_stock_id: int
    batch_id: int
    location_id: int
    quantity: Decimal
    status: str
    picked_by: int | None
    reviewed_by: int | None


class SalesOrderResponse(OrmModel):
    id: int
    order_no: str
    customer_id: int
    warehouse_id: int
    ordered_on: date
    status: str
    created_by: int
    submitted_by: int | None
    quality_approved_by: int | None
    allocated_by: int | None
    picked_by: int | None
    created_at: datetime
    items: list[SalesOrderItemResponse]
    allocations: list[AllocationResponse]


class ShipmentPrepare(ChangeReason):
    shipment_no: str = Field(..., min_length=3, max_length=100)
    carrier_name: str = Field(..., min_length=2, max_length=200)
    vehicle_no: str | None = Field(None, max_length=100)
    driver_name: str | None = Field(None, max_length=100)
    transport_mode: str = Field("NORMAL", min_length=2, max_length=30)
    temperature_record_ref: str | None = Field(None, max_length=500)


class ShipmentResponse(OrmModel):
    id: int
    shipment_no: str
    sales_order_id: int
    carrier_name: str
    vehicle_no: str | None
    driver_name: str | None
    transport_mode: str
    temperature_record_ref: str | None
    status: str
    prepared_by: int
    prepared_at: datetime
    reviewed_by: int | None
    reviewed_at: datetime | None
    dispatched_by: int | None
    dispatched_at: datetime | None

from datetime import datetime
from decimal import Decimal

from pydantic import Field

from app.gsp.schemas import ChangeReason, OrmModel


class NonconformingStockCreate(ChangeReason):
    record_no: str = Field(..., min_length=3, max_length=100)
    stock_id: int
    quantity: Decimal = Field(..., gt=0, decimal_places=3)
    reason_code: str = Field(..., min_length=2, max_length=50)
    description: str = Field(..., min_length=3, max_length=500)
    proposed_disposition: str | None = Field(None, max_length=50)


class DispositionApproval(ChangeReason):
    disposition: str = Field(..., min_length=3, max_length=50)


class DestructionExecution(ChangeReason):
    witnessed_by: int
    supervision_organization: str = Field(..., min_length=2, max_length=200)
    execution_document_ref: str = Field(..., min_length=3, max_length=500)


class NonconformingResponse(OrmModel):
    id: int
    record_no: str
    source_type: str
    source_entity_type: str
    source_entity_id: int
    stock_id: int | None
    quality_hold_id: int | None
    batch_id: int
    warehouse_id: int
    location_id: int | None
    quantity: Decimal
    reason_code: str
    description: str
    proposed_disposition: str | None
    approved_disposition: str | None
    status: str
    registered_by: int
    registered_at: datetime
    approved_by: int | None
    approved_at: datetime | None
    approval_reason: str | None
    executed_by: int | None
    executed_at: datetime | None
    witnessed_by: int | None
    supervision_organization: str | None
    execution_document_ref: str | None
    rejected_by: int | None
    rejected_at: datetime | None
    rejection_reason: str | None


class PurchaseReturnCreate(ChangeReason):
    return_no: str = Field(..., min_length=3, max_length=100)
    nonconforming_record_ids: list[int] = Field(..., min_length=1)


class PurchaseReturnDispatch(ChangeReason):
    outbound_document_no: str = Field(..., min_length=3, max_length=100)
    carrier_name: str = Field(..., min_length=2, max_length=200)


class PurchaseReturnItemResponse(OrmModel):
    id: int
    line_no: int
    nonconforming_record_id: int
    batch_id: int
    quantity: Decimal


class PurchaseReturnResponse(OrmModel):
    id: int
    return_no: str
    supplier_id: int
    warehouse_id: int
    status: str
    created_by: int
    created_at: datetime
    submitted_by: int | None
    submitted_at: datetime | None
    quality_approved_by: int | None
    quality_approved_at: datetime | None
    dispatched_by: int | None
    dispatched_at: datetime | None
    outbound_document_no: str | None
    carrier_name: str | None
    cancelled_by: int | None
    cancelled_at: datetime | None
    cancellation_reason: str | None
    items: list[PurchaseReturnItemResponse]

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, Field

from app.gsp.schemas import ChangeReason, OrmModel


class SalesReturnLineCreate(BaseModel):
    stock_allocation_id: int
    quantity: Decimal = Field(..., gt=0, decimal_places=3)
    reason_code: str = Field(..., min_length=2, max_length=50)
    condition_notes: str = Field(..., min_length=3, max_length=500)
    traceability_code: str | None = Field(None, max_length=200)
    temperature_record_ref: str | None = Field(None, max_length=500)
    recall_target_id: int | None = None


class SalesReturnCreate(ChangeReason):
    return_no: str = Field(..., min_length=3, max_length=100)
    shipment_id: int
    received_at: datetime
    items: list[SalesReturnLineCreate] = Field(..., min_length=1)


class SalesReturnInspection(ChangeReason):
    accepted_quantity: Decimal = Field(..., ge=0, decimal_places=3)
    rejected_quantity: Decimal = Field(..., ge=0, decimal_places=3)
    conclusion: str = Field(..., min_length=3, max_length=500)
    accepted_location_id: int | None = None
    rejection_disposition: str | None = Field(None, max_length=50)
    package_intact: bool = False
    storage_conditions_confirmed: bool = False
    traceability_verified: bool = False


class SalesReturnItemResponse(OrmModel):
    id: int
    line_no: int
    stock_allocation_id: int
    recall_target_id: int | None
    batch_id: int
    goods_id: int
    received_quantity: Decimal
    accepted_quantity: Decimal
    rejected_quantity: Decimal
    reason_code: str
    condition_notes: str
    traceability_code: str | None
    temperature_record_ref: str | None
    inspection_status: str
    inspection_conclusion: str | None
    accepted_location_id: int | None
    rejection_disposition: str | None
    package_intact: bool | None
    storage_conditions_confirmed: bool | None
    traceability_verified: bool | None
    inspected_by: int | None
    inspected_at: datetime | None


class SalesReturnResponse(OrmModel):
    id: int
    return_no: str
    shipment_id: int
    customer_id: int
    warehouse_id: int
    received_at: datetime
    status: str
    received_by: int
    created_at: datetime
    items: list[SalesReturnItemResponse]


class RecallCreate(ChangeReason):
    recall_no: str = Field(..., min_length=3, max_length=100)
    recall_level: str = Field(..., min_length=1, max_length=10)
    source: str = Field(..., min_length=2, max_length=30)
    regulatory_ref: str | None = Field(None, max_length=200)
    batch_ids: list[int] = Field(..., min_length=1)


class RecallTargetNotification(ChangeReason):
    notification_status: str = Field(..., min_length=3, max_length=30)
    notes: str = Field(..., min_length=3, max_length=500)


class RecallClose(ChangeReason):
    conclusion: str = Field(..., min_length=3, max_length=500)


class RecallProgressCreate(ChangeReason):
    report_ref: str = Field(..., min_length=3, max_length=200)
    summary: str = Field(..., min_length=3, max_length=1000)


class RecallCompletionReportCreate(ChangeReason):
    report_ref: str = Field(..., min_length=3, max_length=200)
    treatment_summary: str = Field(..., min_length=10, max_length=2000)
    effectiveness_evaluation: str = Field(..., min_length=10, max_length=1000)
    regulatory_submission_ref: str = Field(..., min_length=3, max_length=500)


class RecallDrillCreate(ChangeReason):
    drill_no: str = Field(..., min_length=3, max_length=100)
    recall_level: str = Field(..., min_length=1, max_length=10)
    scenario: str = Field(..., min_length=10, max_length=1000)
    objective: str = Field(..., min_length=10, max_length=1000)
    max_allowed_minutes: int = Field(..., gt=0, le=10080)
    batch_ids: list[int] = Field(..., min_length=1)


class RecallDrillTargetVerification(ChangeReason):
    verification_status: str = Field(..., min_length=3, max_length=30)
    notes: str = Field(..., min_length=3, max_length=500)


class RecallDrillComplete(ChangeReason):
    completion_summary: str = Field(..., min_length=10, max_length=2000)
    deviation_notes: str | None = Field(None, max_length=1000)
    capa_ref: str | None = Field(None, max_length=500)


class RecallBatchResponse(OrmModel):
    id: int
    batch_id: int
    target_shipped_quantity: Decimal
    recovered_quantity: Decimal


class RecallTargetResponse(OrmModel):
    id: int
    recall_batch_id: int
    shipment_id: int
    customer_id: int
    stock_allocation_id: int
    batch_id: int
    shipped_quantity: Decimal
    recovered_quantity: Decimal
    notification_status: str
    notified_by: int | None
    notified_at: datetime | None
    notification_notes: str | None


class RecallProgressResponse(OrmModel):
    id: int
    report_ref: str
    summary: str
    reported_by: int
    reported_at: datetime


class RecallCompletionReportResponse(OrmModel):
    id: int
    report_ref: str
    treatment_summary: str
    effectiveness_evaluation: str
    regulatory_submission_ref: str
    reported_by: int
    reported_at: datetime


class RecallDrillBatchResponse(OrmModel):
    id: int
    batch_id: int
    target_shipped_quantity: Decimal


class RecallDrillTargetResponse(OrmModel):
    id: int
    drill_batch_id: int
    shipment_id: int
    customer_id: int
    stock_allocation_id: int
    batch_id: int
    shipped_quantity: Decimal
    verification_status: str
    verified_by: int | None
    verified_at: datetime | None
    verification_notes: str | None


class RecallDrillResponse(OrmModel):
    id: int
    drill_no: str
    recall_level: str
    scenario: str
    objective: str
    max_allowed_minutes: int
    status: str
    created_by: int
    created_at: datetime
    activated_by: int | None
    activated_at: datetime | None
    completed_by: int | None
    completed_at: datetime | None
    result: str | None
    completion_summary: str | None
    deviation_notes: str | None
    capa_ref: str | None
    batches: list[RecallDrillBatchResponse]
    targets: list[RecallDrillTargetResponse]


class RecallResponse(OrmModel):
    id: int
    recall_no: str
    recall_level: str
    source: str
    regulatory_ref: str | None
    reason: str
    status: str
    created_by: int
    created_at: datetime
    activated_by: int | None
    activated_at: datetime | None
    notification_due_at: datetime | None
    next_progress_report_due_at: datetime | None
    last_progress_reported_at: datetime | None
    closed_by: int | None
    closed_at: datetime | None
    closure_conclusion: str | None
    completion_report_due_at: datetime | None
    batches: list[RecallBatchResponse]
    targets: list[RecallTargetResponse]
    progress_reports: list[RecallProgressResponse]
    completion_report: RecallCompletionReportResponse | None

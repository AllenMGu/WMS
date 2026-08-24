from datetime import date, datetime
from decimal import Decimal

from pydantic import BaseModel, Field

from app.gsp.schemas import ChangeReason, OrmModel


class MaintenancePlanItemCreate(BaseModel):
    stock_id: int
    priority_reason: str | None = Field(None, max_length=500)


class MaintenancePlanCreate(ChangeReason):
    plan_no: str = Field(..., min_length=3, max_length=100)
    warehouse_id: int
    plan_type: str = Field(..., min_length=3, max_length=30)
    scheduled_from: date
    scheduled_to: date
    scope_summary: str = Field(..., min_length=10, max_length=1000)
    items: list[MaintenancePlanItemCreate] = Field(..., min_length=1)


class MaintenanceInspection(ChangeReason):
    result: str = Field(..., min_length=3, max_length=30)
    appearance_ok: bool
    package_ok: bool
    storage_condition_ok: bool
    temperature_humidity_ok: bool
    finding: str = Field(..., min_length=3, max_length=1000)
    next_due_on: date


class MaintenanceCompletion(ChangeReason):
    conclusion: str = Field(..., min_length=10, max_length=1000)


class ExpiryAlertDecision(ChangeReason):
    resolution: str = Field(..., min_length=10, max_length=500)
    evidence_ref: str = Field(..., min_length=3, max_length=500)
    review_due_on: date


class ExpiryAlertResponse(OrmModel):
    id: int
    batch_id: int
    alert_type: str
    threshold_days: int
    status: str
    quality_hold_id: int | None
    created_by: int
    created_at: datetime
    last_evaluated_at: datetime
    resolved_by: int | None
    resolved_at: datetime | None
    resolution: str | None
    evidence_ref: str | None
    review_due_on: date | None


class MaintenancePlanItemResponse(OrmModel):
    id: int
    line_no: int
    stock_id: int
    batch_id: int
    planned_quantity: Decimal
    priority_reason: str | None
    status: str
    appearance_ok: bool | None
    package_ok: bool | None
    storage_condition_ok: bool | None
    temperature_humidity_ok: bool | None
    finding: str | None
    next_due_on: date | None
    quality_hold_id: int | None
    checked_by: int | None
    checked_at: datetime | None


class MaintenancePlanResponse(OrmModel):
    id: int
    plan_no: str
    warehouse_id: int
    plan_type: str
    scheduled_from: date
    scheduled_to: date
    scope_summary: str
    status: str
    created_by: int
    created_at: datetime
    submitted_by: int | None
    submitted_at: datetime | None
    approved_by: int | None
    approved_at: datetime | None
    completed_by: int | None
    completed_at: datetime | None
    completion_conclusion: str | None
    items: list[MaintenancePlanItemResponse]

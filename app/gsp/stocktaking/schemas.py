from datetime import datetime
from decimal import Decimal

from pydantic import Field

from app.gsp.schemas import ChangeReason, OrmModel


class StocktakePlanCreate(ChangeReason):
    plan_no: str = Field(..., min_length=3, max_length=100)
    warehouse_id: int
    scope_type: str = Field(..., min_length=3, max_length=30)
    scope_summary: str = Field(..., min_length=10, max_length=1000)
    selection_rule: str = Field("MANUAL", min_length=3, max_length=50)
    sample_size: int | None = Field(None, gt=0, le=10000)
    stock_ids: list[int] = Field(default_factory=list)


class StocktakeCount(ChangeReason):
    counted_quantity: Decimal = Field(..., ge=0, decimal_places=3)
    discrepancy_reason: str | None = Field(None, max_length=1000)


class StocktakeReview(ChangeReason):
    decision: str = Field(..., min_length=3, max_length=30)
    conclusion: str = Field(..., min_length=10, max_length=1000)
    capa_ref: str | None = Field(None, min_length=3, max_length=500)


class StocktakeItemResponse(OrmModel):
    id: int
    line_no: int
    stock_id: int
    batch_id: int
    location_id: int
    status: str
    book_quantity: Decimal | None
    book_reserved_quantity: Decimal | None
    counted_quantity: Decimal | None
    difference_quantity: Decimal | None
    discrepancy_reason: str | None
    count_round: int
    counted_by: int | None
    counted_at: datetime | None
    adjusted_by: int | None
    adjusted_at: datetime | None


class StocktakePlanResponse(OrmModel):
    id: int
    plan_no: str
    warehouse_id: int
    scope_type: str
    scope_summary: str
    selection_rule: str
    status: str
    transactions_frozen: bool
    frozen_at: datetime | None
    created_by: int
    created_at: datetime
    submitted_by: int | None
    submitted_at: datetime | None
    approved_by: int | None
    approved_at: datetime | None
    reviewed_by: int | None
    reviewed_at: datetime | None
    review_conclusion: str | None
    capa_ref: str | None
    completed_by: int | None
    completed_at: datetime | None
    items: list[StocktakeItemResponse]

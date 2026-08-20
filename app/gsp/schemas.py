from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class OrmModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ChangeReason(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)


class RoleGrant(ChangeReason):
    user_id: int
    role: str = Field(..., min_length=3, max_length=50)
    approval_ref: str = Field(..., min_length=3, max_length=200)
    review_due_at: datetime
    expires_at: Optional[datetime] = None


class RoleReview(ChangeReason):
    decision: str = Field(..., pattern="^(RETAIN|REVOKE)$")
    next_review_due_at: Optional[datetime] = None


class RoleRevoke(ChangeReason):
    pass


class DrugProfileUpsert(ChangeReason):
    approval_no: str
    generic_name: str
    dosage_form: str
    manufacturer: str
    marketing_authorization_holder: Optional[str] = None
    storage_condition: str = "NORMAL"
    min_temperature: Optional[float] = None
    max_temperature: Optional[float] = None
    is_prescription: bool = True
    is_special_controlled: bool = False
    traceability_required: bool = True
    registration_valid_to: Optional[date] = None


class DrugProfileResponse(OrmModel):
    id: int
    goods_id: int
    approval_no: str
    generic_name: str
    dosage_form: str
    manufacturer: str
    storage_condition: str
    status: str
    registration_valid_to: Optional[date]
    created_at: datetime
    updated_at: datetime


class PartnerCreate(ChangeReason):
    code: str
    name: str
    partner_type: str
    unified_social_credit_code: Optional[str] = None
    license_no: str
    license_scope: str
    license_valid_from: Optional[date] = None
    license_valid_to: date
    quality_agreement_valid_to: Optional[date] = None


class PartnerResponse(OrmModel):
    id: int
    code: str
    name: str
    partner_type: str
    license_no: str
    license_scope: str
    license_valid_to: date
    quality_agreement_valid_to: Optional[date]
    status: str
    suspension_reason: Optional[str]
    created_at: datetime
    updated_at: datetime


class BatchCreate(ChangeReason):
    goods_id: int
    batch_no: str
    production_date: date
    expiry_date: date
    supplier_id: int
    receipt_document_no: str
    inspection_report_no: Optional[str] = None
    traceability_code: Optional[str] = None
    arrival_temperature: Optional[float] = None
    transport_temperature_min: Optional[float] = None
    transport_temperature_max: Optional[float] = None
    temperature_record_ref: Optional[str] = None


class BatchResponse(OrmModel):
    id: int
    goods_id: int
    batch_no: str
    production_date: date
    expiry_date: date
    supplier_id: int
    receipt_document_no: str
    inspection_report_no: Optional[str]
    traceability_code: Optional[str]
    arrival_temperature: Optional[float]
    temperature_record_ref: Optional[str]
    acceptance_conclusion: Optional[str]
    status: str
    accepted_by: Optional[int]
    accepted_at: Optional[datetime]
    created_at: datetime


class QualityHoldCreate(ChangeReason):
    batch_id: int
    reason_code: str


class QualityHoldRelease(ChangeReason):
    pass


class BatchAcceptance(ChangeReason):
    conclusion: str = Field(..., min_length=2, max_length=500)


class BatchStockReceipt(ChangeReason):
    batch_id: int
    warehouse_id: int
    location_id: int
    quantity: Decimal = Field(..., gt=0, decimal_places=3)


class QualityHoldResponse(OrmModel):
    id: int
    batch_id: int
    reason_code: str
    reason: str
    status: str
    initiated_by: int
    initiated_at: datetime
    released_by: Optional[int]
    released_at: Optional[datetime]
    release_reason: Optional[str]


class AuditEventResponse(OrmModel):
    id: int
    actor_user_id: int
    action: str
    entity_type: str
    entity_id: str
    reason: str
    before_data: Optional[dict[str, Any]]
    after_data: Optional[dict[str, Any]]
    previous_hash: Optional[str]
    event_hash: str
    occurred_at: datetime

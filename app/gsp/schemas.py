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
    registration_document_ref: str = Field(..., min_length=3, max_length=500)
    nmpa_verification_ref: str = Field(..., min_length=3, max_length=500)


class DrugProfileResponse(OrmModel):
    id: int
    goods_id: int
    goods_name: Optional[str] = None
    approval_no: str
    generic_name: str
    dosage_form: str
    manufacturer: str
    marketing_authorization_holder: Optional[str]
    storage_condition: str
    min_temperature: Optional[float]
    max_temperature: Optional[float]
    is_prescription: bool
    is_special_controlled: bool
    traceability_required: bool
    status: str
    registration_valid_to: Optional[date]
    registration_document_ref: Optional[str]
    nmpa_verification_ref: Optional[str]
    nmpa_verified_by: Optional[int]
    nmpa_verified_at: Optional[datetime]
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


class PartnerDocumentCreate(ChangeReason):
    document_type: str = Field(..., min_length=3, max_length=50)
    document_no: str = Field(..., min_length=1, max_length=100)
    valid_from: Optional[date] = None
    valid_to: date
    file_ref: str = Field(..., min_length=3, max_length=500)
    person_name: Optional[str] = Field(None, min_length=2, max_length=200)
    person_role: Optional[str] = Field(None, min_length=2, max_length=50)


class PartnerDocumentResponse(OrmModel):
    id: int
    partner_id: int
    document_type: str
    document_no: Optional[str]
    valid_from: Optional[date]
    valid_to: date
    file_ref: Optional[str]
    person_name: Optional[str]
    person_role: Optional[str]
    verified_by: Optional[int]
    verified_at: Optional[datetime]
    status: str


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
    goods_name: Optional[str] = None
    batch_no: str
    production_date: date
    expiry_date: date
    supplier_id: int
    supplier_name: Optional[str] = None
    receipt_document_no: str
    inspection_report_no: Optional[str]
    traceability_code: Optional[str]
    arrival_temperature: Optional[float]
    transport_temperature_min: Optional[float]
    transport_temperature_max: Optional[float]
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


class BatchStockResponse(OrmModel):
    id: int
    batch_id: int
    batch_no: str
    goods_id: int
    goods_name: str
    warehouse_id: int
    warehouse_name: str
    location_id: int
    location_code: str
    quantity: Decimal
    reserved_quantity: Decimal
    stock_status: str
    lock_version: int
    updated_at: datetime


class QualityHoldResponse(OrmModel):
    id: int
    batch_id: int
    batch_no: Optional[str] = None
    goods_id: Optional[int] = None
    goods_name: Optional[str] = None
    reason_code: str
    reason: str
    status: str
    initiated_by: int
    initiated_at: datetime
    released_by: Optional[int]
    released_at: Optional[datetime]
    release_reason: Optional[str]


class EffectiveRoleAssignmentResponse(OrmModel):
    id: int
    user_id: int
    role: str
    approval_ref: str
    review_due_at: datetime
    expires_at: Optional[datetime]
    is_active: bool


class CurrentUserRolesResponse(BaseModel):
    user_id: int
    roles: list[str]
    assignments: list[EffectiveRoleAssignmentResponse]


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


class AuditVerificationCreate(ChangeReason):
    trigger_source: str = Field("MANUAL", pattern="^(MANUAL|SCHEDULED)$")
    evidence_ref: str = Field(..., min_length=3, max_length=500)


class AuditVerificationResponse(OrmModel):
    id: int
    requested_by: int
    trigger_source: str
    evidence_ref: str
    checked_event_count: int
    valid: bool
    broken_event_id: Optional[int]
    verified_at: datetime

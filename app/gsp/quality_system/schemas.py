from datetime import date, datetime

from pydantic import Field, model_validator

from app.gsp.schemas import ChangeReason, OrmModel


class PartnerReviewCreate(ChangeReason):
    review_no: str = Field(..., min_length=3, max_length=100)
    partner_id: int
    review_year: int = Field(..., ge=2000, le=2200)
    review_type: str = Field(..., min_length=3, max_length=30)
    scope: str = Field(..., min_length=3)
    survey_summary: str = Field(..., min_length=3)
    findings: str | None = None
    risk_level: str = Field(..., min_length=3, max_length=20)
    action_plan: str | None = None
    action_due_date: date | None = None


class PartnerReviewDecision(ChangeReason):
    conclusion: str = Field(..., min_length=3, max_length=30)
    next_review_date: date | None = None


class PartnerReviewClosure(ChangeReason):
    closure_evidence_ref: str = Field(..., min_length=3, max_length=500)


class PartnerReviewResponse(OrmModel):
    id: int
    review_no: str
    partner_id: int
    review_year: int
    review_type: str
    scope: str
    survey_summary: str
    findings: str | None
    risk_level: str
    conclusion: str | None
    action_plan: str | None
    action_due_date: date | None
    next_review_date: date | None
    status: str
    created_by: int
    created_at: datetime
    submitted_by: int | None
    submitted_at: datetime | None
    approved_by: int | None
    approved_at: datetime | None
    closed_by: int | None
    closed_at: datetime | None
    closure_evidence_ref: str | None


class QualityRiskCreate(ChangeReason):
    risk_no: str = Field(..., min_length=3, max_length=100)
    category: str = Field(..., min_length=3, max_length=50)
    source_type: str = Field(..., min_length=3, max_length=50)
    source_ref: str | None = Field(None, max_length=200)
    title: str = Field(..., min_length=3, max_length=200)
    description: str = Field(..., min_length=3)
    initial_likelihood: int = Field(..., ge=1, le=5)
    initial_severity: int = Field(..., ge=1, le=5)
    initial_detectability: int = Field(..., ge=1, le=5)
    controls: str = Field(..., min_length=3)
    owner_id: int
    review_due_date: date


class QualityRiskDecision(ChangeReason):
    conclusion: str = Field(..., min_length=3)
    residual_likelihood: int = Field(..., ge=1, le=5)
    residual_severity: int = Field(..., ge=1, le=5)
    residual_detectability: int = Field(..., ge=1, le=5)
    close: bool = False


class QualityRiskResponse(OrmModel):
    id: int
    risk_no: str
    category: str
    source_type: str
    source_ref: str | None
    title: str
    description: str
    initial_likelihood: int
    initial_severity: int
    initial_detectability: int
    initial_rpn: int
    controls: str
    residual_likelihood: int | None
    residual_severity: int | None
    residual_detectability: int | None
    residual_rpn: int | None
    owner_id: int
    review_due_date: date
    status: str
    created_by: int
    created_at: datetime
    submitted_by: int | None
    submitted_at: datetime | None
    reviewed_by: int | None
    reviewed_at: datetime | None
    review_conclusion: str | None
    closed_at: datetime | None


class QualityEventCreate(ChangeReason):
    event_no: str = Field(..., min_length=3, max_length=100)
    event_type: str = Field(..., min_length=3, max_length=40)
    title: str = Field(..., min_length=3, max_length=200)
    occurred_on: date
    source: str = Field(..., min_length=2, max_length=200)
    reporter_name: str | None = Field(None, max_length=200)
    contact_ref: str | None = Field(None, max_length=200)
    description: str = Field(..., min_length=3)
    severity: str = Field(..., min_length=3, max_length=20)
    affected_goods_id: int | None = None
    affected_batch_id: int | None = None
    immediate_action: str = Field(..., min_length=3)
    assigned_to: int
    regulatory_report_required: bool = False
    regulatory_report_ref: str | None = Field(None, max_length=500)

    @model_validator(mode="after")
    def require_regulatory_reference(self):
        if self.regulatory_report_required and not self.regulatory_report_ref:
            raise ValueError("要求监管报告时必须填写报告引用")
        return self


class QualityEventInvestigation(ChangeReason):
    root_cause: str = Field(..., min_length=3)
    conclusion: str = Field(..., min_length=3)


class QualityEventResponse(OrmModel):
    id: int
    event_no: str
    event_type: str
    title: str
    occurred_on: date
    source: str
    reporter_name: str | None
    contact_ref: str | None
    description: str
    severity: str
    affected_goods_id: int | None
    affected_batch_id: int | None
    immediate_action: str
    assigned_to: int
    regulatory_report_required: bool
    regulatory_report_ref: str | None
    root_cause: str | None
    conclusion: str | None
    status: str
    created_by: int
    created_at: datetime
    investigated_by: int | None
    investigated_at: datetime | None
    closed_by: int | None
    closed_at: datetime | None


class CapaCreate(ChangeReason):
    action_no: str = Field(..., min_length=3, max_length=100)
    event_id: int | None = None
    risk_id: int | None = None
    action_type: str = Field(..., min_length=3, max_length=30)
    description: str = Field(..., min_length=3)
    owner_id: int
    due_date: date

    @model_validator(mode="after")
    def require_source(self):
        if self.event_id is None and self.risk_id is None:
            raise ValueError("CAPA必须关联质量事件或风险")
        return self


class CapaImplementation(ChangeReason):
    completion_evidence_ref: str = Field(..., min_length=3, max_length=500)


class CapaVerification(ChangeReason):
    effectiveness_result: str = Field(..., min_length=3)
    effective: bool


class CapaResponse(OrmModel):
    id: int
    action_no: str
    event_id: int | None
    risk_id: int | None
    action_type: str
    description: str
    owner_id: int
    due_date: date
    completion_evidence_ref: str | None
    effectiveness_result: str | None
    status: str
    created_by: int
    created_at: datetime
    implemented_by: int | None
    implemented_at: datetime | None
    verified_by: int | None
    verified_at: datetime | None


class TrainingCreate(ChangeReason):
    training_no: str = Field(..., min_length=3, max_length=100)
    user_id: int
    subject: str = Field(..., min_length=2, max_length=200)
    training_type: str = Field(..., min_length=3, max_length=30)
    requirement_ref: str = Field(..., min_length=3, max_length=500)
    planned_date: date


class TrainingCompletion(ChangeReason):
    trainer: str = Field(..., min_length=2, max_length=200)
    completed_on: date
    score: int | None = Field(None, ge=0, le=100)
    result: str = Field(..., min_length=3, max_length=30)
    evidence_ref: str = Field(..., min_length=3, max_length=500)
    valid_to: date | None = None


class TrainingResponse(OrmModel):
    id: int
    training_no: str
    user_id: int
    subject: str
    training_type: str
    requirement_ref: str
    planned_date: date
    trainer: str | None
    completed_on: date | None
    score: int | None
    result: str | None
    evidence_ref: str | None
    valid_to: date | None
    status: str
    created_by: int
    created_at: datetime
    completed_by: int | None
    verified_by: int | None
    verified_at: datetime | None


class ControlledDocumentCreate(ChangeReason):
    document_no: str = Field(..., min_length=3, max_length=100)
    title: str = Field(..., min_length=3, max_length=200)
    document_type: str = Field(..., min_length=3, max_length=30)
    department: str = Field(..., min_length=2, max_length=100)
    owner_id: int


class DocumentRevisionCreate(ChangeReason):
    version: str = Field(..., min_length=1, max_length=50)
    change_summary: str = Field(..., min_length=3)
    content_ref: str = Field(..., min_length=3, max_length=500)
    content_sha256: str = Field(..., pattern="^[0-9a-f]{64}$")
    effective_date: date


class DocumentCopyCreate(ChangeReason):
    copy_no: str = Field(..., min_length=3, max_length=100)
    holder: str = Field(..., min_length=2, max_length=200)
    location: str = Field(..., min_length=2, max_length=200)
    purpose: str = Field(..., min_length=3, max_length=500)


class DocumentCopyDisposition(ChangeReason):
    action: str = Field(..., min_length=3, max_length=20)
    evidence_ref: str = Field(..., min_length=3, max_length=500)


class DocumentRevisionResponse(OrmModel):
    id: int
    document_id: int
    version: str
    change_summary: str
    content_ref: str
    content_sha256: str
    effective_date: date
    status: str
    drafted_by: int
    drafted_at: datetime
    submitted_by: int | None
    submitted_at: datetime | None
    approved_by: int | None
    approved_at: datetime | None
    obsoleted_at: datetime | None


class ControlledDocumentResponse(OrmModel):
    id: int
    document_no: str
    title: str
    document_type: str
    department: str
    owner_id: int
    current_version: str | None
    status: str
    created_by: int
    created_at: datetime


class DocumentCopyResponse(OrmModel):
    id: int
    revision_id: int
    copy_no: str
    holder: str
    location: str
    purpose: str
    status: str
    issued_by: int
    issued_at: datetime
    returned_by: int | None
    returned_at: datetime | None
    destroyed_by: int | None
    destroyed_at: datetime | None
    disposition_evidence_ref: str | None


class EquipmentCreate(ChangeReason):
    equipment_no: str = Field(..., min_length=3, max_length=100)
    name: str = Field(..., min_length=2, max_length=200)
    category: str = Field(..., min_length=3, max_length=50)
    location: str = Field(..., min_length=2, max_length=200)
    criticality: str = Field(..., min_length=3, max_length=20)
    qualification_required: bool = True
    calibration_required: bool = False


class EquipmentActivityCreate(ChangeReason):
    activity_no: str = Field(..., min_length=3, max_length=100)
    activity_type: str = Field(..., min_length=3, max_length=30)
    performed_on: date
    valid_to: date | None = None
    provider: str = Field(..., min_length=2, max_length=200)
    certificate_ref: str = Field(..., min_length=3, max_length=500)
    result: str = Field(..., min_length=3, max_length=30)


class EquipmentResponse(OrmModel):
    id: int
    equipment_no: str
    name: str
    category: str
    location: str
    criticality: str
    qualification_required: bool
    calibration_required: bool
    next_qualification_date: date | None
    next_calibration_date: date | None
    status: str
    created_by: int
    created_at: datetime
    approved_by: int | None
    approved_at: datetime | None


class EquipmentActivityResponse(OrmModel):
    id: int
    activity_no: str
    equipment_id: int
    activity_type: str
    performed_on: date
    valid_to: date | None
    provider: str
    certificate_ref: str
    result: str
    status: str
    recorded_by: int
    recorded_at: datetime
    reviewed_by: int | None
    reviewed_at: datetime | None
    review_reason: str | None


class ScopeAuthorizationCreate(ChangeReason):
    category: str = Field(..., min_length=3, max_length=40)
    authorization_no: str = Field(..., min_length=3, max_length=100)
    authorization_ref: str = Field(..., min_length=3, max_length=500)
    valid_to: date
    controls_summary: str = Field(..., min_length=3)


class ScopeAuthorizationResponse(OrmModel):
    id: int
    category: str
    authorization_no: str
    authorization_ref: str
    valid_to: date
    controls_summary: str
    status: str
    created_by: int
    created_at: datetime
    approved_by: int | None
    approved_at: datetime | None

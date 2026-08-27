"""Persistent quality-system governance records.

These records complement transactional GSP controls with the management-system
evidence found in the legacy application: periodic partner review, risk and
CAPA, audits and complaints, training, controlled documents, equipment
qualification, and authorization for specially regulated product scopes.
"""

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from app.core.database import Base
from app.core.time import utc_now


class GspPartnerReview(Base):
    __tablename__ = "gsp_partner_reviews"

    id = Column(Integer, primary_key=True)
    review_no = Column(String(100), nullable=False, unique=True)
    partner_id = Column(Integer, ForeignKey("gsp_business_partners.id"), nullable=False, index=True)
    review_year = Column(Integer, nullable=False, index=True)
    review_type = Column(String(30), nullable=False, index=True)
    scope = Column(Text, nullable=False)
    survey_summary = Column(Text, nullable=False)
    findings = Column(Text, nullable=True)
    risk_level = Column(String(20), nullable=False)
    conclusion = Column(String(30), nullable=True, index=True)
    action_plan = Column(Text, nullable=True)
    action_due_date = Column(Date, nullable=True)
    next_review_date = Column(Date, nullable=True, index=True)
    status = Column(String(30), nullable=False, default="DRAFT", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    submitted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    submitted_at = Column(DateTime, nullable=True)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    closed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    closed_at = Column(DateTime, nullable=True)
    closure_evidence_ref = Column(String(500), nullable=True)
    __table_args__ = (
        UniqueConstraint("partner_id", "review_year", "review_type", name="uq_gsp_partner_periodic_review"),
        CheckConstraint("review_year >= 2000", name="ck_gsp_partner_review_year"),
    )


class GspQualityRisk(Base):
    __tablename__ = "gsp_quality_risks"

    id = Column(Integer, primary_key=True)
    risk_no = Column(String(100), nullable=False, unique=True)
    category = Column(String(50), nullable=False, index=True)
    source_type = Column(String(50), nullable=False, index=True)
    source_ref = Column(String(200), nullable=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    initial_likelihood = Column(Integer, nullable=False)
    initial_severity = Column(Integer, nullable=False)
    initial_detectability = Column(Integer, nullable=False)
    initial_rpn = Column(Integer, nullable=False, index=True)
    controls = Column(Text, nullable=False)
    residual_likelihood = Column(Integer, nullable=True)
    residual_severity = Column(Integer, nullable=True)
    residual_detectability = Column(Integer, nullable=True)
    residual_rpn = Column(Integer, nullable=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    review_due_date = Column(Date, nullable=False, index=True)
    status = Column(String(30), nullable=False, default="DRAFT", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    submitted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    submitted_at = Column(DateTime, nullable=True)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_conclusion = Column(Text, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    __table_args__ = (
        CheckConstraint(
            "initial_likelihood BETWEEN 1 AND 5 AND initial_severity BETWEEN 1 AND 5 "
            "AND initial_detectability BETWEEN 1 AND 5",
            name="ck_gsp_quality_risk_initial_scores",
        ),
        CheckConstraint(
            "(residual_likelihood IS NULL OR residual_likelihood BETWEEN 1 AND 5) "
            "AND (residual_severity IS NULL OR residual_severity BETWEEN 1 AND 5) "
            "AND (residual_detectability IS NULL OR residual_detectability BETWEEN 1 AND 5)",
            name="ck_gsp_quality_risk_residual_scores",
        ),
    )


class GspQualityEvent(Base):
    __tablename__ = "gsp_quality_events"

    id = Column(Integer, primary_key=True)
    event_no = Column(String(100), nullable=False, unique=True)
    event_type = Column(String(40), nullable=False, index=True)
    title = Column(String(200), nullable=False)
    occurred_on = Column(Date, nullable=False, index=True)
    source = Column(String(200), nullable=False)
    reporter_name = Column(String(200), nullable=True)
    contact_ref = Column(String(200), nullable=True)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    affected_goods_id = Column(Integer, ForeignKey("goods.id"), nullable=True, index=True)
    affected_batch_id = Column(Integer, ForeignKey("gsp_drug_batches.id"), nullable=True, index=True)
    immediate_action = Column(Text, nullable=False)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    regulatory_report_required = Column(Boolean, nullable=False, default=False)
    regulatory_report_ref = Column(String(500), nullable=True)
    root_cause = Column(Text, nullable=True)
    conclusion = Column(Text, nullable=True)
    status = Column(String(30), nullable=False, default="OPEN", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    investigated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    investigated_at = Column(DateTime, nullable=True)
    closed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    closed_at = Column(DateTime, nullable=True)


class GspCapaAction(Base):
    __tablename__ = "gsp_capa_actions"

    id = Column(Integer, primary_key=True)
    action_no = Column(String(100), nullable=False, unique=True)
    event_id = Column(Integer, ForeignKey("gsp_quality_events.id"), nullable=True, index=True)
    risk_id = Column(Integer, ForeignKey("gsp_quality_risks.id"), nullable=True, index=True)
    action_type = Column(String(30), nullable=False)
    description = Column(Text, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    due_date = Column(Date, nullable=False, index=True)
    completion_evidence_ref = Column(String(500), nullable=True)
    effectiveness_result = Column(Text, nullable=True)
    status = Column(String(30), nullable=False, default="OPEN", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    implemented_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    implemented_at = Column(DateTime, nullable=True)
    verified_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    verified_at = Column(DateTime, nullable=True)
    __table_args__ = (
        CheckConstraint(
            "event_id IS NOT NULL OR risk_id IS NOT NULL",
            name="ck_gsp_capa_has_source",
        ),
    )


class GspTrainingRecord(Base):
    __tablename__ = "gsp_training_records"

    id = Column(Integer, primary_key=True)
    training_no = Column(String(100), nullable=False, unique=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    subject = Column(String(200), nullable=False)
    training_type = Column(String(30), nullable=False, index=True)
    requirement_ref = Column(String(500), nullable=False)
    planned_date = Column(Date, nullable=False, index=True)
    trainer = Column(String(200), nullable=True)
    completed_on = Column(Date, nullable=True)
    score = Column(Integer, nullable=True)
    result = Column(String(30), nullable=True, index=True)
    evidence_ref = Column(String(500), nullable=True)
    valid_to = Column(Date, nullable=True, index=True)
    status = Column(String(30), nullable=False, default="PLANNED", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    completed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    verified_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    verified_at = Column(DateTime, nullable=True)
    __table_args__ = (
        CheckConstraint("score IS NULL OR score BETWEEN 0 AND 100", name="ck_gsp_training_score"),
    )


class GspControlledDocument(Base):
    __tablename__ = "gsp_controlled_documents"

    id = Column(Integer, primary_key=True)
    document_no = Column(String(100), nullable=False, unique=True)
    title = Column(String(200), nullable=False)
    document_type = Column(String(30), nullable=False, index=True)
    department = Column(String(100), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    current_version = Column(String(50), nullable=True)
    status = Column(String(30), nullable=False, default="DRAFT", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)


class GspDocumentRevision(Base):
    __tablename__ = "gsp_document_revisions"

    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, ForeignKey("gsp_controlled_documents.id"), nullable=False, index=True)
    version = Column(String(50), nullable=False)
    change_summary = Column(Text, nullable=False)
    content_ref = Column(String(500), nullable=False)
    content_sha256 = Column(String(64), nullable=False)
    effective_date = Column(Date, nullable=False, index=True)
    status = Column(String(30), nullable=False, default="DRAFT", index=True)
    drafted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    drafted_at = Column(DateTime, nullable=False, default=utc_now)
    submitted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    submitted_at = Column(DateTime, nullable=True)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    obsoleted_at = Column(DateTime, nullable=True)
    __table_args__ = (UniqueConstraint("document_id", "version", name="uq_gsp_document_revision"),)


class GspDocumentCopy(Base):
    __tablename__ = "gsp_document_copies"

    id = Column(Integer, primary_key=True)
    revision_id = Column(Integer, ForeignKey("gsp_document_revisions.id"), nullable=False, index=True)
    copy_no = Column(String(100), nullable=False, unique=True)
    holder = Column(String(200), nullable=False)
    location = Column(String(200), nullable=False)
    purpose = Column(String(500), nullable=False)
    status = Column(String(30), nullable=False, default="ISSUED", index=True)
    issued_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    issued_at = Column(DateTime, nullable=False, default=utc_now)
    returned_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    returned_at = Column(DateTime, nullable=True)
    destroyed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    destroyed_at = Column(DateTime, nullable=True)
    disposition_evidence_ref = Column(String(500), nullable=True)


class GspQualityEquipment(Base):
    __tablename__ = "gsp_quality_equipment"

    id = Column(Integer, primary_key=True)
    equipment_no = Column(String(100), nullable=False, unique=True)
    name = Column(String(200), nullable=False)
    category = Column(String(50), nullable=False, index=True)
    location = Column(String(200), nullable=False)
    criticality = Column(String(20), nullable=False)
    qualification_required = Column(Boolean, nullable=False, default=True)
    calibration_required = Column(Boolean, nullable=False, default=False)
    next_qualification_date = Column(Date, nullable=True, index=True)
    next_calibration_date = Column(Date, nullable=True, index=True)
    status = Column(String(30), nullable=False, default="PENDING", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)


class GspEquipmentActivity(Base):
    __tablename__ = "gsp_equipment_activities"

    id = Column(Integer, primary_key=True)
    activity_no = Column(String(100), nullable=False, unique=True)
    equipment_id = Column(Integer, ForeignKey("gsp_quality_equipment.id"), nullable=False, index=True)
    activity_type = Column(String(30), nullable=False, index=True)
    performed_on = Column(Date, nullable=False)
    valid_to = Column(Date, nullable=True, index=True)
    provider = Column(String(200), nullable=False)
    certificate_ref = Column(String(500), nullable=False)
    result = Column(String(30), nullable=False)
    status = Column(String(30), nullable=False, default="PENDING_REVIEW", index=True)
    recorded_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    recorded_at = Column(DateTime, nullable=False, default=utc_now)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_reason = Column(String(500), nullable=True)


class GspRegulatedScopeAuthorization(Base):
    __tablename__ = "gsp_regulated_scope_authorizations"

    id = Column(Integer, primary_key=True)
    category = Column(String(40), nullable=False, index=True)
    authorization_no = Column(String(100), nullable=False, unique=True)
    authorization_ref = Column(String(500), nullable=False)
    valid_to = Column(Date, nullable=False, index=True)
    controls_summary = Column(Text, nullable=False)
    status = Column(String(30), nullable=False, default="PENDING", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)

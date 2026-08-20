"""Persistence model for the GSP bounded context.

The original WMS tables remain available for compatibility.  These tables add
quality master data, lot-level control and an append-only audit trail without
coupling the domain to a specific distributor interface.
"""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)

from app.core.database import Base
from app.core.time import utc_now


class GspRoleAssignment(Base):
    __tablename__ = "gsp_role_assignments"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    role = Column(String(50), nullable=False, index=True)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    granted_at = Column(DateTime, nullable=False, default=utc_now)
    approval_ref = Column(String(200), nullable=False)
    review_due_at = Column(DateTime, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    last_reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    last_reviewed_at = Column(DateTime, nullable=True)
    revoked_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    revocation_reason = Column(String(500), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    __table_args__ = (UniqueConstraint("user_id", "role", name="uq_gsp_user_role"),)


class GspDrugProfile(Base):
    __tablename__ = "gsp_drug_profiles"
    id = Column(Integer, primary_key=True)
    goods_id = Column(Integer, ForeignKey("goods.id"), nullable=False, unique=True, index=True)
    approval_no = Column(String(100), nullable=False, unique=True, index=True)
    generic_name = Column(String(200), nullable=False)
    dosage_form = Column(String(100), nullable=False)
    manufacturer = Column(String(200), nullable=False)
    marketing_authorization_holder = Column(String(200), nullable=True)
    storage_condition = Column(String(30), nullable=False, default="NORMAL")
    min_temperature = Column(Float, nullable=True)
    max_temperature = Column(Float, nullable=True)
    is_prescription = Column(Boolean, nullable=False, default=True)
    is_special_controlled = Column(Boolean, nullable=False, default=False)
    traceability_required = Column(Boolean, nullable=False, default=True)
    registration_valid_to = Column(Date, nullable=True)
    registration_document_ref = Column(String(500), nullable=True)
    nmpa_verification_ref = Column(String(500), nullable=True)
    nmpa_verified_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    nmpa_verified_at = Column(DateTime, nullable=True)
    status = Column(String(30), nullable=False, default="PENDING", index=True)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    updated_at = Column(DateTime, nullable=False, default=utc_now, onupdate=utc_now)


class GspBusinessPartner(Base):
    __tablename__ = "gsp_business_partners"
    id = Column(Integer, primary_key=True)
    code = Column(String(50), nullable=False, unique=True, index=True)
    name = Column(String(200), nullable=False, index=True)
    partner_type = Column(String(20), nullable=False, index=True)
    unified_social_credit_code = Column(String(50), nullable=True, index=True)
    license_no = Column(String(100), nullable=False)
    license_scope = Column(Text, nullable=False)
    license_valid_from = Column(Date, nullable=True)
    license_valid_to = Column(Date, nullable=False, index=True)
    quality_agreement_valid_to = Column(Date, nullable=True)
    status = Column(String(30), nullable=False, default="PENDING", index=True)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    suspension_reason = Column(String(500), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    updated_at = Column(DateTime, nullable=False, default=utc_now, onupdate=utc_now)


class GspPartnerDocument(Base):
    __tablename__ = "gsp_partner_documents"
    id = Column(Integer, primary_key=True)
    partner_id = Column(Integer, ForeignKey("gsp_business_partners.id"), nullable=False, index=True)
    document_type = Column(String(50), nullable=False)
    document_no = Column(String(100), nullable=True)
    valid_from = Column(Date, nullable=True)
    valid_to = Column(Date, nullable=False, index=True)
    file_ref = Column(String(500), nullable=True)
    person_name = Column(String(200), nullable=True)
    person_role = Column(String(50), nullable=True)
    verified_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    verified_at = Column(DateTime, nullable=True)
    status = Column(String(30), nullable=False, default="PENDING")
    created_at = Column(DateTime, nullable=False, default=utc_now)
    __table_args__ = (
        UniqueConstraint("partner_id", "document_type", "document_no", name="uq_gsp_partner_document"),
    )


class GspDrugBatch(Base):
    __tablename__ = "gsp_drug_batches"
    id = Column(Integer, primary_key=True)
    goods_id = Column(Integer, ForeignKey("goods.id"), nullable=False, index=True)
    batch_no = Column(String(100), nullable=False, index=True)
    production_date = Column(Date, nullable=False)
    expiry_date = Column(Date, nullable=False, index=True)
    supplier_id = Column(Integer, ForeignKey("gsp_business_partners.id"), nullable=False, index=True)
    receipt_document_no = Column(String(100), nullable=False)
    inspection_report_no = Column(String(100), nullable=True)
    traceability_code = Column(String(200), nullable=True, index=True)
    arrival_temperature = Column(Float, nullable=True)
    transport_temperature_min = Column(Float, nullable=True)
    transport_temperature_max = Column(Float, nullable=True)
    temperature_record_ref = Column(String(500), nullable=True)
    acceptance_conclusion = Column(String(500), nullable=True)
    status = Column(String(30), nullable=False, default="PENDING_INSPECTION", index=True)
    accepted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    accepted_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    __table_args__ = (UniqueConstraint("goods_id", "batch_no", name="uq_gsp_goods_batch"),)


class GspBatchStock(Base):
    __tablename__ = "gsp_batch_stock"
    id = Column(Integer, primary_key=True)
    batch_id = Column(Integer, ForeignKey("gsp_drug_batches.id"), nullable=False, index=True)
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), nullable=False, index=True)
    location_id = Column(Integer, ForeignKey("locations.id"), nullable=False, index=True)
    quantity = Column(Numeric(18, 3), nullable=False, default=0)
    reserved_quantity = Column(Numeric(18, 3), nullable=False, default=0)
    stock_status = Column(String(30), nullable=False, default="AVAILABLE", index=True)
    lock_version = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime, nullable=False, default=utc_now, onupdate=utc_now)
    __table_args__ = (
        UniqueConstraint("batch_id", "warehouse_id", "location_id", name="uq_gsp_batch_location"),
        CheckConstraint("quantity >= 0", name="ck_gsp_batch_stock_quantity_nonnegative"),
        CheckConstraint("reserved_quantity >= 0", name="ck_gsp_batch_stock_reserved_nonnegative"),
        CheckConstraint(
            "reserved_quantity <= quantity",
            name="ck_gsp_batch_stock_reserved_not_over",
        ),
    )


class GspQualityHold(Base):
    __tablename__ = "gsp_quality_holds"
    id = Column(Integer, primary_key=True)
    batch_id = Column(Integer, ForeignKey("gsp_drug_batches.id"), nullable=False, index=True)
    reason_code = Column(String(50), nullable=False)
    reason = Column(String(500), nullable=False)
    status = Column(String(30), nullable=False, default="ACTIVE", index=True)
    initiated_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    initiated_at = Column(DateTime, nullable=False, default=utc_now)
    released_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    released_at = Column(DateTime, nullable=True)
    release_reason = Column(String(500), nullable=True)


class GspIntegrationMessage(Base):
    """Transactional outbox for 九州通 or other external integrations."""

    __tablename__ = "gsp_integration_outbox"
    id = Column(Integer, primary_key=True)
    destination = Column(String(50), nullable=False, index=True)
    message_type = Column(String(100), nullable=False, index=True)
    aggregate_type = Column(String(50), nullable=False)
    aggregate_id = Column(String(100), nullable=False)
    idempotency_key = Column(String(100), nullable=False, unique=True, index=True)
    payload = Column(JSON, nullable=False)
    status = Column(String(30), nullable=False, default="PENDING", index=True)
    attempt_count = Column(Integer, nullable=False, default=0)
    last_error = Column(Text, nullable=True)
    next_attempt_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    sent_at = Column(DateTime, nullable=True)


class GspAuditEvent(Base):
    """Append-only, hash-chained audit trail for regulated changes."""

    __tablename__ = "gsp_audit_events"
    id = Column(Integer, primary_key=True)
    actor_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    action = Column(String(100), nullable=False, index=True)
    entity_type = Column(String(100), nullable=False, index=True)
    entity_id = Column(String(100), nullable=False, index=True)
    reason = Column(String(500), nullable=False)
    before_data = Column(JSON, nullable=True)
    after_data = Column(JSON, nullable=True)
    source_ip = Column(String(100), nullable=True)
    previous_hash = Column(String(64), nullable=True)
    event_hash = Column(String(64), nullable=False, unique=True)
    occurred_at = Column(DateTime, nullable=False, default=utc_now, index=True)


class GspAuditVerification(Base):
    __tablename__ = "gsp_audit_verifications"

    id = Column(Integer, primary_key=True)
    requested_by = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    trigger_source = Column(String(50), nullable=False, default="MANUAL")
    evidence_ref = Column(String(500), nullable=False)
    checked_event_count = Column(Integer, nullable=False)
    valid = Column(Boolean, nullable=False, index=True)
    broken_event_id = Column(Integer, ForeignKey("gsp_audit_events.id"), nullable=True)
    verified_at = Column(DateTime, nullable=False, default=utc_now, index=True)

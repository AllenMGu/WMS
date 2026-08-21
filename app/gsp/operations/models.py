"""Persistence models for regulated operational controls.

Only secret-store metadata and evidence references are persisted.  Secret
values must never be submitted to or stored by these tables.
"""

from __future__ import annotations

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)

from app.core.database import Base
from app.core.time import utc_now


class GspSecretRotation(Base):
    __tablename__ = "gsp_secret_rotations"

    id = Column(Integer, primary_key=True)
    secret_name = Column(String(100), nullable=False, index=True)
    provider = Column(String(100), nullable=False)
    change_ref = Column(String(200), nullable=False)
    current_version_ref = Column(String(500), nullable=True)
    proposed_version_ref = Column(String(500), nullable=False)
    status = Column(String(40), nullable=False, default="SUBMITTED", index=True)
    reason = Column(String(500), nullable=False)
    requested_by = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    requested_at = Column(DateTime, nullable=False, default=utc_now)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    approval_evidence_ref = Column(String(500), nullable=True)
    implemented_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    implemented_at = Column(DateTime, nullable=True)
    implementation_evidence_ref = Column(String(500), nullable=True)
    verified_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    verified_at = Column(DateTime, nullable=True)
    verification_evidence_ref = Column(String(500), nullable=True)
    next_rotation_due_at = Column(DateTime, nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint(
            "secret_name",
            "proposed_version_ref",
            name="uq_gsp_secret_rotation_version",
        ),
        CheckConstraint(
            "status IN ('SUBMITTED','APPROVED','REJECTED','PENDING_VERIFICATION','VERIFIED','FAILED')",
            name="ck_gsp_secret_rotation_status",
        ),
    )


class GspBackupEvidence(Base):
    __tablename__ = "gsp_backup_evidence"

    id = Column(Integer, primary_key=True)
    backup_id = Column(String(100), nullable=False, unique=True, index=True)
    backup_type = Column(String(30), nullable=False)
    status = Column(String(20), nullable=False, index=True)
    scheduled_for = Column(DateTime, nullable=False, index=True)
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=False)
    checksum_sha256 = Column(String(64), nullable=True)
    size_bytes = Column(Integer, nullable=True)
    primary_storage_ref = Column(String(500), nullable=True)
    offsite_storage_ref = Column(String(500), nullable=True)
    offline_storage_ref = Column(String(500), nullable=True)
    retention_until = Column(DateTime, nullable=True)
    evidence_ref = Column(String(500), nullable=False)
    alert_evidence_ref = Column(String(500), nullable=True)
    recorded_by = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    recorded_at = Column(DateTime, nullable=False, default=utc_now)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_result = Column(String(20), nullable=True)
    review_evidence_ref = Column(String(500), nullable=True)

    __table_args__ = (
        CheckConstraint("backup_type IN ('FULL','INCREMENTAL')", name="ck_gsp_backup_type"),
        CheckConstraint("status IN ('SUCCESS','FAILED')", name="ck_gsp_backup_status"),
        CheckConstraint(
            "review_result IS NULL OR review_result IN ('ACCEPTED','REJECTED')",
            name="ck_gsp_backup_review_result",
        ),
        CheckConstraint("size_bytes IS NULL OR size_bytes > 0", name="ck_gsp_backup_size"),
    )


class GspRecoveryDrill(Base):
    __tablename__ = "gsp_recovery_drills"

    id = Column(Integer, primary_key=True)
    backup_evidence_id = Column(
        Integer,
        ForeignKey("gsp_backup_evidence.id"),
        nullable=False,
        index=True,
    )
    change_ref = Column(String(200), nullable=False)
    plan_ref = Column(String(500), nullable=False)
    scheduled_for = Column(DateTime, nullable=False, index=True)
    target_rto_minutes = Column(Integer, nullable=False)
    target_rpo_minutes = Column(Integer, nullable=False)
    status = Column(String(30), nullable=False, default="SUBMITTED", index=True)
    reason = Column(String(500), nullable=False)
    requested_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    requested_at = Column(DateTime, nullable=False, default=utc_now)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    approval_evidence_ref = Column(String(500), nullable=True)
    executed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    executed_at = Column(DateTime, nullable=True)
    restore_target_ref = Column(String(500), nullable=True)
    execution_evidence_ref = Column(String(500), nullable=True)
    actual_rto_minutes = Column(Integer, nullable=True)
    actual_rpo_minutes = Column(Integer, nullable=True)
    result = Column(String(20), nullable=True)
    verified_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    verified_at = Column(DateTime, nullable=True)
    verification_evidence_ref = Column(String(500), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "status IN ('SUBMITTED','APPROVED','REJECTED','EXECUTED','VERIFIED')",
            name="ck_gsp_recovery_drill_status",
        ),
        CheckConstraint("result IS NULL OR result IN ('PASS','FAIL')", name="ck_gsp_recovery_result"),
        CheckConstraint("target_rto_minutes > 0", name="ck_gsp_recovery_target_rto"),
        CheckConstraint("target_rpo_minutes >= 0", name="ck_gsp_recovery_target_rpo"),
        CheckConstraint(
            "actual_rto_minutes IS NULL OR actual_rto_minutes >= 0",
            name="ck_gsp_recovery_actual_rto",
        ),
        CheckConstraint(
            "actual_rpo_minutes IS NULL OR actual_rpo_minutes >= 0",
            name="ck_gsp_recovery_actual_rpo",
        ),
    )


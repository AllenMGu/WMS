from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OrmModel(StrictModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class Decision(StrictModel):
    decision: str = Field(..., pattern="^(APPROVE|REJECT)$")
    evidence_ref: str = Field(..., min_length=3, max_length=500)
    reason: str = Field(..., min_length=3, max_length=500)


class Verification(StrictModel):
    decision: str = Field(..., pattern="^(PASS|FAIL)$")
    evidence_ref: str = Field(..., min_length=3, max_length=500)
    reason: str = Field(..., min_length=3, max_length=500)


class SecretRotationCreate(StrictModel):
    secret_name: str = Field(..., min_length=3, max_length=100)
    provider: str = Field(..., min_length=3, max_length=100)
    change_ref: str = Field(..., min_length=3, max_length=200)
    current_version_ref: Optional[str] = Field(None, min_length=3, max_length=500)
    proposed_version_ref: str = Field(..., min_length=3, max_length=500)
    next_rotation_due_at: datetime
    reason: str = Field(..., min_length=3, max_length=500)

    @model_validator(mode="after")
    def version_must_change(self):
        if self.current_version_ref == self.proposed_version_ref:
            raise ValueError("新旧秘密版本引用不能相同")
        return self


class SecretRotationImplement(StrictModel):
    evidence_ref: str = Field(..., min_length=3, max_length=500)
    reason: str = Field(..., min_length=3, max_length=500)


class SecretRotationResponse(OrmModel):
    id: int
    secret_name: str
    provider: str
    change_ref: str
    current_version_ref: Optional[str]
    proposed_version_ref: str
    status: str
    reason: str
    requested_by: int
    requested_at: datetime
    approved_by: Optional[int]
    approved_at: Optional[datetime]
    approval_evidence_ref: Optional[str]
    implemented_by: Optional[int]
    implemented_at: Optional[datetime]
    implementation_evidence_ref: Optional[str]
    verified_by: Optional[int]
    verified_at: Optional[datetime]
    verification_evidence_ref: Optional[str]
    next_rotation_due_at: datetime


class BackupEvidenceCreate(StrictModel):
    backup_id: str = Field(..., min_length=3, max_length=100)
    backup_type: str = Field("FULL", pattern="^(FULL|INCREMENTAL)$")
    status: str = Field(..., pattern="^(SUCCESS|FAILED)$")
    scheduled_for: datetime
    started_at: datetime
    completed_at: datetime
    checksum_sha256: Optional[str] = Field(None, pattern="^[0-9a-f]{64}$")
    size_bytes: Optional[int] = Field(None, gt=0)
    primary_storage_ref: Optional[str] = Field(None, min_length=3, max_length=500)
    offsite_storage_ref: Optional[str] = Field(None, min_length=3, max_length=500)
    offline_storage_ref: Optional[str] = Field(None, min_length=3, max_length=500)
    retention_until: Optional[datetime] = None
    evidence_ref: str = Field(..., min_length=3, max_length=500)
    alert_evidence_ref: Optional[str] = Field(None, min_length=3, max_length=500)


class BackupReview(StrictModel):
    decision: str = Field(..., pattern="^(ACCEPTED|REJECTED)$")
    evidence_ref: str = Field(..., min_length=3, max_length=500)
    reason: str = Field(..., min_length=3, max_length=500)


class BackupEvidenceResponse(OrmModel):
    id: int
    backup_id: str
    backup_type: str
    status: str
    scheduled_for: datetime
    started_at: datetime
    completed_at: datetime
    checksum_sha256: Optional[str]
    size_bytes: Optional[int]
    primary_storage_ref: Optional[str]
    offsite_storage_ref: Optional[str]
    offline_storage_ref: Optional[str]
    retention_until: Optional[datetime]
    evidence_ref: str
    alert_evidence_ref: Optional[str]
    recorded_by: int
    recorded_at: datetime
    reviewed_by: Optional[int]
    reviewed_at: Optional[datetime]
    review_result: Optional[str]
    review_evidence_ref: Optional[str]


class RecoveryDrillCreate(StrictModel):
    backup_evidence_id: int
    change_ref: str = Field(..., min_length=3, max_length=200)
    plan_ref: str = Field(..., min_length=3, max_length=500)
    scheduled_for: datetime
    target_rto_minutes: int = Field(..., gt=0)
    target_rpo_minutes: int = Field(..., ge=0)
    reason: str = Field(..., min_length=3, max_length=500)


class RecoveryDrillExecute(StrictModel):
    restore_target_ref: str = Field(..., min_length=3, max_length=500)
    evidence_ref: str = Field(..., min_length=3, max_length=500)
    actual_rto_minutes: int = Field(..., ge=0)
    actual_rpo_minutes: int = Field(..., ge=0)
    result: str = Field(..., pattern="^(PASS|FAIL)$")
    reason: str = Field(..., min_length=3, max_length=500)


class RecoveryDrillResponse(OrmModel):
    id: int
    backup_evidence_id: int
    change_ref: str
    plan_ref: str
    scheduled_for: datetime
    target_rto_minutes: int
    target_rpo_minutes: int
    status: str
    reason: str
    requested_by: int
    requested_at: datetime
    approved_by: Optional[int]
    approved_at: Optional[datetime]
    approval_evidence_ref: Optional[str]
    executed_by: Optional[int]
    executed_at: Optional[datetime]
    restore_target_ref: Optional[str]
    execution_evidence_ref: Optional[str]
    actual_rto_minutes: Optional[int]
    actual_rpo_minutes: Optional[int]
    result: Optional[str]
    verified_by: Optional[int]
    verified_at: Optional[datetime]
    verification_evidence_ref: Optional[str]


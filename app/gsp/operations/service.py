"""State transitions for controlled operational evidence."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.audit import write_audit_event
from app.gsp.operations.models import GspBackupEvidence, GspRecoveryDrill, GspSecretRotation
from app.gsp.operations.schemas import (
    BackupEvidenceCreate,
    BackupReview,
    Decision,
    RecoveryDrillCreate,
    RecoveryDrillExecute,
    SecretRotationCreate,
    SecretRotationImplement,
    Verification,
)
from app.gsp.snapshots import model_snapshot


def _utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _audit(
    db: Session,
    *,
    actor_id: int,
    action: str,
    entity,
    reason: str,
    before: dict | None = None,
    source_ip: str | None = None,
) -> None:
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action=action,
        entity_type=type(entity).__name__,
        entity_id=str(entity.id),
        reason=reason,
        before_data=before,
        after_data=model_snapshot(entity),
        source_ip=source_ip,
    )


def request_secret_rotation(
    db: Session,
    *,
    payload: SecretRotationCreate,
    actor_id: int,
    source_ip: str | None = None,
) -> GspSecretRotation:
    due_at = _utc_naive(payload.next_rotation_due_at)
    if due_at <= utc_now():
        raise HTTPException(400, "下次轮换日期必须晚于当前时间")
    rotation = GspSecretRotation(
        **payload.model_dump(exclude={"next_rotation_due_at"}),
        next_rotation_due_at=due_at,
        status="SUBMITTED",
        requested_by=actor_id,
    )
    db.add(rotation)
    _audit(
        db,
        actor_id=actor_id,
        action="SECRET_ROTATION_SUBMITTED",
        entity=rotation,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return rotation


def decide_secret_rotation(
    db: Session,
    *,
    rotation: GspSecretRotation,
    payload: Decision,
    actor_id: int,
    source_ip: str | None = None,
) -> GspSecretRotation:
    if rotation.status != "SUBMITTED":
        raise HTTPException(409, "秘密轮换申请不在待审批状态")
    if rotation.requested_by == actor_id:
        raise HTTPException(400, "申请人不得审批自己的秘密轮换申请")
    before = model_snapshot(rotation)
    rotation.status = "APPROVED" if payload.decision == "APPROVE" else "REJECTED"
    rotation.approved_by = actor_id
    rotation.approved_at = utc_now()
    rotation.approval_evidence_ref = payload.evidence_ref
    _audit(
        db,
        actor_id=actor_id,
        action=f"SECRET_ROTATION_{rotation.status}",
        entity=rotation,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    return rotation


def implement_secret_rotation(
    db: Session,
    *,
    rotation: GspSecretRotation,
    payload: SecretRotationImplement,
    actor_id: int,
    source_ip: str | None = None,
) -> GspSecretRotation:
    if rotation.status != "APPROVED":
        raise HTTPException(409, "秘密轮换尚未通过独立审批")
    if rotation.approved_by == actor_id:
        raise HTTPException(400, "审批人不得实施秘密轮换")
    before = model_snapshot(rotation)
    rotation.status = "PENDING_VERIFICATION"
    rotation.implemented_by = actor_id
    rotation.implemented_at = utc_now()
    rotation.implementation_evidence_ref = payload.evidence_ref
    _audit(
        db,
        actor_id=actor_id,
        action="SECRET_ROTATION_IMPLEMENTED",
        entity=rotation,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    return rotation


def verify_secret_rotation(
    db: Session,
    *,
    rotation: GspSecretRotation,
    payload: Verification,
    actor_id: int,
    source_ip: str | None = None,
) -> GspSecretRotation:
    if rotation.status != "PENDING_VERIFICATION":
        raise HTTPException(409, "秘密轮换不在待验证状态")
    if actor_id in {rotation.requested_by, rotation.implemented_by}:
        raise HTTPException(400, "申请人或实施人不得验证秘密轮换结果")
    before = model_snapshot(rotation)
    rotation.status = "VERIFIED" if payload.decision == "PASS" else "FAILED"
    rotation.verified_by = actor_id
    rotation.verified_at = utc_now()
    rotation.verification_evidence_ref = payload.evidence_ref
    _audit(
        db,
        actor_id=actor_id,
        action=f"SECRET_ROTATION_{rotation.status}",
        entity=rotation,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    return rotation


def record_backup_evidence(
    db: Session,
    *,
    payload: BackupEvidenceCreate,
    actor_id: int,
    source_ip: str | None = None,
) -> GspBackupEvidence:
    values = payload.model_dump()
    for field in ("scheduled_for", "started_at", "completed_at", "retention_until"):
        if values[field] is not None:
            values[field] = _utc_naive(values[field])
    if values["completed_at"] < values["started_at"]:
        raise HTTPException(400, "备份完成时间不能早于开始时间")
    if payload.status == "SUCCESS":
        required = {
            "checksum_sha256": payload.checksum_sha256,
            "size_bytes": payload.size_bytes,
            "primary_storage_ref": payload.primary_storage_ref,
            "retention_until": payload.retention_until,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            raise HTTPException(400, f"成功备份缺少证据字段：{', '.join(missing)}")
        if not payload.offsite_storage_ref and not payload.offline_storage_ref:
            raise HTTPException(400, "成功备份必须提供异地或离线副本引用")
        if values["retention_until"] <= values["completed_at"]:
            raise HTTPException(400, "备份保留期限必须晚于完成时间")
    elif not payload.alert_evidence_ref:
        raise HTTPException(400, "失败备份必须提供告警证据引用")

    evidence = GspBackupEvidence(**values, recorded_by=actor_id)
    db.add(evidence)
    _audit(
        db,
        actor_id=actor_id,
        action=f"BACKUP_{payload.status}_RECORDED",
        entity=evidence,
        reason=f"记录计划备份结果 {payload.backup_id}",
        source_ip=source_ip,
    )
    return evidence


def review_backup_evidence(
    db: Session,
    *,
    evidence: GspBackupEvidence,
    payload: BackupReview,
    actor_id: int,
    source_ip: str | None = None,
) -> GspBackupEvidence:
    if evidence.reviewed_at is not None:
        raise HTTPException(409, "备份证据已经复核")
    if evidence.recorded_by == actor_id:
        raise HTTPException(400, "备份记录人不得复核自己的备份证据")
    before = model_snapshot(evidence)
    evidence.reviewed_by = actor_id
    evidence.reviewed_at = utc_now()
    evidence.review_result = payload.decision
    evidence.review_evidence_ref = payload.evidence_ref
    _audit(
        db,
        actor_id=actor_id,
        action=f"BACKUP_EVIDENCE_{payload.decision}",
        entity=evidence,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    return evidence


def request_recovery_drill(
    db: Session,
    *,
    payload: RecoveryDrillCreate,
    actor_id: int,
    source_ip: str | None = None,
) -> GspRecoveryDrill:
    backup = db.query(GspBackupEvidence).filter_by(id=payload.backup_evidence_id).first()
    if backup is None:
        raise HTTPException(404, "备份证据不存在")
    if backup.status != "SUCCESS" or backup.review_result != "ACCEPTED":
        raise HTTPException(409, "只能使用已独立复核通过的成功备份进行恢复演练")
    values = payload.model_dump()
    values["scheduled_for"] = _utc_naive(values["scheduled_for"])
    drill = GspRecoveryDrill(**values, status="SUBMITTED", requested_by=actor_id)
    db.add(drill)
    _audit(
        db,
        actor_id=actor_id,
        action="RECOVERY_DRILL_SUBMITTED",
        entity=drill,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return drill


def decide_recovery_drill(
    db: Session,
    *,
    drill: GspRecoveryDrill,
    payload: Decision,
    actor_id: int,
    source_ip: str | None = None,
) -> GspRecoveryDrill:
    if drill.status != "SUBMITTED":
        raise HTTPException(409, "恢复演练不在待审批状态")
    if drill.requested_by == actor_id:
        raise HTTPException(400, "申请人不得审批自己的恢复演练")
    before = model_snapshot(drill)
    drill.status = "APPROVED" if payload.decision == "APPROVE" else "REJECTED"
    drill.approved_by = actor_id
    drill.approved_at = utc_now()
    drill.approval_evidence_ref = payload.evidence_ref
    _audit(
        db,
        actor_id=actor_id,
        action=f"RECOVERY_DRILL_{drill.status}",
        entity=drill,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    return drill


def execute_recovery_drill(
    db: Session,
    *,
    drill: GspRecoveryDrill,
    payload: RecoveryDrillExecute,
    actor_id: int,
    source_ip: str | None = None,
) -> GspRecoveryDrill:
    if drill.status != "APPROVED":
        raise HTTPException(409, "恢复演练尚未通过独立审批")
    if drill.approved_by == actor_id:
        raise HTTPException(400, "审批人不得执行恢复演练")
    before = model_snapshot(drill)
    drill.status = "EXECUTED"
    drill.executed_by = actor_id
    drill.executed_at = utc_now()
    drill.restore_target_ref = payload.restore_target_ref
    drill.execution_evidence_ref = payload.evidence_ref
    drill.actual_rto_minutes = payload.actual_rto_minutes
    drill.actual_rpo_minutes = payload.actual_rpo_minutes
    drill.result = payload.result
    _audit(
        db,
        actor_id=actor_id,
        action="RECOVERY_DRILL_EXECUTED",
        entity=drill,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    return drill


def verify_recovery_drill(
    db: Session,
    *,
    drill: GspRecoveryDrill,
    payload: Verification,
    actor_id: int,
    source_ip: str | None = None,
) -> GspRecoveryDrill:
    if drill.status != "EXECUTED":
        raise HTTPException(409, "恢复演练尚未执行")
    if actor_id in {drill.requested_by, drill.executed_by}:
        raise HTTPException(400, "申请人或执行人不得验证恢复演练")
    if payload.decision != drill.result:
        raise HTTPException(400, "验证结论必须与受控执行结果一致；如有偏差应先更正执行记录")
    before = model_snapshot(drill)
    drill.status = "VERIFIED"
    drill.verified_by = actor_id
    drill.verified_at = utc_now()
    drill.verification_evidence_ref = payload.evidence_ref
    _audit(
        db,
        actor_id=actor_id,
        action=f"RECOVERY_DRILL_VERIFIED_{drill.result}",
        entity=drill,
        reason=payload.reason,
        before=before,
        source_ip=source_ip,
    )
    return drill


import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.core.database import SessionLocal
from app.core.time import utc_now
from app.gsp.audit import verify_audit_chain
from app.gsp.models import GspRoleAssignment
from app.gsp.operations.models import GspBackupEvidence
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
from app.gsp.operations.service import (
    decide_recovery_drill,
    decide_secret_rotation,
    execute_recovery_drill,
    implement_secret_rotation,
    record_backup_evidence,
    request_recovery_drill,
    request_secret_rotation,
    review_backup_evidence,
    verify_recovery_drill,
    verify_secret_rotation,
)
from app.legacy import User, UserRole
from scripts.register_backup_evidence import register


def _user(db, name: str) -> User:
    user = User(
        username=f"{name}-{uuid4().hex[:10]}",
        hashed_password="test-only",
        full_name=name,
        role=UserRole.OPERATOR,
    )
    db.add(user)
    db.flush()
    return user


def test_backup_json_is_registered_idempotently_by_scheduled_system_admin(tmp_path):
    import main  # noqa: F401

    db = SessionLocal()
    backup_id = f"AUTO-{uuid4().hex[:10]}"
    try:
        administrator = _user(db, "自动备份记录人")
        db.add(
            GspRoleAssignment(
                user_id=administrator.id,
                role="SYSTEM_ADMIN",
                approval_ref="QA-AUTO-BACKUP-001",
                review_due_at=utc_now() + timedelta(days=30),
                is_active=True,
            )
        )
        db.commit()
        now = datetime.now(UTC)
        evidence_file = tmp_path / "backup.evidence.json"
        evidence_file.write_text(
            json.dumps(
                {
                    "backup_id": backup_id,
                    "backup_type": "FULL",
                    "status": "SUCCESS",
                    "scheduled_for": now.isoformat(),
                    "started_at": now.isoformat(),
                    "completed_at": (now + timedelta(minutes=1)).isoformat(),
                    "checksum_sha256": "a" * 64,
                    "size_bytes": 1024,
                    "primary_storage_ref": "/backup/test.dump",
                    "offsite_storage_ref": "/offsite/test.dump",
                    "retention_until": (now + timedelta(days=90)).isoformat(),
                    "evidence_ref": str(evidence_file),
                }
            ),
            encoding="utf-8",
        )
        first_id = register(evidence_file)
        assert register(evidence_file) == first_id
        assert db.query(GspBackupEvidence).filter_by(backup_id=backup_id).count() == 1
    finally:
        db.query(GspBackupEvidence).filter_by(backup_id=backup_id).delete()
        db.query(GspRoleAssignment).filter(
            GspRoleAssignment.user_id == administrator.id
        ).delete()
        db.query(User).filter(User.id == administrator.id).delete()
        db.commit()
        db.close()


def test_secret_rotation_requires_independent_approval_implementation_and_verification():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        administrator = _user(db, "系统管理员")
        approver = _user(db, "质量审批人")
        verifier = _user(db, "独立验证人")
        rotation = request_secret_rotation(
            db,
            payload=SecretRotationCreate(
                secret_name="JWT_SIGNING_KEY",
                provider="azure-key-vault",
                change_ref="CHG-2026-081",
                current_version_ref="kv://jwt/v1",
                proposed_version_ref="kv://jwt/v2",
                next_rotation_due_at=datetime.now(UTC) + timedelta(days=90),
                reason="按批准周期轮换JWT签名密钥",
            ),
            actor_id=administrator.id,
        )
        with pytest.raises(HTTPException, match="申请人不得审批"):
            decide_secret_rotation(
                db,
                rotation=rotation,
                payload=Decision(
                    decision="APPROVE",
                    evidence_ref="oa://approval/081",
                    reason="错误的自行审批尝试",
                ),
                actor_id=administrator.id,
            )

        decide_secret_rotation(
            db,
            rotation=rotation,
            payload=Decision(
                decision="APPROVE",
                evidence_ref="oa://approval/081",
                reason="风险评估与回退方案已批准",
            ),
            actor_id=approver.id,
        )
        implement_secret_rotation(
            db,
            rotation=rotation,
            payload=SecretRotationImplement(
                evidence_ref="vault://audit/JWT_SIGNING_KEY/v2",
                reason="在批准窗口激活新版本并保留回退版本",
            ),
            actor_id=administrator.id,
        )
        with pytest.raises(HTTPException, match="申请人或实施人不得验证"):
            verify_secret_rotation(
                db,
                rotation=rotation,
                payload=Verification(
                    decision="PASS",
                    evidence_ref="test://jwt/smoke/081",
                    reason="错误的自行验证尝试",
                ),
                actor_id=administrator.id,
            )
        verify_secret_rotation(
            db,
            rotation=rotation,
            payload=Verification(
                decision="PASS",
                evidence_ref="test://jwt/smoke/081",
                reason="新旧会话与回退测试均通过",
            ),
            actor_id=verifier.id,
        )
        db.commit()

        assert rotation.status == "VERIFIED"
        assert rotation.requested_by != rotation.approved_by
        assert rotation.implemented_by != rotation.approved_by
        assert rotation.verified_by not in {rotation.requested_by, rotation.implemented_by}
        assert verify_audit_chain(db) == (True, None)
    finally:
        db.close()


def test_secret_rotation_schema_forbids_secret_values():
    with pytest.raises(ValidationError, match="secret_value"):
        SecretRotationCreate(
            secret_name="DATABASE_PASSWORD",
            provider="vault",
            change_ref="CHG-2026-082",
            proposed_version_ref="vault://database/v2",
            next_rotation_due_at=datetime.now(UTC) + timedelta(days=90),
            reason="计划轮换数据库密码",
            secret_value="must-never-be-stored",
        )


def test_backup_and_recovery_drill_evidence_are_independently_reviewed():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        administrator = _user(db, "备份管理员")
        approver = _user(db, "恢复审批人")
        verifier = _user(db, "恢复验证人")
        now = datetime.now(UTC)
        backup = record_backup_evidence(
            db,
            payload=BackupEvidenceCreate(
                backup_id=f"backup-{uuid4().hex[:10]}",
                backup_type="FULL",
                status="SUCCESS",
                scheduled_for=now - timedelta(minutes=20),
                started_at=now - timedelta(minutes=19),
                completed_at=now - timedelta(minutes=10),
                checksum_sha256="a" * 64,
                size_bytes=1024,
                primary_storage_ref="backup://primary/20260821.dump",
                offsite_storage_ref="backup://offsite/20260821.dump",
                retention_until=now + timedelta(days=90),
                evidence_ref="log://backup/20260821",
            ),
            actor_id=administrator.id,
        )
        with pytest.raises(HTTPException, match="不得复核自己的"):
            review_backup_evidence(
                db,
                evidence=backup,
                payload=BackupReview(
                    decision="ACCEPTED",
                    evidence_ref="review://backup/20260821",
                    reason="错误的自行复核尝试",
                ),
                actor_id=administrator.id,
            )
        review_backup_evidence(
            db,
            evidence=backup,
            payload=BackupReview(
                decision="ACCEPTED",
                evidence_ref="review://backup/20260821",
                reason="校验和、异地副本和保留期均符合要求",
            ),
            actor_id=verifier.id,
        )

        drill = request_recovery_drill(
            db,
            payload=RecoveryDrillCreate(
                backup_evidence_id=backup.id,
                change_ref="CHG-2026-083",
                plan_ref="sop://disaster-recovery/quarterly-v3",
                scheduled_for=now + timedelta(days=1),
                target_rto_minutes=60,
                target_rpo_minutes=1440,
                reason="执行季度独立恢复演练",
            ),
            actor_id=administrator.id,
        )
        decide_recovery_drill(
            db,
            drill=drill,
            payload=Decision(
                decision="APPROVE",
                evidence_ref="oa://recovery-drill/083",
                reason="隔离环境、回退与核对清单已批准",
            ),
            actor_id=approver.id,
        )
        execute_recovery_drill(
            db,
            drill=drill,
            payload=RecoveryDrillExecute(
                restore_target_ref="drill://postgres/isolated-20260821",
                evidence_ref="log://restore/20260821",
                actual_rto_minutes=35,
                actual_rpo_minutes=720,
                result="PASS",
                reason="完成空库恢复、迁移版本与关键记录核对",
            ),
            actor_id=administrator.id,
        )
        verify_recovery_drill(
            db,
            drill=drill,
            payload=Verification(
                decision="PASS",
                evidence_ref="qa://recovery/verification-083",
                reason="独立复核RTO、RPO、行数和审计链均通过",
            ),
            actor_id=verifier.id,
        )
        db.commit()

        assert backup.review_result == "ACCEPTED"
        assert drill.status == "VERIFIED"
        assert drill.result == "PASS"
        assert verify_audit_chain(db) == (True, None)
    finally:
        db.close()


def test_failed_backup_requires_alert_evidence():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        administrator = _user(db, "告警测试管理员")
        now = datetime.now(UTC)
        with pytest.raises(HTTPException, match="告警证据"):
            record_backup_evidence(
                db,
                payload=BackupEvidenceCreate(
                    backup_id=f"failed-{uuid4().hex[:10]}",
                    backup_type="FULL",
                    status="FAILED",
                    scheduled_for=now - timedelta(minutes=2),
                    started_at=now - timedelta(minutes=1),
                    completed_at=now,
                    evidence_ref="log://backup/failed",
                ),
                actor_id=administrator.id,
            )
    finally:
        db.rollback()
        db.close()

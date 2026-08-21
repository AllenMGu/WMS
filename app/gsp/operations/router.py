from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.dependencies import require_gsp_roles
from app.gsp.operations.models import GspBackupEvidence, GspRecoveryDrill, GspSecretRotation
from app.gsp.operations.schemas import (
    BackupEvidenceCreate,
    BackupEvidenceResponse,
    BackupReview,
    Decision,
    RecoveryDrillCreate,
    RecoveryDrillExecute,
    RecoveryDrillResponse,
    SecretRotationCreate,
    SecretRotationImplement,
    SecretRotationResponse,
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
from app.legacy import User

router = APIRouter(prefix="/gsp/operations", tags=["GSP运维合规"])


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _get(db: Session, model, entity_id: int, detail: str):
    entity = db.query(model).filter(model.id == entity_id).first()
    if entity is None:
        raise HTTPException(404, detail)
    return entity


@router.post("/secret-rotations", response_model=SecretRotationResponse, status_code=201)
async def create_secret_rotation(
    payload: SecretRotationCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("SYSTEM_ADMIN")),
    db: Session = Depends(get_db),
):
    rotation = request_secret_rotation(
        db, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
    )
    db.commit()
    db.refresh(rotation)
    return rotation


@router.post("/secret-rotations/{rotation_id}/decision", response_model=SecretRotationResponse)
async def approve_secret_rotation(
    rotation_id: int,
    payload: Decision,
    request: Request,
    current_user: User = Depends(require_gsp_roles("QUALITY_MANAGER", "QUALITY_REVIEWER")),
    db: Session = Depends(get_db),
):
    rotation = _get(db, GspSecretRotation, rotation_id, "秘密轮换申请不存在")
    decide_secret_rotation(
        db,
        rotation=rotation,
        payload=payload,
        actor_id=current_user.id,
        source_ip=_source_ip(request),
    )
    db.commit()
    return rotation


@router.post("/secret-rotations/{rotation_id}/implement", response_model=SecretRotationResponse)
async def activate_secret_rotation(
    rotation_id: int,
    payload: SecretRotationImplement,
    request: Request,
    current_user: User = Depends(require_gsp_roles("SYSTEM_ADMIN")),
    db: Session = Depends(get_db),
):
    rotation = _get(db, GspSecretRotation, rotation_id, "秘密轮换申请不存在")
    implement_secret_rotation(
        db,
        rotation=rotation,
        payload=payload,
        actor_id=current_user.id,
        source_ip=_source_ip(request),
    )
    db.commit()
    return rotation


@router.post("/secret-rotations/{rotation_id}/verify", response_model=SecretRotationResponse)
async def confirm_secret_rotation(
    rotation_id: int,
    payload: Verification,
    request: Request,
    current_user: User = Depends(require_gsp_roles("AUDITOR", "QUALITY_REVIEWER")),
    db: Session = Depends(get_db),
):
    rotation = _get(db, GspSecretRotation, rotation_id, "秘密轮换申请不存在")
    verify_secret_rotation(
        db,
        rotation=rotation,
        payload=payload,
        actor_id=current_user.id,
        source_ip=_source_ip(request),
    )
    db.commit()
    return rotation


@router.get("/secret-rotations", response_model=list[SecretRotationResponse])
async def list_secret_rotations(
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(
        require_gsp_roles("SYSTEM_ADMIN", "AUDITOR", "QUALITY_MANAGER", "QUALITY_REVIEWER")
    ),
    db: Session = Depends(get_db),
):
    return db.query(GspSecretRotation).order_by(GspSecretRotation.id.desc()).limit(limit).all()


@router.post("/backups", response_model=BackupEvidenceResponse, status_code=201)
async def create_backup_evidence(
    payload: BackupEvidenceCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("SYSTEM_ADMIN")),
    db: Session = Depends(get_db),
):
    evidence = record_backup_evidence(
        db, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
    )
    db.commit()
    db.refresh(evidence)
    return evidence


@router.post("/backups/{evidence_id}/review", response_model=BackupEvidenceResponse)
async def review_backup(
    evidence_id: int,
    payload: BackupReview,
    request: Request,
    current_user: User = Depends(require_gsp_roles("AUDITOR", "QUALITY_REVIEWER")),
    db: Session = Depends(get_db),
):
    evidence = _get(db, GspBackupEvidence, evidence_id, "备份证据不存在")
    review_backup_evidence(
        db,
        evidence=evidence,
        payload=payload,
        actor_id=current_user.id,
        source_ip=_source_ip(request),
    )
    db.commit()
    return evidence


@router.get("/backups", response_model=list[BackupEvidenceResponse])
async def list_backups(
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(
        require_gsp_roles("SYSTEM_ADMIN", "AUDITOR", "QUALITY_MANAGER", "QUALITY_REVIEWER")
    ),
    db: Session = Depends(get_db),
):
    return db.query(GspBackupEvidence).order_by(GspBackupEvidence.id.desc()).limit(limit).all()


@router.post("/recovery-drills", response_model=RecoveryDrillResponse, status_code=201)
async def create_recovery_drill(
    payload: RecoveryDrillCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("SYSTEM_ADMIN")),
    db: Session = Depends(get_db),
):
    drill = request_recovery_drill(
        db, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
    )
    db.commit()
    db.refresh(drill)
    return drill


@router.post("/recovery-drills/{drill_id}/decision", response_model=RecoveryDrillResponse)
async def approve_recovery_drill(
    drill_id: int,
    payload: Decision,
    request: Request,
    current_user: User = Depends(require_gsp_roles("QUALITY_MANAGER", "QUALITY_REVIEWER")),
    db: Session = Depends(get_db),
):
    drill = _get(db, GspRecoveryDrill, drill_id, "恢复演练不存在")
    decide_recovery_drill(
        db,
        drill=drill,
        payload=payload,
        actor_id=current_user.id,
        source_ip=_source_ip(request),
    )
    db.commit()
    return drill


@router.post("/recovery-drills/{drill_id}/execute", response_model=RecoveryDrillResponse)
async def run_recovery_drill(
    drill_id: int,
    payload: RecoveryDrillExecute,
    request: Request,
    current_user: User = Depends(require_gsp_roles("SYSTEM_ADMIN")),
    db: Session = Depends(get_db),
):
    drill = _get(db, GspRecoveryDrill, drill_id, "恢复演练不存在")
    execute_recovery_drill(
        db,
        drill=drill,
        payload=payload,
        actor_id=current_user.id,
        source_ip=_source_ip(request),
    )
    db.commit()
    return drill


@router.post("/recovery-drills/{drill_id}/verify", response_model=RecoveryDrillResponse)
async def confirm_recovery_drill(
    drill_id: int,
    payload: Verification,
    request: Request,
    current_user: User = Depends(require_gsp_roles("AUDITOR", "QUALITY_REVIEWER")),
    db: Session = Depends(get_db),
):
    drill = _get(db, GspRecoveryDrill, drill_id, "恢复演练不存在")
    verify_recovery_drill(
        db,
        drill=drill,
        payload=payload,
        actor_id=current_user.id,
        source_ip=_source_ip(request),
    )
    db.commit()
    return drill


@router.get("/recovery-drills", response_model=list[RecoveryDrillResponse])
async def list_recovery_drills(
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(
        require_gsp_roles("SYSTEM_ADMIN", "AUDITOR", "QUALITY_MANAGER", "QUALITY_REVIEWER")
    ),
    db: Session = Depends(get_db),
):
    return db.query(GspRecoveryDrill).order_by(GspRecoveryDrill.id.desc()).limit(limit).all()


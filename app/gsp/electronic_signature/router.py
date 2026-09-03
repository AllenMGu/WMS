from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.dependencies import require_gsp_roles
from app.gsp.electronic_signature.models import GspElectronicSignature
from app.gsp.electronic_signature.schemas import (
    ElectronicSignatureResponse,
    SignatureChainVerificationResponse,
    SignatureChallengeCreate,
    SignatureChallengeResponse,
    SignatureVerificationResponse,
)
from app.gsp.electronic_signature.service import (
    SIGNATURE_POLICIES,
    create_signature_challenge,
    verify_signature,
    verify_signature_chain,
)
from app.gsp.errors import WorkflowError
from app.legacy import User, get_current_user

router = APIRouter(prefix="/gsp/electronic-signatures", tags=["GSP电子签名"])


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("/policies")
async def list_signature_policies(
    current_user: User = Depends(get_current_user),
):
    return [
        {"action": action, "entity_type": policy[0], "meaning": policy[1]}
        for action, policy in sorted(SIGNATURE_POLICIES.items())
    ]


@router.post("/challenges", response_model=SignatureChallengeResponse, status_code=201)
async def create_challenge(
    payload: SignatureChallengeCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        challenge, token = create_signature_challenge(
            db,
            user=current_user,
            payload=payload,
            source_ip=_source_ip(request),
        )
        db.commit()
        return SignatureChallengeResponse(
            challenge_ref=challenge.challenge_ref,
            signature_token=token,
            action=challenge.action,
            entity_type=challenge.entity_type,
            entity_id=challenge.entity_id,
            meaning=challenge.meaning,
            payload_hash=challenge.payload_hash,
            verified_at=challenge.verified_at,
            expires_at=challenge.expires_at,
        )
    except WorkflowError as error:
        db.rollback()
        raise HTTPException(error.status_code, error.detail) from error
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(409, "电子签名挑战重复，请重试") from error


@router.get("", response_model=list[ElectronicSignatureResponse])
async def list_signatures(
    signer_user_id: int | None = Query(None, gt=0),
    entity_type: str | None = None,
    entity_id: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_gsp_roles("AUDITOR", "QUALITY_MANAGER", "QUALITY_REVIEWER")),
    db: Session = Depends(get_db),
):
    query = db.query(GspElectronicSignature)
    if signer_user_id:
        query = query.filter(GspElectronicSignature.signer_user_id == signer_user_id)
    if entity_type:
        query = query.filter(GspElectronicSignature.entity_type == entity_type)
    if entity_id:
        query = query.filter(GspElectronicSignature.entity_id == entity_id)
    return query.order_by(GspElectronicSignature.id.desc()).offset(offset).limit(limit).all()


@router.get("/{signature_ref}/verify", response_model=SignatureVerificationResponse)
async def verify_one_signature(
    signature_ref: str,
    current_user: User = Depends(require_gsp_roles("AUDITOR", "QUALITY_MANAGER", "QUALITY_REVIEWER")),
    db: Session = Depends(get_db),
):
    signature = db.query(GspElectronicSignature).filter(
        GspElectronicSignature.signature_ref == signature_ref
    ).first()
    if signature is None:
        raise HTTPException(404, "电子签名不存在")
    return SignatureVerificationResponse(
        signature_ref=signature.signature_ref,
        valid=verify_signature(signature),
    )


@router.get("/verify-chain/all", response_model=SignatureChainVerificationResponse)
async def verify_all_signatures(
    current_user: User = Depends(require_gsp_roles("AUDITOR", "QUALITY_MANAGER")),
    db: Session = Depends(get_db),
):
    valid, broken_signature_id, checked = verify_signature_chain(db)
    return SignatureChainVerificationResponse(
        valid=valid,
        checked_signature_count=checked,
        broken_signature_id=broken_signature_id,
    )

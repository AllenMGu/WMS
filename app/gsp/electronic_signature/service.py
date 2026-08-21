"""Credential re-confirmation and tamper-evident electronic signature service."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.audit import write_audit_event
from app.gsp.electronic_signature.models import (
    GspElectronicSignature,
    GspSignatureChallenge,
)
from app.gsp.electronic_signature.schemas import SignatureChallengeCreate
from app.gsp.errors import WorkflowError
from app.legacy import User, ldap_authenticate, verify_password

CHALLENGE_TTL_MINUTES = 5

# Frontends use this registry to request the exact signature meaning required by
# a regulated endpoint.  The server also rejects challenges outside this list.
SIGNATURE_POLICIES: dict[str, tuple[str, str]] = {
    "ROLE_ASSIGNMENT_REVIEW": ("GspRoleAssignment", "REVIEW"),
    "ROLE_ASSIGNMENT_REVOKE": ("GspRoleAssignment", "RESPONSIBILITY"),
    "PARTNER_APPROVE": ("GspBusinessPartner", "APPROVAL"),
    "PARTNER_DOCUMENT_VERIFY": ("GspPartnerDocument", "REVIEW"),
    "PARTNER_SUSPEND": ("GspBusinessPartner", "RESPONSIBILITY"),
    "DRUG_PROFILE_APPROVE": ("GspDrugProfile", "APPROVAL"),
    "BATCH_ACCEPT": ("GspDrugBatch", "CONFIRMATION"),
    "QUALITY_HOLD_RELEASE": ("GspQualityHold", "RELEASE"),
    "PURCHASE_ORDER_APPROVE": ("GspPurchaseOrder", "APPROVAL"),
    "RECEIPT_ITEM_INSPECT": ("GspReceiptItem", "CONFIRMATION"),
    "SALES_ORDER_APPROVE": ("GspSalesOrder", "APPROVAL"),
    "SHIPMENT_REVIEW": ("GspShipment", "REVIEW"),
    "SHIPMENT_DISPATCH": ("GspShipment", "RESPONSIBILITY"),
    "NONCONFORMING_DISPOSITION_APPROVE": ("GspNonconformingRecord", "APPROVAL"),
    "NONCONFORMING_DESTROY": ("GspNonconformingRecord", "RESPONSIBILITY"),
    "PURCHASE_RETURN_APPROVE": ("GspPurchaseReturn", "APPROVAL"),
    "PURCHASE_RETURN_DISPATCH": ("GspPurchaseReturn", "RESPONSIBILITY"),
    "ENVIRONMENT_DEVICE_DECISION": ("GspEnvironmentDevice", "APPROVAL"),
    "ENVIRONMENT_DEVICE_SUSPEND": ("GspEnvironmentDevice", "RESPONSIBILITY"),
    "ENVIRONMENT_ASSIGNMENT_DECISION": ("GspEnvironmentAssignment", "APPROVAL"),
    "ENVIRONMENT_ASSIGNMENT_CLOSE": ("GspEnvironmentAssignment", "RESPONSIBILITY"),
    "ENVIRONMENT_ALARM_DECISION": ("GspEnvironmentAlarm", "APPROVAL"),
    "CARRIER_DOCUMENT_DECISION": ("GspCarrierDocument", "REVIEW"),
    "CARRIER_DECISION": ("GspCarrier", "APPROVAL"),
    "CARRIER_VEHICLE_DECISION": ("GspCarrierVehicle", "APPROVAL"),
    "CARRIER_DRIVER_DECISION": ("GspCarrierDriver", "APPROVAL"),
    "TRANSPORT_EXCEPTION_DECISION": ("GspTransportException", "APPROVAL"),
    "TRANSPORT_DELIVERY": ("GspTransportTask", "CONFIRMATION"),
    "TRANSPORT_CLOSE": ("GspTransportTask", "REVIEW"),
    "MAINTENANCE_PLAN_APPROVE": ("GspMaintenancePlan", "APPROVAL"),
    "MAINTENANCE_PLAN_COMPLETE": ("GspMaintenancePlan", "REVIEW"),
    "STOCKTAKE_PLAN_APPROVE": ("GspStocktakePlan", "APPROVAL"),
    "STOCKTAKE_RESULTS_REVIEW": ("GspStocktakePlan", "REVIEW"),
    "STOCKTAKE_ADJUSTMENTS_APPLY": ("GspStocktakePlan", "RESPONSIBILITY"),
    "SECRET_ROTATION_DECISION": ("GspSecretRotation", "APPROVAL"),
    "SECRET_ROTATION_IMPLEMENT": ("GspSecretRotation", "RESPONSIBILITY"),
    "SECRET_ROTATION_VERIFY": ("GspSecretRotation", "REVIEW"),
    "BACKUP_EVIDENCE_REVIEW": ("GspBackupEvidence", "REVIEW"),
    "RECOVERY_DRILL_DECISION": ("GspRecoveryDrill", "APPROVAL"),
    "RECOVERY_DRILL_EXECUTE": ("GspRecoveryDrill", "RESPONSIBILITY"),
    "RECOVERY_DRILL_VERIFY": ("GspRecoveryDrill", "REVIEW"),
    "SALES_RETURN_ITEM_INSPECT": ("GspSalesReturnItem", "APPROVAL"),
    "RECALL_ACTIVATE": ("GspRecall", "RESPONSIBILITY"),
    "RECALL_CLOSE": ("GspRecall", "REVIEW"),
    "RECALL_COMPLETION_REPORT": ("GspRecall", "RESPONSIBILITY"),
    "RECALL_DRILL_COMPLETE": ("GspRecallDrill", "REVIEW"),
}


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def payload_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _signature_hash(
    *,
    signature_ref: str,
    challenge_ref: str,
    signer_user_id: int,
    signer_username: str,
    signer_full_name: str,
    authentication_method: str,
    meaning: str,
    action: str,
    entity_type: str,
    entity_id: str,
    payload_snapshot: dict[str, Any],
    payload_digest: str,
    reason: str,
    source_ip: str | None,
    previous_hash: str | None,
    credential_verified_at,
    signed_at,
) -> str:
    canonical = _canonical_json(
        {
            "signature_ref": signature_ref,
            "challenge_ref": challenge_ref,
            "signer_user_id": signer_user_id,
            "signer_username": signer_username,
            "signer_full_name": signer_full_name,
            "authentication_method": authentication_method,
            "meaning": meaning,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "payload_snapshot": payload_snapshot,
            "payload_hash": payload_digest,
            "reason": reason,
            "source_ip": source_ip,
            "previous_hash": previous_hash,
            "credential_verified_at": credential_verified_at.isoformat(timespec="microseconds"),
            "signed_at": signed_at.isoformat(timespec="microseconds"),
        }
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _verify_credentials(user: User, password: str) -> str:
    if user.is_ldap_user:
        authenticated, _ = ldap_authenticate(user.username, password)
        if authenticated:
            return "LDAP"
    elif user.hashed_password:
        try:
            if verify_password(password, user.hashed_password):
                return "LOCAL"
        except (TypeError, ValueError):
            pass
    raise WorkflowError(401, "电子签名身份再确认失败")


def create_signature_challenge(
    db: Session,
    *,
    user: User,
    payload: SignatureChallengeCreate,
    source_ip: str | None = None,
) -> tuple[GspSignatureChallenge, str]:
    policy = SIGNATURE_POLICIES.get(payload.action)
    if policy is None:
        raise WorkflowError(422, "该操作未配置电子签名策略")
    if policy != (payload.entity_type, payload.meaning):
        raise WorkflowError(422, "电子签名的记录类型或签名含义不符合操作策略")
    authentication_method = _verify_credentials(user, payload.password.get_secret_value())
    now = utc_now()
    token = secrets.token_urlsafe(32)
    challenge = GspSignatureChallenge(
        challenge_ref=str(uuid4()),
        token_hash=_token_hash(token),
        signer_user_id=user.id,
        signer_username=user.username,
        signer_full_name=user.full_name or user.username,
        authentication_method=authentication_method,
        meaning=payload.meaning,
        action=payload.action,
        entity_type=payload.entity_type,
        entity_id=payload.entity_id,
        payload_snapshot=payload.payload,
        payload_hash=payload_hash(payload.payload),
        reason=payload.reason,
        status="READY",
        verified_at=now,
        expires_at=now + timedelta(minutes=CHALLENGE_TTL_MINUTES),
        source_ip=source_ip,
    )
    db.add(challenge)
    db.flush()
    write_audit_event(
        db,
        actor_user_id=user.id,
        action="ELECTRONIC_SIGNATURE_IDENTITY_RECONFIRMED",
        entity_type="GspSignatureChallenge",
        entity_id=challenge.challenge_ref,
        reason=payload.reason,
        after_data={
            "action": payload.action,
            "entity_type": payload.entity_type,
            "entity_id": payload.entity_id,
            "meaning": payload.meaning,
            "payload_hash": challenge.payload_hash,
            "authentication_method": authentication_method,
            "expires_at": challenge.expires_at.isoformat(timespec="microseconds"),
        },
        source_ip=source_ip,
    )
    return challenge, token


def consume_signature_challenge(
    db: Session,
    *,
    token: str,
    actor_id: int,
    action: str,
    entity_type: str,
    entity_id: str,
    meaning: str,
    payload: dict[str, Any],
    source_ip: str | None = None,
) -> GspElectronicSignature:
    challenge = (
        db.query(GspSignatureChallenge)
        .filter(GspSignatureChallenge.token_hash == _token_hash(token))
        .with_for_update()
        .first()
    )
    if challenge is None:
        raise WorkflowError(401, "电子签名令牌无效")
    if challenge.signer_user_id != actor_id:
        raise WorkflowError(403, "电子签名令牌不属于当前用户")
    if challenge.status != "READY":
        raise WorkflowError(409, "电子签名令牌已使用")
    if challenge.expires_at <= utc_now():
        raise WorkflowError(401, "电子签名令牌已过期，请重新确认身份")
    expected = (action, entity_type, str(entity_id), meaning, payload_hash(payload))
    actual = (
        challenge.action,
        challenge.entity_type,
        challenge.entity_id,
        challenge.meaning,
        challenge.payload_hash,
    )
    if actual != expected:
        raise WorkflowError(409, "电子签名与当前操作、记录、含义或请求内容不匹配")

    db.flush()
    previous = db.query(GspElectronicSignature).order_by(GspElectronicSignature.id.desc()).first()
    previous_hash = previous.signature_hash if previous else None
    signed_at = utc_now()
    signature_ref = str(uuid4())
    signature_digest = _signature_hash(
        signature_ref=signature_ref,
        challenge_ref=challenge.challenge_ref,
        signer_user_id=challenge.signer_user_id,
        signer_username=challenge.signer_username,
        signer_full_name=challenge.signer_full_name,
        authentication_method=challenge.authentication_method,
        meaning=meaning,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        payload_snapshot=payload,
        payload_digest=challenge.payload_hash,
        reason=challenge.reason,
        source_ip=source_ip,
        previous_hash=previous_hash,
        credential_verified_at=challenge.verified_at,
        signed_at=signed_at,
    )
    signature = GspElectronicSignature(
        signature_ref=signature_ref,
        challenge_id=challenge.id,
        challenge_ref=challenge.challenge_ref,
        signer_user_id=challenge.signer_user_id,
        signer_username=challenge.signer_username,
        signer_full_name=challenge.signer_full_name,
        authentication_method=challenge.authentication_method,
        meaning=meaning,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        payload_snapshot=payload,
        payload_hash=challenge.payload_hash,
        reason=challenge.reason,
        source_ip=source_ip,
        previous_hash=previous_hash,
        signature_hash=signature_digest,
        credential_verified_at=challenge.verified_at,
        signed_at=signed_at,
    )
    db.add(signature)
    challenge.status = "CONSUMED"
    challenge.consumed_at = signed_at
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="ELECTRONIC_SIGNATURE_APPLIED",
        entity_type=entity_type,
        entity_id=str(entity_id),
        reason=challenge.reason,
        after_data={
            "signature_ref": signature.signature_ref,
            "meaning": meaning,
            "signed_action": action,
            "payload_hash": signature.payload_hash,
            "signature_hash": signature.signature_hash,
        },
        source_ip=source_ip,
    )
    return signature


def verify_signature(signature: GspElectronicSignature) -> bool:
    expected = _signature_hash(
        signature_ref=signature.signature_ref,
        challenge_ref=signature.challenge_ref,
        signer_user_id=signature.signer_user_id,
        signer_username=signature.signer_username,
        signer_full_name=signature.signer_full_name,
        authentication_method=signature.authentication_method,
        meaning=signature.meaning,
        action=signature.action,
        entity_type=signature.entity_type,
        entity_id=signature.entity_id,
        payload_snapshot=signature.payload_snapshot,
        payload_digest=signature.payload_hash,
        reason=signature.reason,
        source_ip=signature.source_ip,
        previous_hash=signature.previous_hash,
        credential_verified_at=signature.credential_verified_at,
        signed_at=signature.signed_at,
    )
    return signature.payload_hash == payload_hash(signature.payload_snapshot) and (
        signature.signature_hash == expected
    )


def verify_signature_chain(db: Session) -> tuple[bool, int | None, int]:
    expected_previous_hash = None
    checked = 0
    for signature in db.query(GspElectronicSignature).order_by(GspElectronicSignature.id):
        checked += 1
        if signature.previous_hash != expected_previous_hash or not verify_signature(signature):
            return False, signature.id, checked
        expected_previous_hash = signature.signature_hash
    return True, None, checked

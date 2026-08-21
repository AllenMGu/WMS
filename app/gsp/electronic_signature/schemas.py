from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class SignatureChallengeCreate(BaseModel):
    action: str = Field(..., min_length=3, max_length=100)
    entity_type: str = Field(..., min_length=3, max_length=100)
    entity_id: str = Field(..., min_length=1, max_length=100)
    meaning: str = Field(
        ...,
        pattern="^(APPROVAL|REVIEW|RELEASE|CONFIRMATION|RESPONSIBILITY)$",
    )
    payload: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(..., min_length=3, max_length=500)
    password: SecretStr


class SignatureChallengeResponse(BaseModel):
    challenge_ref: str
    signature_token: str
    action: str
    entity_type: str
    entity_id: str
    meaning: str
    payload_hash: str
    verified_at: datetime
    expires_at: datetime


class ElectronicSignatureResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    signature_ref: str
    challenge_ref: str
    signer_user_id: int
    signer_username: str
    signer_full_name: str
    authentication_method: str
    meaning: str
    action: str
    entity_type: str
    entity_id: str
    payload_snapshot: dict[str, Any]
    payload_hash: str
    reason: str
    source_ip: str | None
    previous_hash: str | None
    signature_hash: str
    credential_verified_at: datetime
    signed_at: datetime


class SignatureVerificationResponse(BaseModel):
    signature_ref: str
    valid: bool


class SignatureChainVerificationResponse(BaseModel):
    valid: bool
    checked_signature_count: int
    broken_signature_id: int | None

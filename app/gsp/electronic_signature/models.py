"""Persistence models for short-lived signing challenges and immutable signatures."""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    event,
)

from app.core.database import Base
from app.core.time import utc_now


class GspSignatureChallenge(Base):
    __tablename__ = "gsp_signature_challenges"

    id = Column(Integer, primary_key=True)
    challenge_ref = Column(String(36), nullable=False, unique=True, index=True)
    token_hash = Column(String(64), nullable=False, unique=True)
    signer_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    signer_username = Column(String(50), nullable=False)
    signer_full_name = Column(String(100), nullable=False)
    authentication_method = Column(String(20), nullable=False)
    meaning = Column(String(30), nullable=False, index=True)
    action = Column(String(100), nullable=False, index=True)
    entity_type = Column(String(100), nullable=False, index=True)
    entity_id = Column(String(100), nullable=False, index=True)
    payload_snapshot = Column(JSON, nullable=False)
    payload_hash = Column(String(64), nullable=False)
    reason = Column(String(500), nullable=False)
    status = Column(String(20), nullable=False, default="READY", index=True)
    verified_at = Column(DateTime, nullable=False, default=utc_now)
    expires_at = Column(DateTime, nullable=False, index=True)
    consumed_at = Column(DateTime, nullable=True)
    source_ip = Column(String(100), nullable=True)
    __table_args__ = (
        CheckConstraint(
            "authentication_method IN ('LOCAL','LDAP')",
            name="ck_gsp_signature_challenge_auth_method",
        ),
        CheckConstraint(
            "meaning IN ('APPROVAL','REVIEW','RELEASE','CONFIRMATION','RESPONSIBILITY','REJECTION')",
            name="ck_gsp_signature_challenge_meaning",
        ),
        CheckConstraint(
            "status IN ('READY','CONSUMED')",
            name="ck_gsp_signature_challenge_status",
        ),
    )


class GspElectronicSignature(Base):
    __tablename__ = "gsp_electronic_signatures"

    id = Column(Integer, primary_key=True)
    signature_ref = Column(String(36), nullable=False, unique=True, index=True)
    challenge_id = Column(
        Integer,
        ForeignKey("gsp_signature_challenges.id"),
        nullable=False,
        unique=True,
    )
    challenge_ref = Column(String(36), nullable=False)
    signer_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    signer_username = Column(String(50), nullable=False)
    signer_full_name = Column(String(100), nullable=False)
    authentication_method = Column(String(20), nullable=False)
    meaning = Column(String(30), nullable=False, index=True)
    action = Column(String(100), nullable=False, index=True)
    entity_type = Column(String(100), nullable=False, index=True)
    entity_id = Column(String(100), nullable=False, index=True)
    payload_snapshot = Column(JSON, nullable=False)
    payload_hash = Column(String(64), nullable=False)
    reason = Column(String(500), nullable=False)
    source_ip = Column(String(100), nullable=True)
    previous_hash = Column(String(64), nullable=True)
    signature_hash = Column(String(64), nullable=False, unique=True)
    credential_verified_at = Column(DateTime, nullable=False)
    signed_at = Column(DateTime, nullable=False, default=utc_now, index=True)
    __table_args__ = (
        CheckConstraint(
            "authentication_method IN ('LOCAL','LDAP')",
            name="ck_gsp_electronic_signature_auth_method",
        ),
        CheckConstraint(
            "meaning IN ('APPROVAL','REVIEW','RELEASE','CONFIRMATION','RESPONSIBILITY','REJECTION')",
            name="ck_gsp_electronic_signature_meaning",
        ),
    )


def _immutable_signature(_mapper, _connection, _target) -> None:
    raise RuntimeError("电子签名为不可变记录，禁止更新或删除")


event.listen(GspElectronicSignature, "before_update", _immutable_signature)
event.listen(GspElectronicSignature, "before_delete", _immutable_signature)

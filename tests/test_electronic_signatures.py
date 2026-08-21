from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest

from app.core.database import SessionLocal
from app.core.time import utc_now
from app.gsp.electronic_signature.models import GspElectronicSignature
from app.gsp.electronic_signature.schemas import SignatureChallengeCreate
from app.gsp.electronic_signature.service import (
    consume_signature_challenge,
    create_signature_challenge,
    verify_signature,
    verify_signature_chain,
)
from app.gsp.errors import WorkflowError
from app.legacy import User, UserRole, get_password_hash


def _signature_request(*, password: str, payload: dict | None = None):
    return SignatureChallengeCreate(
        action="SALES_ORDER_APPROVE",
        entity_type="GspSalesOrder",
        entity_id="42",
        meaning="APPROVAL",
        payload=payload or {"reason": "购货方和品种资质复核通过"},
        reason="本人批准销售订单并承担审批责任",
        password=password,
    )


def test_signature_reconfirms_identity_binds_payload_and_is_single_use():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        signature_count_before = db.query(GspElectronicSignature).count()
        suffix = uuid4().hex[:10]
        signer = User(
            username=f"signature-{suffix}",
            hashed_password=get_password_hash("correct-password"),
            full_name="质量签署人",
            role=UserRole.ADMIN,
            is_active=True,
            is_ldap_user=False,
        )
        other = User(
            username=f"signature-other-{suffix}",
            hashed_password=get_password_hash("other-password"),
            full_name="其他用户",
            role=UserRole.ADMIN,
            is_active=True,
            is_ldap_user=False,
        )
        db.add_all([signer, other])
        db.flush()

        with pytest.raises(WorkflowError, match="身份再确认失败"):
            create_signature_challenge(
                db,
                user=signer,
                payload=_signature_request(password="wrong-password"),
            )

        challenge, token = create_signature_challenge(
            db,
            user=signer,
            payload=_signature_request(password="correct-password"),
            source_ip="127.0.0.1",
        )
        assert challenge.authentication_method == "LOCAL"
        assert challenge.token_hash != token

        with pytest.raises(WorkflowError, match="不属于当前用户"):
            consume_signature_challenge(
                db,
                token=token,
                actor_id=other.id,
                action="SALES_ORDER_APPROVE",
                entity_type="GspSalesOrder",
                entity_id="42",
                meaning="APPROVAL",
                payload={"reason": "购货方和品种资质复核通过"},
            )

        with pytest.raises(WorkflowError, match="不匹配"):
            consume_signature_challenge(
                db,
                token=token,
                actor_id=signer.id,
                action="SALES_ORDER_APPROVE",
                entity_type="GspSalesOrder",
                entity_id="42",
                meaning="APPROVAL",
                payload={"reason": "请求内容已经被替换"},
            )

        signature = consume_signature_challenge(
            db,
            token=token,
            actor_id=signer.id,
            action="SALES_ORDER_APPROVE",
            entity_type="GspSalesOrder",
            entity_id="42",
            meaning="APPROVAL",
            payload={"reason": "购货方和品种资质复核通过"},
            source_ip="127.0.0.1",
        )
        db.commit()
        assert signature.signer_username == signer.username
        assert signature.signer_full_name == "质量签署人"
        assert signature.meaning == "APPROVAL"
        assert verify_signature(signature) is True
        assert verify_signature_chain(db) == (True, None, signature_count_before + 1)

        with pytest.raises(WorkflowError, match="已使用"):
            consume_signature_challenge(
                db,
                token=token,
                actor_id=signer.id,
                action="SALES_ORDER_APPROVE",
                entity_type="GspSalesOrder",
                entity_id="42",
                meaning="APPROVAL",
                payload={"reason": "购货方和品种资质复核通过"},
            )

        signature.reason = "禁止修改签署理由"
        with pytest.raises(RuntimeError, match="不可变记录"):
            db.flush()
        db.rollback()
        assert db.query(GspElectronicSignature).filter_by(id=signature.id).one()

        expired_challenge, expired_token = create_signature_challenge(
            db,
            user=signer,
            payload=_signature_request(password="correct-password"),
        )
        expired_challenge.expires_at = utc_now() - timedelta(seconds=1)
        with pytest.raises(WorkflowError, match="已过期"):
            consume_signature_challenge(
                db,
                token=expired_token,
                actor_id=signer.id,
                action="SALES_ORDER_APPROVE",
                entity_type="GspSalesOrder",
                entity_id="42",
                meaning="APPROVAL",
                payload={"reason": "购货方和品种资质复核通过"},
            )
    finally:
        db.close()


def test_regulated_routes_publish_signature_header_gate():
    import main

    schema = main.app.openapi()
    assert "/api/gsp/electronic-signatures/challenges" in schema["paths"]
    assert "/api/gsp/electronic-signatures/verify-chain/all" in schema["paths"]
    operation = schema["paths"]["/api/gsp/sales/orders/{order_id}/approve"]["post"]
    signature_headers = {
        parameter["name"]
        for parameter in operation["parameters"]
        if parameter["in"] == "header"
    }
    assert "X-GSP-Signature-Token" in signature_headers

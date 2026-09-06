from datetime import date, timedelta
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.core.database import SessionLocal
from app.gsp.models import GspBusinessPartner, GspPartnerDocument
from app.gsp.router import approve_partner, verify_partner_document
from app.gsp.schemas import ChangeReason
from app.legacy import User, UserRole


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/gsp/partners/test",
            "headers": [],
            "client": ("127.0.0.1", 12345),
        }
    )


def _user(db, name: str) -> User:
    user = User(
        username=f"partner-{name}-{uuid4().hex[:8]}",
        hashed_password="test-only",
        full_name=name,
        role=UserRole.OPERATOR,
    )
    db.add(user)
    db.flush()
    return user


def test_partner_and_document_reviews_require_independent_users():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        creator = _user(db, "建档上传人")
        reviewer = _user(db, "质量核验人")
        suffix = uuid4().hex[:10]
        partner = GspBusinessPartner(
            code=f"IND-{suffix}",
            name="首营职责分离测试企业",
            partner_type="SUPPLIER",
            license_no=f"LIC-{suffix}",
            license_scope="药品批发",
            license_valid_to=date.today() + timedelta(days=365),
            status="PENDING",
            created_by=creator.id,
        )
        db.add(partner)
        db.flush()
        document = GspPartnerDocument(
            partner_id=partner.id,
            document_type="BUSINESS_LICENSE",
            document_no=f"DOC-{suffix}",
            valid_to=date.today() + timedelta(days=365),
            file_ref=f"test://partner/{suffix}",
            file_sha256="a" * 64,
            file_size_bytes=1024,
            created_by=creator.id,
            status="PENDING",
        )
        db.add(document)
        db.flush()

        with pytest.raises(HTTPException, match="建档人与质量审批人必须分离") as error:
            approve_partner(
                    partner.id,
                    ChangeReason(reason="同一用户不得审批"),
                    _request(),
                    current_user=creator,
                    db=db,
                )
        assert error.value.status_code == 409

        with pytest.raises(HTTPException, match="上传人与核验人必须分离") as error:
            verify_partner_document(
                    partner.id,
                    document.id,
                    ChangeReason(reason="同一用户不得核验"),
                    _request(),
                    current_user=creator,
                    db=db,
                )
        assert error.value.status_code == 409

        verified = verify_partner_document(
                partner.id,
                document.id,
                ChangeReason(reason="质量人员独立核验"),
                _request(),
                current_user=reviewer,
                db=db,
            )
        assert verified.status == "VERIFIED"
        assert verified.verified_by == reviewer.id
    finally:
        db.close()

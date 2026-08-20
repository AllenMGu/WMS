from datetime import date

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.models import GspBusinessPartner, GspPartnerDocument
from app.gsp.qualification import AUTHORIZED_DOCUMENTS, required_document_types


def add_verified_partner_evidence(
    db: Session,
    *,
    partner: GspBusinessPartner,
    verifier_id: int,
    valid_to: date,
) -> None:
    for document_type in required_document_types(partner.partner_type):
        authorized = document_type in AUTHORIZED_DOCUMENTS
        db.add(
            GspPartnerDocument(
                partner_id=partner.id,
                document_type=document_type,
                document_no=f"{document_type}-{partner.id}",
                valid_to=valid_to,
                file_ref=f"test://partner/{partner.id}/{document_type}",
                person_name="测试授权人员" if authorized else None,
                person_role="授权业务员" if authorized else None,
                verified_by=verifier_id,
                verified_at=utc_now(),
                status="VERIFIED",
            )
        )
    db.flush()

from datetime import date, timedelta

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.models import GspBusinessPartner, GspPartnerDocument
from app.gsp.qualification import AUTHORIZED_DOCUMENTS, required_document_types
from app.gsp.transport.models import (
    GspCarrier,
    GspCarrierDocument,
    GspCarrierDriver,
    GspCarrierVehicle,
)


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
                created_by=verifier_id,
                verified_by=verifier_id,
                verified_at=utc_now(),
                status="VERIFIED",
            )
        )
    db.flush()


def add_approved_transport_resources(
    db: Session,
    *,
    creator_id: int,
    approver_id: int,
    suffix: str,
    service_modes: tuple[str, ...] = ("NORMAL",),
) -> tuple[GspCarrier, GspCarrierVehicle, GspCarrierDriver]:
    valid_to = date.today() + timedelta(days=365)
    carrier = GspCarrier(
        code=f"CAR-{suffix}",
        name=f"受控承运商-{suffix}",
        unified_social_credit_code=f"USCC-{suffix}",
        license_no=f"LIC-{suffix}",
        license_valid_to=valid_to,
        service_modes=list(service_modes),
        quality_agreement_valid_to=valid_to,
        status="APPROVED",
        created_by=creator_id,
        approved_by=approver_id,
        approved_at=utc_now(),
    )
    db.add(carrier)
    db.flush()
    required_documents = {
        "BUSINESS_LICENSE",
        "ROAD_TRANSPORT_LICENSE",
        "QUALITY_AGREEMENT",
    }
    if set(service_modes) & {"COLD", "FROZEN"}:
        required_documents.add("COLD_CHAIN_QUALIFICATION")
    for document_type in required_documents:
        db.add(
            GspCarrierDocument(
                carrier_id=carrier.id,
                document_type=document_type,
                document_no=f"{document_type}-{suffix}",
                valid_to=valid_to,
                file_ref=f"test://carrier/{suffix}/{document_type}",
                status="VERIFIED",
                created_by=creator_id,
                verified_by=approver_id,
                verified_at=utc_now(),
            )
        )
    cold = bool(set(service_modes) & {"COLD", "FROZEN"})
    vehicle = GspCarrierVehicle(
        carrier_id=carrier.id,
        vehicle_no=f"TEST-{suffix}",
        vehicle_type="REFRIGERATED" if cold else "NORMAL",
        qualification_ref=f"test://vehicle/{suffix}",
        qualification_valid_to=valid_to,
        calibration_ref=f"test://calibration/{suffix}" if cold else None,
        calibration_valid_to=valid_to if cold else None,
        status="APPROVED",
        created_by=creator_id,
        approved_by=approver_id,
        approved_at=utc_now(),
    )
    driver = GspCarrierDriver(
        carrier_id=carrier.id,
        name=f"受控驾驶员-{suffix}",
        personnel_code=f"DRV-{suffix}",
        qualification_ref=f"test://driver/{suffix}",
        authorization_valid_to=valid_to,
        status="APPROVED",
        created_by=creator_id,
        approved_by=approver_id,
        approved_at=utc_now(),
    )
    db.add_all([vehicle, driver])
    db.flush()
    return carrier, vehicle, driver

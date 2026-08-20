"""Database-backed partner qualification evidence checks."""

from __future__ import annotations

from datetime import date

from sqlalchemy.orm import Session

from app.gsp.models import GspBusinessPartner, GspPartnerDocument
from app.gsp.rules import Finding, QualificationResult, evaluate_partner

SUPPLIER_DOCUMENTS = {
    "BUSINESS_LICENSE",
    "DRUG_LICENSE",
    "QUALITY_AGREEMENT",
    "SALES_AUTHORIZATION",
}
CUSTOMER_DOCUMENTS = {
    "BUSINESS_LICENSE",
    "DRUG_LICENSE",
    "PROCUREMENT_AUTHORIZATION",
}
AUTHORIZED_DOCUMENTS = {"SALES_AUTHORIZATION", "PROCUREMENT_AUTHORIZATION"}
PARTNER_DOCUMENT_TYPES = SUPPLIER_DOCUMENTS | CUSTOMER_DOCUMENTS


def required_document_types(partner_type: str) -> set[str]:
    if partner_type == "SUPPLIER":
        return set(SUPPLIER_DOCUMENTS)
    if partner_type == "CUSTOMER":
        return set(CUSTOMER_DOCUMENTS)
    if partner_type == "BOTH":
        return set(SUPPLIER_DOCUMENTS | CUSTOMER_DOCUMENTS)
    return set()


def evaluate_partner_evidence(
    db: Session,
    partner: GspBusinessPartner,
    *,
    status: str | None = None,
    on_date: date | None = None,
) -> QualificationResult:
    documents = (
        db.query(GspPartnerDocument)
        .filter(GspPartnerDocument.partner_id == partner.id)
        .all()
    )
    verified: dict[str, GspPartnerDocument] = {}
    for item in documents:
        current = verified.get(item.document_type)
        if item.status == "VERIFIED" and (
            current is None or (item.valid_to, item.id) > (current.valid_to, current.id)
        ):
            verified[item.document_type] = item
    required = required_document_types(partner.partner_type)
    findings = list(
        evaluate_partner(
            status=status or partner.status,
            license_valid_to=partner.license_valid_to,
            quality_agreement_valid_to=partner.quality_agreement_valid_to,
            document_expiries=[item.valid_to for item in verified.values()],
            on_date=on_date,
        ).findings
    )
    missing = required - set(verified)
    if missing:
        findings.append(
            Finding(
                "PARTNER_EVIDENCE_INCOMPLETE",
                f"缺少已核验资质：{', '.join(sorted(missing))}",
            )
        )
    for document_type in required & AUTHORIZED_DOCUMENTS:
        document = verified.get(document_type)
        if document and (not document.person_name or not document.person_role):
            findings.append(
                Finding(
                    "AUTHORIZED_PERSON_INCOMPLETE",
                    f"{document_type}缺少授权人员姓名或岗位",
                )
            )
    return QualificationResult(not findings, tuple(findings))

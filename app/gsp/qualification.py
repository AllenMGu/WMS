"""Database-backed partner qualification evidence checks."""

from __future__ import annotations

from datetime import date

from sqlalchemy.orm import Session

from app.gsp.models import (
    GspBusinessPartner,
    GspDrugProfile,
    GspPartnerDocument,
    GspSupplierProductAuthorization,
)
from app.gsp.quality_system.models import GspRegulatedScopeAuthorization
from app.gsp.rules import Finding, QualificationResult, evaluate_partner, evaluate_product

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
    documents = db.query(GspPartnerDocument).filter(GspPartnerDocument.partner_id == partner.id).all()
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


def evaluate_product_evidence(
    db: Session,
    profile: GspDrugProfile,
    *,
    status: str | None = None,
    on_date: date | None = None,
) -> QualificationResult:
    """Evaluate product approval plus any specially regulated business scope."""
    today = on_date or date.today()
    findings = list(
        evaluate_product(
            status=status or profile.status,
            registration_valid_to=profile.registration_valid_to,
            registration_document_ref=profile.registration_document_ref,
            nmpa_verification_ref=profile.nmpa_verification_ref,
            on_date=today,
        ).findings
    )
    category = profile.regulatory_category or "GENERAL"
    if profile.is_special_controlled and category == "GENERAL":
        category = "SPECIAL_CONTROLLED"
    if category != "GENERAL":
        authorization = (
            db.query(GspRegulatedScopeAuthorization)
            .filter(
                GspRegulatedScopeAuthorization.category == category,
                GspRegulatedScopeAuthorization.status == "APPROVED",
                GspRegulatedScopeAuthorization.valid_to >= today,
            )
            .order_by(GspRegulatedScopeAuthorization.valid_to.desc())
            .first()
        )
        if authorization is None:
            existing = (
                db.query(GspRegulatedScopeAuthorization)
                .filter(GspRegulatedScopeAuthorization.category == category)
                .first()
            )
            code = "REGULATED_SCOPE_INVALID" if existing else "REGULATED_SCOPE_MISSING"
            findings.append(Finding(code, f"缺少有效且已批准的{category}经营范围授权"))
    return QualificationResult(not findings, tuple(findings))


def evaluate_supplier_product_authorization(
    db: Session,
    *,
    supplier_id: int,
    goods_id: int,
    on_date: date | None = None,
) -> QualificationResult:
    """Verify that this approved supplier may supply this exact product SKU."""
    today = on_date or date.today()
    authorization = (
        db.query(GspSupplierProductAuthorization)
        .filter(
            GspSupplierProductAuthorization.supplier_id == supplier_id,
            GspSupplierProductAuthorization.goods_id == goods_id,
        )
        .first()
    )
    if authorization is None:
        findings = (
            Finding(
                "SUPPLIER_PRODUCT_AUTHORIZATION_MISSING",
                f"供货方未获准供应货物 {goods_id}",
            ),
        )
        return QualificationResult(False, findings)
    findings: list[Finding] = []
    if authorization.status != "APPROVED":
        findings.append(
            Finding(
                "SUPPLIER_PRODUCT_AUTHORIZATION_NOT_APPROVED",
                f"供货方与货物 {goods_id} 的供货品种关联未批准",
            )
        )
    if not authorization.authorization_sha256 or not authorization.authorization_size_bytes:
        findings.append(
            Finding(
                "SUPPLIER_PRODUCT_AUTHORIZATION_EVIDENCE_INCOMPLETE",
                f"供货方与货物 {goods_id} 的供货授权证据不完整",
            )
        )
    if authorization.valid_from > today or authorization.valid_to < today:
        findings.append(
            Finding(
                "SUPPLIER_PRODUCT_AUTHORIZATION_EXPIRED",
                f"供货方与货物 {goods_id} 的供货授权不在有效期内",
            )
        )
    return QualificationResult(not findings, tuple(findings))

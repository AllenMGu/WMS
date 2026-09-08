from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.time import utc_now
from app.gsp.attachments.bindings import resolve_attachment
from app.gsp.audit import (
    write_audit_event,
)
from app.gsp.catalog_queries import (
    list_partner_documents,
)
from app.gsp.dependencies import (
    require_any_gsp_role,
    require_gsp_roles,
)
from app.gsp.electronic_signature.dependencies import require_electronic_signature
from app.gsp.http_utils import (
    QUALITY_ROLES,
    _findings_detail,
    _invalidate_supplier_product_authorizations,
    _snapshot,
    _source_ip,
)
from app.gsp.models import (
    GspBusinessPartner,
    GspDrugProfile,
    GspPartnerDocument,
    GspSupplierProductAuthorization,
)
from app.gsp.outbox import enqueue_integration_message
from app.gsp.qualification import (
    AUTHORIZED_DOCUMENTS,
    PARTNER_DOCUMENT_TYPES,
    evaluate_partner_evidence,
    evaluate_product_evidence,
)
from app.gsp.schemas import (
    ChangeReason,
    PartnerCreate,
    PartnerDocumentCreate,
    PartnerDocumentResponse,
    PartnerResponse,
    SupplierProductAuthorizationBulkImport,
    SupplierProductAuthorizationBulkResult,
    SupplierProductAuthorizationCreate,
    SupplierProductAuthorizationResponse,
)
from app.legacy import Goods, User, get_current_user

router = APIRouter(tags=["GSP合规"])

@router.post("/partners", response_model=PartnerResponse, status_code=201)
def create_partner(
    payload: PartnerCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES, "PROCUREMENT")),
    db: Session = Depends(get_db),
):
    if payload.partner_type not in {"SUPPLIER", "CUSTOMER", "BOTH"}:
        raise HTTPException(422, "partner_type只能是SUPPLIER、CUSTOMER或BOTH")
    if payload.license_valid_to < date.today():
        raise HTTPException(422, "不能录入已经过期的许可证")
    partner = GspBusinessPartner(
        **payload.dict(exclude={"reason"}),
        status="PENDING",
        created_by=current_user.id,
    )
    db.add(partner)
    db.flush()
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="PARTNER_CREATED",
        entity_type="GspBusinessPartner",
        entity_id=str(partner.id),
        reason=payload.reason,
        after_data=_snapshot(partner),
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(partner)
    return partner


@router.get("/partners", response_model=list[PartnerResponse])
def list_partners(
    partner_type: str | None = None,
    status: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(GspBusinessPartner)
    if partner_type:
        query = query.filter(GspBusinessPartner.partner_type == partner_type)
    if status:
        query = query.filter(GspBusinessPartner.status == status)
    return (
        query.order_by(GspBusinessPartner.name)
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.post(
    "/partners/{partner_id}/approve",
    response_model=PartnerResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "PARTNER_APPROVE",
                "GspBusinessPartner",
                entity_id_param="partner_id",
                meaning="APPROVAL",
            )
        )
    ],
)
def approve_partner(
    partner_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    partner = db.query(GspBusinessPartner).filter(GspBusinessPartner.id == partner_id).first()
    if not partner:
        raise HTTPException(404, "合作方不存在")
    if partner.status != "PENDING":
        raise HTTPException(409, "只有待审批的合作方可以质量审批（资质变更会自动回到待审批）")
    if partner.created_by == current_user.id:
        raise HTTPException(409, "合作方首营建档人与质量审批人必须分离")
    result = evaluate_partner_evidence(db, partner, status="APPROVED")
    if not result.qualified:
        raise HTTPException(
            409, {"message": "合作方资质不满足审批条件", "findings": _findings_detail(result)}
        )
    before = _snapshot(partner)
    partner.status = "APPROVED"
    partner.approved_by = current_user.id
    partner.approved_at = utc_now()
    partner.suspension_reason = None
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="PARTNER_QUALIFIED",
        aggregate_type="GspBusinessPartner",
        aggregate_id=str(partner.id),
        payload=_snapshot(partner),
    )
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="PARTNER_APPROVED",
        entity_type="GspBusinessPartner",
        entity_id=str(partner.id),
        reason=payload.reason,
        before_data=before,
        after_data=_snapshot(partner),
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(partner)
    return partner


@router.get(
    "/partners/{partner_id}/documents",
    response_model=list[PartnerDocumentResponse],
)
def get_partner_documents(
    partner_id: int,
    status: str | None = None,
    document_type: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    partner = db.query(GspBusinessPartner).filter(GspBusinessPartner.id == partner_id).first()
    if partner is None:
        raise HTTPException(404, "合作方不存在")
    return list_partner_documents(
        db,
        partner_id=partner_id,
        status=status,
        document_type=document_type,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/partners/{partner_id}/documents",
    response_model=PartnerDocumentResponse,
    status_code=201,
)
def create_partner_document(
    partner_id: int,
    payload: PartnerDocumentCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES, "PROCUREMENT", "SALES")),
    db: Session = Depends(get_db),
):
    partner = db.query(GspBusinessPartner).filter(GspBusinessPartner.id == partner_id).first()
    if partner is None:
        raise HTTPException(404, "合作方不存在")
    document_type = payload.document_type.upper()
    if document_type not in PARTNER_DOCUMENT_TYPES:
        raise HTTPException(422, "资质文件类型不在批准清单中")
    if payload.valid_to < date.today():
        raise HTTPException(422, "不能录入已过期的资质文件")
    if document_type in AUTHORIZED_DOCUMENTS and (not payload.person_name or not payload.person_role):
        raise HTTPException(422, "授权文件必须填写授权人员姓名和岗位")
    if partner.status == "APPROVED":
        partner.status = "PENDING"
        partner.approved_by = None
        partner.approved_at = None
        _invalidate_supplier_product_authorizations(
            db,
            supplier_id=partner.id,
            actor_id=current_user.id,
            reason=f"供货方资质变更：{payload.reason}",
            source_ip=_source_ip(request),
        )
    file_ref, file_sha256, file_size_bytes = resolve_attachment(
        db,
        value=payload.file_ref,
        expected_purpose="PARTNER_DOCUMENT",
        declared_sha=payload.file_sha256,
        declared_size=payload.file_size_bytes,
    )
    document = GspPartnerDocument(
        partner_id=partner.id,
        document_type=document_type,
        document_no=payload.document_no,
        valid_from=payload.valid_from,
        valid_to=payload.valid_to,
        file_ref=file_ref,
        file_sha256=file_sha256,
        file_size_bytes=file_size_bytes,
        person_name=payload.person_name,
        person_role=payload.person_role,
        created_by=current_user.id,
        status="PENDING",
    )
    db.add(document)
    db.flush()
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="PARTNER_DOCUMENT_CREATED",
        entity_type="GspPartnerDocument",
        entity_id=str(document.id),
        reason=payload.reason,
        after_data=_snapshot(document),
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(document)
    return document


@router.post(
    "/partners/{partner_id}/documents/{document_id}/verify",
    response_model=PartnerDocumentResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "PARTNER_DOCUMENT_VERIFY",
                "GspPartnerDocument",
                entity_id_param="document_id",
                meaning="REVIEW",
            )
        )
    ],
)
def verify_partner_document(
    partner_id: int,
    document_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    document = (
        db.query(GspPartnerDocument)
        .filter(
            GspPartnerDocument.id == document_id,
            GspPartnerDocument.partner_id == partner_id,
        )
        .first()
    )
    if document is None:
        raise HTTPException(404, "合作方资质文件不存在")
    if document.created_by == current_user.id:
        raise HTTPException(409, "资质文件上传人与核验人必须分离")
    if document.valid_to < date.today():
        raise HTTPException(409, "已过期资质文件不能核验通过")
    if not document.file_sha256 or not document.file_size_bytes:
        raise HTTPException(409, "资质文件缺少SHA-256或文件大小证据")
    before = _snapshot(document)
    document.status = "VERIFIED"
    document.verified_by = current_user.id
    document.verified_at = utc_now()
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="PARTNER_DOCUMENT_VERIFIED",
        entity_type="GspPartnerDocument",
        entity_id=str(document.id),
        reason=payload.reason,
        before_data=before,
        after_data=_snapshot(document),
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(document)
    return document


@router.post(
    "/partners/{partner_id}/suspend",
    response_model=PartnerResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "PARTNER_SUSPEND",
                "GspBusinessPartner",
                entity_id_param="partner_id",
                meaning="RESPONSIBILITY",
            )
        )
    ],
)
def suspend_partner(
    partner_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    partner = db.query(GspBusinessPartner).filter(GspBusinessPartner.id == partner_id).first()
    if not partner:
        raise HTTPException(404, "合作方不存在")
    if partner.status != "APPROVED":
        raise HTTPException(409, "只有已批准的合作方可以挂起")
    before = _snapshot(partner)
    partner.status = "SUSPENDED"
    partner.suspension_reason = payload.reason
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="PARTNER_SUSPENDED",
        entity_type="GspBusinessPartner",
        entity_id=str(partner.id),
        reason=payload.reason,
        before_data=before,
        after_data=_snapshot(partner),
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(partner)
    return partner


def _upsert_supplier_product_record(
    db: Session,
    *,
    supplier_id: int,
    goods_id: int,
    values: dict,
    actor_id: int,
) -> tuple[GspSupplierProductAuthorization, dict | None, bool]:
    authorization = (
        db.query(GspSupplierProductAuthorization)
        .filter(
            GspSupplierProductAuthorization.supplier_id == supplier_id,
            GspSupplierProductAuthorization.goods_id == goods_id,
        )
        .first()
    )
    before = _snapshot(authorization) if authorization else None
    created = authorization is None
    if authorization is None:
        authorization = GspSupplierProductAuthorization(
            supplier_id=supplier_id,
            goods_id=goods_id,
            **values,
            status="PENDING",
            created_by=actor_id,
            updated_by=actor_id,
        )
        db.add(authorization)
    else:
        for key, value in values.items():
            setattr(authorization, key, value)
        authorization.status = "PENDING"
        authorization.updated_by = actor_id
        authorization.approved_by = None
        authorization.approved_at = None
        authorization.suspended_by = None
        authorization.suspended_at = None
        authorization.suspension_reason = None
    return authorization, before, created


def _bind_supplier_authorization_values(db: Session, values: dict) -> None:
    """Validate/normalise supplier-product authorisation evidence attachment.

    Token (``gspf:``) references are resolved against the controlled store and
    the server-side hash/size win; under ATTACHMENT_POLICY=enforce plain
    references are rejected.  Mutates ``values`` in place.
    """
    resolved = resolve_attachment(
        db,
        value=values.get("authorization_ref"),
        expected_purpose="SUPPLIER_PRODUCT_AUTHORIZATION",
        declared_sha=values.get("authorization_sha256"),
        declared_size=values.get("authorization_size_bytes"),
    )
    values["authorization_ref"] = resolved[0]
    values["authorization_sha256"] = resolved[1]
    values["authorization_size_bytes"] = resolved[2]


@router.get(
    "/supplier-product-authorizations",
    response_model=list[SupplierProductAuthorizationResponse],
)
def list_supplier_product_authorizations(
    supplier_id: int | None = Query(None, gt=0),
    status: str | None = None,
    alert_only: bool = False,
    warning_days: int = Query(30, ge=1, le=3650),
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    query = db.query(GspSupplierProductAuthorization)
    if supplier_id is not None:
        query = query.filter(GspSupplierProductAuthorization.supplier_id == supplier_id)
    if status:
        query = query.filter(GspSupplierProductAuthorization.status == status.upper())
    if alert_only:
        today = date.today()
        warning_date = today + timedelta(days=warning_days)
        query = query.filter(
            or_(
                GspSupplierProductAuthorization.status == "PENDING",
                and_(
                    GspSupplierProductAuthorization.status == "APPROVED",
                    GspSupplierProductAuthorization.valid_to <= warning_date,
                ),
            )
        )
    return query.order_by(
        GspSupplierProductAuthorization.valid_to,
        GspSupplierProductAuthorization.id,
    ).all()


@router.get(
    "/partners/{partner_id}/products",
    response_model=list[SupplierProductAuthorizationResponse],
)
def list_supplier_products(
    partner_id: int,
    status: str | None = None,
    effective_only: bool = False,
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    partner = db.get(GspBusinessPartner, partner_id)
    if partner is None or partner.partner_type not in {"SUPPLIER", "BOTH"}:
        raise HTTPException(404, "供货方不存在")
    query = db.query(GspSupplierProductAuthorization).filter(
        GspSupplierProductAuthorization.supplier_id == partner_id
    )
    if status:
        query = query.filter(GspSupplierProductAuthorization.status == status.upper())
    if effective_only:
        today = date.today()
        query = query.filter(
            GspSupplierProductAuthorization.status == "APPROVED",
            GspSupplierProductAuthorization.valid_from <= today,
            GspSupplierProductAuthorization.valid_to >= today,
        )
    authorizations = query.order_by(GspSupplierProductAuthorization.goods_id).all()
    if not effective_only:
        return authorizations
    if not evaluate_partner_evidence(db, partner).qualified:
        return []
    effective_authorizations = []
    for authorization in authorizations:
        profile = db.query(GspDrugProfile).filter(GspDrugProfile.goods_id == authorization.goods_id).first()
        if profile and evaluate_product_evidence(db, profile).qualified:
            effective_authorizations.append(authorization)
    return effective_authorizations


@router.post(
    "/partners/{partner_id}/products",
    response_model=SupplierProductAuthorizationResponse,
    status_code=201,
)
def upsert_supplier_product(
    partner_id: int,
    payload: SupplierProductAuthorizationCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES, "PROCUREMENT")),
    db: Session = Depends(get_db),
):
    partner = db.get(GspBusinessPartner, partner_id)
    if partner is None or partner.partner_type not in {"SUPPLIER", "BOTH"}:
        raise HTTPException(404, "供货方不存在")
    profile = db.query(GspDrugProfile).filter(GspDrugProfile.goods_id == payload.goods_id).first()
    if profile is None:
        raise HTTPException(409, "必须先建立药品品种质量档案")
    if payload.valid_to < payload.valid_from:
        raise HTTPException(422, "供货授权有效期结束日期不能早于开始日期")
    if payload.valid_to < date.today():
        raise HTTPException(422, "不能录入已经过期的供货品种授权")
    values = payload.model_dump(exclude={"reason", "goods_id"})
    _bind_supplier_authorization_values(db, values)
    authorization, before, _ = _upsert_supplier_product_record(
        db,
        supplier_id=partner_id,
        goods_id=payload.goods_id,
        values=values,
        actor_id=current_user.id,
    )
    db.flush()
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="SUPPLIER_PRODUCT_AUTHORIZATION_UPSERTED",
        entity_type="GspSupplierProductAuthorization",
        entity_id=str(authorization.id),
        reason=payload.reason,
        before_data=before,
        after_data=_snapshot(authorization),
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(authorization)
    return authorization


@router.post(
    "/partners/{partner_id}/products/bulk-import",
    response_model=SupplierProductAuthorizationBulkResult,
)
def bulk_import_supplier_products(
    partner_id: int,
    payload: SupplierProductAuthorizationBulkImport,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES, "PROCUREMENT")),
    db: Session = Depends(get_db),
):
    partner = db.get(GspBusinessPartner, partner_id)
    if partner is None or partner.partner_type not in {"SUPPLIER", "BOTH"}:
        raise HTTPException(404, "供货方不存在")

    barcodes = [row.goods_barcode.strip() for row in payload.rows]
    if len(barcodes) != len(set(barcodes)):
        raise HTTPException(422, "批量导入文件中存在重复货物条码")
    goods_by_barcode = {
        goods.barcode: goods for goods in db.query(Goods).filter(Goods.barcode.in_(barcodes)).all()
    }
    missing_barcodes = sorted(set(barcodes) - set(goods_by_barcode))
    if missing_barcodes:
        raise HTTPException(422, f"货物条码不存在：{', '.join(missing_barcodes[:10])}")
    goods_ids = [goods.id for goods in goods_by_barcode.values()]
    profiles = {
        profile.goods_id: profile
        for profile in db.query(GspDrugProfile).filter(GspDrugProfile.goods_id.in_(goods_ids)).all()
    }

    prepared = []
    for row in payload.rows:
        barcode = row.goods_barcode.strip()
        goods = goods_by_barcode[barcode]
        profile = profiles.get(goods.id)
        if profile is None:
            raise HTTPException(422, f"货物 {barcode} 尚未建立药品品种质量档案")
        if profile.approval_no != row.approval_no.strip():
            raise HTTPException(422, f"货物 {barcode} 的批准文号与品种档案不一致")
        if row.valid_to < row.valid_from:
            raise HTTPException(422, f"货物 {barcode} 的授权结束日期早于开始日期")
        if row.valid_to < date.today():
            raise HTTPException(422, f"货物 {barcode} 的供货授权已经过期")
        row_values = row.model_dump(exclude={"goods_barcode", "approval_no"})
        _bind_supplier_authorization_values(db, row_values)
        prepared.append((goods.id, row_values))

    created = 0
    updated = 0
    authorizations = []
    for goods_id, values in prepared:
        authorization, before, is_created = _upsert_supplier_product_record(
            db,
            supplier_id=partner_id,
            goods_id=goods_id,
            values=values,
            actor_id=current_user.id,
        )
        db.flush()
        write_audit_event(
            db,
            actor_user_id=current_user.id,
            action="SUPPLIER_PRODUCT_AUTHORIZATION_BULK_UPSERTED",
            entity_type="GspSupplierProductAuthorization",
            entity_id=str(authorization.id),
            reason=payload.reason,
            before_data=before,
            after_data=_snapshot(authorization),
            source_ip=_source_ip(request),
        )
        authorizations.append(authorization)
        created += int(is_created)
        updated += int(not is_created)
    db.commit()
    return SupplierProductAuthorizationBulkResult(
        created=created,
        updated=updated,
        pending_approval=len(authorizations),
        authorization_ids=[authorization.id for authorization in authorizations],
    )


@router.post(
    "/partners/{partner_id}/products/{authorization_id}/approve",
    response_model=SupplierProductAuthorizationResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "SUPPLIER_PRODUCT_APPROVE",
                "GspSupplierProductAuthorization",
                entity_id_param="authorization_id",
                meaning="APPROVAL",
            )
        )
    ],
)
def approve_supplier_product(
    partner_id: int,
    authorization_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    authorization = (
        db.query(GspSupplierProductAuthorization)
        .filter(
            GspSupplierProductAuthorization.id == authorization_id,
            GspSupplierProductAuthorization.supplier_id == partner_id,
        )
        .first()
    )
    if authorization is None:
        raise HTTPException(404, "供应商供货品种关联不存在")
    if authorization.status != "PENDING":
        raise HTTPException(409, "只有待审批的供货品种关联可以批准")
    if authorization.updated_by == current_user.id:
        raise HTTPException(409, "供货品种关联维护人与批准人必须分离")
    if not authorization.authorization_sha256 or not authorization.authorization_size_bytes:
        raise HTTPException(409, "供货授权证据缺少SHA-256或文件大小")
    today = date.today()
    if authorization.valid_from > today or authorization.valid_to < today:
        raise HTTPException(409, "供货品种授权不在有效期内")
    supplier = db.get(GspBusinessPartner, partner_id)
    supplier_result = evaluate_partner_evidence(db, supplier)
    profile = db.query(GspDrugProfile).filter(GspDrugProfile.goods_id == authorization.goods_id).first()
    product_result = evaluate_product_evidence(db, profile) if profile else None
    findings = _findings_detail(supplier_result)
    if product_result is None:
        findings.append({"code": "PRODUCT_PROFILE_MISSING", "message": "药品质量档案不存在"})
    else:
        findings.extend(_findings_detail(product_result))
    if findings:
        raise HTTPException(
            409,
            {"message": "供应商或品种首营资料不满足关联批准条件", "findings": findings},
        )
    before = _snapshot(authorization)
    authorization.status = "APPROVED"
    authorization.approved_by = current_user.id
    authorization.approved_at = utc_now()
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="SUPPLIER_PRODUCT_AUTHORIZATION_APPROVED",
        entity_type="GspSupplierProductAuthorization",
        entity_id=str(authorization.id),
        reason=payload.reason,
        before_data=before,
        after_data=_snapshot(authorization),
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(authorization)
    return authorization


@router.post(
    "/partners/{partner_id}/products/{authorization_id}/suspend",
    response_model=SupplierProductAuthorizationResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "SUPPLIER_PRODUCT_SUSPEND",
                "GspSupplierProductAuthorization",
                entity_id_param="authorization_id",
                meaning="RESPONSIBILITY",
            )
        )
    ],
)
def suspend_supplier_product(
    partner_id: int,
    authorization_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    authorization = (
        db.query(GspSupplierProductAuthorization)
        .filter(
            GspSupplierProductAuthorization.id == authorization_id,
            GspSupplierProductAuthorization.supplier_id == partner_id,
        )
        .first()
    )
    if authorization is None:
        raise HTTPException(404, "供应商供货品种关联不存在")
    if authorization.status != "APPROVED":
        raise HTTPException(409, "只有已批准的供货品种关联可以暂停")
    before = _snapshot(authorization)
    authorization.status = "SUSPENDED"
    authorization.suspended_by = current_user.id
    authorization.suspended_at = utc_now()
    authorization.suspension_reason = payload.reason
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="SUPPLIER_PRODUCT_AUTHORIZATION_SUSPENDED",
        entity_type="GspSupplierProductAuthorization",
        entity_id=str(authorization.id),
        reason=payload.reason,
        before_data=before,
        after_data=_snapshot(authorization),
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(authorization)
    return authorization

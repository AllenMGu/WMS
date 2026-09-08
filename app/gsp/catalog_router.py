from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.time import utc_now
from app.gsp.attachments.bindings import resolve_attachment
from app.gsp.audit import (
    write_audit_event,
    write_stock_audit_event,
)
from app.gsp.catalog_queries import (
    list_batch_stock,
    list_drug_batches,
    list_drug_profiles,
    list_quality_holds,
)
from app.gsp.dependencies import (
    require_any_gsp_role,
    require_gsp_roles,
)
from app.gsp.electronic_signature.dependencies import require_electronic_signature
from app.gsp.http_utils import (
    COMPLIANCE_SETTING_DEFAULTS,
    QUALITY_ROLES,
    _findings_detail,
    _invalidate_supplier_product_authorizations,
    _snapshot,
    _source_ip,
)
from app.gsp.models import (
    GspBatchStock,
    GspBusinessPartner,
    GspComplianceSetting,
    GspDrugBatch,
    GspDrugProfile,
    GspQualityHold,
)
from app.gsp.outbox import enqueue_integration_message
from app.gsp.qualification import (
    evaluate_partner_evidence,
    evaluate_product_evidence,
)
from app.gsp.quality_disposition.models import (
    GspNonconformingRecord,
)
from app.gsp.returns_recalls.models import (
    GspRecall,
    GspRecallBatch,
)
from app.gsp.rules import evaluate_batch
from app.gsp.schemas import (
    BatchAcceptance,
    BatchCreate,
    BatchResponse,
    BatchStockReceipt,
    BatchStockResponse,
    ChangeReason,
    DrugProfileResponse,
    DrugProfileUpsert,
    QualityHoldCreate,
    QualityHoldRelease,
    QualityHoldResponse,
)
from app.legacy import Goods, User

router = APIRouter(tags=["GSP合规"])

@router.get("/products", response_model=list[DrugProfileResponse])
def get_drug_profiles(
    status: str | None = None,
    goods_id: int | None = Query(None, gt=0),
    keyword: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    return list_drug_profiles(
        db,
        status=status,
        goods_id=goods_id,
        keyword=keyword,
        limit=limit,
        offset=offset,
    )


@router.put("/products/{goods_id}/profile", response_model=DrugProfileResponse)
def upsert_drug_profile(
    goods_id: int,
    payload: DrugProfileUpsert,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    if not db.query(Goods).filter(Goods.id == goods_id).first():
        raise HTTPException(404, "WMS货物主数据不存在")
    if payload.storage_condition not in {"NORMAL", "COOL", "COLD", "FROZEN", "SPECIAL"}:
        raise HTTPException(422, "storage_condition值无效")
    regulatory_category = payload.regulatory_category.upper()
    if regulatory_category not in {"GENERAL", "SPECIAL_CONTROLLED", "VACCINE"}:
        raise HTTPException(422, "regulatory_category值无效")
    profile = db.query(GspDrugProfile).filter(GspDrugProfile.goods_id == goods_id).first()
    before = _snapshot(profile) if profile else None
    values = payload.dict(exclude={"reason"})
    values["regulatory_category"] = regulatory_category
    values["is_special_controlled"] = regulatory_category != "GENERAL"
    _reg_ref, _reg_sha, _reg_size = resolve_attachment(
        db,
        value=values.get("registration_document_ref"),
        expected_purpose="DRUG_REGISTRATION",
        declared_sha=values.get("registration_document_sha256"),
        declared_size=values.get("registration_document_size_bytes"),
    )
    values["registration_document_ref"] = _reg_ref
    values["registration_document_sha256"] = _reg_sha
    values["registration_document_size_bytes"] = _reg_size
    if profile:
        _invalidate_supplier_product_authorizations(
            db,
            goods_id=goods_id,
            actor_id=current_user.id,
            reason=f"品种质量档案变更：{payload.reason}",
            source_ip=_source_ip(request),
        )
        for key, value in values.items():
            setattr(profile, key, value)
        profile.status = "PENDING"
        profile.approved_by = None
        profile.approved_at = None
        profile.nmpa_verified_by = None
        profile.nmpa_verified_at = None
        profile.updated_by = current_user.id
    else:
        profile = GspDrugProfile(
            goods_id=goods_id,
            **values,
            status="PENDING",
            created_by=current_user.id,
            updated_by=current_user.id,
        )
        db.add(profile)
    db.flush()
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="PRODUCT_PROFILE_UPSERTED",
        entity_type="GspDrugProfile",
        entity_id=str(profile.id),
        reason=payload.reason,
        before_data=before,
        after_data=_snapshot(profile),
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(profile)
    return profile


@router.post(
    "/products/{goods_id}/approve",
    response_model=DrugProfileResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "DRUG_PROFILE_APPROVE",
                "GspDrugProfile",
                entity_id_param="goods_id",
                meaning="APPROVAL",
            )
        )
    ],
)
def approve_drug_profile(
    goods_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    profile = db.query(GspDrugProfile).filter(GspDrugProfile.goods_id == goods_id).first()
    if not profile:
        raise HTTPException(404, "药品质量主数据不存在")
    if profile.status != "PENDING":
        raise HTTPException(409, "只有待审批的品种档案可以质量核验批准（档案更新会自动回到待审批）")
    if not profile.registration_document_sha256 or not profile.registration_document_size_bytes:
        raise HTTPException(409, "注册批准档案缺少SHA-256或文件大小证据")
    if profile.updated_by == current_user.id:
        raise HTTPException(409, "质量档案维护人与批准核验人必须分离")
    result = evaluate_product_evidence(db, profile, status="APPROVED")
    if not result.qualified:
        raise HTTPException(409, {"message": "品种不满足审批条件", "findings": _findings_detail(result)})
    before = _snapshot(profile)
    profile.status = "APPROVED"
    profile.approved_by = current_user.id
    profile.approved_at = utc_now()
    profile.nmpa_verified_by = current_user.id
    profile.nmpa_verified_at = profile.approved_at
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="PRODUCT_MASTER_CHANGED",
        aggregate_type="GspDrugProfile",
        aggregate_id=str(profile.id),
        payload=_snapshot(profile),
    )
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="PRODUCT_APPROVED",
        entity_type="GspDrugProfile",
        entity_id=str(profile.id),
        reason=payload.reason,
        before_data=before,
        after_data=_snapshot(profile),
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(profile)
    return profile


@router.get("/batches", response_model=list[BatchResponse])
def get_drug_batches(
    status: str | None = None,
    goods_id: int | None = Query(None, gt=0),
    supplier_id: int | None = Query(None, gt=0),
    batch_no: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    return list_drug_batches(
        db,
        status=status,
        goods_id=goods_id,
        supplier_id=supplier_id,
        batch_no=batch_no,
        limit=limit,
        offset=offset,
    )


@router.post("/batches", response_model=BatchResponse, status_code=201)
def create_batch(
    payload: BatchCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("RECEIVER", "INSPECTOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    raise HTTPException(
        409,
        "手工批次建档入口已停用；批次必须由受控采购收货流程自动生成",
    )


@router.post(
    "/batches/{batch_id}/accept",
    response_model=BatchResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "BATCH_ACCEPT",
                "GspDrugBatch",
                entity_id_param="batch_id",
                meaning="CONFIRMATION",
            )
        )
    ],
)
def accept_batch(
    batch_id: int,
    payload: BatchAcceptance,
    request: Request,
    current_user: User = Depends(require_gsp_roles("INSPECTOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    raise HTTPException(
        409,
        "手工批次放行入口已停用；请在受控收货明细中完成抽样和独立验收",
    )


@router.get("/batch-stock", response_model=list[BatchStockResponse])
def get_batch_stock(
    warehouse_id: int | None = Query(None, gt=0),
    location_id: int | None = Query(None, gt=0),
    batch_id: int | None = Query(None, gt=0),
    stock_status: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    return list_batch_stock(
        db,
        warehouse_id=warehouse_id,
        location_id=location_id,
        batch_id=batch_id,
        stock_status=stock_status,
        limit=limit,
        offset=offset,
    )


@router.post("/batch-stock/receipt", status_code=201)
def receive_batch_stock(
    payload: BatchStockReceipt,
    request: Request,
    current_user: User = Depends(require_gsp_roles("WAREHOUSE_CUSTODIAN", "RECEIVER")),
    db: Session = Depends(get_db),
):
    raise HTTPException(
        409,
        "直接增加批号库存入口已停用；库存只能由受控验收、退货检验或批准的盘点调整形成",
    )


@router.get("/quality-holds", response_model=list[QualityHoldResponse])
def get_quality_holds(
    status: str | None = None,
    batch_id: int | None = Query(None, gt=0),
    reason_code: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    return list_quality_holds(
        db,
        status=status,
        batch_id=batch_id,
        reason_code=reason_code,
        limit=limit,
        offset=offset,
    )


@router.post("/quality-holds", response_model=QualityHoldResponse, status_code=201)
def create_quality_hold(
    payload: QualityHoldCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES, "MAINTENANCE")),
    db: Session = Depends(get_db),
):
    batch = db.query(GspDrugBatch).filter(GspDrugBatch.id == payload.batch_id).first()
    if not batch:
        raise HTTPException(404, "批次不存在")
    duplicate = (
        db.query(GspQualityHold)
        .filter(
            GspQualityHold.batch_id == payload.batch_id,
            GspQualityHold.status == "ACTIVE",
            GspQualityHold.reason_code == payload.reason_code.upper(),
        )
        .first()
    )
    if duplicate is not None:
        raise HTTPException(409, "该批次已有同原因生效的质量锁定，不能重复冻结")
    hold = GspQualityHold(
        batch_id=payload.batch_id,
        reason_code=payload.reason_code,
        reason=payload.reason,
        initiated_by=current_user.id,
    )
    db.add(hold)
    db.flush()
    for stock in db.query(GspBatchStock).filter(GspBatchStock.batch_id == payload.batch_id):
        if stock.stock_status != "HOLD":
            stock_before = _snapshot(stock)
            stock.stock_status = "HOLD"
            stock.lock_version += 1
            write_stock_audit_event(
                db,
                actor_user_id=current_user.id,
                action="STOCK_HELD",
                stock=stock,
                reason=payload.reason,
                source_ip=_source_ip(request),
                before_data=stock_before,
                after_data=_snapshot(stock),
            )
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="QUALITY_HOLD_CREATED",
        entity_type="GspQualityHold",
        entity_id=str(hold.id),
        reason=payload.reason,
        after_data=_snapshot(hold),
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(hold)
    return hold


@router.post(
    "/quality-holds/{hold_id}/release",
    response_model=QualityHoldResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "QUALITY_HOLD_RELEASE",
                "GspQualityHold",
                entity_id_param="hold_id",
                meaning="RELEASE",
            )
        )
    ],
)
def release_quality_hold(
    hold_id: int,
    payload: QualityHoldRelease,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    hold = db.query(GspQualityHold).filter(GspQualityHold.id == hold_id).with_for_update().first()
    if not hold:
        raise HTTPException(404, "质量锁定记录不存在")
    if hold.status != "ACTIVE":
        raise HTTPException(409, "质量锁定已经解除")
    if hold.reason_code == "RECALL":
        active_recall = (
            db.query(GspRecallBatch)
            .join(GspRecall, GspRecall.id == GspRecallBatch.recall_id)
            .filter(
                GspRecallBatch.batch_id == hold.batch_id,
                GspRecall.status == "ACTIVE",
            )
            .count()
        )
        if active_recall:
            raise HTTPException(409, "召回执行期间不能解除对应批次的质量锁定")
    if hold.reason_code == "NONCONFORMING":
        active_disposition = (
            db.query(GspNonconformingRecord)
            .filter(
                GspNonconformingRecord.quality_hold_id == hold.id,
                GspNonconformingRecord.status.in_(["PENDING_APPROVAL", "APPROVED"]),
            )
            .count()
        )
        if active_disposition:
            raise HTTPException(409, "不合格品尚未完成批准处置，不能解除对应质量锁定")
    if hold.initiated_by == current_user.id:
        raise HTTPException(409, "质量锁定发起人不能自行解除，需由另一名质量授权人员复核")
    batch = db.query(GspDrugBatch).filter(GspDrugBatch.id == hold.batch_id).with_for_update().first()
    if batch is None:
        raise HTTPException(409, "锁定关联批次不存在，不能解除")
    other_holds = (
        db.query(GspQualityHold)
        .filter(
            GspQualityHold.batch_id == hold.batch_id,
            GspQualityHold.status == "ACTIVE",
            GspQualityHold.id != hold.id,
        )
        .count()
    )
    if not other_holds:
        profile = db.query(GspDrugProfile).filter(GspDrugProfile.goods_id == batch.goods_id).first()
        partner = db.query(GspBusinessPartner).filter(GspBusinessPartner.id == batch.supplier_id).first()
        if profile is None or partner is None:
            raise HTTPException(409, "批次关联品种或供货方质量档案缺失，不能解除锁定")
        if partner.partner_type not in {"SUPPLIER", "BOTH"}:
            raise HTTPException(409, "批次关联合作方不是有效供货方，不能解除锁定")
        stop_sale_setting = (
            db.query(GspComplianceSetting).filter(GspComplianceSetting.key == "STOP_SALE_DAYS").first()
        )
        stop_sale_days = (
            stop_sale_setting.integer_value
            if stop_sale_setting is not None
            else COMPLIANCE_SETTING_DEFAULTS["STOP_SALE_DAYS"]
        )
        findings = (
            _findings_detail(evaluate_partner_evidence(db, partner))
            + _findings_detail(evaluate_product_evidence(db, profile))
            + _findings_detail(
                evaluate_batch(
                    status=batch.status,
                    expiry_date=batch.expiry_date,
                    has_active_hold=False,
                    traceability_required=profile.traceability_required,
                    traceability_code=batch.traceability_code,
                    minimum_remaining_days=stop_sale_days,
                )
            )
        )
        if findings:
            raise HTTPException(
                409,
                {"message": "批次重新放行条件不满足，不能解除最后一个质量锁定", "findings": findings},
            )
    before = _snapshot(hold)
    hold.status = "RELEASED"
    hold.released_by = current_user.id
    hold.released_at = utc_now()
    hold.release_reason = payload.reason
    if not other_holds:
        for stock in db.query(GspBatchStock).filter(GspBatchStock.batch_id == hold.batch_id):
            if stock.stock_status != "AVAILABLE":
                stock_before = _snapshot(stock)
                stock.stock_status = "AVAILABLE"
                stock.lock_version += 1
                write_stock_audit_event(
                    db,
                    actor_user_id=current_user.id,
                    action="STOCK_UNHELD",
                    stock=stock,
                    reason=payload.reason,
                    source_ip=_source_ip(request),
                    before_data=stock_before,
                    after_data=_snapshot(stock),
                )
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="QUALITY_HOLD_RELEASED",
        entity_type="GspQualityHold",
        entity_id=str(hold.id),
        reason=payload.reason,
        before_data=before,
        after_data=_snapshot(hold),
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(hold)
    return hold

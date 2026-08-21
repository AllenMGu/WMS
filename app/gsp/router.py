from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.time import utc_now
from app.gsp.access_control import grant_gsp_role, review_gsp_role, revoke_gsp_role
from app.gsp.audit import record_audit_verification, verify_audit_chain, write_audit_event
from app.gsp.dependencies import require_gsp_roles, require_quality_manager_or_bootstrap
from app.gsp.environment.models import (
    GspEnvironmentAlarm,
    GspEnvironmentAssignment,
    GspEnvironmentDevice,
)
from app.gsp.maintenance.models import GspMaintenancePlan, GspMaintenancePlanItem
from app.gsp.models import (
    GspAuditEvent,
    GspAuditVerification,
    GspBatchStock,
    GspBusinessPartner,
    GspDrugBatch,
    GspDrugProfile,
    GspIntegrationMessage,
    GspPartnerDocument,
    GspQualityHold,
    GspRoleAssignment,
)
from app.gsp.operations.models import GspBackupEvidence, GspRecoveryDrill, GspSecretRotation
from app.gsp.outbox import enqueue_integration_message
from app.gsp.qualification import (
    AUTHORIZED_DOCUMENTS,
    PARTNER_DOCUMENT_TYPES,
    evaluate_partner_evidence,
)
from app.gsp.quality_disposition.models import (
    GspNonconformingRecord,
    GspPurchaseReturn,
    GspPurchaseReturnItem,
)
from app.gsp.returns_recalls.models import (
    GspRecall,
    GspRecallBatch,
    GspRecallCompletionReport,
    GspRecallDrill,
    GspRecallDrillBatch,
    GspRecallTarget,
    GspSalesReturnItem,
)
from app.gsp.rules import evaluate_product
from app.gsp.sales_shipping.models import GspSalesOrder, GspShipment
from app.gsp.schemas import (
    AuditEventResponse,
    AuditVerificationCreate,
    AuditVerificationResponse,
    BatchAcceptance,
    BatchCreate,
    BatchResponse,
    BatchStockReceipt,
    ChangeReason,
    DrugProfileResponse,
    DrugProfileUpsert,
    PartnerCreate,
    PartnerDocumentCreate,
    PartnerDocumentResponse,
    PartnerResponse,
    QualityHoldCreate,
    QualityHoldRelease,
    QualityHoldResponse,
    RoleGrant,
    RoleReview,
    RoleRevoke,
)
from app.gsp.snapshots import model_snapshot
from app.gsp.stocktaking.models import GspStocktakeItem, GspStocktakePlan
from app.gsp.transport.models import (
    GspCarrier,
    GspTransportException,
    GspTransportTask,
)
from app.legacy import Goods, Location, User, get_current_user

router = APIRouter(prefix="/gsp", tags=["GSP合规"])

QUALITY_ROLES = ("QUALITY_MANAGER", "QUALITY_REVIEWER")


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _snapshot(model) -> dict:
    """Compatibility alias for callers from the first GSP foundation phase."""
    return model_snapshot(model)


def _findings_detail(result) -> list[dict]:
    return [{"code": item.code, "message": item.message} for item in result.findings]


@router.get("/compliance/summary")
async def compliance_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    today = date.today()
    near_expiry = today + timedelta(days=90)
    return {
        "as_of": today,
        "pending_product_approvals": db.query(GspDrugProfile)
        .filter(GspDrugProfile.status == "PENDING")
        .count(),
        "pending_partner_approvals": db.query(GspBusinessPartner)
        .filter(GspBusinessPartner.status == "PENDING")
        .count(),
        "expired_partner_licenses": db.query(GspBusinessPartner)
        .filter(GspBusinessPartner.license_valid_to < today)
        .count(),
        "expired_partner_documents": db.query(GspPartnerDocument)
        .filter(
            GspPartnerDocument.status == "VERIFIED",
            GspPartnerDocument.valid_to < today,
        )
        .count(),
        "near_expiry_batches": db.query(GspDrugBatch)
        .filter(
            GspDrugBatch.expiry_date >= today,
            GspDrugBatch.expiry_date <= near_expiry,
        )
        .count(),
        "expired_batches": db.query(GspDrugBatch).filter(GspDrugBatch.expiry_date < today).count(),
        "active_quality_holds": db.query(GspQualityHold).filter(GspQualityHold.status == "ACTIVE").count(),
        "pending_integration_messages": db.query(GspIntegrationMessage)
        .filter(GspIntegrationMessage.status.in_(["PENDING", "RETRY"]))
        .count(),
        "pending_sales_orders": db.query(GspSalesOrder)
        .filter(
            GspSalesOrder.status.in_(
                ["SUBMITTED", "APPROVED", "ALLOCATED", "PICKED", "PREPARED", "REVIEWED"]
            )
        )
        .count(),
        "pending_outbound_reviews": db.query(GspShipment)
        .filter(GspShipment.status == "PREPARED")
        .count(),
        "pending_carrier_approvals": db.query(GspCarrier)
        .filter(GspCarrier.status == "PENDING")
        .count(),
        "expired_carrier_licenses": db.query(GspCarrier)
        .filter(GspCarrier.license_valid_to < today)
        .count(),
        "open_transport_exceptions": db.query(GspTransportException)
        .filter(GspTransportException.status == "PENDING_QUALITY")
        .count(),
        "overdue_in_transit_tasks": db.query(GspTransportTask)
        .filter(
            GspTransportTask.status.in_(["IN_TRANSIT", "EXCEPTION"]),
            GspTransportTask.expected_arrival_at < utc_now(),
        )
        .count(),
        "delivered_pending_transport_close": db.query(GspTransportTask)
        .filter(GspTransportTask.status == "DELIVERED")
        .count(),
        "open_environment_alarms": db.query(GspEnvironmentAlarm)
        .filter(GspEnvironmentAlarm.status.in_(["OPEN", "ACKNOWLEDGED"]))
        .count(),
        "critical_environment_alarms": db.query(GspEnvironmentAlarm)
        .filter(
            GspEnvironmentAlarm.status.in_(["OPEN", "ACKNOWLEDGED"]),
            GspEnvironmentAlarm.severity == "CRITICAL",
        )
        .count(),
        "expired_environment_calibrations": db.query(GspEnvironmentDevice)
        .filter(GspEnvironmentDevice.calibration_valid_to < today)
        .count(),
        "active_environment_assignments_without_reading": db.query(
            GspEnvironmentAssignment
        )
        .filter(
            GspEnvironmentAssignment.status == "ACTIVE",
            GspEnvironmentAssignment.last_reading_at.is_(None),
        )
        .count(),
        "reserved_batch_quantity": float(
            db.query(func.coalesce(func.sum(GspBatchStock.reserved_quantity), 0)).scalar()
        ),
        "pending_return_inspections": db.query(GspSalesReturnItem)
        .filter(GspSalesReturnItem.inspection_status == "PENDING")
        .count(),
        "pending_nonconforming_dispositions": db.query(GspNonconformingRecord)
        .filter(GspNonconformingRecord.status == "PENDING_APPROVAL")
        .count(),
        "approved_nonconforming_pending_execution": db.query(GspNonconformingRecord)
        .filter(GspNonconformingRecord.status == "APPROVED")
        .count(),
        "active_recalls": db.query(GspRecall).filter(GspRecall.status == "ACTIVE").count(),
        "pending_recall_completion_reports": db.query(GspRecall)
        .outerjoin(
            GspRecallCompletionReport,
            GspRecallCompletionReport.recall_id == GspRecall.id,
        )
        .filter(
            GspRecall.status == "CLOSED",
            GspRecallCompletionReport.id.is_(None),
        )
        .count(),
        "overdue_recall_completion_reports": db.query(GspRecall)
        .outerjoin(
            GspRecallCompletionReport,
            GspRecallCompletionReport.recall_id == GspRecall.id,
        )
        .filter(
            GspRecall.status == "CLOSED",
            GspRecall.completion_report_due_at < utc_now(),
            GspRecallCompletionReport.id.is_(None),
        )
        .count(),
        "active_recall_drills": db.query(GspRecallDrill)
        .filter(GspRecallDrill.status == "ACTIVE")
        .count(),
        "failed_recall_drills": db.query(GspRecallDrill)
        .filter(GspRecallDrill.result == "FAILED")
        .count(),
        "pending_maintenance_items": db.query(GspMaintenancePlanItem)
        .join(
            GspMaintenancePlan,
            GspMaintenancePlan.id == GspMaintenancePlanItem.plan_id,
        )
        .filter(
            GspMaintenancePlan.status.in_(["APPROVED", "IN_PROGRESS"]),
            GspMaintenancePlanItem.status == "PENDING",
        )
        .count(),
        "overdue_maintenance_plans": db.query(GspMaintenancePlan)
        .filter(
            GspMaintenancePlan.status.in_(["APPROVED", "IN_PROGRESS"]),
            GspMaintenancePlan.scheduled_to < today,
        )
        .count(),
        "abnormal_maintenance_findings": db.query(GspMaintenancePlanItem)
        .filter(GspMaintenancePlanItem.status == "ABNORMAL")
        .count(),
        "overdue_access_reviews": db.query(GspRoleAssignment)
        .filter(
            GspRoleAssignment.is_active.is_(True),
            GspRoleAssignment.review_due_at <= utc_now(),
        )
        .count(),
        "expired_role_assignments": db.query(GspRoleAssignment)
        .filter(
            GspRoleAssignment.is_active.is_(True),
            GspRoleAssignment.expires_at.is_not(None),
            GspRoleAssignment.expires_at <= utc_now(),
        )
        .count(),
        "inactive_users_with_active_roles": db.query(GspRoleAssignment)
        .join(User, User.id == GspRoleAssignment.user_id)
        .filter(
            GspRoleAssignment.is_active.is_(True),
            User.is_active.is_(False),
        )
        .count(),
        "failed_audit_verifications": db.query(GspAuditVerification)
        .filter(GspAuditVerification.valid.is_(False))
        .count(),
        "pending_secret_rotations": db.query(GspSecretRotation)
        .filter(GspSecretRotation.status.in_(["SUBMITTED", "APPROVED", "PENDING_VERIFICATION"]))
        .count(),
        "overdue_secret_rotations": db.query(GspSecretRotation)
        .filter(
            GspSecretRotation.status == "VERIFIED",
            GspSecretRotation.next_rotation_due_at <= utc_now(),
        )
        .count(),
        "unreviewed_backup_evidence": db.query(GspBackupEvidence)
        .filter(GspBackupEvidence.reviewed_at.is_(None))
        .count(),
        "failed_backups": db.query(GspBackupEvidence)
        .filter(GspBackupEvidence.status == "FAILED")
        .count(),
        "pending_recovery_drills": db.query(GspRecoveryDrill)
        .filter(GspRecoveryDrill.status.in_(["SUBMITTED", "APPROVED", "EXECUTED"]))
        .count(),
        "failed_verified_recovery_drills": db.query(GspRecoveryDrill)
        .filter(GspRecoveryDrill.status == "VERIFIED", GspRecoveryDrill.result == "FAIL")
        .count(),
        "pending_stocktake_plans": db.query(GspStocktakePlan)
        .filter(GspStocktakePlan.status.in_(["SUBMITTED", "COUNTING", "COUNTED"]))
        .count(),
        "pending_stocktake_adjustments": db.query(GspStocktakePlan)
        .filter(GspStocktakePlan.status == "ADJUSTMENT_APPROVED")
        .count(),
        "pending_recall_notifications": db.query(GspRecallTarget)
        .filter(GspRecallTarget.notification_status == "PENDING")
        .count(),
        "overdue_recall_notifications": db.query(GspRecall)
        .filter(
            GspRecall.status == "ACTIVE",
            GspRecall.notification_due_at < utc_now(),
            GspRecall.id.in_(
                db.query(GspRecallTarget.recall_id).filter(
                    GspRecallTarget.notification_status == "PENDING"
                )
            ),
        )
        .count(),
        "overdue_recall_progress_reports": db.query(GspRecall)
        .filter(
            GspRecall.status == "ACTIVE",
            GspRecall.next_progress_report_due_at < utc_now(),
        )
        .count(),
        "outstanding_recall_quantity": float(
            db.query(
                func.coalesce(
                    func.sum(
                        GspRecallBatch.target_shipped_quantity
                        - GspRecallBatch.recovered_quantity
                    ),
                    0,
                )
            )
            .join(GspRecall, GspRecall.id == GspRecallBatch.recall_id)
            .filter(GspRecall.status == "ACTIVE")
            .scalar()
        ),
    }


@router.post("/roles", status_code=201)
async def grant_role(
    payload: RoleGrant,
    request: Request,
    current_user: User = Depends(require_quality_manager_or_bootstrap),
    db: Session = Depends(get_db),
):
    valid_quality_manager_exists = (
        db.query(GspRoleAssignment)
        .filter(
            GspRoleAssignment.role == "QUALITY_MANAGER",
            GspRoleAssignment.is_active.is_(True),
            GspRoleAssignment.review_due_at > utc_now(),
            or_(
                GspRoleAssignment.expires_at.is_(None),
                GspRoleAssignment.expires_at > utc_now(),
            ),
        )
        .first()
        is not None
    )
    role_value = getattr(current_user.role, "value", current_user.role)
    if not valid_quality_manager_exists and role_value == "admin" and payload.role.upper() != "QUALITY_MANAGER":
        raise HTTPException(status_code=400, detail="首次GSP授权必须建立QUALITY_MANAGER岗位")
    assignment = grant_gsp_role(
        db,
        payload=payload,
        actor_id=current_user.id,
        source_ip=_source_ip(request),
    )
    db.commit()
    return _role_assignment_response(assignment)


def _role_assignment_response(assignment: GspRoleAssignment) -> dict:
    return {
        "id": assignment.id,
        "user_id": assignment.user_id,
        "role": assignment.role,
        "approval_ref": assignment.approval_ref,
        "review_due_at": assignment.review_due_at,
        "expires_at": assignment.expires_at,
        "last_reviewed_by": assignment.last_reviewed_by,
        "last_reviewed_at": assignment.last_reviewed_at,
        "is_active": assignment.is_active,
        "revoked_by": assignment.revoked_by,
        "revoked_at": assignment.revoked_at,
        "revocation_reason": assignment.revocation_reason,
    }


@router.get("/roles")
async def list_roles(
    user_id: int | None = None,
    active_only: bool = False,
    current_user: User = Depends(require_gsp_roles("AUDITOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    query = db.query(GspRoleAssignment)
    if user_id is not None:
        query = query.filter(GspRoleAssignment.user_id == user_id)
    if active_only:
        query = query.filter(GspRoleAssignment.is_active.is_(True))
    return [_role_assignment_response(row) for row in query.order_by(GspRoleAssignment.id).all()]


@router.post("/roles/{assignment_id}/review")
async def review_role(
    assignment_id: int,
    payload: RoleReview,
    request: Request,
    current_user: User = Depends(require_gsp_roles("QUALITY_MANAGER")),
    db: Session = Depends(get_db),
):
    assignment = db.query(GspRoleAssignment).filter(GspRoleAssignment.id == assignment_id).first()
    if assignment is None:
        raise HTTPException(status_code=404, detail="岗位授权不存在")
    review_gsp_role(
        db,
        assignment=assignment,
        payload=payload,
        actor_id=current_user.id,
        source_ip=_source_ip(request),
    )
    db.commit()
    return _role_assignment_response(assignment)


@router.post("/roles/{assignment_id}/revoke")
async def revoke_role(
    assignment_id: int,
    payload: RoleRevoke,
    request: Request,
    current_user: User = Depends(require_gsp_roles("QUALITY_MANAGER")),
    db: Session = Depends(get_db),
):
    assignment = db.query(GspRoleAssignment).filter(GspRoleAssignment.id == assignment_id).first()
    if assignment is None:
        raise HTTPException(status_code=404, detail="岗位授权不存在")
    revoke_gsp_role(
        db,
        assignment=assignment,
        actor_id=current_user.id,
        reason=payload.reason,
        source_ip=_source_ip(request),
    )
    db.commit()
    return _role_assignment_response(assignment)


@router.post("/partners", response_model=PartnerResponse, status_code=201)
async def create_partner(
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
async def list_partners(
    partner_type: str | None = None,
    status: str | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(GspBusinessPartner)
    if partner_type:
        query = query.filter(GspBusinessPartner.partner_type == partner_type)
    if status:
        query = query.filter(GspBusinessPartner.status == status)
    return query.order_by(GspBusinessPartner.name).all()


@router.post("/partners/{partner_id}/approve", response_model=PartnerResponse)
async def approve_partner(
    partner_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    partner = db.query(GspBusinessPartner).filter(GspBusinessPartner.id == partner_id).first()
    if not partner:
        raise HTTPException(404, "合作方不存在")
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


@router.post(
    "/partners/{partner_id}/documents",
    response_model=PartnerDocumentResponse,
    status_code=201,
)
async def create_partner_document(
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
    if document_type in AUTHORIZED_DOCUMENTS and (
        not payload.person_name or not payload.person_role
    ):
        raise HTTPException(422, "授权文件必须填写授权人员姓名和岗位")
    if partner.status == "APPROVED":
        partner.status = "PENDING"
        partner.approved_by = None
        partner.approved_at = None
    document = GspPartnerDocument(
        partner_id=partner.id,
        document_type=document_type,
        document_no=payload.document_no,
        valid_from=payload.valid_from,
        valid_to=payload.valid_to,
        file_ref=payload.file_ref,
        person_name=payload.person_name,
        person_role=payload.person_role,
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
)
async def verify_partner_document(
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
    if document.valid_to < date.today():
        raise HTTPException(409, "已过期资质文件不能核验通过")
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


@router.post("/partners/{partner_id}/suspend", response_model=PartnerResponse)
async def suspend_partner(
    partner_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    partner = db.query(GspBusinessPartner).filter(GspBusinessPartner.id == partner_id).first()
    if not partner:
        raise HTTPException(404, "合作方不存在")
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


@router.put("/products/{goods_id}/profile", response_model=DrugProfileResponse)
async def upsert_drug_profile(
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
    profile = db.query(GspDrugProfile).filter(GspDrugProfile.goods_id == goods_id).first()
    before = _snapshot(profile) if profile else None
    values = payload.dict(exclude={"reason"})
    if profile:
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


@router.post("/products/{goods_id}/approve", response_model=DrugProfileResponse)
async def approve_drug_profile(
    goods_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    profile = db.query(GspDrugProfile).filter(GspDrugProfile.goods_id == goods_id).first()
    if not profile:
        raise HTTPException(404, "药品质量主数据不存在")
    if profile.updated_by == current_user.id:
        raise HTTPException(409, "质量档案维护人与批准核验人必须分离")
    result = evaluate_product(
        status="APPROVED",
        registration_valid_to=profile.registration_valid_to,
        registration_document_ref=profile.registration_document_ref,
        nmpa_verification_ref=profile.nmpa_verification_ref,
    )
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


@router.post("/batches", response_model=BatchResponse, status_code=201)
async def create_batch(
    payload: BatchCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("RECEIVER", "INSPECTOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    if payload.expiry_date <= payload.production_date:
        raise HTTPException(422, "有效期必须晚于生产日期")
    partner = db.query(GspBusinessPartner).filter(GspBusinessPartner.id == payload.supplier_id).first()
    profile = db.query(GspDrugProfile).filter(GspDrugProfile.goods_id == payload.goods_id).first()
    if not partner or not profile:
        raise HTTPException(409, "缺少已建档的供货方或药品质量主数据")
    if partner.partner_type not in {"SUPPLIER", "BOTH"}:
        raise HTTPException(409, "所选合作方不是合格供货方")
    partner_result = evaluate_partner_evidence(db, partner)
    product_result = evaluate_product(
        status=profile.status,
        registration_valid_to=profile.registration_valid_to,
        registration_document_ref=profile.registration_document_ref,
        nmpa_verification_ref=profile.nmpa_verification_ref,
    )
    findings = _findings_detail(partner_result) + _findings_detail(product_result)
    if findings:
        raise HTTPException(409, {"message": "收货被GSP质量规则阻止", "findings": findings})
    if profile.traceability_required and not payload.traceability_code:
        raise HTTPException(409, "该品种必须录入药品追溯信息")
    if profile.storage_condition in {"COLD", "FROZEN"} and not payload.temperature_record_ref:
        raise HTTPException(409, "冷藏/冷冻药品必须关联运输温度记录")
    batch = GspDrugBatch(
        **payload.dict(exclude={"reason"}),
        status="PENDING_INSPECTION",
        created_by=current_user.id,
    )
    db.add(batch)
    db.flush()
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="BATCH_RECEIVED",
        entity_type="GspDrugBatch",
        entity_id=str(batch.id),
        reason=payload.reason,
        after_data=_snapshot(batch),
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(batch)
    return batch


@router.post("/batches/{batch_id}/accept", response_model=BatchResponse)
async def accept_batch(
    batch_id: int,
    payload: BatchAcceptance,
    request: Request,
    current_user: User = Depends(require_gsp_roles("INSPECTOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    batch = db.query(GspDrugBatch).filter(GspDrugBatch.id == batch_id).first()
    if not batch:
        raise HTTPException(404, "批次不存在")
    if batch.status != "PENDING_INSPECTION":
        raise HTTPException(409, "只有待验批次可以验收放行")
    profile = db.query(GspDrugProfile).filter(GspDrugProfile.goods_id == batch.goods_id).first()
    if not batch.inspection_report_no:
        raise HTTPException(409, "缺少检验报告书编号，不能验收放行")
    partner = db.query(GspBusinessPartner).filter(GspBusinessPartner.id == batch.supplier_id).first()
    if not profile or not partner:
        raise HTTPException(409, "供货方或药品质量主数据缺失")
    partner_result = evaluate_partner_evidence(db, partner)
    product_result = evaluate_product(
        status=profile.status,
        registration_valid_to=profile.registration_valid_to,
        registration_document_ref=profile.registration_document_ref,
        nmpa_verification_ref=profile.nmpa_verification_ref,
    )
    findings = _findings_detail(partner_result) + _findings_detail(product_result)
    if findings:
        raise HTTPException(409, {"message": "验收放行被GSP规则阻止", "findings": findings})
    if profile and profile.storage_condition in {"COLD", "FROZEN"}:
        if batch.transport_temperature_min is None or batch.transport_temperature_max is None:
            raise HTTPException(409, "冷藏/冷冻药品缺少运输温度范围")
        if profile.min_temperature is not None and batch.transport_temperature_min < profile.min_temperature:
            raise HTTPException(409, "运输最低温度超出品种允许范围")
        if profile.max_temperature is not None and batch.transport_temperature_max > profile.max_temperature:
            raise HTTPException(409, "运输最高温度超出品种允许范围")
    before = _snapshot(batch)
    batch.status = "RELEASED"
    batch.accepted_by = current_user.id
    batch.accepted_at = utc_now()
    batch.acceptance_conclusion = payload.conclusion
    enqueue_integration_message(
        db,
        destination="JZT",
        message_type="BATCH_ACCEPTED",
        aggregate_type="GspDrugBatch",
        aggregate_id=str(batch.id),
        payload=_snapshot(batch),
    )
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="BATCH_ACCEPTED",
        entity_type="GspDrugBatch",
        entity_id=str(batch.id),
        reason=payload.reason,
        before_data=before,
        after_data=_snapshot(batch),
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(batch)
    return batch


@router.post("/batch-stock/receipt", status_code=201)
async def receive_batch_stock(
    payload: BatchStockReceipt,
    request: Request,
    current_user: User = Depends(require_gsp_roles("WAREHOUSE_CUSTODIAN", "RECEIVER")),
    db: Session = Depends(get_db),
):
    batch = db.query(GspDrugBatch).filter(GspDrugBatch.id == payload.batch_id).first()
    location = db.query(Location).filter(Location.id == payload.location_id).first()
    if not batch or batch.status != "RELEASED":
        raise HTTPException(409, "只有验收放行批次可以形成可用库存")
    if not location or location.warehouse_id != payload.warehouse_id:
        raise HTTPException(422, "库位不属于指定仓库")
    stock = (
        db.query(GspBatchStock)
        .filter(
            GspBatchStock.batch_id == payload.batch_id,
            GspBatchStock.warehouse_id == payload.warehouse_id,
            GspBatchStock.location_id == payload.location_id,
        )
        .with_for_update()
        .first()
    )
    before = _snapshot(stock) if stock else None
    if stock:
        stock.quantity += payload.quantity
        stock.lock_version += 1
    else:
        stock = GspBatchStock(
            batch_id=payload.batch_id,
            warehouse_id=payload.warehouse_id,
            location_id=payload.location_id,
            quantity=payload.quantity,
        )
        db.add(stock)
    db.flush()
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="BATCH_STOCK_RECEIVED",
        entity_type="GspBatchStock",
        entity_id=str(stock.id),
        reason=payload.reason,
        before_data=before,
        after_data=_snapshot(stock),
        source_ip=_source_ip(request),
    )
    db.commit()
    return {"id": stock.id, "quantity": stock.quantity, "status": stock.stock_status}


@router.post("/quality-holds", response_model=QualityHoldResponse, status_code=201)
async def create_quality_hold(
    payload: QualityHoldCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES, "MAINTENANCE")),
    db: Session = Depends(get_db),
):
    batch = db.query(GspDrugBatch).filter(GspDrugBatch.id == payload.batch_id).first()
    if not batch:
        raise HTTPException(404, "批次不存在")
    hold = GspQualityHold(
        batch_id=payload.batch_id,
        reason_code=payload.reason_code,
        reason=payload.reason,
        initiated_by=current_user.id,
    )
    db.add(hold)
    db.flush()
    for stock in db.query(GspBatchStock).filter(GspBatchStock.batch_id == payload.batch_id):
        stock.stock_status = "HOLD"
        stock.lock_version += 1
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


@router.post("/quality-holds/{hold_id}/release", response_model=QualityHoldResponse)
async def release_quality_hold(
    hold_id: int,
    payload: QualityHoldRelease,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    hold = db.query(GspQualityHold).filter(GspQualityHold.id == hold_id).first()
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
    before = _snapshot(hold)
    hold.status = "RELEASED"
    hold.released_by = current_user.id
    hold.released_at = utc_now()
    hold.release_reason = payload.reason
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
        for stock in db.query(GspBatchStock).filter(GspBatchStock.batch_id == hold.batch_id):
            stock.stock_status = "AVAILABLE"
            stock.lock_version += 1
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


@router.get("/trace/batches/{batch_no}")
async def trace_batch(
    batch_no: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    batches = db.query(GspDrugBatch).filter(GspDrugBatch.batch_no == batch_no).all()
    if not batches:
        raise HTTPException(404, "未找到该批号")
    result = []
    for batch in batches:
        quality_holds = (
            db.query(GspQualityHold).filter(GspQualityHold.batch_id == batch.id).all()
        )
        sales_returns = (
            db.query(GspSalesReturnItem)
            .filter(GspSalesReturnItem.batch_id == batch.id)
            .all()
        )
        recalls = (
            db.query(GspRecallBatch).filter(GspRecallBatch.batch_id == batch.id).all()
        )
        recall_drills = (
            db.query(GspRecallDrillBatch)
            .filter(GspRecallDrillBatch.batch_id == batch.id)
            .all()
        )
        maintenance_items = (
            db.query(GspMaintenancePlanItem)
            .filter(GspMaintenancePlanItem.batch_id == batch.id)
            .all()
        )
        stocktake_items = (
            db.query(GspStocktakeItem)
            .filter(GspStocktakeItem.batch_id == batch.id)
            .all()
        )
        nonconforming_records = (
            db.query(GspNonconformingRecord)
            .filter(GspNonconformingRecord.batch_id == batch.id)
            .all()
        )
        nonconforming_ids = [item.id for item in nonconforming_records]
        purchase_return_items = (
            db.query(GspPurchaseReturnItem)
            .filter(GspPurchaseReturnItem.nonconforming_record_id.in_(nonconforming_ids))
            .all()
            if nonconforming_ids
            else []
        )
        purchase_return_ids = {
            item.purchase_return_id for item in purchase_return_items
        }
        purchase_returns = (
            db.query(GspPurchaseReturn)
            .filter(GspPurchaseReturn.id.in_(purchase_return_ids))
            .all()
            if purchase_return_ids
            else []
        )
        hold_ids = [str(item.id) for item in quality_holds]
        return_item_ids = [str(item.id) for item in sales_returns]
        recall_ids = [str(item.recall_id) for item in recalls]
        recall_drill_ids = [str(item.drill_id) for item in recall_drills]
        maintenance_item_ids = [str(item.id) for item in maintenance_items]
        stocktake_item_ids = [str(item.id) for item in stocktake_items]
        stocktake_plan_ids = [str(item.plan_id) for item in stocktake_items]
        nonconforming_audit_ids = [str(item.id) for item in nonconforming_records]
        purchase_return_audit_ids = [str(item.id) for item in purchase_returns]
        result.append(
            {
                "batch": _snapshot(batch),
                "stock": [
                    _snapshot(item)
                    for item in db.query(GspBatchStock).filter(GspBatchStock.batch_id == batch.id)
                ],
                "quality_holds": [_snapshot(item) for item in quality_holds],
                "sales_returns": [_snapshot(item) for item in sales_returns],
                "recalls": [_snapshot(item) for item in recalls],
                "recall_drills": [_snapshot(item) for item in recall_drills],
                "maintenance_items": [_snapshot(item) for item in maintenance_items],
                "stocktake_items": [_snapshot(item) for item in stocktake_items],
                "nonconforming_records": [
                    _snapshot(item) for item in nonconforming_records
                ],
                "purchase_returns": [
                    _snapshot(item) for item in purchase_returns
                ],
                "audit_events": [
                    _snapshot(item)
                    for item in db.query(GspAuditEvent)
                    .filter(
                        or_(
                            and_(
                                GspAuditEvent.entity_type == "GspDrugBatch",
                                GspAuditEvent.entity_id == str(batch.id),
                            ),
                            and_(
                                GspAuditEvent.entity_type == "GspQualityHold",
                                GspAuditEvent.entity_id.in_(hold_ids),
                            ),
                            and_(
                                GspAuditEvent.entity_type == "GspSalesReturnItem",
                                GspAuditEvent.entity_id.in_(return_item_ids),
                            ),
                            and_(
                                GspAuditEvent.entity_type == "GspRecall",
                                GspAuditEvent.entity_id.in_(recall_ids),
                            ),
                            and_(
                                GspAuditEvent.entity_type == "GspRecallDrill",
                                GspAuditEvent.entity_id.in_(recall_drill_ids),
                            ),
                            and_(
                                GspAuditEvent.entity_type == "GspMaintenancePlanItem",
                                GspAuditEvent.entity_id.in_(maintenance_item_ids),
                            ),
                            and_(
                                GspAuditEvent.entity_type == "GspStocktakeItem",
                                GspAuditEvent.entity_id.in_(stocktake_item_ids),
                            ),
                            and_(
                                GspAuditEvent.entity_type == "GspStocktakePlan",
                                GspAuditEvent.entity_id.in_(stocktake_plan_ids),
                            ),
                            and_(
                                GspAuditEvent.entity_type == "GspNonconformingRecord",
                                GspAuditEvent.entity_id.in_(nonconforming_audit_ids),
                            ),
                            and_(
                                GspAuditEvent.entity_type == "GspPurchaseReturn",
                                GspAuditEvent.entity_id.in_(purchase_return_audit_ids),
                            ),
                        )
                    )
                    .order_by(GspAuditEvent.occurred_at)
                ],
            }
        )
    return result


@router.get("/audit-events", response_model=list[AuditEventResponse])
async def list_audit_events(
    entity_type: str | None = None,
    entity_id: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(require_gsp_roles("AUDITOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    query = db.query(GspAuditEvent)
    if entity_type:
        query = query.filter(GspAuditEvent.entity_type == entity_type)
    if entity_id:
        query = query.filter(GspAuditEvent.entity_id == entity_id)
    return query.order_by(GspAuditEvent.occurred_at.desc()).limit(limit).all()


@router.get("/audit-events/verify")
async def verify_audit_events(
    current_user: User = Depends(require_gsp_roles("AUDITOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    valid, broken_event_id = verify_audit_chain(db)
    return {"valid": valid, "broken_event_id": broken_event_id}


@router.post("/audit-verifications", response_model=AuditVerificationResponse, status_code=201)
async def create_audit_verification(
    payload: AuditVerificationCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("AUDITOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    verification = record_audit_verification(
        db,
        actor_user_id=current_user.id,
        trigger_source=payload.trigger_source,
        evidence_ref=payload.evidence_ref,
        reason=payload.reason,
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(verification)
    return verification


@router.get("/audit-verifications", response_model=list[AuditVerificationResponse])
async def list_audit_verifications(
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(require_gsp_roles("AUDITOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return (
        db.query(GspAuditVerification)
        .order_by(GspAuditVerification.verified_at.desc())
        .limit(limit)
        .all()
    )

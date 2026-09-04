from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.time import utc_now
from app.gsp.access_control import grant_gsp_role, review_gsp_role, revoke_gsp_role
from app.gsp.audit import (
    record_audit_verification,
    verify_audit_chain,
    write_audit_event,
    write_stock_audit_event,
)
from app.gsp.catalog_queries import (
    list_batch_stock,
    list_drug_batches,
    list_drug_profiles,
    list_effective_role_assignments,
    list_partner_documents,
    list_quality_holds,
)
from app.gsp.dependencies import (
    require_any_gsp_role,
    require_gsp_roles,
    require_quality_manager_or_bootstrap,
)
from app.gsp.electronic_signature.dependencies import require_electronic_signature
from app.gsp.electronic_signature.models import (
    GspElectronicSignature,
    GspSignatureChallenge,
)
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
    GspComplianceSetting,
    GspDrugBatch,
    GspDrugProfile,
    GspIntegrationMessage,
    GspPartnerDocument,
    GspQualityHold,
    GspRoleAssignment,
    GspSupplierProductAuthorization,
)
from app.gsp.operations.models import GspBackupEvidence, GspRecoveryDrill, GspSecretRotation
from app.gsp.outbox import enqueue_integration_message
from app.gsp.qualification import (
    AUTHORIZED_DOCUMENTS,
    PARTNER_DOCUMENT_TYPES,
    evaluate_partner_evidence,
    evaluate_product_evidence,
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
from app.gsp.rules import evaluate_batch
from app.gsp.sales_shipping.models import GspSalesOrder, GspShipment
from app.gsp.schemas import (
    AuditEventResponse,
    AuditVerificationCreate,
    AuditVerificationResponse,
    BatchAcceptance,
    BatchCreate,
    BatchResponse,
    BatchStockReceipt,
    BatchStockResponse,
    ChangeReason,
    ComplianceSettingResponse,
    ComplianceSettingSet,
    CurrentUserRolesResponse,
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
    SupplierProductAuthorizationBulkImport,
    SupplierProductAuthorizationBulkResult,
    SupplierProductAuthorizationCreate,
    SupplierProductAuthorizationResponse,
    UserDirectoryItem,
)
from app.gsp.snapshots import model_snapshot
from app.gsp.stocktaking.models import GspStocktakeItem, GspStocktakePlan
from app.gsp.transport.models import (
    GspCarrier,
    GspTransportException,
    GspTransportTask,
)
from app.legacy import Goods, User, get_current_user

router = APIRouter(prefix="/gsp", tags=["GSP合规"])

QUALITY_ROLES = ("QUALITY_MANAGER", "QUALITY_REVIEWER")
COMPLIANCE_SETTING_DEFAULTS = {
    "NEAR_EXPIRY_WARNING_DAYS": 90,
    "STOP_SALE_DAYS": 30,
    "MAINTENANCE_SELECTION_DAYS": 120,
    "SUPPLIER_PRODUCT_WARNING_DAYS": 30,
}


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _snapshot(model) -> dict:
    """Compatibility alias for callers from the first GSP foundation phase."""
    return model_snapshot(model)


def _findings_detail(result) -> list[dict]:
    return [{"code": item.code, "message": item.message} for item in result.findings]


def _invalidate_supplier_product_authorizations(
    db: Session,
    *,
    actor_id: int,
    reason: str,
    source_ip: str | None,
    supplier_id: int | None = None,
    goods_id: int | None = None,
) -> None:
    query = db.query(GspSupplierProductAuthorization).filter(
        GspSupplierProductAuthorization.status == "APPROVED"
    )
    if supplier_id is not None:
        query = query.filter(GspSupplierProductAuthorization.supplier_id == supplier_id)
    if goods_id is not None:
        query = query.filter(GspSupplierProductAuthorization.goods_id == goods_id)
    for authorization in query.all():
        before = _snapshot(authorization)
        authorization.status = "PENDING"
        authorization.approved_by = None
        authorization.approved_at = None
        authorization.updated_by = actor_id
        authorization.suspended_by = None
        authorization.suspended_at = None
        authorization.suspension_reason = None
        write_audit_event(
            db,
            actor_user_id=actor_id,
            action="SUPPLIER_PRODUCT_AUTHORIZATION_INVALIDATED",
            entity_type="GspSupplierProductAuthorization",
            entity_id=str(authorization.id),
            reason=reason,
            before_data=before,
            after_data=_snapshot(authorization),
            source_ip=source_ip,
        )


@router.get("/compliance/summary")
async def compliance_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    today = date.today()
    configured = {
        row.key: row.integer_value
        for row in db.query(GspComplianceSetting).filter(
            GspComplianceSetting.key.in_(COMPLIANCE_SETTING_DEFAULTS)
        )
    }
    warning_days = configured.get(
        "NEAR_EXPIRY_WARNING_DAYS", COMPLIANCE_SETTING_DEFAULTS["NEAR_EXPIRY_WARNING_DAYS"]
    )
    near_expiry = today + timedelta(days=warning_days)
    supplier_product_warning_days = configured.get(
        "SUPPLIER_PRODUCT_WARNING_DAYS",
        COMPLIANCE_SETTING_DEFAULTS["SUPPLIER_PRODUCT_WARNING_DAYS"],
    )
    supplier_product_warning_date = today + timedelta(days=supplier_product_warning_days)
    return {
        "as_of": today,
        "near_expiry_warning_days": warning_days,
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
        "supplier_product_warning_days": supplier_product_warning_days,
        "pending_supplier_product_authorizations": db.query(GspSupplierProductAuthorization)
        .filter(GspSupplierProductAuthorization.status == "PENDING")
        .count(),
        "near_expiry_supplier_product_authorizations": db.query(GspSupplierProductAuthorization)
        .filter(
            GspSupplierProductAuthorization.status == "APPROVED",
            GspSupplierProductAuthorization.valid_to >= today,
            GspSupplierProductAuthorization.valid_to <= supplier_product_warning_date,
        )
        .count(),
        "expired_supplier_product_authorizations": db.query(GspSupplierProductAuthorization)
        .filter(
            GspSupplierProductAuthorization.status == "APPROVED",
            GspSupplierProductAuthorization.valid_to < today,
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
        "dead_integration_messages": db.query(GspIntegrationMessage)
        .filter(GspIntegrationMessage.status == "DEAD")
        .count(),
        "pending_sales_orders": db.query(GspSalesOrder)
        .filter(
            GspSalesOrder.status.in_(["SUBMITTED", "APPROVED", "ALLOCATED", "PICKED", "PREPARED", "REVIEWED"])
        )
        .count(),
        "pending_outbound_reviews": db.query(GspShipment).filter(GspShipment.status == "PREPARED").count(),
        "pending_carrier_approvals": db.query(GspCarrier).filter(GspCarrier.status == "PENDING").count(),
        "expired_carrier_licenses": db.query(GspCarrier).filter(GspCarrier.license_valid_to < today).count(),
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
        "active_environment_assignments_without_reading": db.query(GspEnvironmentAssignment)
        .filter(
            GspEnvironmentAssignment.status == "ACTIVE",
            GspEnvironmentAssignment.last_reading_at.is_(None),
        )
        .count(),
        "expired_unused_signature_challenges": db.query(GspSignatureChallenge)
        .filter(
            GspSignatureChallenge.status == "READY",
            GspSignatureChallenge.expires_at <= utc_now(),
        )
        .count(),
        "electronic_signature_count": db.query(GspElectronicSignature).count(),
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
        "active_recall_drills": db.query(GspRecallDrill).filter(GspRecallDrill.status == "ACTIVE").count(),
        "failed_recall_drills": db.query(GspRecallDrill).filter(GspRecallDrill.result == "FAILED").count(),
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
        "failed_backups": db.query(GspBackupEvidence).filter(GspBackupEvidence.status == "FAILED").count(),
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
                db.query(GspRecallTarget.recall_id).filter(GspRecallTarget.notification_status == "PENDING")
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
                    func.sum(GspRecallBatch.target_shipped_quantity - GspRecallBatch.recovered_quantity),
                    0,
                )
            )
            .join(GspRecall, GspRecall.id == GspRecallBatch.recall_id)
            .filter(GspRecall.status == "ACTIVE")
            .scalar()
        ),
    }


@router.get("/compliance/settings", response_model=list[ComplianceSettingResponse])
async def list_compliance_settings(
    _: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    return db.query(GspComplianceSetting).order_by(GspComplianceSetting.key).all()


@router.post(
    "/compliance/settings/{setting_key}",
    response_model=ComplianceSettingResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "COMPLIANCE_SETTING_SET",
                "GspComplianceSetting",
                entity_id_param="setting_key",
                meaning="APPROVAL",
            )
        )
    ],
)
async def set_compliance_setting(
    setting_key: str,
    payload: ComplianceSettingSet,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    key = setting_key.upper()
    if key not in COMPLIANCE_SETTING_DEFAULTS:
        raise HTTPException(422, "不支持的合规参数")
    proposed = {
        row.key: row.integer_value
        for row in db.query(GspComplianceSetting).filter(
            GspComplianceSetting.key.in_(COMPLIANCE_SETTING_DEFAULTS)
        )
    }
    for default_key, default_value in COMPLIANCE_SETTING_DEFAULTS.items():
        proposed.setdefault(default_key, default_value)
    proposed[key] = payload.integer_value
    if not (
        proposed["STOP_SALE_DAYS"]
        <= proposed["NEAR_EXPIRY_WARNING_DAYS"]
        <= proposed["MAINTENANCE_SELECTION_DAYS"]
    ):
        raise HTTPException(422, "阈值必须满足停销天数 ≤ 预警天数 ≤ 重点养护选取天数")
    setting = db.query(GspComplianceSetting).filter(GspComplianceSetting.key == key).with_for_update().first()
    before = _snapshot(setting) if setting else None
    if setting is None:
        setting = GspComplianceSetting(key=key)
        db.add(setting)
    setting.integer_value = payload.integer_value
    setting.approval_ref = payload.approval_ref
    setting.reason = payload.reason
    setting.approved_by = current_user.id
    setting.approved_at = utc_now()
    db.flush()
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="COMPLIANCE_SETTING_APPROVED",
        entity_type="GspComplianceSetting",
        entity_id=key,
        reason=payload.reason,
        before_data=before,
        after_data=_snapshot(setting),
        source_ip=_source_ip(request),
    )
    db.commit()
    return setting


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
    if (
        not valid_quality_manager_exists
        and role_value == "admin"
        and payload.role.upper() != "QUALITY_MANAGER"
    ):
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


@router.get("/roles/me", response_model=CurrentUserRolesResponse)
async def list_my_roles(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    assignments = list_effective_role_assignments(db, user_id=current_user.id)
    return {
        "user_id": current_user.id,
        "roles": [row.role for row in assignments],
        "assignments": [_role_assignment_response(row) for row in assignments],
    }


@router.get("/reference/users", response_model=list[UserDirectoryItem])
async def list_quality_user_directory(
    _: User = Depends(require_gsp_roles("AUDITOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    """Return only fields needed to assign quality records to active users."""
    return db.query(User).filter(User.is_active.is_(True)).order_by(User.full_name, User.id).all()


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


@router.post(
    "/roles/{assignment_id}/review",
    dependencies=[
        Depends(
            require_electronic_signature(
                "ROLE_ASSIGNMENT_REVIEW",
                "GspRoleAssignment",
                entity_id_param="assignment_id",
                meaning="REVIEW",
            )
        )
    ],
)
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


@router.post(
    "/roles/{assignment_id}/revoke",
    dependencies=[
        Depends(
            require_electronic_signature(
                "ROLE_ASSIGNMENT_REVOKE",
                "GspRoleAssignment",
                entity_id_param="assignment_id",
                meaning="RESPONSIBILITY",
            )
        )
    ],
)
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
async def get_partner_documents(
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
    document = GspPartnerDocument(
        partner_id=partner.id,
        document_type=document_type,
        document_no=payload.document_no,
        valid_from=payload.valid_from,
        valid_to=payload.valid_to,
        file_ref=payload.file_ref,
        file_sha256=payload.file_sha256,
        file_size_bytes=payload.file_size_bytes,
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


@router.get(
    "/supplier-product-authorizations",
    response_model=list[SupplierProductAuthorizationResponse],
)
async def list_supplier_product_authorizations(
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
async def list_supplier_products(
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
async def upsert_supplier_product(
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
async def bulk_import_supplier_products(
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
        prepared.append(
            (
                goods.id,
                row.model_dump(exclude={"goods_barcode", "approval_no"}),
            )
        )

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
async def approve_supplier_product(
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
async def suspend_supplier_product(
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


@router.get("/products", response_model=list[DrugProfileResponse])
async def get_drug_profiles(
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
    regulatory_category = payload.regulatory_category.upper()
    if regulatory_category not in {"GENERAL", "SPECIAL_CONTROLLED", "VACCINE"}:
        raise HTTPException(422, "regulatory_category值无效")
    profile = db.query(GspDrugProfile).filter(GspDrugProfile.goods_id == goods_id).first()
    before = _snapshot(profile) if profile else None
    values = payload.dict(exclude={"reason"})
    values["regulatory_category"] = regulatory_category
    values["is_special_controlled"] = regulatory_category != "GENERAL"
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
async def get_drug_batches(
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
async def create_batch(
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
async def accept_batch(
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
async def get_batch_stock(
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
async def receive_batch_stock(
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
async def get_quality_holds(
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
async def create_quality_hold(
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
async def release_quality_hold(
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
        quality_holds = db.query(GspQualityHold).filter(GspQualityHold.batch_id == batch.id).all()
        sales_returns = db.query(GspSalesReturnItem).filter(GspSalesReturnItem.batch_id == batch.id).all()
        recalls = db.query(GspRecallBatch).filter(GspRecallBatch.batch_id == batch.id).all()
        recall_drills = db.query(GspRecallDrillBatch).filter(GspRecallDrillBatch.batch_id == batch.id).all()
        maintenance_items = (
            db.query(GspMaintenancePlanItem).filter(GspMaintenancePlanItem.batch_id == batch.id).all()
        )
        stocktake_items = db.query(GspStocktakeItem).filter(GspStocktakeItem.batch_id == batch.id).all()
        nonconforming_records = (
            db.query(GspNonconformingRecord).filter(GspNonconformingRecord.batch_id == batch.id).all()
        )
        nonconforming_ids = [item.id for item in nonconforming_records]
        purchase_return_items = (
            db.query(GspPurchaseReturnItem)
            .filter(GspPurchaseReturnItem.nonconforming_record_id.in_(nonconforming_ids))
            .all()
            if nonconforming_ids
            else []
        )
        purchase_return_ids = {item.purchase_return_id for item in purchase_return_items}
        purchase_returns = (
            db.query(GspPurchaseReturn).filter(GspPurchaseReturn.id.in_(purchase_return_ids)).all()
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
                "nonconforming_records": [_snapshot(item) for item in nonconforming_records],
                "purchase_returns": [_snapshot(item) for item in purchase_returns],
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
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_gsp_roles("AUDITOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    query = db.query(GspAuditEvent)
    if entity_type:
        query = query.filter(GspAuditEvent.entity_type == entity_type)
    if entity_id:
        query = query.filter(GspAuditEvent.entity_id == entity_id)
    return (
        query.order_by(GspAuditEvent.occurred_at.desc(), GspAuditEvent.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


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
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_gsp_roles("AUDITOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return (
        db.query(GspAuditVerification)
        .order_by(GspAuditVerification.verified_at.desc(), GspAuditVerification.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

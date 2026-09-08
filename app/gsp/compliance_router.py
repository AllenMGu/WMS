from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.time import utc_now
from app.gsp.access_control import grant_gsp_role, review_gsp_role, revoke_gsp_role
from app.gsp.audit import (
    write_audit_event,
)
from app.gsp.catalog_queries import (
    list_effective_role_assignments,
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
from app.gsp.http_utils import (
    COMPLIANCE_SETTING_DEFAULTS,
    QUALITY_ROLES,
    _snapshot,
    _source_ip,
)
from app.gsp.maintenance.models import GspMaintenancePlan, GspMaintenancePlanItem
from app.gsp.models import (
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
from app.gsp.quality_disposition.models import (
    GspNonconformingRecord,
)
from app.gsp.returns_recalls.models import (
    GspRecall,
    GspRecallBatch,
    GspRecallCompletionReport,
    GspRecallDrill,
    GspRecallTarget,
    GspSalesReturnItem,
)
from app.gsp.sales_shipping.models import GspSalesOrder, GspShipment
from app.gsp.schemas import (
    ComplianceSettingResponse,
    ComplianceSettingSet,
    CurrentUserRolesResponse,
    RoleGrant,
    RoleReview,
    RoleRevoke,
    UserDirectoryItem,
)
from app.gsp.stocktaking.models import GspStocktakePlan
from app.gsp.transport.models import (
    GspCarrier,
    GspTransportException,
    GspTransportTask,
)
from app.legacy import User, get_current_user

router = APIRouter(tags=["GSP合规"])

@router.get("/compliance/summary")
def compliance_summary(
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
def list_compliance_settings(
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
def set_compliance_setting(
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
def grant_role(
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
def list_my_roles(
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
def list_quality_user_directory(
    _: User = Depends(require_gsp_roles("AUDITOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    """Return only fields needed to assign quality records to active users."""
    return db.query(User).filter(User.is_active.is_(True)).order_by(User.full_name, User.id).all()


@router.get("/roles")
def list_roles(
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
def review_role(
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
def revoke_role(
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

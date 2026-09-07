"""Controlled GSP access assignment, review and offboarding."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.audit import write_audit_event
from app.gsp.models import GspRoleAssignment
from app.gsp.schemas import RoleGrant, RoleReview
from app.gsp.snapshots import model_snapshot
from app.legacy import User, UserWarehouse

GSP_ROLES = frozenset(
    {
        "AUDITOR",
        "DISPATCHER",
        "ENVIRONMENT_MONITOR",
        "INSPECTOR",
        "MAINTENANCE",
        "OUTBOUND_REVIEWER",
        "PICKER",
        "PROCUREMENT",
        "QUALITY_MANAGER",
        "QUALITY_REVIEWER",
        "RECEIVER",
        "RETURNS_RECEIVER",
        "SALES",
        "STOCKTAKE",
        "SYSTEM_ADMIN",
        "TRANSPORT_COORDINATOR",
        "WAREHOUSE_CUSTODIAN",
        "WAREHOUSE_MANAGER",
    }
)

ROLE_CONFLICTS = {
    "AUDITOR": GSP_ROLES - {"AUDITOR"},
    "PROCUREMENT": {"INSPECTOR", "QUALITY_MANAGER", "QUALITY_REVIEWER", "RECEIVER"},
    "INSPECTOR": {"PROCUREMENT"},
    "RECEIVER": {"PROCUREMENT"},
    "SALES": {"DISPATCHER", "OUTBOUND_REVIEWER", "QUALITY_MANAGER", "QUALITY_REVIEWER"},
    "DISPATCHER": {"SALES"},
    "ENVIRONMENT_MONITOR": {"AUDITOR", "QUALITY_MANAGER", "QUALITY_REVIEWER"},
    "OUTBOUND_REVIEWER": {"PICKER", "SALES", "WAREHOUSE_CUSTODIAN"},
    "PICKER": {"OUTBOUND_REVIEWER"},
    "WAREHOUSE_CUSTODIAN": {"OUTBOUND_REVIEWER"},
    "STOCKTAKE": {"QUALITY_MANAGER", "QUALITY_REVIEWER"},
    "WAREHOUSE_MANAGER": {"QUALITY_MANAGER", "QUALITY_REVIEWER"},
    "QUALITY_MANAGER": {"PROCUREMENT", "SALES", "STOCKTAKE", "WAREHOUSE_MANAGER"},
    "QUALITY_REVIEWER": {"PROCUREMENT", "SALES", "STOCKTAKE", "WAREHOUSE_MANAGER"},
    "SYSTEM_ADMIN": {"AUDITOR", "QUALITY_MANAGER", "QUALITY_REVIEWER"},
    "TRANSPORT_COORDINATOR": {"AUDITOR", "QUALITY_MANAGER", "QUALITY_REVIEWER"},
}


def _normalized_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _validate_future(value: datetime, field_name: str) -> datetime:
    normalized = _normalized_utc(value)
    if normalized <= utc_now():
        raise HTTPException(status_code=400, detail=f"{field_name}必须晚于当前时间")
    return normalized


def grant_gsp_role(
    db: Session,
    *,
    payload: RoleGrant,
    actor_id: int,
    source_ip: str | None = None,
) -> GspRoleAssignment:
    role = payload.role.upper()
    if role not in GSP_ROLES:
        raise HTTPException(status_code=400, detail="岗位不在已批准的GSP授权矩阵中")
    if payload.user_id == actor_id:
        raise HTTPException(status_code=400, detail="不得为自己授予GSP岗位")
    review_due_at = _validate_future(payload.review_due_at, "复核日期")
    expires_at = None
    if payload.expires_at is not None:
        expires_at = _validate_future(payload.expires_at, "失效日期")
        if expires_at <= review_due_at:
            raise HTTPException(status_code=400, detail="失效日期必须晚于复核日期")

    target = db.query(User).filter(User.id == payload.user_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    if not target.is_active:
        raise HTTPException(status_code=400, detail="不能为停用用户授权")

    active_roles = {
        row.role
        for row in db.query(GspRoleAssignment).filter(
            GspRoleAssignment.user_id == payload.user_id,
            GspRoleAssignment.is_active.is_(True),
        )
    }
    conflicts = {
        active_role
        for active_role in active_roles
        if active_role in ROLE_CONFLICTS.get(role, set())
        or role in ROLE_CONFLICTS.get(active_role, set())
    }
    if conflicts:
        raise HTTPException(
            status_code=409,
            detail=f"岗位职责冲突：{role} 与 {', '.join(sorted(conflicts))} 不得兼任",
        )

    assignment = (
        db.query(GspRoleAssignment)
        .filter(
            GspRoleAssignment.user_id == payload.user_id,
            GspRoleAssignment.role == role,
        )
        .first()
    )
    before = model_snapshot(assignment) if assignment else None
    if assignment is None:
        assignment = GspRoleAssignment(user_id=payload.user_id, role=role)
        db.add(assignment)
    assignment.granted_by = actor_id
    assignment.granted_at = utc_now()
    assignment.approval_ref = payload.approval_ref
    assignment.review_due_at = review_due_at
    assignment.expires_at = expires_at
    assignment.last_reviewed_by = None
    assignment.last_reviewed_at = None
    assignment.revoked_by = None
    assignment.revoked_at = None
    assignment.revocation_reason = None
    assignment.is_active = True
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="ROLE_GRANTED",
        entity_type="GspRoleAssignment",
        entity_id=str(assignment.id),
        reason=payload.reason,
        before_data=before,
        after_data=model_snapshot(assignment),
        source_ip=source_ip,
    )
    return assignment


def review_gsp_role(
    db: Session,
    *,
    assignment: GspRoleAssignment,
    payload: RoleReview,
    actor_id: int,
    source_ip: str | None = None,
) -> GspRoleAssignment:
    if assignment.user_id == actor_id:
        raise HTTPException(status_code=400, detail="不得复核自己的GSP岗位")
    if not assignment.is_active:
        raise HTTPException(status_code=409, detail="岗位授权已撤销")
    before = model_snapshot(assignment)
    now = utc_now()
    assignment.last_reviewed_by = actor_id
    assignment.last_reviewed_at = now
    if payload.decision == "RETAIN":
        if payload.next_review_due_at is None:
            raise HTTPException(status_code=400, detail="保留岗位时必须填写下次复核日期")
        next_review_due_at = _validate_future(payload.next_review_due_at, "下次复核日期")
        if assignment.expires_at and next_review_due_at >= assignment.expires_at:
            raise HTTPException(status_code=400, detail="下次复核日期必须早于岗位失效日期")
        assignment.review_due_at = next_review_due_at
        action = "ROLE_REVIEWED_RETAINED"
    else:
        assignment.is_active = False
        assignment.revoked_by = actor_id
        assignment.revoked_at = now
        assignment.revocation_reason = payload.reason
        action = "ROLE_REVIEWED_REVOKED"
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action=action,
        entity_type="GspRoleAssignment",
        entity_id=str(assignment.id),
        reason=payload.reason,
        before_data=before,
        after_data=model_snapshot(assignment),
        source_ip=source_ip,
    )
    return assignment


def revoke_gsp_role(
    db: Session,
    *,
    assignment: GspRoleAssignment,
    actor_id: int,
    reason: str,
    source_ip: str | None = None,
) -> GspRoleAssignment:
    if assignment.user_id == actor_id:
        raise HTTPException(status_code=400, detail="不得自行撤销岗位，应由独立管理员处理")
    if not assignment.is_active:
        raise HTTPException(status_code=409, detail="岗位授权已撤销")
    before = model_snapshot(assignment)
    assignment.is_active = False
    assignment.revoked_by = actor_id
    assignment.revoked_at = utc_now()
    assignment.revocation_reason = reason
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="ROLE_REVOKED",
        entity_type="GspRoleAssignment",
        entity_id=str(assignment.id),
        reason=reason,
        before_data=before,
        after_data=model_snapshot(assignment),
        source_ip=source_ip,
    )
    return assignment


def deactivate_user_access(
    db: Session,
    *,
    user: User,
    actor_id: int,
    reason: str,
    source_ip: str | None = None,
) -> None:
    if user.id == actor_id:
        raise HTTPException(status_code=400, detail="不能停用自己的账户")
    roles = db.query(GspRoleAssignment).filter(GspRoleAssignment.user_id == user.id).all()
    warehouses = db.query(UserWarehouse).filter(UserWarehouse.user_id == user.id).all()
    before = {
        "user": {"id": user.id, "is_active": user.is_active, "current_warehouse_id": user.current_warehouse_id},
        "active_roles": [row.role for row in roles if row.is_active],
        "warehouse_ids": [row.warehouse_id for row in warehouses],
    }
    now = utc_now()
    user.is_active = False
    user.current_warehouse_id = None
    for assignment in roles:
        if assignment.is_active:
            assignment.is_active = False
            assignment.revoked_by = actor_id
            assignment.revoked_at = now
            assignment.revocation_reason = reason
    for mapping in warehouses:
        db.delete(mapping)
    _deactivate_uploaded_controlled_files(db, user_id=user.id, actor_id=actor_id, reason=reason, source_ip=source_ip)
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="USER_ACCESS_REVOKED",
        entity_type="User",
        entity_id=str(user.id),
        reason=reason,
        before_data=before,
        after_data={"user": {"id": user.id, "is_active": False, "current_warehouse_id": None}, "active_roles": [], "warehouse_ids": []},
        source_ip=source_ip,
    )


def _deactivate_uploaded_controlled_files(
    db: Session,
    *,
    user_id: int,
    actor_id: int,
    reason: str,
    source_ip: str | None = None,
) -> None:
    """Uploader-offboarding protection for controlled evidence (GSP P1-2).

    On account deactivation, files uploaded by that user are no longer allowed to
    stay silently ACTIVE.  Files not yet bound to any business record are disabled
    right away (DISABLED blocks new download / new reference while keeping bytes +
    audit).  Files already bound to an approved business record stay readable so the
    evidence chain is not broken, but every one of the user's ACTIVE files is
    enumerated in an audit record for the quality team to review.

    Mirrors the documented "uploader deactivation protection" claim in README:
    https://github.com/AllenMGu/WMS (access_control.deactivate_user_access).
    """
    from app.gsp.attachments.bindings import referenced_by_business
    from app.gsp.attachments.models import (
        STATUS_ACTIVE,
        GspControlledFile,
    )

    uploaded = (
        db.query(GspControlledFile)
        .filter(
            GspControlledFile.uploaded_by == user_id,
            GspControlledFile.status == STATUS_ACTIVE,
        )
        .order_by(GspControlledFile.id)
        # 行锁：与业务绑定路径 resolve_attachment(attachments/bindings.py) 的
        # with_for_update() 互斥。必须先锁定候选文件行、再检查业务引用，否则并发
        # 绑定事务(尚未提交)的业务引用不可见，会把刚被绑定的证据文件误置 DISABLED。
        .with_for_update()
        .all()
    )
    if not uploaded:
        return
    disabled_keys: list[str] = []
    bound_keys: list[str] = []
    now = utc_now()
    for obj in uploaded:
        if referenced_by_business(db, obj.object_key):
            bound_keys.append(obj.object_key)
            continue
        obj.status = "DISABLED"
        note = (obj.note or "").rstrip()
        marker = f"[uploader offboarded {now.isoformat(timespec='seconds')}: {reason}]"
        obj.note = f"{note} {marker}".strip() if note else marker
        disabled_keys.append(obj.object_key)
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="CONTROLLED_FILES_UPLOADER_REVOKED",
        entity_type="User",
        entity_id=str(user_id),
        reason=reason,
        before_data={
            "active_uploaded_files": [o.object_key for o in uploaded],
        },
        after_data={
            "disabled_unbound_files": disabled_keys,
            "kept_bound_evidence_files": bound_keys,
            "note": "上传人已停用：未绑定业务记录的受控文件已级联停用；已被业务记录绑定的证据文件保留以便证据链核验，请质量复核决定是否停用",
        },
        source_ip=source_ip,
    )

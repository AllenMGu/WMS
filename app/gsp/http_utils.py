"""gsp 共享 HTTP 工具函数与常量（自 router.py 提取，供各领域 router 复用）。"""
from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from app.gsp.audit import write_audit_event
from app.gsp.models import GspSupplierProductAuthorization
from app.gsp.snapshots import model_snapshot

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

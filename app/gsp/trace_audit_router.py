from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.audit import (
    record_audit_verification,
    verify_audit_chain,
)
from app.gsp.dependencies import (
    require_gsp_roles,
)
from app.gsp.http_utils import (
    QUALITY_ROLES,
    _snapshot,
    _source_ip,
)
from app.gsp.maintenance.models import GspMaintenancePlanItem
from app.gsp.models import (
    GspAuditEvent,
    GspAuditVerification,
    GspBatchStock,
    GspDrugBatch,
    GspQualityHold,
)
from app.gsp.quality_disposition.models import (
    GspNonconformingRecord,
    GspPurchaseReturn,
    GspPurchaseReturnItem,
)
from app.gsp.returns_recalls.models import (
    GspRecallBatch,
    GspRecallDrillBatch,
    GspSalesReturnItem,
)
from app.gsp.schemas import (
    AuditEventResponse,
    AuditVerificationCreate,
    AuditVerificationResponse,
)
from app.gsp.stocktaking.models import GspStocktakeItem
from app.legacy import User, get_current_user

router = APIRouter(tags=["GSP合规"])

@router.get("/trace/batches/{batch_no}")
def trace_batch(
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
def list_audit_events(
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
def verify_audit_events(
    current_user: User = Depends(require_gsp_roles("AUDITOR", *QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    valid, broken_event_id = verify_audit_chain(db)
    return {"valid": valid, "broken_event_id": broken_event_id}


@router.post("/audit-verifications", response_model=AuditVerificationResponse, status_code=201)
def create_audit_verification(
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
def list_audit_verifications(
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

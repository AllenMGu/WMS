"""Read models used by the split GSP web client.

External registries and document stores remain behind reference fields; these
queries only expose data owned by the WMS database.
"""

from __future__ import annotations

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.models import (
    GspBatchStock,
    GspBusinessPartner,
    GspDrugBatch,
    GspDrugProfile,
    GspPartnerDocument,
    GspQualityHold,
    GspRoleAssignment,
)
from app.gsp.snapshots import model_snapshot
from app.legacy import Goods, Location, Warehouse


def list_drug_profiles(
    db: Session,
    *,
    status: str | None = None,
    goods_id: int | None = None,
    keyword: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> list[dict]:
    query = db.query(GspDrugProfile, Goods.name).join(
        Goods, Goods.id == GspDrugProfile.goods_id
    )
    if status:
        query = query.filter(GspDrugProfile.status == status)
    if goods_id is not None:
        query = query.filter(GspDrugProfile.goods_id == goods_id)
    if keyword and keyword.strip():
        pattern = f"%{keyword.strip()}%"
        query = query.filter(
            or_(
                Goods.name.ilike(pattern),
                GspDrugProfile.approval_no.ilike(pattern),
                GspDrugProfile.generic_name.ilike(pattern),
                GspDrugProfile.manufacturer.ilike(pattern),
            )
        )
    rows = query.order_by(Goods.name, GspDrugProfile.id).offset(offset).limit(limit).all()
    return [{**model_snapshot(profile), "goods_name": goods_name} for profile, goods_name in rows]


def list_drug_batches(
    db: Session,
    *,
    status: str | None = None,
    goods_id: int | None = None,
    supplier_id: int | None = None,
    batch_no: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> list[dict]:
    query = (
        db.query(GspDrugBatch, Goods.name, GspBusinessPartner.name)
        .join(Goods, Goods.id == GspDrugBatch.goods_id)
        .join(GspBusinessPartner, GspBusinessPartner.id == GspDrugBatch.supplier_id)
    )
    if status:
        query = query.filter(GspDrugBatch.status == status)
    if goods_id is not None:
        query = query.filter(GspDrugBatch.goods_id == goods_id)
    if supplier_id is not None:
        query = query.filter(GspDrugBatch.supplier_id == supplier_id)
    if batch_no and batch_no.strip():
        query = query.filter(GspDrugBatch.batch_no.ilike(f"%{batch_no.strip()}%"))
    rows = query.order_by(GspDrugBatch.expiry_date, GspDrugBatch.id).offset(offset).limit(limit).all()
    return [
        {
            **model_snapshot(batch),
            "goods_name": goods_name,
            "supplier_name": supplier_name,
        }
        for batch, goods_name, supplier_name in rows
    ]


def list_batch_stock(
    db: Session,
    *,
    warehouse_id: int | None = None,
    location_id: int | None = None,
    batch_id: int | None = None,
    stock_status: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> list[dict]:
    query = (
        db.query(
            GspBatchStock,
            GspDrugBatch.batch_no,
            GspDrugBatch.goods_id,
            Goods.name,
            Warehouse.name,
            Location.location_code,
        )
        .join(GspDrugBatch, GspDrugBatch.id == GspBatchStock.batch_id)
        .join(Goods, Goods.id == GspDrugBatch.goods_id)
        .join(Warehouse, Warehouse.id == GspBatchStock.warehouse_id)
        .join(Location, Location.id == GspBatchStock.location_id)
    )
    if warehouse_id is not None:
        query = query.filter(GspBatchStock.warehouse_id == warehouse_id)
    if location_id is not None:
        query = query.filter(GspBatchStock.location_id == location_id)
    if batch_id is not None:
        query = query.filter(GspBatchStock.batch_id == batch_id)
    if stock_status:
        query = query.filter(GspBatchStock.stock_status == stock_status)
    rows = query.order_by(GspDrugBatch.expiry_date, Location.location_code).offset(offset).limit(limit).all()
    return [
        {
            **model_snapshot(stock),
            "batch_no": batch_no,
            "goods_id": goods_id,
            "goods_name": goods_name,
            "warehouse_name": warehouse_name,
            "location_code": location_code,
        }
        for stock, batch_no, goods_id, goods_name, warehouse_name, location_code in rows
    ]


def list_quality_holds(
    db: Session,
    *,
    status: str | None = None,
    batch_id: int | None = None,
    reason_code: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> list[dict]:
    query = (
        db.query(GspQualityHold, GspDrugBatch.batch_no, GspDrugBatch.goods_id, Goods.name)
        .join(GspDrugBatch, GspDrugBatch.id == GspQualityHold.batch_id)
        .join(Goods, Goods.id == GspDrugBatch.goods_id)
    )
    if status:
        query = query.filter(GspQualityHold.status == status)
    if batch_id is not None:
        query = query.filter(GspQualityHold.batch_id == batch_id)
    if reason_code:
        query = query.filter(GspQualityHold.reason_code == reason_code)
    rows = query.order_by(GspQualityHold.id.desc()).offset(offset).limit(limit).all()
    return [
        {
            **model_snapshot(hold),
            "batch_no": batch_no,
            "goods_id": goods_id,
            "goods_name": goods_name,
        }
        for hold, batch_no, goods_id, goods_name in rows
    ]


def list_partner_documents(
    db: Session,
    *,
    partner_id: int,
    status: str | None = None,
    document_type: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> list[dict]:
    query = db.query(GspPartnerDocument).filter(GspPartnerDocument.partner_id == partner_id)
    if status:
        query = query.filter(GspPartnerDocument.status == status)
    if document_type:
        query = query.filter(GspPartnerDocument.document_type == document_type)
    return [
        model_snapshot(row)
        for row in query.order_by(GspPartnerDocument.valid_to, GspPartnerDocument.id).offset(offset).limit(limit).all()
    ]


def list_effective_role_assignments(db: Session, *, user_id: int) -> list[GspRoleAssignment]:
    now = utc_now()
    return (
        db.query(GspRoleAssignment)
        .filter(
            GspRoleAssignment.user_id == user_id,
            GspRoleAssignment.is_active.is_(True),
            GspRoleAssignment.review_due_at > now,
            (
                GspRoleAssignment.expires_at.is_(None)
                | (GspRoleAssignment.expires_at > now)
            ),
        )
        .order_by(GspRoleAssignment.role, GspRoleAssignment.id)
        .all()
    )

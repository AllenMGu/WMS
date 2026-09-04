"""Persistence models for nonconforming products and purchase returns."""

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
)

from app.core.database import Base
from app.core.time import utc_now


class GspNonconformingRecord(Base):
    __tablename__ = "gsp_nonconforming_records"

    id = Column(Integer, primary_key=True)
    record_no = Column(String(100), nullable=False, unique=True, index=True)
    source_type = Column(String(50), nullable=False, index=True)
    source_entity_type = Column(String(100), nullable=False)
    source_entity_id = Column(Integer, nullable=False, index=True)
    stock_id = Column(Integer, ForeignKey("gsp_batch_stock.id"), nullable=True, index=True)
    quality_hold_id = Column(
        Integer,
        ForeignKey("gsp_quality_holds.id"),
        nullable=True,
        index=True,
    )
    batch_id = Column(Integer, ForeignKey("gsp_drug_batches.id"), nullable=False, index=True)
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), nullable=False, index=True)
    location_id = Column(Integer, ForeignKey("locations.id"), nullable=True, index=True)
    quantity = Column(Numeric(18, 3), nullable=False)
    reason_code = Column(String(50), nullable=False)
    description = Column(String(500), nullable=False)
    proposed_disposition = Column(String(50), nullable=True)
    approved_disposition = Column(String(50), nullable=True, index=True)
    status = Column(String(30), nullable=False, default="PENDING_APPROVAL", index=True)
    registered_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    registered_at = Column(DateTime, nullable=False, default=utc_now)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    approval_reason = Column(String(500), nullable=True)
    executed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    executed_at = Column(DateTime, nullable=True)
    witnessed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    supervision_organization = Column(String(200), nullable=True)
    execution_document_ref = Column(String(500), nullable=True)
    rejected_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    rejected_at = Column(DateTime, nullable=True)
    rejection_reason = Column(String(500), nullable=True)
    __table_args__ = (
        CheckConstraint("quantity > 0", name="ck_gsp_nonconforming_quantity_positive"),
    )


class GspPurchaseReturn(Base):
    __tablename__ = "gsp_purchase_returns"

    id = Column(Integer, primary_key=True)
    return_no = Column(String(100), nullable=False, unique=True, index=True)
    supplier_id = Column(
        Integer,
        ForeignKey("gsp_business_partners.id"),
        nullable=False,
        index=True,
    )
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), nullable=False, index=True)
    status = Column(String(30), nullable=False, default="DRAFT", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    submitted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    submitted_at = Column(DateTime, nullable=True)
    quality_approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    quality_approved_at = Column(DateTime, nullable=True)
    dispatched_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    dispatched_at = Column(DateTime, nullable=True)
    outbound_document_no = Column(String(100), nullable=True, index=True)
    carrier_name = Column(String(200), nullable=True)
    cancelled_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    cancelled_at = Column(DateTime, nullable=True)
    cancellation_reason = Column(String(500), nullable=True)


class GspPurchaseReturnItem(Base):
    __tablename__ = "gsp_purchase_return_items"

    id = Column(Integer, primary_key=True)
    purchase_return_id = Column(
        Integer,
        ForeignKey("gsp_purchase_returns.id"),
        nullable=False,
        index=True,
    )
    line_no = Column(Integer, nullable=False)
    nonconforming_record_id = Column(
        Integer,
        ForeignKey("gsp_nonconforming_records.id"),
        nullable=False,
        unique=True,
        index=True,
    )
    batch_id = Column(Integer, ForeignKey("gsp_drug_batches.id"), nullable=False, index=True)
    quantity = Column(Numeric(18, 3), nullable=False)
    __table_args__ = (
        UniqueConstraint("purchase_return_id", "line_no", name="uq_gsp_purchase_return_line"),
        CheckConstraint("quantity > 0", name="ck_gsp_purchase_return_quantity_positive"),
    )

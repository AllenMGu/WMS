"""Persistence models for the controlled purchase-to-stock workflow."""

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
)

from app.core.database import Base
from app.core.time import utc_now


class GspPurchaseOrder(Base):
    __tablename__ = "gsp_purchase_orders"

    id = Column(Integer, primary_key=True)
    order_no = Column(String(100), nullable=False, unique=True, index=True)
    supplier_id = Column(
        Integer,
        ForeignKey("gsp_business_partners.id"),
        nullable=False,
        index=True,
    )
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), nullable=False, index=True)
    ordered_on = Column(Date, nullable=False)
    status = Column(String(30), nullable=False, default="DRAFT", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    submitted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    submitted_at = Column(DateTime, nullable=True)
    quality_approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    quality_approved_at = Column(DateTime, nullable=True)


class GspPurchaseOrderItem(Base):
    __tablename__ = "gsp_purchase_order_items"

    id = Column(Integer, primary_key=True)
    purchase_order_id = Column(
        Integer,
        ForeignKey("gsp_purchase_orders.id"),
        nullable=False,
        index=True,
    )
    line_no = Column(Integer, nullable=False)
    goods_id = Column(Integer, ForeignKey("goods.id"), nullable=False, index=True)
    ordered_quantity = Column(Numeric(18, 3), nullable=False)
    received_quantity = Column(Numeric(18, 3), nullable=False, default=0)
    unit = Column(String(30), nullable=False)
    __table_args__ = (
        UniqueConstraint("purchase_order_id", "line_no", name="uq_gsp_po_line"),
        CheckConstraint("ordered_quantity > 0", name="ck_gsp_po_item_ordered_positive"),
        CheckConstraint("received_quantity >= 0", name="ck_gsp_po_item_received_nonnegative"),
        CheckConstraint(
            "received_quantity <= ordered_quantity",
            name="ck_gsp_po_item_received_not_over",
        ),
    )


class GspReceipt(Base):
    __tablename__ = "gsp_receipts"

    id = Column(Integer, primary_key=True)
    receipt_no = Column(String(100), nullable=False, unique=True, index=True)
    purchase_order_id = Column(
        Integer,
        ForeignKey("gsp_purchase_orders.id"),
        nullable=False,
        index=True,
    )
    delivery_document_no = Column(String(100), nullable=False, index=True)
    arrived_at = Column(DateTime, nullable=False)
    status = Column(String(30), nullable=False, default="PENDING_INSPECTION", index=True)
    received_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)


class GspReceiptItem(Base):
    __tablename__ = "gsp_receipt_items"

    id = Column(Integer, primary_key=True)
    receipt_id = Column(Integer, ForeignKey("gsp_receipts.id"), nullable=False, index=True)
    purchase_order_item_id = Column(
        Integer,
        ForeignKey("gsp_purchase_order_items.id"),
        nullable=False,
        index=True,
    )
    batch_id = Column(Integer, ForeignKey("gsp_drug_batches.id"), nullable=False, index=True)
    location_id = Column(Integer, ForeignKey("locations.id"), nullable=False, index=True)
    received_quantity = Column(Numeric(18, 3), nullable=False)
    accepted_quantity = Column(Numeric(18, 3), nullable=False, default=0)
    rejected_quantity = Column(Numeric(18, 3), nullable=False, default=0)
    inspection_status = Column(String(30), nullable=False, default="PENDING", index=True)
    inspection_conclusion = Column(String(500), nullable=True)
    inspection_report_no = Column(String(100), nullable=True)
    traceability_code = Column(String(200), nullable=True, index=True)
    arrival_temperature = Column(Numeric(8, 2), nullable=True)
    transport_temperature_min = Column(Numeric(8, 2), nullable=True)
    transport_temperature_max = Column(Numeric(8, 2), nullable=True)
    temperature_record_ref = Column(String(500), nullable=True)
    sampling_plan_ref = Column(String(500), nullable=True)
    sampling_method = Column(String(100), nullable=True)
    sample_quantity = Column(Numeric(18, 3), nullable=True)
    sampling_record_no = Column(String(100), nullable=True, unique=True, index=True)
    sampled_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    sampled_at = Column(DateTime, nullable=True)
    inspected_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    inspected_at = Column(DateTime, nullable=True)
    __table_args__ = (
        UniqueConstraint(
            "receipt_id",
            "purchase_order_item_id",
            "batch_id",
            name="uq_gsp_receipt_po_item_batch",
        ),
        CheckConstraint("received_quantity > 0", name="ck_gsp_receipt_received_positive"),
        CheckConstraint("accepted_quantity >= 0", name="ck_gsp_receipt_accepted_nonnegative"),
        CheckConstraint("rejected_quantity >= 0", name="ck_gsp_receipt_rejected_nonnegative"),
        CheckConstraint(
            "accepted_quantity + rejected_quantity <= received_quantity",
            name="ck_gsp_receipt_inspected_not_over",
        ),
        CheckConstraint(
            "sample_quantity IS NULL OR sample_quantity > 0",
            name="ck_gsp_receipt_sample_positive",
        ),
    )


class GspControlledPrintRecord(Base):
    __tablename__ = "gsp_controlled_print_records"

    id = Column(Integer, primary_key=True)
    document_type = Column(String(50), nullable=False, index=True)
    entity_id = Column(Integer, nullable=False, index=True)
    template_version = Column(String(50), nullable=False)
    copy_no = Column(String(100), nullable=False, unique=True, index=True)
    purpose = Column(String(500), nullable=False)
    status = Column(String(30), nullable=False, default="GENERATED", server_default="LEGACY")
    snapshot_data = Column(JSON, nullable=True)
    content_hash = Column(String(64), nullable=True, index=True)
    printed_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    printed_at = Column(DateTime, nullable=False, default=utc_now)

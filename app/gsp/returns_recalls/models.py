"""Persistence models for controlled sales returns and product recalls."""

from sqlalchemy import (
    Boolean,
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


class GspBusinessCalendarDay(Base):
    __tablename__ = "gsp_business_calendar_days"

    id = Column(Integer, primary_key=True)
    calendar_date = Column(Date, nullable=False, unique=True, index=True)
    is_working_day = Column(Boolean, nullable=False)
    approval_ref = Column(String(200), nullable=False)
    reason = Column(String(500), nullable=False)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    approved_at = Column(DateTime, nullable=False, default=utc_now)


class GspSalesReturn(Base):
    __tablename__ = "gsp_sales_returns"

    id = Column(Integer, primary_key=True)
    return_no = Column(String(100), nullable=False, unique=True, index=True)
    shipment_id = Column(Integer, ForeignKey("gsp_shipments.id"), nullable=False, index=True)
    customer_id = Column(
        Integer,
        ForeignKey("gsp_business_partners.id"),
        nullable=False,
        index=True,
    )
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), nullable=False, index=True)
    received_at = Column(DateTime, nullable=False)
    status = Column(String(30), nullable=False, default="PENDING_INSPECTION", index=True)
    received_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    cancelled_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    cancelled_at = Column(DateTime, nullable=True)
    cancellation_reason = Column(String(500), nullable=True)


class GspRecall(Base):
    __tablename__ = "gsp_recalls"

    id = Column(Integer, primary_key=True)
    recall_no = Column(String(100), nullable=False, unique=True, index=True)
    recall_level = Column(String(10), nullable=False)
    source = Column(String(30), nullable=False)
    regulatory_ref = Column(String(200), nullable=True)
    reason = Column(String(500), nullable=False)
    status = Column(String(30), nullable=False, default="DRAFT", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    activated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    activated_at = Column(DateTime, nullable=True)
    notification_due_at = Column(DateTime, nullable=True, index=True)
    next_progress_report_due_at = Column(DateTime, nullable=True, index=True)
    last_progress_reported_at = Column(DateTime, nullable=True)
    closed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    closed_at = Column(DateTime, nullable=True)
    closure_conclusion = Column(String(500), nullable=True)
    completion_report_due_at = Column(DateTime, nullable=True, index=True)


class GspRecallProgressReport(Base):
    __tablename__ = "gsp_recall_progress_reports"

    id = Column(Integer, primary_key=True)
    recall_id = Column(Integer, ForeignKey("gsp_recalls.id"), nullable=False, index=True)
    report_ref = Column(String(200), nullable=False)
    summary = Column(String(1000), nullable=False)
    reported_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    reported_at = Column(DateTime, nullable=False, default=utc_now, index=True)
    __table_args__ = (
        UniqueConstraint("recall_id", "report_ref", name="uq_gsp_recall_progress_ref"),
    )


class GspRecallCompletionReport(Base):
    __tablename__ = "gsp_recall_completion_reports"

    id = Column(Integer, primary_key=True)
    recall_id = Column(
        Integer,
        ForeignKey("gsp_recalls.id"),
        nullable=False,
        unique=True,
        index=True,
    )
    report_ref = Column(String(200), nullable=False, unique=True, index=True)
    treatment_summary = Column(String(2000), nullable=False)
    effectiveness_evaluation = Column(String(1000), nullable=False)
    regulatory_submission_ref = Column(String(500), nullable=False)
    reported_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    reported_at = Column(DateTime, nullable=False, default=utc_now, index=True)


class GspRecallDrill(Base):
    __tablename__ = "gsp_recall_drills"

    id = Column(Integer, primary_key=True)
    drill_no = Column(String(100), nullable=False, unique=True, index=True)
    recall_level = Column(String(10), nullable=False)
    scenario = Column(String(1000), nullable=False)
    objective = Column(String(1000), nullable=False)
    max_allowed_minutes = Column(Integer, nullable=False)
    status = Column(String(30), nullable=False, default="DRAFT", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    activated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    activated_at = Column(DateTime, nullable=True)
    completed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    completed_at = Column(DateTime, nullable=True)
    result = Column(String(30), nullable=True, index=True)
    completion_summary = Column(String(2000), nullable=True)
    deviation_notes = Column(String(1000), nullable=True)
    capa_ref = Column(String(500), nullable=True)
    __table_args__ = (
        CheckConstraint(
            "max_allowed_minutes > 0",
            name="ck_gsp_recall_drill_max_minutes_positive",
        ),
    )


class GspRecallDrillBatch(Base):
    __tablename__ = "gsp_recall_drill_batches"

    id = Column(Integer, primary_key=True)
    drill_id = Column(Integer, ForeignKey("gsp_recall_drills.id"), nullable=False, index=True)
    batch_id = Column(Integer, ForeignKey("gsp_drug_batches.id"), nullable=False, index=True)
    target_shipped_quantity = Column(Numeric(18, 3), nullable=False, default=0)
    __table_args__ = (
        UniqueConstraint("drill_id", "batch_id", name="uq_gsp_recall_drill_batch"),
        CheckConstraint(
            "target_shipped_quantity >= 0",
            name="ck_gsp_recall_drill_batch_target_nonnegative",
        ),
    )


class GspRecallDrillTarget(Base):
    __tablename__ = "gsp_recall_drill_targets"

    id = Column(Integer, primary_key=True)
    drill_id = Column(Integer, ForeignKey("gsp_recall_drills.id"), nullable=False, index=True)
    drill_batch_id = Column(
        Integer,
        ForeignKey("gsp_recall_drill_batches.id"),
        nullable=False,
        index=True,
    )
    shipment_id = Column(Integer, ForeignKey("gsp_shipments.id"), nullable=False, index=True)
    customer_id = Column(
        Integer,
        ForeignKey("gsp_business_partners.id"),
        nullable=False,
        index=True,
    )
    stock_allocation_id = Column(
        Integer,
        ForeignKey("gsp_stock_allocations.id"),
        nullable=False,
        index=True,
    )
    batch_id = Column(Integer, ForeignKey("gsp_drug_batches.id"), nullable=False, index=True)
    shipped_quantity = Column(Numeric(18, 3), nullable=False)
    verification_status = Column(String(30), nullable=False, default="PENDING", index=True)
    verified_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    verified_at = Column(DateTime, nullable=True)
    verification_notes = Column(String(500), nullable=True)
    __table_args__ = (
        UniqueConstraint(
            "drill_id",
            "stock_allocation_id",
            name="uq_gsp_recall_drill_allocation",
        ),
        CheckConstraint(
            "shipped_quantity > 0",
            name="ck_gsp_recall_drill_target_shipped_positive",
        ),
    )


class GspRecallBatch(Base):
    __tablename__ = "gsp_recall_batches"

    id = Column(Integer, primary_key=True)
    recall_id = Column(Integer, ForeignKey("gsp_recalls.id"), nullable=False, index=True)
    batch_id = Column(Integer, ForeignKey("gsp_drug_batches.id"), nullable=False, index=True)
    target_shipped_quantity = Column(Numeric(18, 3), nullable=False, default=0)
    recovered_quantity = Column(Numeric(18, 3), nullable=False, default=0)
    __table_args__ = (
        UniqueConstraint("recall_id", "batch_id", name="uq_gsp_recall_batch"),
        CheckConstraint(
            "target_shipped_quantity >= 0",
            name="ck_gsp_recall_batch_target_nonnegative",
        ),
        CheckConstraint(
            "recovered_quantity >= 0",
            name="ck_gsp_recall_batch_recovered_nonnegative",
        ),
        CheckConstraint(
            "recovered_quantity <= target_shipped_quantity",
            name="ck_gsp_recall_batch_recovered_not_over",
        ),
    )


class GspRecallTarget(Base):
    __tablename__ = "gsp_recall_targets"

    id = Column(Integer, primary_key=True)
    recall_id = Column(Integer, ForeignKey("gsp_recalls.id"), nullable=False, index=True)
    recall_batch_id = Column(
        Integer,
        ForeignKey("gsp_recall_batches.id"),
        nullable=False,
        index=True,
    )
    shipment_id = Column(Integer, ForeignKey("gsp_shipments.id"), nullable=False, index=True)
    customer_id = Column(
        Integer,
        ForeignKey("gsp_business_partners.id"),
        nullable=False,
        index=True,
    )
    stock_allocation_id = Column(
        Integer,
        ForeignKey("gsp_stock_allocations.id"),
        nullable=False,
        index=True,
    )
    batch_id = Column(Integer, ForeignKey("gsp_drug_batches.id"), nullable=False, index=True)
    shipped_quantity = Column(Numeric(18, 3), nullable=False)
    recovered_quantity = Column(Numeric(18, 3), nullable=False, default=0)
    notification_status = Column(String(30), nullable=False, default="PENDING", index=True)
    notified_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    notified_at = Column(DateTime, nullable=True)
    notification_notes = Column(String(500), nullable=True)
    __table_args__ = (
        UniqueConstraint("recall_id", "stock_allocation_id", name="uq_gsp_recall_allocation"),
        CheckConstraint("shipped_quantity > 0", name="ck_gsp_recall_target_shipped_positive"),
        CheckConstraint(
            "recovered_quantity >= 0",
            name="ck_gsp_recall_target_recovered_nonnegative",
        ),
        CheckConstraint(
            "recovered_quantity <= shipped_quantity",
            name="ck_gsp_recall_target_recovered_not_over",
        ),
    )


class GspSalesReturnItem(Base):
    __tablename__ = "gsp_sales_return_items"

    id = Column(Integer, primary_key=True)
    sales_return_id = Column(
        Integer,
        ForeignKey("gsp_sales_returns.id"),
        nullable=False,
        index=True,
    )
    line_no = Column(Integer, nullable=False)
    stock_allocation_id = Column(
        Integer,
        ForeignKey("gsp_stock_allocations.id"),
        nullable=False,
        index=True,
    )
    recall_target_id = Column(
        Integer,
        ForeignKey("gsp_recall_targets.id"),
        nullable=True,
        index=True,
    )
    batch_id = Column(Integer, ForeignKey("gsp_drug_batches.id"), nullable=False, index=True)
    goods_id = Column(Integer, ForeignKey("goods.id"), nullable=False, index=True)
    received_quantity = Column(Numeric(18, 3), nullable=False)
    accepted_quantity = Column(Numeric(18, 3), nullable=False, default=0)
    rejected_quantity = Column(Numeric(18, 3), nullable=False, default=0)
    reason_code = Column(String(50), nullable=False)
    condition_notes = Column(String(500), nullable=False)
    traceability_code = Column(String(200), nullable=True, index=True)
    temperature_record_ref = Column(String(500), nullable=True)
    inspection_status = Column(String(30), nullable=False, default="PENDING", index=True)
    inspection_conclusion = Column(String(500), nullable=True)
    accepted_location_id = Column(Integer, ForeignKey("locations.id"), nullable=True)
    rejection_disposition = Column(String(50), nullable=True)
    package_intact = Column(Boolean, nullable=True)
    storage_conditions_confirmed = Column(Boolean, nullable=True)
    traceability_verified = Column(Boolean, nullable=True)
    inspected_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    inspected_at = Column(DateTime, nullable=True)
    __table_args__ = (
        UniqueConstraint(
            "sales_return_id",
            "stock_allocation_id",
            name="uq_gsp_return_allocation",
        ),
        CheckConstraint("received_quantity > 0", name="ck_gsp_return_received_positive"),
        CheckConstraint("accepted_quantity >= 0", name="ck_gsp_return_accepted_nonnegative"),
        CheckConstraint("rejected_quantity >= 0", name="ck_gsp_return_rejected_nonnegative"),
        CheckConstraint(
            "accepted_quantity + rejected_quantity <= received_quantity",
            name="ck_gsp_return_inspected_not_over",
        ),
    )

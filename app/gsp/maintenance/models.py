"""Persistence models for GSP drug maintenance plans and inspections."""

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


class GspMaintenancePlan(Base):
    __tablename__ = "gsp_maintenance_plans"

    id = Column(Integer, primary_key=True)
    plan_no = Column(String(100), nullable=False, unique=True, index=True)
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), nullable=False, index=True)
    plan_type = Column(String(30), nullable=False)
    scheduled_from = Column(Date, nullable=False, index=True)
    scheduled_to = Column(Date, nullable=False, index=True)
    scope_summary = Column(String(1000), nullable=False)
    status = Column(String(30), nullable=False, default="DRAFT", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    submitted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    submitted_at = Column(DateTime, nullable=True)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    completed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    completed_at = Column(DateTime, nullable=True)
    completion_conclusion = Column(String(1000), nullable=True)
    __table_args__ = (
        CheckConstraint(
            "scheduled_to >= scheduled_from",
            name="ck_gsp_maintenance_plan_date_range",
        ),
    )


class GspMaintenancePlanItem(Base):
    __tablename__ = "gsp_maintenance_plan_items"

    id = Column(Integer, primary_key=True)
    plan_id = Column(
        Integer,
        ForeignKey("gsp_maintenance_plans.id"),
        nullable=False,
        index=True,
    )
    line_no = Column(Integer, nullable=False)
    stock_id = Column(Integer, ForeignKey("gsp_batch_stock.id"), nullable=False, index=True)
    batch_id = Column(Integer, ForeignKey("gsp_drug_batches.id"), nullable=False, index=True)
    planned_quantity = Column(Numeric(18, 3), nullable=False)
    priority_reason = Column(String(500), nullable=True)
    status = Column(String(30), nullable=False, default="PENDING", index=True)
    appearance_ok = Column(Boolean, nullable=True)
    package_ok = Column(Boolean, nullable=True)
    storage_condition_ok = Column(Boolean, nullable=True)
    temperature_humidity_ok = Column(Boolean, nullable=True)
    finding = Column(String(1000), nullable=True)
    next_due_on = Column(Date, nullable=True, index=True)
    quality_hold_id = Column(Integer, ForeignKey("gsp_quality_holds.id"), nullable=True, index=True)
    checked_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    checked_at = Column(DateTime, nullable=True)
    __table_args__ = (
        UniqueConstraint("plan_id", "line_no", name="uq_gsp_maintenance_plan_line"),
        UniqueConstraint("plan_id", "stock_id", name="uq_gsp_maintenance_plan_stock"),
        CheckConstraint(
            "planned_quantity > 0",
            name="ck_gsp_maintenance_planned_quantity_positive",
        ),
    )


class GspExpiryAlert(Base):
    __tablename__ = "gsp_expiry_alerts"

    id = Column(Integer, primary_key=True)
    batch_id = Column(Integer, ForeignKey("gsp_drug_batches.id"), nullable=False, index=True)
    alert_type = Column(String(30), nullable=False, index=True)
    threshold_days = Column(Integer, nullable=False)
    status = Column(String(30), nullable=False, default="OPEN", index=True)
    quality_hold_id = Column(Integer, ForeignKey("gsp_quality_holds.id"), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    last_evaluated_at = Column(DateTime, nullable=False, default=utc_now)
    resolved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolution = Column(String(500), nullable=True)
    evidence_ref = Column(String(500), nullable=True)
    __table_args__ = (
        UniqueConstraint("batch_id", "alert_type", name="uq_gsp_expiry_batch_alert"),
    )

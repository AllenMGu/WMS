"""Persistence models for controlled GSP lot-level stocktaking."""

from sqlalchemy import (
    Boolean,
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


class GspStocktakePlan(Base):
    __tablename__ = "gsp_stocktake_plans"

    id = Column(Integer, primary_key=True)
    plan_no = Column(String(100), nullable=False, unique=True, index=True)
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), nullable=False, index=True)
    scope_type = Column(String(30), nullable=False)
    scope_summary = Column(String(1000), nullable=False)
    selection_rule = Column(String(50), nullable=False, default="MANUAL")
    status = Column(String(30), nullable=False, default="DRAFT", index=True)
    transactions_frozen = Column(Boolean, nullable=False, default=False)
    frozen_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    submitted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    submitted_at = Column(DateTime, nullable=True)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_conclusion = Column(String(1000), nullable=True)
    capa_ref = Column(String(500), nullable=True)
    completed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    completed_at = Column(DateTime, nullable=True)


class GspStocktakeItem(Base):
    __tablename__ = "gsp_stocktake_items"

    id = Column(Integer, primary_key=True)
    plan_id = Column(Integer, ForeignKey("gsp_stocktake_plans.id"), nullable=False, index=True)
    line_no = Column(Integer, nullable=False)
    stock_id = Column(Integer, ForeignKey("gsp_batch_stock.id"), nullable=False, index=True)
    batch_id = Column(Integer, ForeignKey("gsp_drug_batches.id"), nullable=False, index=True)
    location_id = Column(Integer, ForeignKey("locations.id"), nullable=False, index=True)
    status = Column(String(30), nullable=False, default="PENDING", index=True)
    book_quantity = Column(Numeric(18, 3), nullable=True)
    book_reserved_quantity = Column(Numeric(18, 3), nullable=True)
    book_lock_version = Column(Integer, nullable=True)
    counted_quantity = Column(Numeric(18, 3), nullable=True)
    difference_quantity = Column(Numeric(18, 3), nullable=True)
    discrepancy_reason = Column(String(1000), nullable=True)
    count_round = Column(Integer, nullable=False, default=0)
    counted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    counted_at = Column(DateTime, nullable=True)
    adjusted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    adjusted_at = Column(DateTime, nullable=True)
    __table_args__ = (
        UniqueConstraint("plan_id", "line_no", name="uq_gsp_stocktake_plan_line"),
        UniqueConstraint("plan_id", "stock_id", name="uq_gsp_stocktake_plan_stock"),
        CheckConstraint(
            "book_quantity IS NULL OR book_quantity >= 0",
            name="ck_gsp_stocktake_book_quantity_nonnegative",
        ),
        CheckConstraint(
            "book_reserved_quantity IS NULL OR book_reserved_quantity >= 0",
            name="ck_gsp_stocktake_book_reserved_nonnegative",
        ),
        CheckConstraint(
            "counted_quantity IS NULL OR counted_quantity >= 0",
            name="ck_gsp_stocktake_counted_quantity_nonnegative",
        ),
        CheckConstraint("count_round >= 0", name="ck_gsp_stocktake_round_nonnegative"),
    )

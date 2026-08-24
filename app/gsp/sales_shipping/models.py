"""Persistence models for the controlled order-to-shipment workflow."""

from sqlalchemy import (
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


class GspSalesOrder(Base):
    __tablename__ = "gsp_sales_orders"

    id = Column(Integer, primary_key=True)
    order_no = Column(String(100), nullable=False, unique=True, index=True)
    customer_id = Column(
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
    allocated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    allocated_at = Column(DateTime, nullable=True)
    picked_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    picked_at = Column(DateTime, nullable=True)
    cancelled_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    cancelled_at = Column(DateTime, nullable=True)
    cancellation_reason = Column(String(500), nullable=True)


class GspSalesOrderItem(Base):
    __tablename__ = "gsp_sales_order_items"

    id = Column(Integer, primary_key=True)
    sales_order_id = Column(
        Integer,
        ForeignKey("gsp_sales_orders.id"),
        nullable=False,
        index=True,
    )
    line_no = Column(Integer, nullable=False)
    goods_id = Column(Integer, ForeignKey("goods.id"), nullable=False, index=True)
    ordered_quantity = Column(Numeric(18, 3), nullable=False)
    allocated_quantity = Column(Numeric(18, 3), nullable=False, default=0)
    shipped_quantity = Column(Numeric(18, 3), nullable=False, default=0)
    unit = Column(String(30), nullable=False)
    minimum_remaining_days = Column(Integer, nullable=False, default=0)
    __table_args__ = (
        UniqueConstraint("sales_order_id", "line_no", name="uq_gsp_sales_order_line"),
        CheckConstraint("ordered_quantity > 0", name="ck_gsp_sales_item_ordered_positive"),
        CheckConstraint("allocated_quantity >= 0", name="ck_gsp_sales_item_allocated_nonnegative"),
        CheckConstraint("shipped_quantity >= 0", name="ck_gsp_sales_item_shipped_nonnegative"),
        CheckConstraint(
            "allocated_quantity <= ordered_quantity",
            name="ck_gsp_sales_item_allocated_not_over",
        ),
        CheckConstraint(
            "shipped_quantity <= allocated_quantity",
            name="ck_gsp_sales_item_shipped_not_over",
        ),
        CheckConstraint(
            "minimum_remaining_days >= 0",
            name="ck_gsp_sales_item_shelf_life_nonnegative",
        ),
    )


class GspStockAllocation(Base):
    __tablename__ = "gsp_stock_allocations"

    id = Column(Integer, primary_key=True)
    sales_order_item_id = Column(
        Integer,
        ForeignKey("gsp_sales_order_items.id"),
        nullable=False,
        index=True,
    )
    batch_stock_id = Column(
        Integer,
        ForeignKey("gsp_batch_stock.id"),
        nullable=False,
        index=True,
    )
    batch_id = Column(Integer, ForeignKey("gsp_drug_batches.id"), nullable=False, index=True)
    location_id = Column(Integer, ForeignKey("locations.id"), nullable=False, index=True)
    quantity = Column(Numeric(18, 3), nullable=False)
    status = Column(String(30), nullable=False, default="ALLOCATED", index=True)
    picked_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    picked_at = Column(DateTime, nullable=True)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    shipped_at = Column(DateTime, nullable=True)
    __table_args__ = (
        UniqueConstraint(
            "sales_order_item_id",
            "batch_stock_id",
            name="uq_gsp_sales_item_batch_stock",
        ),
        CheckConstraint("quantity > 0", name="ck_gsp_allocation_quantity_positive"),
    )


class GspShipment(Base):
    __tablename__ = "gsp_shipments"

    id = Column(Integer, primary_key=True)
    shipment_no = Column(String(100), nullable=False, unique=True, index=True)
    sales_order_id = Column(
        Integer,
        ForeignKey("gsp_sales_orders.id"),
        nullable=False,
        unique=True,
        index=True,
    )
    carrier_id = Column(Integer, ForeignKey("gsp_carriers.id"), nullable=True, index=True)
    vehicle_id = Column(
        Integer,
        ForeignKey("gsp_carrier_vehicles.id"),
        nullable=True,
        index=True,
    )
    driver_id = Column(
        Integer,
        ForeignKey("gsp_carrier_drivers.id"),
        nullable=True,
        index=True,
    )
    carrier_name = Column(String(200), nullable=False)
    vehicle_no = Column(String(100), nullable=True)
    driver_name = Column(String(100), nullable=True)
    transport_mode = Column(String(30), nullable=False, default="NORMAL")
    temperature_record_ref = Column(String(500), nullable=True)
    status = Column(String(30), nullable=False, default="PREPARED", index=True)
    prepared_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    prepared_at = Column(DateTime, nullable=False, default=utc_now)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    dispatched_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    dispatched_at = Column(DateTime, nullable=True)


class GspShipmentPackage(Base):
    __tablename__ = "gsp_shipment_packages"

    id = Column(Integer, primary_key=True)
    shipment_id = Column(Integer, ForeignKey("gsp_shipments.id"), nullable=False, index=True)
    package_no = Column(String(100), nullable=False)
    package_type = Column(String(50), nullable=False)
    seal_no = Column(String(100), nullable=False)
    packing_condition = Column(String(500), nullable=False)
    delivery_note_no = Column(String(100), nullable=False)
    packing_record_ref = Column(String(500), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    __table_args__ = (
        UniqueConstraint("shipment_id", "package_no", name="uq_gsp_shipment_package_no"),
    )


class GspShipmentPackageItem(Base):
    __tablename__ = "gsp_shipment_package_items"

    id = Column(Integer, primary_key=True)
    package_id = Column(Integer, ForeignKey("gsp_shipment_packages.id"), nullable=False, index=True)
    allocation_id = Column(Integer, ForeignKey("gsp_stock_allocations.id"), nullable=False, index=True)
    quantity = Column(Numeric(18, 3), nullable=False)
    traceability_code = Column(String(200), nullable=True, index=True)
    __table_args__ = (
        UniqueConstraint("package_id", "allocation_id", name="uq_gsp_package_allocation"),
        CheckConstraint("quantity > 0", name="ck_gsp_package_item_quantity_positive"),
    )

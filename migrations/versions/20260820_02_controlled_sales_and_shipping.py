"""controlled sales and shipping

Revision ID: 20260820_02
Revises: 20260820_01
Create Date: 2026-08-20
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260820_02"
down_revision: Union[str, None] = "20260820_01"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("gsp_batch_stock") as batch_op:
        batch_op.add_column(
            sa.Column(
                "reserved_quantity",
                sa.Numeric(precision=18, scale=3),
                server_default=sa.text("0"),
                nullable=False,
            )
        )
        batch_op.create_check_constraint(
            "ck_gsp_batch_stock_reserved_nonnegative",
            "reserved_quantity >= 0",
        )
        batch_op.create_check_constraint(
            "ck_gsp_batch_stock_reserved_not_over",
            "reserved_quantity <= quantity",
        )

    op.create_table(
        "gsp_sales_orders",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("order_no", sa.String(length=100), nullable=False),
        sa.Column("customer_id", sa.Integer(), nullable=False),
        sa.Column("warehouse_id", sa.Integer(), nullable=False),
        sa.Column("ordered_on", sa.Date(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("submitted_by", sa.Integer(), nullable=True),
        sa.Column("submitted_at", sa.DateTime(), nullable=True),
        sa.Column("quality_approved_by", sa.Integer(), nullable=True),
        sa.Column("quality_approved_at", sa.DateTime(), nullable=True),
        sa.Column("allocated_by", sa.Integer(), nullable=True),
        sa.Column("allocated_at", sa.DateTime(), nullable=True),
        sa.Column("picked_by", sa.Integer(), nullable=True),
        sa.Column("picked_at", sa.DateTime(), nullable=True),
        sa.Column("cancelled_by", sa.Integer(), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(), nullable=True),
        sa.Column("cancellation_reason", sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(["allocated_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["cancelled_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["customer_id"], ["gsp_business_partners.id"]),
        sa.ForeignKeyConstraint(["picked_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["quality_approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["submitted_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["warehouse_id"], ["warehouses.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_gsp_sales_orders_customer_id", "gsp_sales_orders", ["customer_id"])
    op.create_index("ix_gsp_sales_orders_order_no", "gsp_sales_orders", ["order_no"], unique=True)
    op.create_index("ix_gsp_sales_orders_status", "gsp_sales_orders", ["status"])
    op.create_index("ix_gsp_sales_orders_warehouse_id", "gsp_sales_orders", ["warehouse_id"])

    op.create_table(
        "gsp_sales_order_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("sales_order_id", sa.Integer(), nullable=False),
        sa.Column("line_no", sa.Integer(), nullable=False),
        sa.Column("goods_id", sa.Integer(), nullable=False),
        sa.Column("ordered_quantity", sa.Numeric(precision=18, scale=3), nullable=False),
        sa.Column("allocated_quantity", sa.Numeric(precision=18, scale=3), nullable=False),
        sa.Column("shipped_quantity", sa.Numeric(precision=18, scale=3), nullable=False),
        sa.Column("unit", sa.String(length=30), nullable=False),
        sa.Column("minimum_remaining_days", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "allocated_quantity <= ordered_quantity",
            name="ck_gsp_sales_item_allocated_not_over",
        ),
        sa.CheckConstraint(
            "allocated_quantity >= 0",
            name="ck_gsp_sales_item_allocated_nonnegative",
        ),
        sa.CheckConstraint(
            "minimum_remaining_days >= 0",
            name="ck_gsp_sales_item_shelf_life_nonnegative",
        ),
        sa.CheckConstraint(
            "ordered_quantity > 0",
            name="ck_gsp_sales_item_ordered_positive",
        ),
        sa.CheckConstraint(
            "shipped_quantity <= allocated_quantity",
            name="ck_gsp_sales_item_shipped_not_over",
        ),
        sa.CheckConstraint(
            "shipped_quantity >= 0",
            name="ck_gsp_sales_item_shipped_nonnegative",
        ),
        sa.ForeignKeyConstraint(["goods_id"], ["goods.id"]),
        sa.ForeignKeyConstraint(["sales_order_id"], ["gsp_sales_orders.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sales_order_id", "line_no", name="uq_gsp_sales_order_line"),
    )
    op.create_index(
        "ix_gsp_sales_order_items_goods_id",
        "gsp_sales_order_items",
        ["goods_id"],
    )
    op.create_index(
        "ix_gsp_sales_order_items_sales_order_id",
        "gsp_sales_order_items",
        ["sales_order_id"],
    )

    op.create_table(
        "gsp_stock_allocations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("sales_order_item_id", sa.Integer(), nullable=False),
        sa.Column("batch_stock_id", sa.Integer(), nullable=False),
        sa.Column("batch_id", sa.Integer(), nullable=False),
        sa.Column("location_id", sa.Integer(), nullable=False),
        sa.Column("quantity", sa.Numeric(precision=18, scale=3), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("picked_by", sa.Integer(), nullable=True),
        sa.Column("picked_at", sa.DateTime(), nullable=True),
        sa.Column("reviewed_by", sa.Integer(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("shipped_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("quantity > 0", name="ck_gsp_allocation_quantity_positive"),
        sa.ForeignKeyConstraint(["batch_id"], ["gsp_drug_batches.id"]),
        sa.ForeignKeyConstraint(["batch_stock_id"], ["gsp_batch_stock.id"]),
        sa.ForeignKeyConstraint(["location_id"], ["locations.id"]),
        sa.ForeignKeyConstraint(["picked_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["sales_order_item_id"], ["gsp_sales_order_items.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "sales_order_item_id",
            "batch_stock_id",
            name="uq_gsp_sales_item_batch_stock",
        ),
    )
    op.create_index("ix_gsp_stock_allocations_batch_id", "gsp_stock_allocations", ["batch_id"])
    op.create_index(
        "ix_gsp_stock_allocations_batch_stock_id",
        "gsp_stock_allocations",
        ["batch_stock_id"],
    )
    op.create_index(
        "ix_gsp_stock_allocations_location_id",
        "gsp_stock_allocations",
        ["location_id"],
    )
    op.create_index(
        "ix_gsp_stock_allocations_sales_order_item_id",
        "gsp_stock_allocations",
        ["sales_order_item_id"],
    )
    op.create_index("ix_gsp_stock_allocations_status", "gsp_stock_allocations", ["status"])

    op.create_table(
        "gsp_shipments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("shipment_no", sa.String(length=100), nullable=False),
        sa.Column("sales_order_id", sa.Integer(), nullable=False),
        sa.Column("carrier_name", sa.String(length=200), nullable=False),
        sa.Column("vehicle_no", sa.String(length=100), nullable=True),
        sa.Column("driver_name", sa.String(length=100), nullable=True),
        sa.Column("transport_mode", sa.String(length=30), nullable=False),
        sa.Column("temperature_record_ref", sa.String(length=500), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("prepared_by", sa.Integer(), nullable=False),
        sa.Column("prepared_at", sa.DateTime(), nullable=False),
        sa.Column("reviewed_by", sa.Integer(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("dispatched_by", sa.Integer(), nullable=True),
        sa.Column("dispatched_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["dispatched_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["prepared_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["sales_order_id"], ["gsp_sales_orders.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_gsp_shipments_sales_order_id", "gsp_shipments", ["sales_order_id"], unique=True)
    op.create_index("ix_gsp_shipments_shipment_no", "gsp_shipments", ["shipment_no"], unique=True)
    op.create_index("ix_gsp_shipments_status", "gsp_shipments", ["status"])


def downgrade() -> None:
    op.drop_index("ix_gsp_shipments_status", table_name="gsp_shipments")
    op.drop_index("ix_gsp_shipments_shipment_no", table_name="gsp_shipments")
    op.drop_index("ix_gsp_shipments_sales_order_id", table_name="gsp_shipments")
    op.drop_table("gsp_shipments")
    op.drop_index("ix_gsp_stock_allocations_status", table_name="gsp_stock_allocations")
    op.drop_index(
        "ix_gsp_stock_allocations_sales_order_item_id",
        table_name="gsp_stock_allocations",
    )
    op.drop_index("ix_gsp_stock_allocations_location_id", table_name="gsp_stock_allocations")
    op.drop_index("ix_gsp_stock_allocations_batch_stock_id", table_name="gsp_stock_allocations")
    op.drop_index("ix_gsp_stock_allocations_batch_id", table_name="gsp_stock_allocations")
    op.drop_table("gsp_stock_allocations")
    op.drop_index(
        "ix_gsp_sales_order_items_sales_order_id",
        table_name="gsp_sales_order_items",
    )
    op.drop_index("ix_gsp_sales_order_items_goods_id", table_name="gsp_sales_order_items")
    op.drop_table("gsp_sales_order_items")
    op.drop_index("ix_gsp_sales_orders_warehouse_id", table_name="gsp_sales_orders")
    op.drop_index("ix_gsp_sales_orders_status", table_name="gsp_sales_orders")
    op.drop_index("ix_gsp_sales_orders_order_no", table_name="gsp_sales_orders")
    op.drop_index("ix_gsp_sales_orders_customer_id", table_name="gsp_sales_orders")
    op.drop_table("gsp_sales_orders")
    with op.batch_alter_table("gsp_batch_stock") as batch_op:
        batch_op.drop_constraint(
            "ck_gsp_batch_stock_reserved_not_over",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_gsp_batch_stock_reserved_nonnegative",
            type_="check",
        )
        batch_op.drop_column("reserved_quantity")

"""controlled sales returns and product recalls

Revision ID: 20260820_03
Revises: 20260820_02
Create Date: 2026-08-20
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260820_03"
down_revision: Union[str, None] = "20260820_02"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "gsp_sales_returns",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("return_no", sa.String(length=100), nullable=False),
        sa.Column("shipment_id", sa.Integer(), nullable=False),
        sa.Column("customer_id", sa.Integer(), nullable=False),
        sa.Column("warehouse_id", sa.Integer(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("received_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["customer_id"], ["gsp_business_partners.id"]),
        sa.ForeignKeyConstraint(["received_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["shipment_id"], ["gsp_shipments.id"]),
        sa.ForeignKeyConstraint(["warehouse_id"], ["warehouses.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_gsp_sales_returns_customer_id",
        "gsp_sales_returns",
        ["customer_id"],
    )
    op.create_index(
        "ix_gsp_sales_returns_return_no",
        "gsp_sales_returns",
        ["return_no"],
        unique=True,
    )
    op.create_index(
        "ix_gsp_sales_returns_shipment_id",
        "gsp_sales_returns",
        ["shipment_id"],
    )
    op.create_index("ix_gsp_sales_returns_status", "gsp_sales_returns", ["status"])
    op.create_index(
        "ix_gsp_sales_returns_warehouse_id",
        "gsp_sales_returns",
        ["warehouse_id"],
    )

    op.create_table(
        "gsp_recalls",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("recall_no", sa.String(length=100), nullable=False),
        sa.Column("recall_level", sa.String(length=10), nullable=False),
        sa.Column("source", sa.String(length=30), nullable=False),
        sa.Column("regulatory_ref", sa.String(length=200), nullable=True),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("activated_by", sa.Integer(), nullable=True),
        sa.Column("activated_at", sa.DateTime(), nullable=True),
        sa.Column("closed_by", sa.Integer(), nullable=True),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        sa.Column("closure_conclusion", sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(["activated_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["closed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_gsp_recalls_recall_no",
        "gsp_recalls",
        ["recall_no"],
        unique=True,
    )
    op.create_index("ix_gsp_recalls_status", "gsp_recalls", ["status"])

    op.create_table(
        "gsp_recall_batches",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("recall_id", sa.Integer(), nullable=False),
        sa.Column("batch_id", sa.Integer(), nullable=False),
        sa.Column(
            "target_shipped_quantity",
            sa.Numeric(precision=18, scale=3),
            nullable=False,
        ),
        sa.Column(
            "recovered_quantity",
            sa.Numeric(precision=18, scale=3),
            nullable=False,
        ),
        sa.CheckConstraint(
            "recovered_quantity <= target_shipped_quantity",
            name="ck_gsp_recall_batch_recovered_not_over",
        ),
        sa.CheckConstraint(
            "recovered_quantity >= 0",
            name="ck_gsp_recall_batch_recovered_nonnegative",
        ),
        sa.CheckConstraint(
            "target_shipped_quantity >= 0",
            name="ck_gsp_recall_batch_target_nonnegative",
        ),
        sa.ForeignKeyConstraint(["batch_id"], ["gsp_drug_batches.id"]),
        sa.ForeignKeyConstraint(["recall_id"], ["gsp_recalls.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("recall_id", "batch_id", name="uq_gsp_recall_batch"),
    )
    op.create_index(
        "ix_gsp_recall_batches_batch_id",
        "gsp_recall_batches",
        ["batch_id"],
    )
    op.create_index(
        "ix_gsp_recall_batches_recall_id",
        "gsp_recall_batches",
        ["recall_id"],
    )

    op.create_table(
        "gsp_recall_targets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("recall_id", sa.Integer(), nullable=False),
        sa.Column("recall_batch_id", sa.Integer(), nullable=False),
        sa.Column("shipment_id", sa.Integer(), nullable=False),
        sa.Column("customer_id", sa.Integer(), nullable=False),
        sa.Column("stock_allocation_id", sa.Integer(), nullable=False),
        sa.Column("batch_id", sa.Integer(), nullable=False),
        sa.Column("shipped_quantity", sa.Numeric(precision=18, scale=3), nullable=False),
        sa.Column("recovered_quantity", sa.Numeric(precision=18, scale=3), nullable=False),
        sa.Column("notification_status", sa.String(length=30), nullable=False),
        sa.Column("notified_by", sa.Integer(), nullable=True),
        sa.Column("notified_at", sa.DateTime(), nullable=True),
        sa.Column("notification_notes", sa.String(length=500), nullable=True),
        sa.CheckConstraint(
            "recovered_quantity <= shipped_quantity",
            name="ck_gsp_recall_target_recovered_not_over",
        ),
        sa.CheckConstraint(
            "recovered_quantity >= 0",
            name="ck_gsp_recall_target_recovered_nonnegative",
        ),
        sa.CheckConstraint(
            "shipped_quantity > 0",
            name="ck_gsp_recall_target_shipped_positive",
        ),
        sa.ForeignKeyConstraint(["batch_id"], ["gsp_drug_batches.id"]),
        sa.ForeignKeyConstraint(["customer_id"], ["gsp_business_partners.id"]),
        sa.ForeignKeyConstraint(["notified_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["recall_batch_id"], ["gsp_recall_batches.id"]),
        sa.ForeignKeyConstraint(["recall_id"], ["gsp_recalls.id"]),
        sa.ForeignKeyConstraint(["shipment_id"], ["gsp_shipments.id"]),
        sa.ForeignKeyConstraint(["stock_allocation_id"], ["gsp_stock_allocations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "recall_id",
            "stock_allocation_id",
            name="uq_gsp_recall_allocation",
        ),
    )
    for column in (
        "batch_id",
        "customer_id",
        "recall_batch_id",
        "recall_id",
        "shipment_id",
        "stock_allocation_id",
    ):
        op.create_index(
            f"ix_gsp_recall_targets_{column}",
            "gsp_recall_targets",
            [column],
        )
    op.create_index(
        "ix_gsp_recall_targets_notification_status",
        "gsp_recall_targets",
        ["notification_status"],
    )

    op.create_table(
        "gsp_sales_return_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("sales_return_id", sa.Integer(), nullable=False),
        sa.Column("line_no", sa.Integer(), nullable=False),
        sa.Column("stock_allocation_id", sa.Integer(), nullable=False),
        sa.Column("recall_target_id", sa.Integer(), nullable=True),
        sa.Column("batch_id", sa.Integer(), nullable=False),
        sa.Column("goods_id", sa.Integer(), nullable=False),
        sa.Column("received_quantity", sa.Numeric(precision=18, scale=3), nullable=False),
        sa.Column("accepted_quantity", sa.Numeric(precision=18, scale=3), nullable=False),
        sa.Column("rejected_quantity", sa.Numeric(precision=18, scale=3), nullable=False),
        sa.Column("reason_code", sa.String(length=50), nullable=False),
        sa.Column("condition_notes", sa.String(length=500), nullable=False),
        sa.Column("traceability_code", sa.String(length=200), nullable=True),
        sa.Column("temperature_record_ref", sa.String(length=500), nullable=True),
        sa.Column("inspection_status", sa.String(length=30), nullable=False),
        sa.Column("inspection_conclusion", sa.String(length=500), nullable=True),
        sa.Column("accepted_location_id", sa.Integer(), nullable=True),
        sa.Column("rejection_disposition", sa.String(length=50), nullable=True),
        sa.Column("package_intact", sa.Boolean(), nullable=True),
        sa.Column("storage_conditions_confirmed", sa.Boolean(), nullable=True),
        sa.Column("traceability_verified", sa.Boolean(), nullable=True),
        sa.Column("inspected_by", sa.Integer(), nullable=True),
        sa.Column("inspected_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "accepted_quantity >= 0",
            name="ck_gsp_return_accepted_nonnegative",
        ),
        sa.CheckConstraint(
            "accepted_quantity + rejected_quantity <= received_quantity",
            name="ck_gsp_return_inspected_not_over",
        ),
        sa.CheckConstraint(
            "received_quantity > 0",
            name="ck_gsp_return_received_positive",
        ),
        sa.CheckConstraint(
            "rejected_quantity >= 0",
            name="ck_gsp_return_rejected_nonnegative",
        ),
        sa.ForeignKeyConstraint(["accepted_location_id"], ["locations.id"]),
        sa.ForeignKeyConstraint(["batch_id"], ["gsp_drug_batches.id"]),
        sa.ForeignKeyConstraint(["goods_id"], ["goods.id"]),
        sa.ForeignKeyConstraint(["inspected_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["recall_target_id"], ["gsp_recall_targets.id"]),
        sa.ForeignKeyConstraint(["sales_return_id"], ["gsp_sales_returns.id"]),
        sa.ForeignKeyConstraint(["stock_allocation_id"], ["gsp_stock_allocations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "sales_return_id",
            "stock_allocation_id",
            name="uq_gsp_return_allocation",
        ),
    )
    for column in (
        "batch_id",
        "goods_id",
        "recall_target_id",
        "sales_return_id",
        "stock_allocation_id",
    ):
        op.create_index(
            f"ix_gsp_sales_return_items_{column}",
            "gsp_sales_return_items",
            [column],
        )
    op.create_index(
        "ix_gsp_sales_return_items_inspection_status",
        "gsp_sales_return_items",
        ["inspection_status"],
    )
    op.create_index(
        "ix_gsp_sales_return_items_traceability_code",
        "gsp_sales_return_items",
        ["traceability_code"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_gsp_sales_return_items_traceability_code",
        table_name="gsp_sales_return_items",
    )
    op.drop_index(
        "ix_gsp_sales_return_items_inspection_status",
        table_name="gsp_sales_return_items",
    )
    for column in reversed(
        (
            "batch_id",
            "goods_id",
            "recall_target_id",
            "sales_return_id",
            "stock_allocation_id",
        )
    ):
        op.drop_index(
            f"ix_gsp_sales_return_items_{column}",
            table_name="gsp_sales_return_items",
        )
    op.drop_table("gsp_sales_return_items")

    op.drop_index(
        "ix_gsp_recall_targets_notification_status",
        table_name="gsp_recall_targets",
    )
    for column in reversed(
        (
            "batch_id",
            "customer_id",
            "recall_batch_id",
            "recall_id",
            "shipment_id",
            "stock_allocation_id",
        )
    ):
        op.drop_index(
            f"ix_gsp_recall_targets_{column}",
            table_name="gsp_recall_targets",
        )
    op.drop_table("gsp_recall_targets")

    op.drop_index("ix_gsp_recall_batches_recall_id", table_name="gsp_recall_batches")
    op.drop_index("ix_gsp_recall_batches_batch_id", table_name="gsp_recall_batches")
    op.drop_table("gsp_recall_batches")

    op.drop_index("ix_gsp_recalls_status", table_name="gsp_recalls")
    op.drop_index("ix_gsp_recalls_recall_no", table_name="gsp_recalls")
    op.drop_table("gsp_recalls")

    op.drop_index("ix_gsp_sales_returns_warehouse_id", table_name="gsp_sales_returns")
    op.drop_index("ix_gsp_sales_returns_status", table_name="gsp_sales_returns")
    op.drop_index("ix_gsp_sales_returns_shipment_id", table_name="gsp_sales_returns")
    op.drop_index("ix_gsp_sales_returns_return_no", table_name="gsp_sales_returns")
    op.drop_index("ix_gsp_sales_returns_customer_id", table_name="gsp_sales_returns")
    op.drop_table("gsp_sales_returns")

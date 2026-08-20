"""controlled lot-level stocktaking and adjustment

Revision ID: 20260820_06
Revises: 20260820_05
Create Date: 2026-08-20
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260820_06"
down_revision: Union[str, None] = "20260820_05"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "gsp_stocktake_plans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("plan_no", sa.String(length=100), nullable=False),
        sa.Column("warehouse_id", sa.Integer(), nullable=False),
        sa.Column("scope_type", sa.String(length=30), nullable=False),
        sa.Column("scope_summary", sa.String(length=1000), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("submitted_by", sa.Integer(), nullable=True),
        sa.Column("submitted_at", sa.DateTime(), nullable=True),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("reviewed_by", sa.Integer(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("review_conclusion", sa.String(length=1000), nullable=True),
        sa.Column("completed_by", sa.Integer(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["completed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["submitted_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["warehouse_id"], ["warehouses.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_gsp_stocktake_plans_plan_no",
        "gsp_stocktake_plans",
        ["plan_no"],
        unique=True,
    )
    for column in ("status", "warehouse_id"):
        op.create_index(
            f"ix_gsp_stocktake_plans_{column}",
            "gsp_stocktake_plans",
            [column],
        )

    op.create_table(
        "gsp_stocktake_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("plan_id", sa.Integer(), nullable=False),
        sa.Column("line_no", sa.Integer(), nullable=False),
        sa.Column("stock_id", sa.Integer(), nullable=False),
        sa.Column("batch_id", sa.Integer(), nullable=False),
        sa.Column("location_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("book_quantity", sa.Numeric(precision=18, scale=3), nullable=True),
        sa.Column(
            "book_reserved_quantity",
            sa.Numeric(precision=18, scale=3),
            nullable=True,
        ),
        sa.Column("book_lock_version", sa.Integer(), nullable=True),
        sa.Column("counted_quantity", sa.Numeric(precision=18, scale=3), nullable=True),
        sa.Column("difference_quantity", sa.Numeric(precision=18, scale=3), nullable=True),
        sa.Column("discrepancy_reason", sa.String(length=1000), nullable=True),
        sa.Column("count_round", sa.Integer(), nullable=False),
        sa.Column("counted_by", sa.Integer(), nullable=True),
        sa.Column("counted_at", sa.DateTime(), nullable=True),
        sa.Column("adjusted_by", sa.Integer(), nullable=True),
        sa.Column("adjusted_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "book_quantity IS NULL OR book_quantity >= 0",
            name="ck_gsp_stocktake_book_quantity_nonnegative",
        ),
        sa.CheckConstraint(
            "book_reserved_quantity IS NULL OR book_reserved_quantity >= 0",
            name="ck_gsp_stocktake_book_reserved_nonnegative",
        ),
        sa.CheckConstraint(
            "counted_quantity IS NULL OR counted_quantity >= 0",
            name="ck_gsp_stocktake_counted_quantity_nonnegative",
        ),
        sa.CheckConstraint("count_round >= 0", name="ck_gsp_stocktake_round_nonnegative"),
        sa.ForeignKeyConstraint(["adjusted_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["batch_id"], ["gsp_drug_batches.id"]),
        sa.ForeignKeyConstraint(["counted_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["location_id"], ["locations.id"]),
        sa.ForeignKeyConstraint(["plan_id"], ["gsp_stocktake_plans.id"]),
        sa.ForeignKeyConstraint(["stock_id"], ["gsp_batch_stock.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("plan_id", "line_no", name="uq_gsp_stocktake_plan_line"),
        sa.UniqueConstraint("plan_id", "stock_id", name="uq_gsp_stocktake_plan_stock"),
    )
    for column in ("batch_id", "location_id", "plan_id", "status", "stock_id"):
        op.create_index(
            f"ix_gsp_stocktake_items_{column}",
            "gsp_stocktake_items",
            [column],
        )


def downgrade() -> None:
    for column in reversed(("batch_id", "location_id", "plan_id", "status", "stock_id")):
        op.drop_index(
            f"ix_gsp_stocktake_items_{column}",
            table_name="gsp_stocktake_items",
        )
    op.drop_table("gsp_stocktake_items")
    for column in reversed(("status", "warehouse_id")):
        op.drop_index(
            f"ix_gsp_stocktake_plans_{column}",
            table_name="gsp_stocktake_plans",
        )
    op.drop_index("ix_gsp_stocktake_plans_plan_no", table_name="gsp_stocktake_plans")
    op.drop_table("gsp_stocktake_plans")

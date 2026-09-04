"""P0 merge: cancellation and rejection audit columns.

Adds ``cancelled_by``/``cancelled_at``/``cancellation_reason`` to purchase
orders, purchase returns and sales returns, and
``rejected_by``/``rejected_at``/``rejection_reason`` to nonconforming
records so P0 flows can reconstruct who cancelled/rejected a regulated
document and why.

Revision ID: 20260902_26
Revises: 20260902_25
Create Date: 2026-09-02
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260902_26"
down_revision: Union[str, None] = "20260902_25"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # gsp_purchase_orders -- purchase order cancellation audit columns
    op.add_column(
        "gsp_purchase_orders",
        sa.Column("cancelled_by", sa.Integer(), nullable=True),
    )
    op.add_column(
        "gsp_purchase_orders",
        sa.Column("cancelled_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "gsp_purchase_orders",
        sa.Column("cancellation_reason", sa.String(length=500), nullable=True),
    )
    # gsp_purchase_returns -- purchase return cancellation audit columns
    op.add_column(
        "gsp_purchase_returns",
        sa.Column("cancelled_by", sa.Integer(), nullable=True),
    )
    op.add_column(
        "gsp_purchase_returns",
        sa.Column("cancelled_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "gsp_purchase_returns",
        sa.Column("cancellation_reason", sa.String(length=500), nullable=True),
    )
    # gsp_sales_returns -- sales return cancellation audit columns
    op.add_column(
        "gsp_sales_returns",
        sa.Column("cancelled_by", sa.Integer(), nullable=True),
    )
    op.add_column(
        "gsp_sales_returns",
        sa.Column("cancelled_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "gsp_sales_returns",
        sa.Column("cancellation_reason", sa.String(length=500), nullable=True),
    )
    # gsp_nonconforming_records -- nonconforming rejection audit columns
    op.add_column(
        "gsp_nonconforming_records",
        sa.Column("rejected_by", sa.Integer(), nullable=True),
    )
    op.add_column(
        "gsp_nonconforming_records",
        sa.Column("rejected_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "gsp_nonconforming_records",
        sa.Column("rejection_reason", sa.String(length=500), nullable=True),
    )
    for table_name, column_name, constraint_name in (
        (
            "gsp_purchase_orders",
            "cancelled_by",
            "fk_gsp_purchase_orders_cancelled_by_users",
        ),
        (
            "gsp_purchase_returns",
            "cancelled_by",
            "fk_gsp_purchase_returns_cancelled_by_users",
        ),
        (
            "gsp_sales_returns",
            "cancelled_by",
            "fk_gsp_sales_returns_cancelled_by_users",
        ),
        (
            "gsp_nonconforming_records",
            "rejected_by",
            "fk_gsp_nonconforming_records_rejected_by_users",
        ),
    ):
        op.create_foreign_key(
            constraint_name,
            table_name,
            "users",
            [column_name],
            ["id"],
        )

    for table_name, constraint_name in (
        ("gsp_signature_challenges", "ck_gsp_signature_challenge_meaning"),
        ("gsp_electronic_signatures", "ck_gsp_electronic_signature_meaning"),
    ):
        op.drop_constraint(constraint_name, table_name, type_="check")
        op.create_check_constraint(
            constraint_name,
            table_name,
            "meaning IN ('APPROVAL','REVIEW','RELEASE','CONFIRMATION','RESPONSIBILITY','REJECTION')",
        )

    # A cancelled return no longer occupies the nonconforming record, while its
    # controlled line history remains queryable. Application-level row locking
    # serializes creation for the same nonconforming record.
    op.drop_index(
        "ix_gsp_purchase_return_items_nonconforming_record_id",
        table_name="gsp_purchase_return_items",
    )
    op.create_index(
        "ix_gsp_purchase_return_items_nonconforming_record_id",
        "gsp_purchase_return_items",
        ["nonconforming_record_id"],
        unique=False,
    )


def downgrade() -> None:
    for table_name, constraint_name in (
        ("gsp_electronic_signatures", "ck_gsp_electronic_signature_meaning"),
        ("gsp_signature_challenges", "ck_gsp_signature_challenge_meaning"),
    ):
        op.drop_constraint(constraint_name, table_name, type_="check")
        op.create_check_constraint(
            constraint_name,
            table_name,
            "meaning IN ('APPROVAL','REVIEW','RELEASE','CONFIRMATION','RESPONSIBILITY')",
        )
    op.drop_index(
        "ix_gsp_purchase_return_items_nonconforming_record_id",
        table_name="gsp_purchase_return_items",
    )
    op.create_index(
        "ix_gsp_purchase_return_items_nonconforming_record_id",
        "gsp_purchase_return_items",
        ["nonconforming_record_id"],
        unique=True,
    )
    for table_name, constraint_name in (
        (
            "gsp_nonconforming_records",
            "fk_gsp_nonconforming_records_rejected_by_users",
        ),
        ("gsp_sales_returns", "fk_gsp_sales_returns_cancelled_by_users"),
        ("gsp_purchase_returns", "fk_gsp_purchase_returns_cancelled_by_users"),
        ("gsp_purchase_orders", "fk_gsp_purchase_orders_cancelled_by_users"),
    ):
        op.drop_constraint(constraint_name, table_name, type_="foreignkey")
    op.drop_column("gsp_nonconforming_records", "rejection_reason")
    op.drop_column("gsp_nonconforming_records", "rejected_at")
    op.drop_column("gsp_nonconforming_records", "rejected_by")
    op.drop_column("gsp_sales_returns", "cancellation_reason")
    op.drop_column("gsp_sales_returns", "cancelled_at")
    op.drop_column("gsp_sales_returns", "cancelled_by")
    op.drop_column("gsp_purchase_returns", "cancellation_reason")
    op.drop_column("gsp_purchase_returns", "cancelled_at")
    op.drop_column("gsp_purchase_returns", "cancelled_by")
    op.drop_column("gsp_purchase_orders", "cancellation_reason")
    op.drop_column("gsp_purchase_orders", "cancelled_at")
    op.drop_column("gsp_purchase_orders", "cancelled_by")

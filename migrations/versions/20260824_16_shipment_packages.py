"""controlled shipment packages

Revision ID: 20260824_16
Revises: 20260824_15
Create Date: 2026-08-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_16"
down_revision: Union[str, None] = "20260824_15"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "gsp_shipment_packages",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("shipment_id", sa.Integer(), nullable=False),
        sa.Column("package_no", sa.String(100), nullable=False),
        sa.Column("package_type", sa.String(50), nullable=False),
        sa.Column("seal_no", sa.String(100), nullable=False),
        sa.Column("packing_condition", sa.String(500), nullable=False),
        sa.Column("delivery_note_no", sa.String(100), nullable=False),
        sa.Column("packing_record_ref", sa.String(500), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["shipment_id"], ["gsp_shipments.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("shipment_id", "package_no", name="uq_gsp_shipment_package_no"),
    )
    op.create_index("ix_gsp_shipment_packages_shipment_id", "gsp_shipment_packages", ["shipment_id"])
    op.create_table(
        "gsp_shipment_package_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("package_id", sa.Integer(), nullable=False),
        sa.Column("allocation_id", sa.Integer(), nullable=False),
        sa.Column("quantity", sa.Numeric(18, 3), nullable=False),
        sa.Column("traceability_code", sa.String(200), nullable=True),
        sa.CheckConstraint("quantity > 0", name="ck_gsp_package_item_quantity_positive"),
        sa.ForeignKeyConstraint(["allocation_id"], ["gsp_stock_allocations.id"]),
        sa.ForeignKeyConstraint(["package_id"], ["gsp_shipment_packages.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("package_id", "allocation_id", name="uq_gsp_package_allocation"),
    )
    op.create_index(
        "ix_gsp_shipment_package_items_package_id", "gsp_shipment_package_items", ["package_id"]
    )
    op.create_index(
        "ix_gsp_shipment_package_items_allocation_id",
        "gsp_shipment_package_items",
        ["allocation_id"],
    )
    op.create_index(
        "ix_gsp_shipment_package_items_traceability_code",
        "gsp_shipment_package_items",
        ["traceability_code"],
    )


def downgrade() -> None:
    op.drop_table("gsp_shipment_package_items")
    op.drop_table("gsp_shipment_packages")

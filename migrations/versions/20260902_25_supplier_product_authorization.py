"""Supplier-to-product first-business authorization.

Revision ID: 20260902_25
Revises: 20260902_24
Create Date: 2026-09-02
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260902_25"
down_revision: Union[str, None] = "20260902_24"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "gsp_supplier_product_authorizations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("supplier_id", sa.Integer(), nullable=False),
        sa.Column("goods_id", sa.Integer(), nullable=False),
        sa.Column("authorization_ref", sa.String(length=500), nullable=False),
        sa.Column("authorization_sha256", sa.String(length=64), nullable=True),
        sa.Column("authorization_size_bytes", sa.Integer(), nullable=True),
        sa.Column("scope_description", sa.String(length=500), nullable=False),
        sa.Column("valid_from", sa.Date(), nullable=False),
        sa.Column("valid_to", sa.Date(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_by", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("suspended_by", sa.Integer(), nullable=True),
        sa.Column("suspended_at", sa.DateTime(), nullable=True),
        sa.Column("suspension_reason", sa.String(length=500), nullable=True),
        sa.CheckConstraint(
            "status IN ('PENDING','APPROVED','SUSPENDED')",
            name="ck_gsp_supplier_product_authorization_status",
        ),
        sa.CheckConstraint(
            "valid_to >= valid_from",
            name="ck_gsp_supplier_product_authorization_dates",
        ),
        sa.CheckConstraint(
            "authorization_size_bytes IS NULL OR authorization_size_bytes > 0",
            name="ck_gsp_supplier_product_authorization_size",
        ),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["goods_id"], ["goods.id"]),
        sa.ForeignKeyConstraint(["supplier_id"], ["gsp_business_partners.id"]),
        sa.ForeignKeyConstraint(["suspended_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["updated_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("supplier_id", "goods_id", name="uq_gsp_supplier_product_authorization"),
    )
    for column in ("supplier_id", "goods_id", "valid_from", "valid_to", "status"):
        op.create_index(
            op.f(f"ix_gsp_supplier_product_authorizations_{column}"),
            "gsp_supplier_product_authorizations",
            [column],
        )


def downgrade() -> None:
    for column in ("status", "valid_to", "valid_from", "goods_id", "supplier_id"):
        op.drop_index(
            op.f(f"ix_gsp_supplier_product_authorizations_{column}"),
            table_name="gsp_supplier_product_authorizations",
        )
    op.drop_table("gsp_supplier_product_authorizations")

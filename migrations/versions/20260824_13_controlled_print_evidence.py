"""Immutable evidence for controlled receipt copies.

Revision ID: 20260824_13
Revises: 20260821_12
Create Date: 2026-08-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_13"
down_revision: Union[str, None] = "20260821_12"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "gsp_controlled_print_records",
        sa.Column("status", sa.String(length=30), server_default="LEGACY", nullable=False),
    )
    op.add_column(
        "gsp_controlled_print_records",
        sa.Column("snapshot_data", sa.JSON(), nullable=True),
    )
    op.add_column(
        "gsp_controlled_print_records",
        sa.Column("content_hash", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_gsp_controlled_print_records_content_hash",
        "gsp_controlled_print_records",
        ["content_hash"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_gsp_controlled_print_records_content_hash",
        table_name="gsp_controlled_print_records",
    )
    op.drop_column("gsp_controlled_print_records", "content_hash")
    op.drop_column("gsp_controlled_print_records", "snapshot_data")
    op.drop_column("gsp_controlled_print_records", "status")

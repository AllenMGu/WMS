"""approved business calendar

Revision ID: 20260824_17
Revises: 20260824_16
Create Date: 2026-08-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_17"
down_revision: Union[str, None] = "20260824_16"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "gsp_business_calendar_days",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("calendar_date", sa.Date(), nullable=False),
        sa.Column("is_working_day", sa.Boolean(), nullable=False),
        sa.Column("approval_ref", sa.String(200), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("approved_by", sa.Integer(), nullable=False),
        sa.Column("approved_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_gsp_business_calendar_days_calendar_date",
        "gsp_business_calendar_days",
        ["calendar_date"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("gsp_business_calendar_days")

"""Expiry alert periodic review cycle.

Revision ID: 20260824_21
Revises: 20260824_20
Create Date: 2026-08-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_21"
down_revision: Union[str, None] = "20260824_20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("gsp_expiry_alerts", sa.Column("review_due_on", sa.Date(), nullable=True))
    op.create_index(
        "ix_gsp_expiry_alerts_review_due_on",
        "gsp_expiry_alerts",
        ["review_due_on"],
    )


def downgrade() -> None:
    op.drop_index("ix_gsp_expiry_alerts_review_due_on", table_name="gsp_expiry_alerts")
    op.drop_column("gsp_expiry_alerts", "review_due_on")

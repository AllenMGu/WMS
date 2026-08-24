"""outbox governance

Revision ID: 20260824_15
Revises: 20260824_14
Create Date: 2026-08-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_15"
down_revision: Union[str, None] = "20260824_14"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("gsp_integration_outbox", sa.Column("claimed_by", sa.String(100), nullable=True))
    op.add_column("gsp_integration_outbox", sa.Column("claimed_at", sa.DateTime(), nullable=True))
    op.add_column(
        "gsp_integration_outbox", sa.Column("dead_lettered_at", sa.DateTime(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("gsp_integration_outbox", "dead_lettered_at")
    op.drop_column("gsp_integration_outbox", "claimed_at")
    op.drop_column("gsp_integration_outbox", "claimed_by")

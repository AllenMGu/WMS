"""stocktake selection, freeze, CAPA, and controlled-copy controls

Revision ID: 20260824_20
Revises: 20260824_19
Create Date: 2026-08-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_20"
down_revision: Union[str, None] = "20260824_19"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "gsp_stocktake_plans",
        sa.Column("selection_rule", sa.String(50), nullable=False, server_default="MANUAL"),
    )
    op.add_column(
        "gsp_stocktake_plans",
        sa.Column("transactions_frozen", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("gsp_stocktake_plans", sa.Column("frozen_at", sa.DateTime()))
    op.add_column("gsp_stocktake_plans", sa.Column("capa_ref", sa.String(500)))


def downgrade() -> None:
    op.drop_column("gsp_stocktake_plans", "capa_ref")
    op.drop_column("gsp_stocktake_plans", "frozen_at")
    op.drop_column("gsp_stocktake_plans", "transactions_frozen")
    op.drop_column("gsp_stocktake_plans", "selection_rule")

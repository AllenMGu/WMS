"""enforce non-negative stock quantity check constraint

Concurrent barcode scans previously incremented/decremented ``stock.quantity``
without a row lock, so two overlapping outbound scans could drive quantity
negative.  The application now locks the row (``SELECT ... FOR UPDATE``) and
this migration adds a database-level ``CHECK (quantity >= 0)`` as the final
backstop.

The ``stock`` table is created by ``Base.metadata.create_all`` on fresh
installations (legacy path), so the constraint may already exist by the time
this migration runs; probe first to keep ``alembic upgrade head`` idempotent on
both fresh and existing PostgreSQL deployments.

Revision ID: 20260906_32
Revises: 20260905_31
Create Date: 2026-09-06
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260906_32"
down_revision: Union[str, None] = "20260905_31"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

CONSTRAINT_NAME = "ck_stock_quantity_non_negative"


def _has_check_constraint(bind, name: str) -> bool:
    inspector = sa.inspect(bind)
    try:
        constraints = inspector.get_check_constraints("stock")
    except sa.exc.NoSuchTableError:
        return False
    return any(c["name"] == name for c in constraints)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        # SQLite cannot add a CHECK to an existing table without a full rebuild.
        # Local/dev schema is created via Base.metadata.create_all which already
        # carries the constraint from the ORM model, so no-op here.
        return
    if not _has_check_constraint(bind, CONSTRAINT_NAME):
        op.create_check_constraint(
            CONSTRAINT_NAME,
            "stock",
            "quantity >= 0",
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return
    if _has_check_constraint(bind, CONSTRAINT_NAME):
        op.drop_constraint(CONSTRAINT_NAME, "stock", type_="check")

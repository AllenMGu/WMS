"""purchase return items: relax DB-unique NC linkage

A cancelled purchase return keeps its historical line items, and creating a
new return must be able to reference the same nonconforming record again.
Replace the unique index on nonconforming_record_id with a non-unique index;
the active-return invariant is enforced application-side while retaining the
index required by the SQLAlchemy model and lookup path.

Revision ID: 20260902_28
Revises: 20260902_27
Create Date: 2026-09-04
"""

from typing import Sequence, Union

from alembic import op

revision: str = "20260902_28"
down_revision: Union[str, None] = "20260902_27"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

INDEX_NAME = "ix_gsp_purchase_return_items_nonconforming_record_id"
TABLE_NAME = "gsp_purchase_return_items"


def upgrade() -> None:
    op.drop_index(INDEX_NAME, table_name=TABLE_NAME)
    op.create_index(
        INDEX_NAME,
        TABLE_NAME,
        ["nonconforming_record_id"],
        unique=False,
    )


def downgrade() -> None:
    # Recreating the legacy unique index intentionally fails if the database
    # already contains preserved cancelled-history rows for the same NC.
    # Never delete regulated history merely to make a downgrade succeed.
    op.drop_index(INDEX_NAME, table_name=TABLE_NAME)
    op.create_index(
        INDEX_NAME,
        TABLE_NAME,
        ["nonconforming_record_id"],
        unique=True,
    )

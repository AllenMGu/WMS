"""purchase return items: relax DB-unique NC linkage

A cancelled purchase return keeps its historical line items, and creating a
new return must be able to reference the same nonconforming record again.
The unique index on (nonconforming_record_id) blocks that reuse, so drop it;
uniqueness is enforced application-side (create_purchase_return excludes
returns with status=CANCELLED and locks the NC rows).

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


def upgrade() -> None:
    op.drop_index("ix_gsp_purchase_return_items_nonconforming_record_id",
                  table_name="gsp_purchase_return_items")


def downgrade() -> None:
    op.create_index(
        "ix_gsp_purchase_return_items_nonconforming_record_id",
        "gsp_purchase_return_items",
        ["nonconforming_record_id"],
        unique=True,
    )

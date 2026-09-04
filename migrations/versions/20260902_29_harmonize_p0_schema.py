"""harmonize P0 schema with ORM models

Two leftovers from the P0 merge keep ``alembic check`` noisy and the
purchase-return items index missing:
* models keep ``ix_gsp_purchase_return_items_nonconforming_record_id`` as a
  plain (non-unique) index; migration 20260902_28 removed the unique variant
  without recreating it.
* the cancellation/rejection audit columns added by 20260902_26 declare a
  ForeignKey to users.id in the models but the migration added plain columns.

This migration adds the missing index and foreign keys so the schema matches
the models exactly.

Revision ID: 20260902_29
Revises: 20260902_28
Create Date: 2026-09-04
"""

from typing import Sequence, Union

from alembic import op

revision: str = "20260902_29"
down_revision: Union[str, None] = "20260902_28"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_gsp_purchase_return_items_nonconforming_record_id "
        "ON gsp_purchase_return_items (nonconforming_record_id)"
    )
    op.execute(
        "ALTER TABLE gsp_purchase_orders ADD CONSTRAINT fk_gsp_purchase_orders_cancelled_by_users "
        "FOREIGN KEY (cancelled_by) REFERENCES users(id)"
    )
    op.execute(
        "ALTER TABLE gsp_purchase_returns ADD CONSTRAINT fk_gsp_purchase_returns_cancelled_by_users "
        "FOREIGN KEY (cancelled_by) REFERENCES users(id)"
    )
    op.execute(
        "ALTER TABLE gsp_sales_returns ADD CONSTRAINT fk_gsp_sales_returns_cancelled_by_users "
        "FOREIGN KEY (cancelled_by) REFERENCES users(id)"
    )
    op.execute(
        "ALTER TABLE gsp_nonconforming_records ADD CONSTRAINT fk_gsp_nonconforming_records_rejected_by_users "
        "FOREIGN KEY (rejected_by) REFERENCES users(id)"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE gsp_nonconforming_records DROP CONSTRAINT IF EXISTS fk_gsp_nonconforming_records_rejected_by_users"
    )
    op.execute(
        "ALTER TABLE gsp_sales_returns DROP CONSTRAINT IF EXISTS fk_gsp_sales_returns_cancelled_by_users"
    )
    op.execute(
        "ALTER TABLE gsp_purchase_returns DROP CONSTRAINT IF EXISTS fk_gsp_purchase_returns_cancelled_by_users"
    )
    op.execute(
        "ALTER TABLE gsp_purchase_orders DROP CONSTRAINT IF EXISTS fk_gsp_purchase_orders_cancelled_by_users"
    )
    op.execute(
        "DROP INDEX IF EXISTS ix_gsp_purchase_return_items_nonconforming_record_id"
    )

"""harmonize P0 foreign keys on previously upgraded databases

Some environments reached revision 20260902_26 before its four audit-user
foreign keys were present. Fresh installations already receive those foreign
keys from revision 20260902_26. This compatibility migration creates only
missing relationships, so both schema histories converge without duplicating
constraints.

The purchase-return item index is intentionally not touched here; revision
20260902_28 owns its unique-to-non-unique replacement.

Revision ID: 20260902_29
Revises: 20260902_28
Create Date: 2026-09-04
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260902_29"
down_revision: Union[str, None] = "20260902_28"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

FOREIGN_KEYS = (
    (
        "gsp_purchase_orders",
        "cancelled_by",
        "fk_gsp_purchase_orders_cancelled_by_users",
    ),
    (
        "gsp_purchase_returns",
        "cancelled_by",
        "fk_gsp_purchase_returns_cancelled_by_users",
    ),
    (
        "gsp_sales_returns",
        "cancelled_by",
        "fk_gsp_sales_returns_cancelled_by_users",
    ),
    (
        "gsp_nonconforming_records",
        "rejected_by",
        "fk_gsp_nonconforming_records_rejected_by_users",
    ),
)


def _has_users_foreign_key(
    inspector: sa.Inspector,
    *,
    table_name: str,
    column_name: str,
) -> bool:
    return any(
        foreign_key.get("constrained_columns") == [column_name]
        and foreign_key.get("referred_table") == "users"
        and foreign_key.get("referred_columns") == ["id"]
        for foreign_key in inspector.get_foreign_keys(table_name)
    )


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    for table_name, column_name, constraint_name in FOREIGN_KEYS:
        if not _has_users_foreign_key(
            inspector,
            table_name=table_name,
            column_name=column_name,
        ):
            op.create_foreign_key(
                constraint_name,
                table_name,
                "users",
                [column_name],
                ["id"],
            )


def downgrade() -> None:
    # Compatibility migration only: do not remove constraints that belong to
    # the canonical 20260902_26 schema, and never weaken audit-user integrity.
    pass

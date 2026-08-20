"""controlled GSP access governance

Revision ID: 20260820_07
Revises: 20260820_06
Create Date: 2026-08-20
"""

from datetime import timedelta
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from app.core.time import utc_now

revision: str = "20260820_07"
down_revision: Union[str, None] = "20260820_06"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("gsp_role_assignments") as batch_op:
        batch_op.add_column(sa.Column("approval_ref", sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column("review_due_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("expires_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("last_reviewed_by", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("last_reviewed_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("revoked_by", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("revoked_at", sa.DateTime(), nullable=True))
        batch_op.add_column(
            sa.Column("revocation_reason", sa.String(length=500), nullable=True)
        )

    roles = sa.table(
        "gsp_role_assignments",
        sa.column("approval_ref", sa.String(length=200)),
        sa.column("review_due_at", sa.DateTime()),
    )
    op.get_bind().execute(
        roles.update().values(
            approval_ref="MIGRATED-LEGACY-ASSIGNMENT",
            review_due_at=utc_now() + timedelta(days=90),
        )
    )
    with op.batch_alter_table("gsp_role_assignments") as batch_op:
        batch_op.alter_column("approval_ref", nullable=False)
        batch_op.alter_column("review_due_at", nullable=False)
        batch_op.create_foreign_key(
            "fk_gsp_role_assignments_last_reviewed_by_users",
            "users",
            ["last_reviewed_by"],
            ["id"],
        )
        batch_op.create_foreign_key(
            "fk_gsp_role_assignments_revoked_by_users",
            "users",
            ["revoked_by"],
            ["id"],
        )
    op.create_index(
        "ix_gsp_role_assignments_review_due_at",
        "gsp_role_assignments",
        ["review_due_at"],
    )
    op.create_index(
        "ix_gsp_role_assignments_expires_at",
        "gsp_role_assignments",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_gsp_role_assignments_expires_at", table_name="gsp_role_assignments")
    op.drop_index("ix_gsp_role_assignments_review_due_at", table_name="gsp_role_assignments")
    with op.batch_alter_table("gsp_role_assignments") as batch_op:
        batch_op.drop_constraint(
            "fk_gsp_role_assignments_revoked_by_users",
            type_="foreignkey",
        )
        batch_op.drop_constraint(
            "fk_gsp_role_assignments_last_reviewed_by_users",
            type_="foreignkey",
        )
        for column in (
            "revocation_reason",
            "revoked_at",
            "revoked_by",
            "last_reviewed_at",
            "last_reviewed_by",
            "expires_at",
            "review_due_at",
            "approval_ref",
        ):
            batch_op.drop_column(column)

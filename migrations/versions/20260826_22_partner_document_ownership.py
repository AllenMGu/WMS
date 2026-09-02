"""Partner document ownership and independent qualification review.

Revision ID: 20260826_22
Revises: 20260824_21
Create Date: 2026-08-26
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260826_22"
down_revision: Union[str, None] = "20260824_21"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "gsp_partner_documents",
        sa.Column("created_by", sa.Integer(), nullable=True),
    )
    op.execute(
        sa.text(
            "UPDATE gsp_partner_documents "
            "SET created_by = ("
            "SELECT created_by FROM gsp_business_partners "
            "WHERE gsp_business_partners.id = gsp_partner_documents.partner_id"
            ")"
        )
    )
    with op.batch_alter_table("gsp_partner_documents") as batch_op:
        batch_op.alter_column("created_by", existing_type=sa.Integer(), nullable=False)
        batch_op.create_foreign_key(
            "fk_gsp_partner_documents_created_by_users",
            "users",
            ["created_by"],
            ["id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("gsp_partner_documents") as batch_op:
        batch_op.drop_constraint(
            "fk_gsp_partner_documents_created_by_users",
            type_="foreignkey",
        )
        batch_op.drop_column("created_by")

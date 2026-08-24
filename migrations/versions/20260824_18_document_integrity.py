"""document integrity evidence

Revision ID: 20260824_18
Revises: 20260824_17
Create Date: 2026-08-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_18"
down_revision: Union[str, None] = "20260824_17"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "gsp_drug_profiles", sa.Column("registration_document_sha256", sa.String(64), nullable=True)
    )
    op.add_column(
        "gsp_drug_profiles", sa.Column("registration_document_size_bytes", sa.Integer(), nullable=True)
    )
    op.add_column("gsp_partner_documents", sa.Column("file_sha256", sa.String(64), nullable=True))
    op.add_column("gsp_partner_documents", sa.Column("file_size_bytes", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("gsp_partner_documents", "file_size_bytes")
    op.drop_column("gsp_partner_documents", "file_sha256")
    op.drop_column("gsp_drug_profiles", "registration_document_size_bytes")
    op.drop_column("gsp_drug_profiles", "registration_document_sha256")

"""controlled GSP file objects (server-side evidence attachments)

Closes the P0 gap described in the 2026-09-05 code review: qualification and
authorisation records previously stored only client-supplied file references
and hashes.  This revision adds the ``gsp_controlled_files`` table owned by
the new server-side immutable store (content-addressed, SHA-256 computed by
the backend, downloads permission-controlled and audit-trailed).

Revision ID: 20260905_30
Revises: 20260902_29
Create Date: 2026-09-05
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260905_30"
down_revision: Union[str, None] = "20260902_29"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "gsp_controlled_files",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("object_key", sa.String(length=32), nullable=False),
        sa.Column("file_name", sa.String(length=255), nullable=False),
        sa.Column("content_type", sa.String(length=120), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("purpose", sa.String(length=60), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("uploaded_by", sa.Integer(), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(), nullable=False),
        sa.Column("note", sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(["uploaded_by"], ["users.id"]),
        sa.CheckConstraint(
            "size_bytes > 0", name="ck_gsp_controlled_files_size_positive"
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'DISABLED')", name="ck_gsp_controlled_files_status"
        ),
        sa.CheckConstraint(
            "purpose IN ('PARTNER_DOCUMENT', 'SUPPLIER_PRODUCT_AUTHORIZATION', "
            "'DRUG_REGISTRATION', 'CARRIER_DOCUMENT', 'CSV_EVIDENCE', 'OTHER')",
            name="ck_gsp_controlled_files_purpose",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("object_key", name="uq_gsp_controlled_files_object_key"),
    )
    op.create_index(
        "ix_gsp_controlled_files_sha256", "gsp_controlled_files", ["sha256"]
    )
    op.create_index(
        "ix_gsp_controlled_files_purpose_status",
        "gsp_controlled_files",
        ["purpose", "status"],
    )


def downgrade() -> None:
    op.drop_index("ix_gsp_controlled_files_purpose_status", table_name="gsp_controlled_files")
    op.drop_index("ix_gsp_controlled_files_sha256", table_name="gsp_controlled_files")
    op.drop_table("gsp_controlled_files")

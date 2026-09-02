"""Controlled read-only archive for legacy GSP data.

Revision ID: 20260902_24
Revises: 20260826_23
Create Date: 2026-09-02
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260902_24"
down_revision: Union[str, None] = "20260826_23"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "gsp_legacy_import_batches",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("batch_no", sa.String(length=100), nullable=False),
        sa.Column("source_system", sa.String(length=100), nullable=False),
        sa.Column("source_instance", sa.String(length=200), nullable=False),
        sa.Column("manifest_version", sa.String(length=50), nullable=False),
        sa.Column("mapping_version", sa.String(length=50), nullable=False),
        sa.Column("package_sha256", sa.String(length=64), nullable=False),
        sa.Column("retention_until", sa.Date(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("expected_record_count", sa.Integer(), nullable=False),
        sa.Column("imported_record_count", sa.Integer(), nullable=False),
        sa.Column("duplicate_record_count", sa.Integer(), nullable=False),
        sa.Column("aggregate_sha256", sa.String(length=64), nullable=True),
        sa.Column("reconciliation_evidence_ref", sa.String(length=500), nullable=True),
        sa.Column("reconciliation_summary", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("validated_by", sa.Integer(), nullable=True),
        sa.Column("validated_at", sa.DateTime(), nullable=True),
        sa.Column("imported_by", sa.Integer(), nullable=True),
        sa.Column("imported_at", sa.DateTime(), nullable=True),
        sa.Column("reconciled_by", sa.Integer(), nullable=True),
        sa.Column("reconciled_at", sa.DateTime(), nullable=True),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.CheckConstraint(
            "status IN ('DRAFT','VALIDATED','IMPORTED','RECONCILED')",
            name="ck_gsp_legacy_batch_status",
        ),
        sa.CheckConstraint("expected_record_count > 0", name="ck_gsp_legacy_expected_count"),
        sa.CheckConstraint("imported_record_count >= 0", name="ck_gsp_legacy_imported_count"),
        sa.CheckConstraint("duplicate_record_count >= 0", name="ck_gsp_legacy_duplicate_count"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["validated_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["imported_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["reconciled_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("batch_no"),
    )
    for column in ("source_system", "retention_until", "status"):
        op.create_index(
            op.f(f"ix_gsp_legacy_import_batches_{column}"),
            "gsp_legacy_import_batches",
            [column],
        )

    op.create_table(
        "gsp_legacy_archive_records",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("import_batch_id", sa.Integer(), nullable=False),
        sa.Column("source_entity", sa.String(length=50), nullable=False),
        sa.Column("source_table", sa.String(length=100), nullable=False),
        sa.Column("source_key", sa.String(length=200), nullable=False),
        sa.Column("business_date", sa.Date(), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("search_text", sa.Text(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("attachment_manifest", sa.JSON(), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("record_hash", sa.String(length=64), nullable=False),
        sa.Column("imported_by", sa.Integer(), nullable=False),
        sa.Column("imported_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["import_batch_id"], ["gsp_legacy_import_batches.id"]),
        sa.ForeignKeyConstraint(["imported_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "import_batch_id", "source_table", "source_key", name="uq_gsp_legacy_batch_source_record"
        ),
        sa.UniqueConstraint("record_hash"),
    )
    for column in (
        "import_batch_id",
        "source_entity",
        "source_table",
        "source_key",
        "business_date",
    ):
        op.create_index(
            op.f(f"ix_gsp_legacy_archive_records_{column}"),
            "gsp_legacy_archive_records",
            [column],
        )

    op.create_table(
        "gsp_legacy_reconciliation_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("import_batch_id", sa.Integer(), nullable=False),
        sa.Column("source_entity", sa.String(length=50), nullable=False),
        sa.Column("expected_count", sa.Integer(), nullable=False),
        sa.Column("actual_count", sa.Integer(), nullable=False),
        sa.Column("matched", sa.Boolean(), nullable=False),
        sa.Column("checked_by", sa.Integer(), nullable=False),
        sa.Column("checked_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["checked_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["import_batch_id"], ["gsp_legacy_import_batches.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("import_batch_id", "source_entity", name="uq_gsp_legacy_reconcile_entity"),
    )
    op.create_index(
        op.f("ix_gsp_legacy_reconciliation_items_import_batch_id"),
        "gsp_legacy_reconciliation_items",
        ["import_batch_id"],
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_gsp_legacy_reconciliation_items_import_batch_id"),
        table_name="gsp_legacy_reconciliation_items",
    )
    op.drop_table("gsp_legacy_reconciliation_items")
    for column in (
        "business_date",
        "source_key",
        "source_table",
        "source_entity",
        "import_batch_id",
    ):
        op.drop_index(
            op.f(f"ix_gsp_legacy_archive_records_{column}"),
            table_name="gsp_legacy_archive_records",
        )
    op.drop_table("gsp_legacy_archive_records")
    for column in ("status", "retention_until", "source_system"):
        op.drop_index(
            op.f(f"ix_gsp_legacy_import_batches_{column}"),
            table_name="gsp_legacy_import_batches",
        )
    op.drop_table("gsp_legacy_import_batches")

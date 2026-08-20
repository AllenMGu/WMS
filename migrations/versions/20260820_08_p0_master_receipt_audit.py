"""P0 qualification, receipt evidence and audit verification

Revision ID: 20260820_08
Revises: 20260820_07
Create Date: 2026-08-20
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260820_08"
down_revision: Union[str, None] = "20260820_07"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("gsp_partner_documents") as batch_op:
        batch_op.add_column(sa.Column("person_name", sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column("person_role", sa.String(length=50), nullable=True))

    with op.batch_alter_table("gsp_drug_profiles") as batch_op:
        batch_op.add_column(
            sa.Column("registration_document_ref", sa.String(length=500), nullable=True)
        )
        batch_op.add_column(
            sa.Column("nmpa_verification_ref", sa.String(length=500), nullable=True)
        )
        batch_op.add_column(sa.Column("nmpa_verified_by", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("nmpa_verified_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("updated_by", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_gsp_drug_profiles_nmpa_verified_by_users",
            "users",
            ["nmpa_verified_by"],
            ["id"],
        )
        batch_op.create_foreign_key(
            "fk_gsp_drug_profiles_updated_by_users",
            "users",
            ["updated_by"],
            ["id"],
        )

    with op.batch_alter_table("gsp_receipt_items") as batch_op:
        batch_op.add_column(sa.Column("sampling_plan_ref", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("sampling_method", sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column("sample_quantity", sa.Numeric(18, 3), nullable=True))
        batch_op.add_column(sa.Column("sampling_record_no", sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column("sampled_by", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("sampled_at", sa.DateTime(), nullable=True))
        batch_op.create_check_constraint(
            "ck_gsp_receipt_sample_positive",
            "sample_quantity IS NULL OR sample_quantity > 0",
        )
        batch_op.create_foreign_key(
            "fk_gsp_receipt_items_sampled_by_users",
            "users",
            ["sampled_by"],
            ["id"],
        )
    op.create_index(
        "ix_gsp_receipt_items_sampling_record_no",
        "gsp_receipt_items",
        ["sampling_record_no"],
        unique=True,
    )

    op.create_table(
        "gsp_controlled_print_records",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("document_type", sa.String(length=50), nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.Column("template_version", sa.String(length=50), nullable=False),
        sa.Column("copy_no", sa.String(length=100), nullable=False),
        sa.Column("purpose", sa.String(length=500), nullable=False),
        sa.Column("printed_by", sa.Integer(), nullable=False),
        sa.Column("printed_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["printed_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("document_type", "entity_id"):
        op.create_index(
            f"ix_gsp_controlled_print_records_{column}",
            "gsp_controlled_print_records",
            [column],
        )
    op.create_index(
        "ix_gsp_controlled_print_records_copy_no",
        "gsp_controlled_print_records",
        ["copy_no"],
        unique=True,
    )

    op.create_table(
        "gsp_audit_verifications",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("requested_by", sa.Integer(), nullable=False),
        sa.Column("trigger_source", sa.String(length=50), nullable=False),
        sa.Column("evidence_ref", sa.String(length=500), nullable=False),
        sa.Column("checked_event_count", sa.Integer(), nullable=False),
        sa.Column("valid", sa.Boolean(), nullable=False),
        sa.Column("broken_event_id", sa.Integer(), nullable=True),
        sa.Column("verified_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["broken_event_id"], ["gsp_audit_events.id"]),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("requested_by", "valid", "verified_at"):
        op.create_index(
            f"ix_gsp_audit_verifications_{column}",
            "gsp_audit_verifications",
            [column],
        )

    # Existing approvals did not contain the new controlled evidence.  Force a
    # deliberate re-qualification instead of silently grandfathering them.
    op.execute(
        "UPDATE gsp_business_partners SET status = 'PENDING', approved_by = NULL, "
        "approved_at = NULL WHERE status = 'APPROVED'"
    )
    op.execute(
        "UPDATE gsp_drug_profiles SET status = 'PENDING', approved_by = NULL, "
        "approved_at = NULL WHERE status = 'APPROVED'"
    )


def downgrade() -> None:
    for column in reversed(("requested_by", "valid", "verified_at")):
        op.drop_index(
            f"ix_gsp_audit_verifications_{column}",
            table_name="gsp_audit_verifications",
        )
    op.drop_table("gsp_audit_verifications")

    op.drop_index(
        "ix_gsp_controlled_print_records_copy_no",
        table_name="gsp_controlled_print_records",
    )
    for column in reversed(("document_type", "entity_id")):
        op.drop_index(
            f"ix_gsp_controlled_print_records_{column}",
            table_name="gsp_controlled_print_records",
        )
    op.drop_table("gsp_controlled_print_records")

    op.drop_index(
        "ix_gsp_receipt_items_sampling_record_no",
        table_name="gsp_receipt_items",
    )
    with op.batch_alter_table("gsp_receipt_items") as batch_op:
        batch_op.drop_constraint(
            "fk_gsp_receipt_items_sampled_by_users",
            type_="foreignkey",
        )
        batch_op.drop_constraint("ck_gsp_receipt_sample_positive", type_="check")
        for column in (
            "sampled_at",
            "sampled_by",
            "sampling_record_no",
            "sample_quantity",
            "sampling_method",
            "sampling_plan_ref",
        ):
            batch_op.drop_column(column)

    with op.batch_alter_table("gsp_drug_profiles") as batch_op:
        batch_op.drop_constraint(
            "fk_gsp_drug_profiles_updated_by_users",
            type_="foreignkey",
        )
        batch_op.drop_constraint(
            "fk_gsp_drug_profiles_nmpa_verified_by_users",
            type_="foreignkey",
        )
        for column in (
            "updated_by",
            "nmpa_verified_at",
            "nmpa_verified_by",
            "nmpa_verification_ref",
            "registration_document_ref",
        ):
            batch_op.drop_column(column)

    with op.batch_alter_table("gsp_partner_documents") as batch_op:
        batch_op.drop_column("person_role")
        batch_op.drop_column("person_name")

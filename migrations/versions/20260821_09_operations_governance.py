"""Controlled secret rotation, backup evidence and recovery drills

Revision ID: 20260821_09
Revises: 20260820_08
Create Date: 2026-08-21
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260821_09"
down_revision: Union[str, None] = "20260820_08"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "gsp_secret_rotations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("secret_name", sa.String(length=100), nullable=False),
        sa.Column("provider", sa.String(length=100), nullable=False),
        sa.Column("change_ref", sa.String(length=200), nullable=False),
        sa.Column("current_version_ref", sa.String(length=500), nullable=True),
        sa.Column("proposed_version_ref", sa.String(length=500), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("requested_by", sa.Integer(), nullable=False),
        sa.Column("requested_at", sa.DateTime(), nullable=False),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("approval_evidence_ref", sa.String(length=500), nullable=True),
        sa.Column("implemented_by", sa.Integer(), nullable=True),
        sa.Column("implemented_at", sa.DateTime(), nullable=True),
        sa.Column("implementation_evidence_ref", sa.String(length=500), nullable=True),
        sa.Column("verified_by", sa.Integer(), nullable=True),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.Column("verification_evidence_ref", sa.String(length=500), nullable=True),
        sa.Column("next_rotation_due_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "status IN ('SUBMITTED','APPROVED','REJECTED','PENDING_VERIFICATION','VERIFIED','FAILED')",
            name="ck_gsp_secret_rotation_status",
        ),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["implemented_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["verified_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "secret_name", "proposed_version_ref", name="uq_gsp_secret_rotation_version"
        ),
    )
    for column in ("secret_name", "status", "requested_by", "next_rotation_due_at"):
        op.create_index(f"ix_gsp_secret_rotations_{column}", "gsp_secret_rotations", [column])

    op.create_table(
        "gsp_backup_evidence",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("backup_id", sa.String(length=100), nullable=False),
        sa.Column("backup_type", sa.String(length=30), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("scheduled_for", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=False),
        sa.Column("checksum_sha256", sa.String(length=64), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("primary_storage_ref", sa.String(length=500), nullable=True),
        sa.Column("offsite_storage_ref", sa.String(length=500), nullable=True),
        sa.Column("offline_storage_ref", sa.String(length=500), nullable=True),
        sa.Column("retention_until", sa.DateTime(), nullable=True),
        sa.Column("evidence_ref", sa.String(length=500), nullable=False),
        sa.Column("alert_evidence_ref", sa.String(length=500), nullable=True),
        sa.Column("recorded_by", sa.Integer(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(), nullable=False),
        sa.Column("reviewed_by", sa.Integer(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("review_result", sa.String(length=20), nullable=True),
        sa.Column("review_evidence_ref", sa.String(length=500), nullable=True),
        sa.CheckConstraint("backup_type IN ('FULL','INCREMENTAL')", name="ck_gsp_backup_type"),
        sa.CheckConstraint("status IN ('SUCCESS','FAILED')", name="ck_gsp_backup_status"),
        sa.CheckConstraint(
            "review_result IS NULL OR review_result IN ('ACCEPTED','REJECTED')",
            name="ck_gsp_backup_review_result",
        ),
        sa.CheckConstraint("size_bytes IS NULL OR size_bytes > 0", name="ck_gsp_backup_size"),
        sa.ForeignKeyConstraint(["recorded_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("backup_id", "status", "scheduled_for", "recorded_by"):
        op.create_index(
            f"ix_gsp_backup_evidence_{column}",
            "gsp_backup_evidence",
            [column],
            unique=column == "backup_id",
        )

    op.create_table(
        "gsp_recovery_drills",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("backup_evidence_id", sa.Integer(), nullable=False),
        sa.Column("change_ref", sa.String(length=200), nullable=False),
        sa.Column("plan_ref", sa.String(length=500), nullable=False),
        sa.Column("scheduled_for", sa.DateTime(), nullable=False),
        sa.Column("target_rto_minutes", sa.Integer(), nullable=False),
        sa.Column("target_rpo_minutes", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("requested_by", sa.Integer(), nullable=False),
        sa.Column("requested_at", sa.DateTime(), nullable=False),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("approval_evidence_ref", sa.String(length=500), nullable=True),
        sa.Column("executed_by", sa.Integer(), nullable=True),
        sa.Column("executed_at", sa.DateTime(), nullable=True),
        sa.Column("restore_target_ref", sa.String(length=500), nullable=True),
        sa.Column("execution_evidence_ref", sa.String(length=500), nullable=True),
        sa.Column("actual_rto_minutes", sa.Integer(), nullable=True),
        sa.Column("actual_rpo_minutes", sa.Integer(), nullable=True),
        sa.Column("result", sa.String(length=20), nullable=True),
        sa.Column("verified_by", sa.Integer(), nullable=True),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.Column("verification_evidence_ref", sa.String(length=500), nullable=True),
        sa.CheckConstraint(
            "status IN ('SUBMITTED','APPROVED','REJECTED','EXECUTED','VERIFIED')",
            name="ck_gsp_recovery_drill_status",
        ),
        sa.CheckConstraint("result IS NULL OR result IN ('PASS','FAIL')", name="ck_gsp_recovery_result"),
        sa.CheckConstraint("target_rto_minutes > 0", name="ck_gsp_recovery_target_rto"),
        sa.CheckConstraint("target_rpo_minutes >= 0", name="ck_gsp_recovery_target_rpo"),
        sa.CheckConstraint(
            "actual_rto_minutes IS NULL OR actual_rto_minutes >= 0",
            name="ck_gsp_recovery_actual_rto",
        ),
        sa.CheckConstraint(
            "actual_rpo_minutes IS NULL OR actual_rpo_minutes >= 0",
            name="ck_gsp_recovery_actual_rpo",
        ),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["backup_evidence_id"], ["gsp_backup_evidence.id"]),
        sa.ForeignKeyConstraint(["executed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["verified_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("backup_evidence_id", "scheduled_for", "status"):
        op.create_index(f"ix_gsp_recovery_drills_{column}", "gsp_recovery_drills", [column])


def downgrade() -> None:
    for column in reversed(("backup_evidence_id", "scheduled_for", "status")):
        op.drop_index(f"ix_gsp_recovery_drills_{column}", table_name="gsp_recovery_drills")
    op.drop_table("gsp_recovery_drills")

    for column in reversed(("backup_id", "status", "scheduled_for", "recorded_by")):
        op.drop_index(f"ix_gsp_backup_evidence_{column}", table_name="gsp_backup_evidence")
    op.drop_table("gsp_backup_evidence")

    for column in reversed(("secret_name", "status", "requested_by", "next_rotation_due_at")):
        op.drop_index(f"ix_gsp_secret_rotations_{column}", table_name="gsp_secret_rotations")
    op.drop_table("gsp_secret_rotations")


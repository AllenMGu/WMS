"""approved expiry thresholds and automated control evidence

Revision ID: 20260824_19
Revises: 20260824_18
Create Date: 2026-08-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_19"
down_revision: Union[str, None] = "20260824_18"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "gsp_compliance_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String(100), nullable=False),
        sa.Column("integer_value", sa.Integer(), nullable=False),
        sa.Column("approval_ref", sa.String(200), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("approved_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("approved_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_gsp_compliance_settings_key",
        "gsp_compliance_settings",
        ["key"],
        unique=True,
    )
    op.create_table(
        "gsp_expiry_alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("batch_id", sa.Integer(), sa.ForeignKey("gsp_drug_batches.id"), nullable=False),
        sa.Column("alert_type", sa.String(30), nullable=False),
        sa.Column("threshold_days", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("quality_hold_id", sa.Integer(), sa.ForeignKey("gsp_quality_holds.id")),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_evaluated_at", sa.DateTime(), nullable=False),
        sa.Column("resolved_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("resolved_at", sa.DateTime()),
        sa.Column("resolution", sa.String(500)),
        sa.Column("evidence_ref", sa.String(500)),
        sa.UniqueConstraint("batch_id", "alert_type", name="uq_gsp_expiry_batch_alert"),
    )
    op.create_index("ix_gsp_expiry_alerts_batch_id", "gsp_expiry_alerts", ["batch_id"])
    op.create_index("ix_gsp_expiry_alerts_alert_type", "gsp_expiry_alerts", ["alert_type"])
    op.create_index("ix_gsp_expiry_alerts_status", "gsp_expiry_alerts", ["status"])


def downgrade() -> None:
    op.drop_index("ix_gsp_expiry_alerts_status", table_name="gsp_expiry_alerts")
    op.drop_index("ix_gsp_expiry_alerts_alert_type", table_name="gsp_expiry_alerts")
    op.drop_index("ix_gsp_expiry_alerts_batch_id", table_name="gsp_expiry_alerts")
    op.drop_table("gsp_expiry_alerts")
    op.drop_index("ix_gsp_compliance_settings_key", table_name="gsp_compliance_settings")
    op.drop_table("gsp_compliance_settings")

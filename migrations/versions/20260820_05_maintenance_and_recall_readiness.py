"""controlled maintenance and recall readiness

Revision ID: 20260820_05
Revises: 20260820_04
Create Date: 2026-08-20
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260820_05"
down_revision: Union[str, None] = "20260820_04"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "gsp_recalls",
        sa.Column("completion_report_due_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_gsp_recalls_completion_report_due_at",
        "gsp_recalls",
        ["completion_report_due_at"],
    )

    op.create_table(
        "gsp_recall_completion_reports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("recall_id", sa.Integer(), nullable=False),
        sa.Column("report_ref", sa.String(length=200), nullable=False),
        sa.Column("treatment_summary", sa.String(length=2000), nullable=False),
        sa.Column("effectiveness_evaluation", sa.String(length=1000), nullable=False),
        sa.Column("regulatory_submission_ref", sa.String(length=500), nullable=False),
        sa.Column("reported_by", sa.Integer(), nullable=False),
        sa.Column("reported_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["recall_id"], ["gsp_recalls.id"]),
        sa.ForeignKeyConstraint(["reported_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_gsp_recall_completion_reports_recall_id",
        "gsp_recall_completion_reports",
        ["recall_id"],
        unique=True,
    )
    op.create_index(
        "ix_gsp_recall_completion_reports_report_ref",
        "gsp_recall_completion_reports",
        ["report_ref"],
        unique=True,
    )
    op.create_index(
        "ix_gsp_recall_completion_reports_reported_at",
        "gsp_recall_completion_reports",
        ["reported_at"],
    )

    op.create_table(
        "gsp_recall_drills",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("drill_no", sa.String(length=100), nullable=False),
        sa.Column("recall_level", sa.String(length=10), nullable=False),
        sa.Column("scenario", sa.String(length=1000), nullable=False),
        sa.Column("objective", sa.String(length=1000), nullable=False),
        sa.Column("max_allowed_minutes", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("activated_by", sa.Integer(), nullable=True),
        sa.Column("activated_at", sa.DateTime(), nullable=True),
        sa.Column("completed_by", sa.Integer(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("result", sa.String(length=30), nullable=True),
        sa.Column("completion_summary", sa.String(length=2000), nullable=True),
        sa.Column("deviation_notes", sa.String(length=1000), nullable=True),
        sa.Column("capa_ref", sa.String(length=500), nullable=True),
        sa.CheckConstraint(
            "max_allowed_minutes > 0",
            name="ck_gsp_recall_drill_max_minutes_positive",
        ),
        sa.ForeignKeyConstraint(["activated_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["completed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_gsp_recall_drills_drill_no",
        "gsp_recall_drills",
        ["drill_no"],
        unique=True,
    )
    op.create_index("ix_gsp_recall_drills_result", "gsp_recall_drills", ["result"])
    op.create_index("ix_gsp_recall_drills_status", "gsp_recall_drills", ["status"])

    op.create_table(
        "gsp_recall_drill_batches",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("drill_id", sa.Integer(), nullable=False),
        sa.Column("batch_id", sa.Integer(), nullable=False),
        sa.Column(
            "target_shipped_quantity",
            sa.Numeric(precision=18, scale=3),
            nullable=False,
        ),
        sa.CheckConstraint(
            "target_shipped_quantity >= 0",
            name="ck_gsp_recall_drill_batch_target_nonnegative",
        ),
        sa.ForeignKeyConstraint(["batch_id"], ["gsp_drug_batches.id"]),
        sa.ForeignKeyConstraint(["drill_id"], ["gsp_recall_drills.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("drill_id", "batch_id", name="uq_gsp_recall_drill_batch"),
    )
    op.create_index(
        "ix_gsp_recall_drill_batches_batch_id",
        "gsp_recall_drill_batches",
        ["batch_id"],
    )
    op.create_index(
        "ix_gsp_recall_drill_batches_drill_id",
        "gsp_recall_drill_batches",
        ["drill_id"],
    )

    op.create_table(
        "gsp_recall_drill_targets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("drill_id", sa.Integer(), nullable=False),
        sa.Column("drill_batch_id", sa.Integer(), nullable=False),
        sa.Column("shipment_id", sa.Integer(), nullable=False),
        sa.Column("customer_id", sa.Integer(), nullable=False),
        sa.Column("stock_allocation_id", sa.Integer(), nullable=False),
        sa.Column("batch_id", sa.Integer(), nullable=False),
        sa.Column("shipped_quantity", sa.Numeric(precision=18, scale=3), nullable=False),
        sa.Column("verification_status", sa.String(length=30), nullable=False),
        sa.Column("verified_by", sa.Integer(), nullable=True),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.Column("verification_notes", sa.String(length=500), nullable=True),
        sa.CheckConstraint(
            "shipped_quantity > 0",
            name="ck_gsp_recall_drill_target_shipped_positive",
        ),
        sa.ForeignKeyConstraint(["batch_id"], ["gsp_drug_batches.id"]),
        sa.ForeignKeyConstraint(["customer_id"], ["gsp_business_partners.id"]),
        sa.ForeignKeyConstraint(["drill_batch_id"], ["gsp_recall_drill_batches.id"]),
        sa.ForeignKeyConstraint(["drill_id"], ["gsp_recall_drills.id"]),
        sa.ForeignKeyConstraint(["shipment_id"], ["gsp_shipments.id"]),
        sa.ForeignKeyConstraint(
            ["stock_allocation_id"],
            ["gsp_stock_allocations.id"],
        ),
        sa.ForeignKeyConstraint(["verified_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "drill_id",
            "stock_allocation_id",
            name="uq_gsp_recall_drill_allocation",
        ),
    )
    for column in (
        "batch_id",
        "customer_id",
        "drill_batch_id",
        "drill_id",
        "shipment_id",
        "stock_allocation_id",
        "verification_status",
    ):
        op.create_index(
            f"ix_gsp_recall_drill_targets_{column}",
            "gsp_recall_drill_targets",
            [column],
        )

    op.create_table(
        "gsp_maintenance_plans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("plan_no", sa.String(length=100), nullable=False),
        sa.Column("warehouse_id", sa.Integer(), nullable=False),
        sa.Column("plan_type", sa.String(length=30), nullable=False),
        sa.Column("scheduled_from", sa.Date(), nullable=False),
        sa.Column("scheduled_to", sa.Date(), nullable=False),
        sa.Column("scope_summary", sa.String(length=1000), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("submitted_by", sa.Integer(), nullable=True),
        sa.Column("submitted_at", sa.DateTime(), nullable=True),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("completed_by", sa.Integer(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("completion_conclusion", sa.String(length=1000), nullable=True),
        sa.CheckConstraint(
            "scheduled_to >= scheduled_from",
            name="ck_gsp_maintenance_plan_date_range",
        ),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["completed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["submitted_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["warehouse_id"], ["warehouses.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_gsp_maintenance_plans_plan_no",
        "gsp_maintenance_plans",
        ["plan_no"],
        unique=True,
    )
    for column in ("scheduled_from", "scheduled_to", "status", "warehouse_id"):
        op.create_index(
            f"ix_gsp_maintenance_plans_{column}",
            "gsp_maintenance_plans",
            [column],
        )

    op.create_table(
        "gsp_maintenance_plan_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("plan_id", sa.Integer(), nullable=False),
        sa.Column("line_no", sa.Integer(), nullable=False),
        sa.Column("stock_id", sa.Integer(), nullable=False),
        sa.Column("batch_id", sa.Integer(), nullable=False),
        sa.Column("planned_quantity", sa.Numeric(precision=18, scale=3), nullable=False),
        sa.Column("priority_reason", sa.String(length=500), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("appearance_ok", sa.Boolean(), nullable=True),
        sa.Column("package_ok", sa.Boolean(), nullable=True),
        sa.Column("storage_condition_ok", sa.Boolean(), nullable=True),
        sa.Column("temperature_humidity_ok", sa.Boolean(), nullable=True),
        sa.Column("finding", sa.String(length=1000), nullable=True),
        sa.Column("next_due_on", sa.Date(), nullable=True),
        sa.Column("quality_hold_id", sa.Integer(), nullable=True),
        sa.Column("checked_by", sa.Integer(), nullable=True),
        sa.Column("checked_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "planned_quantity > 0",
            name="ck_gsp_maintenance_planned_quantity_positive",
        ),
        sa.ForeignKeyConstraint(["batch_id"], ["gsp_drug_batches.id"]),
        sa.ForeignKeyConstraint(["checked_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["plan_id"], ["gsp_maintenance_plans.id"]),
        sa.ForeignKeyConstraint(["quality_hold_id"], ["gsp_quality_holds.id"]),
        sa.ForeignKeyConstraint(["stock_id"], ["gsp_batch_stock.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("plan_id", "line_no", name="uq_gsp_maintenance_plan_line"),
        sa.UniqueConstraint("plan_id", "stock_id", name="uq_gsp_maintenance_plan_stock"),
    )
    for column in (
        "batch_id",
        "next_due_on",
        "plan_id",
        "quality_hold_id",
        "status",
        "stock_id",
    ):
        op.create_index(
            f"ix_gsp_maintenance_plan_items_{column}",
            "gsp_maintenance_plan_items",
            [column],
        )


def downgrade() -> None:
    for column in reversed(
        ("batch_id", "next_due_on", "plan_id", "quality_hold_id", "status", "stock_id")
    ):
        op.drop_index(
            f"ix_gsp_maintenance_plan_items_{column}",
            table_name="gsp_maintenance_plan_items",
        )
    op.drop_table("gsp_maintenance_plan_items")

    for column in reversed(("scheduled_from", "scheduled_to", "status", "warehouse_id")):
        op.drop_index(
            f"ix_gsp_maintenance_plans_{column}",
            table_name="gsp_maintenance_plans",
        )
    op.drop_index("ix_gsp_maintenance_plans_plan_no", table_name="gsp_maintenance_plans")
    op.drop_table("gsp_maintenance_plans")

    for column in reversed(
        (
            "batch_id",
            "customer_id",
            "drill_batch_id",
            "drill_id",
            "shipment_id",
            "stock_allocation_id",
            "verification_status",
        )
    ):
        op.drop_index(
            f"ix_gsp_recall_drill_targets_{column}",
            table_name="gsp_recall_drill_targets",
        )
    op.drop_table("gsp_recall_drill_targets")

    op.drop_index(
        "ix_gsp_recall_drill_batches_drill_id",
        table_name="gsp_recall_drill_batches",
    )
    op.drop_index(
        "ix_gsp_recall_drill_batches_batch_id",
        table_name="gsp_recall_drill_batches",
    )
    op.drop_table("gsp_recall_drill_batches")

    op.drop_index("ix_gsp_recall_drills_status", table_name="gsp_recall_drills")
    op.drop_index("ix_gsp_recall_drills_result", table_name="gsp_recall_drills")
    op.drop_index("ix_gsp_recall_drills_drill_no", table_name="gsp_recall_drills")
    op.drop_table("gsp_recall_drills")

    op.drop_index(
        "ix_gsp_recall_completion_reports_reported_at",
        table_name="gsp_recall_completion_reports",
    )
    op.drop_index(
        "ix_gsp_recall_completion_reports_report_ref",
        table_name="gsp_recall_completion_reports",
    )
    op.drop_index(
        "ix_gsp_recall_completion_reports_recall_id",
        table_name="gsp_recall_completion_reports",
    )
    op.drop_table("gsp_recall_completion_reports")

    op.drop_index("ix_gsp_recalls_completion_report_due_at", table_name="gsp_recalls")
    op.drop_column("gsp_recalls", "completion_report_due_at")

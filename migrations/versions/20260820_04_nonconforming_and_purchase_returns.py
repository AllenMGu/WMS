"""controlled nonconforming disposition and purchase returns

Revision ID: 20260820_04
Revises: 20260820_03
Create Date: 2026-08-20
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260820_04"
down_revision: Union[str, None] = "20260820_03"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("gsp_recalls", sa.Column("notification_due_at", sa.DateTime(), nullable=True))
    op.add_column(
        "gsp_recalls",
        sa.Column("next_progress_report_due_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "gsp_recalls",
        sa.Column("last_progress_reported_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_gsp_recalls_notification_due_at",
        "gsp_recalls",
        ["notification_due_at"],
    )
    op.create_index(
        "ix_gsp_recalls_next_progress_report_due_at",
        "gsp_recalls",
        ["next_progress_report_due_at"],
    )

    op.create_table(
        "gsp_recall_progress_reports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("recall_id", sa.Integer(), nullable=False),
        sa.Column("report_ref", sa.String(length=200), nullable=False),
        sa.Column("summary", sa.String(length=1000), nullable=False),
        sa.Column("reported_by", sa.Integer(), nullable=False),
        sa.Column("reported_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["recall_id"], ["gsp_recalls.id"]),
        sa.ForeignKeyConstraint(["reported_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "recall_id",
            "report_ref",
            name="uq_gsp_recall_progress_ref",
        ),
    )
    op.create_index(
        "ix_gsp_recall_progress_reports_recall_id",
        "gsp_recall_progress_reports",
        ["recall_id"],
    )
    op.create_index(
        "ix_gsp_recall_progress_reports_reported_at",
        "gsp_recall_progress_reports",
        ["reported_at"],
    )

    op.create_table(
        "gsp_nonconforming_records",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("record_no", sa.String(length=100), nullable=False),
        sa.Column("source_type", sa.String(length=50), nullable=False),
        sa.Column("source_entity_type", sa.String(length=100), nullable=False),
        sa.Column("source_entity_id", sa.Integer(), nullable=False),
        sa.Column("stock_id", sa.Integer(), nullable=True),
        sa.Column("quality_hold_id", sa.Integer(), nullable=True),
        sa.Column("batch_id", sa.Integer(), nullable=False),
        sa.Column("warehouse_id", sa.Integer(), nullable=False),
        sa.Column("location_id", sa.Integer(), nullable=True),
        sa.Column("quantity", sa.Numeric(precision=18, scale=3), nullable=False),
        sa.Column("reason_code", sa.String(length=50), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=False),
        sa.Column("proposed_disposition", sa.String(length=50), nullable=True),
        sa.Column("approved_disposition", sa.String(length=50), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("registered_by", sa.Integer(), nullable=False),
        sa.Column("registered_at", sa.DateTime(), nullable=False),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("approval_reason", sa.String(length=500), nullable=True),
        sa.Column("executed_by", sa.Integer(), nullable=True),
        sa.Column("executed_at", sa.DateTime(), nullable=True),
        sa.Column("witnessed_by", sa.Integer(), nullable=True),
        sa.Column("supervision_organization", sa.String(length=200), nullable=True),
        sa.Column("execution_document_ref", sa.String(length=500), nullable=True),
        sa.CheckConstraint(
            "quantity > 0",
            name="ck_gsp_nonconforming_quantity_positive",
        ),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["batch_id"], ["gsp_drug_batches.id"]),
        sa.ForeignKeyConstraint(["executed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["location_id"], ["locations.id"]),
        sa.ForeignKeyConstraint(["quality_hold_id"], ["gsp_quality_holds.id"]),
        sa.ForeignKeyConstraint(["registered_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["stock_id"], ["gsp_batch_stock.id"]),
        sa.ForeignKeyConstraint(["warehouse_id"], ["warehouses.id"]),
        sa.ForeignKeyConstraint(["witnessed_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "approved_disposition",
        "batch_id",
        "location_id",
        "quality_hold_id",
        "source_entity_id",
        "source_type",
        "status",
        "stock_id",
        "warehouse_id",
    ):
        op.create_index(
            f"ix_gsp_nonconforming_records_{column}",
            "gsp_nonconforming_records",
            [column],
        )
    op.create_index(
        "ix_gsp_nonconforming_records_record_no",
        "gsp_nonconforming_records",
        ["record_no"],
        unique=True,
    )

    op.create_table(
        "gsp_purchase_returns",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("return_no", sa.String(length=100), nullable=False),
        sa.Column("supplier_id", sa.Integer(), nullable=False),
        sa.Column("warehouse_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("submitted_by", sa.Integer(), nullable=True),
        sa.Column("submitted_at", sa.DateTime(), nullable=True),
        sa.Column("quality_approved_by", sa.Integer(), nullable=True),
        sa.Column("quality_approved_at", sa.DateTime(), nullable=True),
        sa.Column("dispatched_by", sa.Integer(), nullable=True),
        sa.Column("dispatched_at", sa.DateTime(), nullable=True),
        sa.Column("outbound_document_no", sa.String(length=100), nullable=True),
        sa.Column("carrier_name", sa.String(length=200), nullable=True),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["dispatched_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["quality_approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["submitted_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["supplier_id"], ["gsp_business_partners.id"]),
        sa.ForeignKeyConstraint(["warehouse_id"], ["warehouses.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("outbound_document_no", "status", "supplier_id", "warehouse_id"):
        op.create_index(
            f"ix_gsp_purchase_returns_{column}",
            "gsp_purchase_returns",
            [column],
        )
    op.create_index(
        "ix_gsp_purchase_returns_return_no",
        "gsp_purchase_returns",
        ["return_no"],
        unique=True,
    )

    op.create_table(
        "gsp_purchase_return_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("purchase_return_id", sa.Integer(), nullable=False),
        sa.Column("line_no", sa.Integer(), nullable=False),
        sa.Column("nonconforming_record_id", sa.Integer(), nullable=False),
        sa.Column("batch_id", sa.Integer(), nullable=False),
        sa.Column("quantity", sa.Numeric(precision=18, scale=3), nullable=False),
        sa.CheckConstraint(
            "quantity > 0",
            name="ck_gsp_purchase_return_quantity_positive",
        ),
        sa.ForeignKeyConstraint(["batch_id"], ["gsp_drug_batches.id"]),
        sa.ForeignKeyConstraint(
            ["nonconforming_record_id"],
            ["gsp_nonconforming_records.id"],
        ),
        sa.ForeignKeyConstraint(["purchase_return_id"], ["gsp_purchase_returns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "purchase_return_id",
            "line_no",
            name="uq_gsp_purchase_return_line",
        ),
    )
    op.create_index(
        "ix_gsp_purchase_return_items_batch_id",
        "gsp_purchase_return_items",
        ["batch_id"],
    )
    op.create_index(
        "ix_gsp_purchase_return_items_nonconforming_record_id",
        "gsp_purchase_return_items",
        ["nonconforming_record_id"],
        unique=True,
    )
    op.create_index(
        "ix_gsp_purchase_return_items_purchase_return_id",
        "gsp_purchase_return_items",
        ["purchase_return_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_gsp_purchase_return_items_purchase_return_id",
        table_name="gsp_purchase_return_items",
    )
    op.drop_index(
        "ix_gsp_purchase_return_items_nonconforming_record_id",
        table_name="gsp_purchase_return_items",
    )
    op.drop_index(
        "ix_gsp_purchase_return_items_batch_id",
        table_name="gsp_purchase_return_items",
    )
    op.drop_table("gsp_purchase_return_items")

    op.drop_index("ix_gsp_purchase_returns_return_no", table_name="gsp_purchase_returns")
    for column in reversed(("outbound_document_no", "status", "supplier_id", "warehouse_id")):
        op.drop_index(f"ix_gsp_purchase_returns_{column}", table_name="gsp_purchase_returns")
    op.drop_table("gsp_purchase_returns")

    op.drop_index(
        "ix_gsp_nonconforming_records_record_no",
        table_name="gsp_nonconforming_records",
    )
    for column in reversed(
        (
            "approved_disposition",
            "batch_id",
            "location_id",
            "quality_hold_id",
            "source_entity_id",
            "source_type",
            "status",
            "stock_id",
            "warehouse_id",
        )
    ):
        op.drop_index(
            f"ix_gsp_nonconforming_records_{column}",
            table_name="gsp_nonconforming_records",
        )
    op.drop_table("gsp_nonconforming_records")

    op.drop_index(
        "ix_gsp_recall_progress_reports_reported_at",
        table_name="gsp_recall_progress_reports",
    )
    op.drop_index(
        "ix_gsp_recall_progress_reports_recall_id",
        table_name="gsp_recall_progress_reports",
    )
    op.drop_table("gsp_recall_progress_reports")

    op.drop_index("ix_gsp_recalls_next_progress_report_due_at", table_name="gsp_recalls")
    op.drop_index("ix_gsp_recalls_notification_due_at", table_name="gsp_recalls")
    op.drop_column("gsp_recalls", "last_progress_reported_at")
    op.drop_column("gsp_recalls", "next_progress_report_due_at")
    op.drop_column("gsp_recalls", "notification_due_at")

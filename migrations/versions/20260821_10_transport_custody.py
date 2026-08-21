"""Controlled carrier qualification, transport custody and delivery proof.

Revision ID: 20260821_10
Revises: 20260821_09
Create Date: 2026-08-21
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260821_10"
down_revision: Union[str, None] = "20260821_09"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _index(table: str, *columns: str, unique: bool = False) -> None:
    for column in columns:
        op.create_index(f"ix_{table}_{column}", table, [column], unique=unique)


def upgrade() -> None:
    op.create_table(
        "gsp_carriers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(length=50), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("unified_social_credit_code", sa.String(length=50), nullable=False),
        sa.Column("license_no", sa.String(length=100), nullable=False),
        sa.Column("license_valid_to", sa.Date(), nullable=False),
        sa.Column("service_modes", sa.JSON(), nullable=False),
        sa.Column("quality_agreement_valid_to", sa.Date(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("suspension_reason", sa.String(length=500), nullable=True),
        sa.CheckConstraint(
            "status IN ('PENDING','APPROVED','SUSPENDED')",
            name="ck_gsp_carrier_status",
        ),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    _index(
        "gsp_carriers",
        "name",
        "license_valid_to",
        "quality_agreement_valid_to",
        "status",
    )
    _index("gsp_carriers", "code", "unified_social_credit_code", unique=True)

    op.create_table(
        "gsp_carrier_documents",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("carrier_id", sa.Integer(), nullable=False),
        sa.Column("document_type", sa.String(length=50), nullable=False),
        sa.Column("document_no", sa.String(length=100), nullable=False),
        sa.Column("valid_to", sa.Date(), nullable=False),
        sa.Column("file_ref", sa.String(length=500), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("verified_by", sa.Integer(), nullable=True),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "status IN ('PENDING','VERIFIED','REJECTED')",
            name="ck_gsp_carrier_document_status",
        ),
        sa.ForeignKeyConstraint(["carrier_id"], ["gsp_carriers.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["verified_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "carrier_id", "document_type", "document_no", name="uq_gsp_carrier_document"
        ),
    )
    _index("gsp_carrier_documents", "carrier_id", "valid_to", "status")

    op.create_table(
        "gsp_carrier_vehicles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("carrier_id", sa.Integer(), nullable=False),
        sa.Column("vehicle_no", sa.String(length=100), nullable=False),
        sa.Column("vehicle_type", sa.String(length=30), nullable=False),
        sa.Column("qualification_ref", sa.String(length=500), nullable=False),
        sa.Column("qualification_valid_to", sa.Date(), nullable=False),
        sa.Column("calibration_ref", sa.String(length=500), nullable=True),
        sa.Column("calibration_valid_to", sa.Date(), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "vehicle_type IN ('NORMAL','REFRIGERATED','FROZEN')",
            name="ck_gsp_carrier_vehicle_type",
        ),
        sa.CheckConstraint(
            "status IN ('PENDING','APPROVED','SUSPENDED')",
            name="ck_gsp_carrier_vehicle_status",
        ),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["carrier_id"], ["gsp_carriers.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    _index(
        "gsp_carrier_vehicles",
        "carrier_id",
        "qualification_valid_to",
        "calibration_valid_to",
        "status",
    )
    _index("gsp_carrier_vehicles", "vehicle_no", unique=True)

    op.create_table(
        "gsp_carrier_drivers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("carrier_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("personnel_code", sa.String(length=100), nullable=False),
        sa.Column("qualification_ref", sa.String(length=500), nullable=False),
        sa.Column("authorization_valid_to", sa.Date(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "status IN ('PENDING','APPROVED','SUSPENDED')",
            name="ck_gsp_carrier_driver_status",
        ),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["carrier_id"], ["gsp_carriers.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    _index(
        "gsp_carrier_drivers",
        "carrier_id",
        "authorization_valid_to",
        "status",
    )
    _index("gsp_carrier_drivers", "personnel_code", unique=True)

    with op.batch_alter_table("gsp_shipments") as batch_op:
        batch_op.add_column(sa.Column("carrier_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("vehicle_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("driver_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_gsp_shipments_carrier_id_gsp_carriers", "gsp_carriers", ["carrier_id"], ["id"]
        )
        batch_op.create_foreign_key(
            "fk_gsp_shipments_vehicle_id_gsp_carrier_vehicles",
            "gsp_carrier_vehicles",
            ["vehicle_id"],
            ["id"],
        )
        batch_op.create_foreign_key(
            "fk_gsp_shipments_driver_id_gsp_carrier_drivers",
            "gsp_carrier_drivers",
            ["driver_id"],
            ["id"],
        )
        batch_op.create_index("ix_gsp_shipments_carrier_id", ["carrier_id"])
        batch_op.create_index("ix_gsp_shipments_vehicle_id", ["vehicle_id"])
        batch_op.create_index("ix_gsp_shipments_driver_id", ["driver_id"])

    op.create_table(
        "gsp_transport_tasks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_no", sa.String(length=120), nullable=False),
        sa.Column("shipment_id", sa.Integer(), nullable=False),
        sa.Column("carrier_id", sa.Integer(), nullable=False),
        sa.Column("vehicle_id", sa.Integer(), nullable=False),
        sa.Column("driver_id", sa.Integer(), nullable=False),
        sa.Column("transport_mode", sa.String(length=30), nullable=False),
        sa.Column("route_plan_ref", sa.String(length=500), nullable=False),
        sa.Column("handover_document_no", sa.String(length=100), nullable=False),
        sa.Column("expected_arrival_at", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("actual_departure_at", sa.DateTime(), nullable=True),
        sa.Column("delivery_recorded_by", sa.Integer(), nullable=True),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
        sa.Column("delivery_location", sa.String(length=500), nullable=True),
        sa.Column("recipient_name", sa.String(length=200), nullable=True),
        sa.Column("recipient_organization", sa.String(length=200), nullable=True),
        sa.Column("delivery_proof_ref", sa.String(length=500), nullable=True),
        sa.Column("package_condition", sa.String(length=30), nullable=True),
        sa.Column("quantity_conclusion", sa.String(length=30), nullable=True),
        sa.Column("closed_by", sa.Integer(), nullable=True),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        sa.Column("close_evidence_ref", sa.String(length=500), nullable=True),
        sa.CheckConstraint(
            "transport_mode IN ('NORMAL','COLD','FROZEN')",
            name="ck_gsp_transport_task_mode",
        ),
        sa.CheckConstraint(
            "status IN ('PREPARED','IN_TRANSIT','EXCEPTION','RETURN_REQUIRED','REJECTED_DELIVERY','DELIVERED','CLOSED','CANCELLED')",
            name="ck_gsp_transport_task_status",
        ),
        sa.CheckConstraint(
            "package_condition IS NULL OR package_condition IN ('INTACT','DAMAGED')",
            name="ck_gsp_transport_package_condition",
        ),
        sa.CheckConstraint(
            "quantity_conclusion IS NULL OR quantity_conclusion IN ('MATCHED','SHORT','OVER')",
            name="ck_gsp_transport_quantity_conclusion",
        ),
        sa.ForeignKeyConstraint(["carrier_id"], ["gsp_carriers.id"]),
        sa.ForeignKeyConstraint(["closed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["delivery_recorded_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["driver_id"], ["gsp_carrier_drivers.id"]),
        sa.ForeignKeyConstraint(["shipment_id"], ["gsp_shipments.id"]),
        sa.ForeignKeyConstraint(["vehicle_id"], ["gsp_carrier_vehicles.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    _index(
        "gsp_transport_tasks",
        "carrier_id",
        "expected_arrival_at",
        "status",
    )
    _index(
        "gsp_transport_tasks",
        "task_no",
        "shipment_id",
        "handover_document_no",
        unique=True,
    )

    op.create_table(
        "gsp_transport_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=50), nullable=False),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("location", sa.String(length=500), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("evidence_ref", sa.String(length=500), nullable=True),
        sa.Column("reported_by", sa.Integer(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["reported_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["task_id"], ["gsp_transport_tasks.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    _index("gsp_transport_events", "task_id", "event_type", "occurred_at")

    op.create_table(
        "gsp_transport_exceptions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=False),
        sa.Column("category", sa.String(length=50), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("quality_impact", sa.Boolean(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("reported_by", sa.Integer(), nullable=False),
        sa.Column("reported_at", sa.DateTime(), nullable=False),
        sa.Column("decision", sa.String(length=30), nullable=True),
        sa.Column("deviation_ref", sa.String(length=500), nullable=True),
        sa.Column("capa_ref", sa.String(length=500), nullable=True),
        sa.Column("decided_by", sa.Integer(), nullable=True),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "severity IN ('LOW','MEDIUM','HIGH','CRITICAL')",
            name="ck_gsp_transport_exception_severity",
        ),
        sa.CheckConstraint(
            "status IN ('PENDING_QUALITY','RESOLVED','RETURN_REQUIRED','REJECTED_DELIVERY')",
            name="ck_gsp_transport_exception_status",
        ),
        sa.CheckConstraint(
            "decision IS NULL OR decision IN ('CONTINUE','RETURN','REJECT_DELIVERY')",
            name="ck_gsp_transport_exception_decision",
        ),
        sa.ForeignKeyConstraint(["decided_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["event_id"], ["gsp_transport_events.id"]),
        sa.ForeignKeyConstraint(["reported_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["task_id"], ["gsp_transport_tasks.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id"),
    )
    _index(
        "gsp_transport_exceptions", "task_id", "category", "severity", "status"
    )


def downgrade() -> None:
    for table in ("gsp_transport_exceptions", "gsp_transport_events", "gsp_transport_tasks"):
        op.drop_table(table)
    with op.batch_alter_table("gsp_shipments") as batch_op:
        for column in ("driver_id", "vehicle_id", "carrier_id"):
            batch_op.drop_index(f"ix_gsp_shipments_{column}")
            batch_op.drop_column(column)
    for table in (
        "gsp_carrier_drivers",
        "gsp_carrier_vehicles",
        "gsp_carrier_documents",
        "gsp_carriers",
    ):
        op.drop_table(table)

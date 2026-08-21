"""Calibrated temperature/humidity monitoring and excursion alarms.

Revision ID: 20260821_11
Revises: 20260821_10
Create Date: 2026-08-21
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260821_11"
down_revision: Union[str, None] = "20260821_10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _indexes(table: str, *columns: str, unique: bool = False) -> None:
    for column in columns:
        op.create_index(f"ix_{table}_{column}", table, [column], unique=unique)


def upgrade() -> None:
    op.create_table(
        "gsp_environment_devices",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_code", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("manufacturer", sa.String(length=200), nullable=False),
        sa.Column("model_no", sa.String(length=100), nullable=False),
        sa.Column("serial_no", sa.String(length=100), nullable=False),
        sa.Column("measurement_scope", sa.String(length=30), nullable=False),
        sa.Column("calibration_ref", sa.String(length=500), nullable=False),
        sa.Column("calibration_valid_to", sa.Date(), nullable=False),
        sa.Column("temperature_accuracy", sa.Numeric(8, 3), nullable=False),
        sa.Column("humidity_accuracy", sa.Numeric(8, 3), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("suspension_reason", sa.String(length=500), nullable=True),
        sa.CheckConstraint(
            "measurement_scope IN ('TEMPERATURE','TEMPERATURE_HUMIDITY')",
            name="ck_gsp_environment_device_scope",
        ),
        sa.CheckConstraint(
            "status IN ('PENDING','APPROVED','SUSPENDED')",
            name="ck_gsp_environment_device_status",
        ),
        sa.CheckConstraint(
            "temperature_accuracy > 0",
            name="ck_gsp_environment_temperature_accuracy",
        ),
        sa.CheckConstraint(
            "humidity_accuracy IS NULL OR humidity_accuracy > 0",
            name="ck_gsp_environment_humidity_accuracy",
        ),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes("gsp_environment_devices", "calibration_valid_to", "status")
    _indexes("gsp_environment_devices", "device_code", "serial_no", unique=True)

    op.create_table(
        "gsp_environment_assignments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("assignment_no", sa.String(length=120), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("context_type", sa.String(length=30), nullable=False),
        sa.Column("warehouse_id", sa.Integer(), nullable=True),
        sa.Column("location_id", sa.Integer(), nullable=True),
        sa.Column("transport_task_id", sa.Integer(), nullable=True),
        sa.Column("temperature_min", sa.Numeric(8, 3), nullable=False),
        sa.Column("temperature_max", sa.Numeric(8, 3), nullable=False),
        sa.Column("critical_temperature_min", sa.Numeric(8, 3), nullable=False),
        sa.Column("critical_temperature_max", sa.Numeric(8, 3), nullable=False),
        sa.Column("humidity_min", sa.Numeric(8, 3), nullable=True),
        sa.Column("humidity_max", sa.Numeric(8, 3), nullable=True),
        sa.Column("critical_humidity_min", sa.Numeric(8, 3), nullable=True),
        sa.Column("critical_humidity_max", sa.Numeric(8, 3), nullable=True),
        sa.Column("sampling_interval_seconds", sa.Integer(), nullable=False),
        sa.Column("offline_after_seconds", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("last_reading_at", sa.DateTime(), nullable=True),
        sa.Column("closed_by", sa.Integer(), nullable=True),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        sa.Column("close_reason", sa.String(length=500), nullable=True),
        sa.CheckConstraint(
            "context_type IN ('WAREHOUSE','TRANSPORT')",
            name="ck_gsp_environment_assignment_context",
        ),
        sa.CheckConstraint(
            "status IN ('PENDING','ACTIVE','CLOSED','SUSPENDED')",
            name="ck_gsp_environment_assignment_status",
        ),
        sa.CheckConstraint(
            "temperature_min < temperature_max",
            name="ck_gsp_environment_temperature_range",
        ),
        sa.CheckConstraint(
            "critical_temperature_min <= temperature_min AND critical_temperature_max >= temperature_max",
            name="ck_gsp_environment_critical_temperature_range",
        ),
        sa.CheckConstraint(
            "humidity_min IS NULL OR (humidity_max IS NOT NULL AND humidity_min < humidity_max)",
            name="ck_gsp_environment_humidity_range",
        ),
        sa.CheckConstraint(
            "critical_humidity_min IS NULL OR (humidity_min IS NOT NULL AND critical_humidity_max IS NOT NULL AND critical_humidity_min <= humidity_min AND critical_humidity_max >= humidity_max)",
            name="ck_gsp_environment_critical_humidity_range",
        ),
        sa.CheckConstraint(
            "(context_type = 'WAREHOUSE' AND warehouse_id IS NOT NULL AND location_id IS NOT NULL AND transport_task_id IS NULL) OR (context_type = 'TRANSPORT' AND warehouse_id IS NULL AND location_id IS NULL AND transport_task_id IS NOT NULL)",
            name="ck_gsp_environment_assignment_target",
        ),
        sa.CheckConstraint(
            "sampling_interval_seconds > 0 AND offline_after_seconds >= sampling_interval_seconds",
            name="ck_gsp_environment_assignment_intervals",
        ),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["closed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["device_id"], ["gsp_environment_devices.id"]),
        sa.ForeignKeyConstraint(["location_id"], ["locations.id"]),
        sa.ForeignKeyConstraint(["transport_task_id"], ["gsp_transport_tasks.id"]),
        sa.ForeignKeyConstraint(["warehouse_id"], ["warehouses.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    _indexes(
        "gsp_environment_assignments",
        "device_id",
        "context_type",
        "warehouse_id",
        "location_id",
        "transport_task_id",
        "status",
        "last_reading_at",
    )
    _indexes("gsp_environment_assignments", "assignment_no", unique=True)

    op.create_table(
        "gsp_environment_readings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("assignment_id", sa.Integer(), nullable=False),
        sa.Column("external_reading_id", sa.String(length=150), nullable=False),
        sa.Column("observed_at", sa.DateTime(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("temperature", sa.Numeric(8, 3), nullable=False),
        sa.Column("humidity", sa.Numeric(8, 3), nullable=True),
        sa.Column("battery_percent", sa.Numeric(6, 2), nullable=True),
        sa.Column("signal_strength", sa.Integer(), nullable=True),
        sa.Column("source_payload", sa.JSON(), nullable=False),
        sa.Column("source_payload_hash", sa.String(length=64), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("record_hash", sa.String(length=64), nullable=False),
        sa.Column("evaluation", sa.String(length=30), nullable=False),
        sa.Column("reported_by", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "evaluation IN ('NORMAL','WARNING','CRITICAL')",
            name="ck_gsp_environment_reading_evaluation",
        ),
        sa.CheckConstraint(
            "humidity IS NULL OR (humidity >= 0 AND humidity <= 100)",
            name="ck_gsp_environment_reading_humidity",
        ),
        sa.CheckConstraint(
            "battery_percent IS NULL OR (battery_percent >= 0 AND battery_percent <= 100)",
            name="ck_gsp_environment_reading_battery",
        ),
        sa.ForeignKeyConstraint(["assignment_id"], ["gsp_environment_assignments.id"]),
        sa.ForeignKeyConstraint(["reported_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "assignment_id",
            "external_reading_id",
            name="uq_gsp_environment_external_reading",
        ),
    )
    _indexes(
        "gsp_environment_readings",
        "assignment_id",
        "observed_at",
        "received_at",
        "evaluation",
    )
    _indexes("gsp_environment_readings", "record_hash", unique=True)

    op.create_table(
        "gsp_environment_alarms",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("alarm_no", sa.String(length=150), nullable=False),
        sa.Column("assignment_id", sa.Integer(), nullable=False),
        sa.Column("reading_id", sa.Integer(), nullable=True),
        sa.Column("alarm_type", sa.String(length=50), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("observed_value", sa.Numeric(12, 3), nullable=False),
        sa.Column("threshold_value", sa.Numeric(12, 3), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("opened_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("acknowledged_by", sa.Integer(), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("acknowledgment_note", sa.String(length=500), nullable=True),
        sa.Column("decision", sa.String(length=30), nullable=True),
        sa.Column("deviation_ref", sa.String(length=500), nullable=True),
        sa.Column("capa_ref", sa.String(length=500), nullable=True),
        sa.Column("resolution_evidence_ref", sa.String(length=500), nullable=True),
        sa.Column("decided_by", sa.Integer(), nullable=True),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "alarm_type IN ('TEMPERATURE_LOW','TEMPERATURE_HIGH','HUMIDITY_LOW','HUMIDITY_HIGH','DEVICE_OFFLINE')",
            name="ck_gsp_environment_alarm_type",
        ),
        sa.CheckConstraint(
            "severity IN ('WARNING','CRITICAL')",
            name="ck_gsp_environment_alarm_severity",
        ),
        sa.CheckConstraint(
            "status IN ('OPEN','ACKNOWLEDGED','RESOLVED')",
            name="ck_gsp_environment_alarm_status",
        ),
        sa.CheckConstraint(
            "decision IS NULL OR decision IN ('CONTINUE','HOLD','RETURN','REJECT')",
            name="ck_gsp_environment_alarm_decision",
        ),
        sa.ForeignKeyConstraint(["acknowledged_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["assignment_id"], ["gsp_environment_assignments.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["decided_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["reading_id"], ["gsp_environment_readings.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("reading_id", "alarm_type", name="uq_gsp_environment_reading_alarm"),
    )
    _indexes(
        "gsp_environment_alarms",
        "assignment_id",
        "reading_id",
        "alarm_type",
        "severity",
        "status",
    )
    _indexes("gsp_environment_alarms", "alarm_no", unique=True)


def downgrade() -> None:
    op.drop_table("gsp_environment_alarms")
    op.drop_table("gsp_environment_readings")
    op.drop_table("gsp_environment_assignments")
    op.drop_table("gsp_environment_devices")

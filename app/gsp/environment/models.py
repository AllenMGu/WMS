"""Persistence models for calibrated devices and immutable environment readings."""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    event,
)

from app.core.database import Base
from app.core.time import utc_now


class GspEnvironmentDevice(Base):
    __tablename__ = "gsp_environment_devices"

    id = Column(Integer, primary_key=True)
    device_code = Column(String(100), nullable=False, unique=True, index=True)
    name = Column(String(200), nullable=False)
    manufacturer = Column(String(200), nullable=False)
    model_no = Column(String(100), nullable=False)
    serial_no = Column(String(100), nullable=False, unique=True, index=True)
    measurement_scope = Column(String(30), nullable=False)
    calibration_ref = Column(String(500), nullable=False)
    calibration_valid_to = Column(Date, nullable=False, index=True)
    temperature_accuracy = Column(Numeric(8, 3), nullable=False)
    humidity_accuracy = Column(Numeric(8, 3), nullable=True)
    status = Column(String(30), nullable=False, default="PENDING", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    suspension_reason = Column(String(500), nullable=True)
    __table_args__ = (
        CheckConstraint(
            "measurement_scope IN ('TEMPERATURE','TEMPERATURE_HUMIDITY')",
            name="ck_gsp_environment_device_scope",
        ),
        CheckConstraint(
            "status IN ('PENDING','APPROVED','SUSPENDED')",
            name="ck_gsp_environment_device_status",
        ),
        CheckConstraint(
            "temperature_accuracy > 0",
            name="ck_gsp_environment_temperature_accuracy",
        ),
        CheckConstraint(
            "humidity_accuracy IS NULL OR humidity_accuracy > 0",
            name="ck_gsp_environment_humidity_accuracy",
        ),
    )


class GspEnvironmentAssignment(Base):
    __tablename__ = "gsp_environment_assignments"

    id = Column(Integer, primary_key=True)
    assignment_no = Column(String(120), nullable=False, unique=True, index=True)
    device_id = Column(
        Integer,
        ForeignKey("gsp_environment_devices.id"),
        nullable=False,
        index=True,
    )
    context_type = Column(String(30), nullable=False, index=True)
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), nullable=True, index=True)
    location_id = Column(Integer, ForeignKey("locations.id"), nullable=True, index=True)
    transport_task_id = Column(
        Integer,
        ForeignKey("gsp_transport_tasks.id"),
        nullable=True,
        index=True,
    )
    temperature_min = Column(Numeric(8, 3), nullable=False)
    temperature_max = Column(Numeric(8, 3), nullable=False)
    critical_temperature_min = Column(Numeric(8, 3), nullable=False)
    critical_temperature_max = Column(Numeric(8, 3), nullable=False)
    humidity_min = Column(Numeric(8, 3), nullable=True)
    humidity_max = Column(Numeric(8, 3), nullable=True)
    critical_humidity_min = Column(Numeric(8, 3), nullable=True)
    critical_humidity_max = Column(Numeric(8, 3), nullable=True)
    sampling_interval_seconds = Column(Integer, nullable=False)
    offline_after_seconds = Column(Integer, nullable=False)
    status = Column(String(30), nullable=False, default="PENDING", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    last_reading_at = Column(DateTime, nullable=True, index=True)
    closed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    closed_at = Column(DateTime, nullable=True)
    close_reason = Column(String(500), nullable=True)
    __table_args__ = (
        CheckConstraint(
            "context_type IN ('WAREHOUSE','TRANSPORT')",
            name="ck_gsp_environment_assignment_context",
        ),
        CheckConstraint(
            "status IN ('PENDING','ACTIVE','CLOSED','SUSPENDED')",
            name="ck_gsp_environment_assignment_status",
        ),
        CheckConstraint(
            "temperature_min < temperature_max",
            name="ck_gsp_environment_temperature_range",
        ),
        CheckConstraint(
            "critical_temperature_min <= temperature_min AND critical_temperature_max >= temperature_max",
            name="ck_gsp_environment_critical_temperature_range",
        ),
        CheckConstraint(
            "humidity_min IS NULL OR (humidity_max IS NOT NULL AND humidity_min < humidity_max)",
            name="ck_gsp_environment_humidity_range",
        ),
        CheckConstraint(
            "critical_humidity_min IS NULL OR (humidity_min IS NOT NULL AND critical_humidity_max IS NOT NULL AND critical_humidity_min <= humidity_min AND critical_humidity_max >= humidity_max)",
            name="ck_gsp_environment_critical_humidity_range",
        ),
        CheckConstraint(
            "(context_type = 'WAREHOUSE' AND warehouse_id IS NOT NULL AND location_id IS NOT NULL AND transport_task_id IS NULL) OR (context_type = 'TRANSPORT' AND warehouse_id IS NULL AND location_id IS NULL AND transport_task_id IS NOT NULL)",
            name="ck_gsp_environment_assignment_target",
        ),
        CheckConstraint(
            "sampling_interval_seconds > 0 AND offline_after_seconds >= sampling_interval_seconds",
            name="ck_gsp_environment_assignment_intervals",
        ),
    )


class GspEnvironmentReading(Base):
    __tablename__ = "gsp_environment_readings"

    id = Column(Integer, primary_key=True)
    assignment_id = Column(
        Integer,
        ForeignKey("gsp_environment_assignments.id"),
        nullable=False,
        index=True,
    )
    external_reading_id = Column(String(150), nullable=False)
    observed_at = Column(DateTime, nullable=False, index=True)
    received_at = Column(DateTime, nullable=False, default=utc_now, index=True)
    temperature = Column(Numeric(8, 3), nullable=False)
    humidity = Column(Numeric(8, 3), nullable=True)
    battery_percent = Column(Numeric(6, 2), nullable=True)
    signal_strength = Column(Integer, nullable=True)
    source_payload = Column(JSON, nullable=False)
    source_payload_hash = Column(String(64), nullable=False)
    previous_hash = Column(String(64), nullable=True)
    record_hash = Column(String(64), nullable=False, unique=True, index=True)
    evaluation = Column(String(30), nullable=False, index=True)
    reported_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    __table_args__ = (
        UniqueConstraint(
            "assignment_id",
            "external_reading_id",
            name="uq_gsp_environment_external_reading",
        ),
        CheckConstraint(
            "evaluation IN ('NORMAL','WARNING','CRITICAL')",
            name="ck_gsp_environment_reading_evaluation",
        ),
        CheckConstraint(
            "humidity IS NULL OR (humidity >= 0 AND humidity <= 100)",
            name="ck_gsp_environment_reading_humidity",
        ),
        CheckConstraint(
            "battery_percent IS NULL OR (battery_percent >= 0 AND battery_percent <= 100)",
            name="ck_gsp_environment_reading_battery",
        ),
    )


class GspEnvironmentAlarm(Base):
    __tablename__ = "gsp_environment_alarms"

    id = Column(Integer, primary_key=True)
    alarm_no = Column(String(150), nullable=False, unique=True, index=True)
    assignment_id = Column(
        Integer,
        ForeignKey("gsp_environment_assignments.id"),
        nullable=False,
        index=True,
    )
    reading_id = Column(
        Integer,
        ForeignKey("gsp_environment_readings.id"),
        nullable=True,
        index=True,
    )
    alarm_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    status = Column(String(30), nullable=False, default="OPEN", index=True)
    observed_value = Column(Numeric(12, 3), nullable=False)
    threshold_value = Column(Numeric(12, 3), nullable=False)
    detail = Column(Text, nullable=False)
    opened_at = Column(DateTime, nullable=False, default=utc_now)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    acknowledged_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledgment_note = Column(String(500), nullable=True)
    decision = Column(String(30), nullable=True)
    deviation_ref = Column(String(500), nullable=True)
    capa_ref = Column(String(500), nullable=True)
    resolution_evidence_ref = Column(String(500), nullable=True)
    decided_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    decided_at = Column(DateTime, nullable=True)
    __table_args__ = (
        UniqueConstraint("reading_id", "alarm_type", name="uq_gsp_environment_reading_alarm"),
        CheckConstraint(
            "alarm_type IN ('TEMPERATURE_LOW','TEMPERATURE_HIGH','HUMIDITY_LOW','HUMIDITY_HIGH','DEVICE_OFFLINE')",
            name="ck_gsp_environment_alarm_type",
        ),
        CheckConstraint(
            "severity IN ('WARNING','CRITICAL')",
            name="ck_gsp_environment_alarm_severity",
        ),
        CheckConstraint(
            "status IN ('OPEN','ACKNOWLEDGED','RESOLVED')",
            name="ck_gsp_environment_alarm_status",
        ),
        CheckConstraint(
            "decision IS NULL OR decision IN ('CONTINUE','HOLD','RETURN','REJECT')",
            name="ck_gsp_environment_alarm_decision",
        ),
    )


def _immutable_reading(_mapper, _connection, _target) -> None:
    raise RuntimeError("温湿度原始读数为不可变记录，不允许更新或删除")


event.listen(GspEnvironmentReading, "before_update", _immutable_reading)
event.listen(GspEnvironmentReading, "before_delete", _immutable_reading)

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.gsp.schemas import ChangeReason, OrmModel


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnvironmentDeviceCreate(ChangeReason):
    device_code: str = Field(..., min_length=3, max_length=100)
    name: str = Field(..., min_length=2, max_length=200)
    manufacturer: str = Field(..., min_length=2, max_length=200)
    model_no: str = Field(..., min_length=1, max_length=100)
    serial_no: str = Field(..., min_length=3, max_length=100)
    measurement_scope: str = Field(..., pattern="^(TEMPERATURE|TEMPERATURE_HUMIDITY)$")
    calibration_ref: str = Field(..., min_length=3, max_length=500)
    calibration_valid_to: date
    temperature_accuracy: Decimal = Field(..., gt=0, decimal_places=3)
    humidity_accuracy: Decimal | None = Field(None, gt=0, decimal_places=3)


class EnvironmentDecision(ChangeReason):
    decision: str = Field(..., pattern="^(APPROVE|REJECT)$")


class DeviceRecalibration(ChangeReason):
    calibration_ref: str = Field(..., min_length=3, max_length=500)
    calibration_valid_to: date
    temperature_accuracy: Decimal = Field(..., gt=0, decimal_places=3)
    humidity_accuracy: Decimal | None = Field(None, gt=0, decimal_places=3)


class EnvironmentAssignmentCreate(ChangeReason):
    assignment_no: str = Field(..., min_length=3, max_length=120)
    device_id: int = Field(..., gt=0)
    context_type: str = Field(..., pattern="^(WAREHOUSE|TRANSPORT)$")
    warehouse_id: int | None = Field(None, gt=0)
    location_id: int | None = Field(None, gt=0)
    transport_task_id: int | None = Field(None, gt=0)
    temperature_min: Decimal = Field(..., decimal_places=3)
    temperature_max: Decimal = Field(..., decimal_places=3)
    critical_temperature_min: Decimal = Field(..., decimal_places=3)
    critical_temperature_max: Decimal = Field(..., decimal_places=3)
    humidity_min: Decimal | None = Field(None, ge=0, le=100, decimal_places=3)
    humidity_max: Decimal | None = Field(None, ge=0, le=100, decimal_places=3)
    critical_humidity_min: Decimal | None = Field(None, ge=0, le=100, decimal_places=3)
    critical_humidity_max: Decimal | None = Field(None, ge=0, le=100, decimal_places=3)
    sampling_interval_seconds: int = Field(..., ge=10, le=86400)
    offline_after_seconds: int = Field(..., ge=30, le=604800)


class EnvironmentReadingCreate(StrictModel):
    external_reading_id: str = Field(..., min_length=1, max_length=150)
    observed_at: datetime
    temperature: Decimal = Field(..., ge=-100, le=200, decimal_places=3)
    humidity: Decimal | None = Field(None, ge=0, le=100, decimal_places=3)
    battery_percent: Decimal | None = Field(None, ge=0, le=100, decimal_places=2)
    signal_strength: int | None = Field(None, ge=-200, le=100)
    source_payload: dict[str, Any] = Field(default_factory=dict)


class AlarmAcknowledge(ChangeReason):
    pass


class AssignmentClose(ChangeReason):
    pass


class AlarmDecision(ChangeReason):
    decision: str = Field(..., pattern="^(CONTINUE|HOLD|RETURN|REJECT)$")
    deviation_ref: str = Field(..., min_length=3, max_length=500)
    capa_ref: str | None = Field(None, min_length=3, max_length=500)
    resolution_evidence_ref: str = Field(..., min_length=3, max_length=500)


class EnvironmentDeviceResponse(OrmModel):
    id: int
    device_code: str
    name: str
    manufacturer: str
    model_no: str
    serial_no: str
    measurement_scope: str
    calibration_ref: str
    calibration_valid_to: date
    temperature_accuracy: Decimal
    humidity_accuracy: Decimal | None
    status: str
    created_by: int
    created_at: datetime
    approved_by: int | None
    approved_at: datetime | None
    suspension_reason: str | None


class EnvironmentAssignmentResponse(OrmModel):
    id: int
    assignment_no: str
    device_id: int
    context_type: str
    warehouse_id: int | None
    location_id: int | None
    transport_task_id: int | None
    temperature_min: Decimal
    temperature_max: Decimal
    critical_temperature_min: Decimal
    critical_temperature_max: Decimal
    humidity_min: Decimal | None
    humidity_max: Decimal | None
    critical_humidity_min: Decimal | None
    critical_humidity_max: Decimal | None
    sampling_interval_seconds: int
    offline_after_seconds: int
    status: str
    created_by: int
    created_at: datetime
    approved_by: int | None
    approved_at: datetime | None
    last_reading_at: datetime | None
    closed_by: int | None
    closed_at: datetime | None
    close_reason: str | None


class EnvironmentReadingResponse(OrmModel):
    id: int
    assignment_id: int
    external_reading_id: str
    observed_at: datetime
    received_at: datetime
    temperature: Decimal
    humidity: Decimal | None
    battery_percent: Decimal | None
    signal_strength: int | None
    source_payload: dict[str, Any]
    source_payload_hash: str
    previous_hash: str | None
    record_hash: str
    evaluation: str
    reported_by: int


class EnvironmentAlarmResponse(OrmModel):
    id: int
    alarm_no: str
    assignment_id: int
    reading_id: int | None
    alarm_type: str
    severity: str
    status: str
    observed_value: Decimal
    threshold_value: Decimal
    detail: str
    opened_at: datetime
    created_by: int
    acknowledged_by: int | None
    acknowledged_at: datetime | None
    acknowledgment_note: str | None
    decision: str | None
    deviation_ref: str | None
    capa_ref: str | None
    resolution_evidence_ref: str | None
    decided_by: int | None
    decided_at: datetime | None

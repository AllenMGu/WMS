from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.gsp.schemas import ChangeReason, OrmModel

TRANSPORT_MODES = {"NORMAL", "COLD", "FROZEN"}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CarrierCreate(ChangeReason):
    code: str = Field(..., min_length=2, max_length=50)
    name: str = Field(..., min_length=2, max_length=200)
    unified_social_credit_code: str = Field(..., min_length=8, max_length=50)
    license_no: str = Field(..., min_length=3, max_length=100)
    license_valid_to: date
    service_modes: list[str] = Field(..., min_length=1, max_length=3)
    quality_agreement_valid_to: date

    @field_validator("service_modes")
    @classmethod
    def validate_modes(cls, value: list[str]) -> list[str]:
        normalized = sorted({item.upper() for item in value})
        if not set(normalized).issubset(TRANSPORT_MODES):
            raise ValueError("service_modes 只能包含 NORMAL、COLD、FROZEN")
        return normalized


class CarrierDocumentCreate(ChangeReason):
    document_type: str = Field(..., min_length=3, max_length=50)
    document_no: str = Field(..., min_length=2, max_length=100)
    valid_to: date
    file_ref: str = Field(..., min_length=3, max_length=500)


class CarrierVehicleCreate(ChangeReason):
    vehicle_no: str = Field(..., min_length=3, max_length=100)
    vehicle_type: str = Field(..., pattern="^(NORMAL|REFRIGERATED|FROZEN)$")
    qualification_ref: str = Field(..., min_length=3, max_length=500)
    qualification_valid_to: date
    calibration_ref: str | None = Field(None, min_length=3, max_length=500)
    calibration_valid_to: date | None = None


class CarrierDriverCreate(ChangeReason):
    name: str = Field(..., min_length=2, max_length=100)
    personnel_code: str = Field(..., min_length=3, max_length=100)
    qualification_ref: str = Field(..., min_length=3, max_length=500)
    authorization_valid_to: date


class ApprovalDecision(ChangeReason):
    decision: str = Field(..., pattern="^(APPROVE|REJECT)$")


class CarrierResponse(OrmModel):
    id: int
    code: str
    name: str
    unified_social_credit_code: str
    license_no: str
    license_valid_to: date
    service_modes: list[str]
    quality_agreement_valid_to: date
    status: str
    created_by: int
    created_at: datetime
    approved_by: int | None
    approved_at: datetime | None
    suspension_reason: str | None


class CarrierDocumentResponse(OrmModel):
    id: int
    carrier_id: int
    document_type: str
    document_no: str
    valid_to: date
    file_ref: str
    status: str
    created_by: int
    verified_by: int | None
    verified_at: datetime | None


class CarrierVehicleResponse(OrmModel):
    id: int
    carrier_id: int
    vehicle_no: str
    vehicle_type: str
    qualification_ref: str
    qualification_valid_to: date
    calibration_ref: str | None
    calibration_valid_to: date | None
    status: str
    created_by: int
    approved_by: int | None
    approved_at: datetime | None


class CarrierDriverResponse(OrmModel):
    id: int
    carrier_id: int
    name: str
    personnel_code: str
    qualification_ref: str
    authorization_valid_to: date
    status: str
    created_by: int
    approved_by: int | None
    approved_at: datetime | None


class TransportEventCreate(StrictModel):
    event_type: str = Field(..., pattern="^(LOCATION_UPDATE|ARRIVED_HUB|DEPARTED_HUB)$")
    occurred_at: datetime
    location: str = Field(..., min_length=2, max_length=500)
    detail: str = Field(..., min_length=3, max_length=2000)
    evidence_ref: str | None = Field(None, min_length=3, max_length=500)


class TransportExceptionCreate(StrictModel):
    category: str = Field(
        ...,
        pattern="^(DELAY|ROUTE_DEVIATION|VEHICLE_BREAKDOWN|PACKAGE_DAMAGE|QUANTITY_MISMATCH|CUSTODY_BREAK|OTHER)$",
    )
    severity: str = Field(..., pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    quality_impact: bool = True
    occurred_at: datetime
    location: str = Field(..., min_length=2, max_length=500)
    description: str = Field(..., min_length=3, max_length=2000)
    evidence_ref: str = Field(..., min_length=3, max_length=500)


class TransportExceptionDecision(ChangeReason):
    decision: str = Field(..., pattern="^(CONTINUE|RETURN|REJECT_DELIVERY)$")
    deviation_ref: str = Field(..., min_length=3, max_length=500)
    capa_ref: str | None = Field(None, min_length=3, max_length=500)


class DeliveryCreate(StrictModel):
    received_at: datetime
    delivery_location: str = Field(..., min_length=2, max_length=500)
    recipient_name: str = Field(..., min_length=2, max_length=200)
    recipient_organization: str = Field(..., min_length=2, max_length=200)
    delivery_proof_ref: str = Field(..., min_length=3, max_length=500)
    package_condition: str = Field(..., pattern="^(INTACT|DAMAGED)$")
    quantity_conclusion: str = Field(..., pattern="^(MATCHED|SHORT|OVER)$")
    reason: str = Field(..., min_length=3, max_length=500)


class TransportClose(ChangeReason):
    evidence_ref: str = Field(..., min_length=3, max_length=500)


class TransportTaskResponse(OrmModel):
    id: int
    task_no: str
    shipment_id: int
    carrier_id: int
    vehicle_id: int
    driver_id: int
    transport_mode: str
    route_plan_ref: str
    handover_document_no: str
    expected_arrival_at: datetime
    status: str
    created_by: int
    actual_departure_at: datetime | None
    delivery_recorded_by: int | None
    delivered_at: datetime | None
    delivery_location: str | None
    recipient_name: str | None
    recipient_organization: str | None
    delivery_proof_ref: str | None
    package_condition: str | None
    quantity_conclusion: str | None
    closed_by: int | None
    closed_at: datetime | None
    close_evidence_ref: str | None


class TransportEventResponse(OrmModel):
    id: int
    task_id: int
    event_type: str
    occurred_at: datetime
    location: str
    detail: str
    evidence_ref: str | None
    reported_by: int
    recorded_at: datetime


class TransportExceptionResponse(OrmModel):
    id: int
    task_id: int
    event_id: int
    category: str
    severity: str
    quality_impact: bool
    description: str
    status: str
    reported_by: int
    reported_at: datetime
    decision: str | None
    deviation_ref: str | None
    capa_ref: str | None
    decided_by: int | None
    decided_at: datetime | None

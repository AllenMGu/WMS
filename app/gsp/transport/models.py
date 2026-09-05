"""Persistence models for carrier qualification and in-transit custody."""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from app.core.database import Base
from app.core.time import utc_now


class GspCarrier(Base):
    __tablename__ = "gsp_carriers"

    id = Column(Integer, primary_key=True)
    code = Column(String(50), nullable=False, unique=True, index=True)
    name = Column(String(200), nullable=False, index=True)
    unified_social_credit_code = Column(String(50), nullable=False, unique=True, index=True)
    license_no = Column(String(100), nullable=False)
    license_valid_to = Column(Date, nullable=False, index=True)
    service_modes = Column(JSON, nullable=False)
    quality_agreement_valid_to = Column(Date, nullable=False, index=True)
    status = Column(String(30), nullable=False, default="PENDING", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    suspension_reason = Column(String(500), nullable=True)
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING','APPROVED','SUSPENDED')",
            name="ck_gsp_carrier_status",
        ),
    )

class GspCarrierDocument(Base):
    __tablename__ = "gsp_carrier_documents"

    id = Column(Integer, primary_key=True)
    carrier_id = Column(Integer, ForeignKey("gsp_carriers.id"), nullable=False, index=True)
    document_type = Column(String(50), nullable=False)
    document_no = Column(String(100), nullable=False)
    valid_to = Column(Date, nullable=False, index=True)
    file_ref = Column(String(500), nullable=False)
    file_sha256 = Column(String(64), nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    status = Column(String(30), nullable=False, default="PENDING", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    verified_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    verified_at = Column(DateTime, nullable=True)
    __table_args__ = (
        UniqueConstraint(
            "carrier_id",
            "document_type",
            "document_no",
            name="uq_gsp_carrier_document",
        ),
        CheckConstraint(
            "status IN ('PENDING','VERIFIED','REJECTED')",
            name="ck_gsp_carrier_document_status",
        ),
    )


class GspCarrierVehicle(Base):
    __tablename__ = "gsp_carrier_vehicles"

    id = Column(Integer, primary_key=True)
    carrier_id = Column(Integer, ForeignKey("gsp_carriers.id"), nullable=False, index=True)
    vehicle_no = Column(String(100), nullable=False, unique=True, index=True)
    vehicle_type = Column(String(30), nullable=False)
    qualification_ref = Column(String(500), nullable=False)
    qualification_valid_to = Column(Date, nullable=False, index=True)
    calibration_ref = Column(String(500), nullable=True)
    calibration_valid_to = Column(Date, nullable=True, index=True)
    status = Column(String(30), nullable=False, default="PENDING", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    __table_args__ = (
        CheckConstraint(
            "vehicle_type IN ('NORMAL','REFRIGERATED','FROZEN')",
            name="ck_gsp_carrier_vehicle_type",
        ),
        CheckConstraint(
            "status IN ('PENDING','APPROVED','SUSPENDED')",
            name="ck_gsp_carrier_vehicle_status",
        ),
    )


class GspCarrierDriver(Base):
    __tablename__ = "gsp_carrier_drivers"

    id = Column(Integer, primary_key=True)
    carrier_id = Column(Integer, ForeignKey("gsp_carriers.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    personnel_code = Column(String(100), nullable=False, unique=True, index=True)
    qualification_ref = Column(String(500), nullable=False)
    authorization_valid_to = Column(Date, nullable=False, index=True)
    status = Column(String(30), nullable=False, default="PENDING", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING','APPROVED','SUSPENDED')",
            name="ck_gsp_carrier_driver_status",
        ),
    )


class GspTransportTask(Base):
    __tablename__ = "gsp_transport_tasks"

    id = Column(Integer, primary_key=True)
    task_no = Column(String(120), nullable=False, unique=True, index=True)
    shipment_id = Column(Integer, ForeignKey("gsp_shipments.id"), nullable=False, unique=True, index=True)
    carrier_id = Column(Integer, ForeignKey("gsp_carriers.id"), nullable=False, index=True)
    vehicle_id = Column(Integer, ForeignKey("gsp_carrier_vehicles.id"), nullable=False)
    driver_id = Column(Integer, ForeignKey("gsp_carrier_drivers.id"), nullable=False)
    transport_mode = Column(String(30), nullable=False)
    route_plan_ref = Column(String(500), nullable=False)
    handover_document_no = Column(String(100), nullable=False, unique=True, index=True)
    expected_arrival_at = Column(DateTime, nullable=False, index=True)
    status = Column(String(30), nullable=False, default="PREPARED", index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    actual_departure_at = Column(DateTime, nullable=True)
    delivery_recorded_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    delivered_at = Column(DateTime, nullable=True)
    delivery_location = Column(String(500), nullable=True)
    recipient_name = Column(String(200), nullable=True)
    recipient_organization = Column(String(200), nullable=True)
    delivery_proof_ref = Column(String(500), nullable=True)
    package_condition = Column(String(30), nullable=True)
    quantity_conclusion = Column(String(30), nullable=True)
    closed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    closed_at = Column(DateTime, nullable=True)
    close_evidence_ref = Column(String(500), nullable=True)
    __table_args__ = (
        CheckConstraint(
            "transport_mode IN ('NORMAL','COLD','FROZEN')",
            name="ck_gsp_transport_task_mode",
        ),
        CheckConstraint(
            "status IN ('PREPARED','IN_TRANSIT','EXCEPTION','RETURN_REQUIRED','REJECTED_DELIVERY','DELIVERED','CLOSED','CANCELLED')",
            name="ck_gsp_transport_task_status",
        ),
        CheckConstraint(
            "package_condition IS NULL OR package_condition IN ('INTACT','DAMAGED')",
            name="ck_gsp_transport_package_condition",
        ),
        CheckConstraint(
            "quantity_conclusion IS NULL OR quantity_conclusion IN ('MATCHED','SHORT','OVER')",
            name="ck_gsp_transport_quantity_conclusion",
        ),
    )


class GspTransportEvent(Base):
    __tablename__ = "gsp_transport_events"

    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey("gsp_transport_tasks.id"), nullable=False, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    occurred_at = Column(DateTime, nullable=False, index=True)
    location = Column(String(500), nullable=False)
    detail = Column(Text, nullable=False)
    evidence_ref = Column(String(500), nullable=True)
    reported_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    recorded_at = Column(DateTime, nullable=False, default=utc_now)


class GspTransportException(Base):
    __tablename__ = "gsp_transport_exceptions"

    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey("gsp_transport_tasks.id"), nullable=False, index=True)
    event_id = Column(Integer, ForeignKey("gsp_transport_events.id"), nullable=False, unique=True)
    category = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    quality_impact = Column(Boolean, nullable=False, default=True)
    description = Column(Text, nullable=False)
    status = Column(String(30), nullable=False, default="PENDING_QUALITY", index=True)
    reported_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    reported_at = Column(DateTime, nullable=False, default=utc_now)
    decision = Column(String(30), nullable=True)
    deviation_ref = Column(String(500), nullable=True)
    capa_ref = Column(String(500), nullable=True)
    decided_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    decided_at = Column(DateTime, nullable=True)
    __table_args__ = (
        CheckConstraint(
            "severity IN ('LOW','MEDIUM','HIGH','CRITICAL')",
            name="ck_gsp_transport_exception_severity",
        ),
        CheckConstraint(
            "status IN ('PENDING_QUALITY','RESOLVED','RETURN_REQUIRED','REJECTED_DELIVERY')",
            name="ck_gsp_transport_exception_status",
        ),
        CheckConstraint(
            "decision IS NULL OR decision IN ('CONTINUE','RETURN','REJECT_DELIVERY')",
            name="ck_gsp_transport_exception_decision",
        ),
    )

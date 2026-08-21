from datetime import date, timedelta
from uuid import uuid4

import pytest

from app.core.database import SessionLocal
from app.core.time import utc_now
from app.gsp.audit import verify_audit_chain
from app.gsp.errors import WorkflowError
from app.gsp.models import GspIntegrationMessage, GspQualityHold
from app.gsp.transport.models import GspTransportEvent, GspTransportTask
from app.gsp.transport.schemas import (
    ApprovalDecision,
    CarrierCreate,
    CarrierDocumentCreate,
    CarrierDriverCreate,
    CarrierVehicleCreate,
    DeliveryCreate,
    TransportClose,
    TransportEventCreate,
    TransportExceptionCreate,
    TransportExceptionDecision,
)
from app.gsp.transport.service import (
    add_carrier_document,
    close_transport_task,
    create_carrier,
    create_driver,
    create_transport_exception,
    create_vehicle,
    decide_carrier,
    decide_driver,
    decide_transport_exception,
    decide_vehicle,
    record_delivery,
    record_transport_event,
    validate_transport_resources,
    verify_carrier_document,
)
from app.legacy import User, UserRole
from tests.test_returns_recalls import _seed_dispatched_batch


def _users(db):
    suffix = uuid4().hex[:10]
    coordinator = User(
        username=f"transport-coordinator-{suffix}",
        hashed_password="test-only",
        full_name="运输协调员",
        role=UserRole.OPERATOR,
    )
    quality = User(
        username=f"transport-quality-{suffix}",
        hashed_password="test-only",
        full_name="质量审核员",
        role=UserRole.OPERATOR,
    )
    db.add_all([coordinator, quality])
    db.flush()
    return coordinator, quality, suffix


def test_carrier_requires_verified_documents_and_independent_approval():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        coordinator, quality, suffix = _users(db)
        valid_to = date.today() + timedelta(days=365)
        carrier = create_carrier(
            db,
            payload=CarrierCreate(
                code=f"QUAL-{suffix}",
                name="资质测试承运商",
                unified_social_credit_code=f"QUAL-USCC-{suffix}",
                license_no=f"QUAL-LIC-{suffix}",
                license_valid_to=valid_to,
                service_modes=["NORMAL"],
                quality_agreement_valid_to=valid_to,
                reason="登记受控承运商",
            ),
            actor_id=coordinator.id,
        )
        with pytest.raises(WorkflowError, match="资质证据不完整"):
            decide_carrier(
                db,
                carrier=carrier,
                payload=ApprovalDecision(decision="APPROVE", reason="证据尚不完整"),
                actor_id=quality.id,
            )

        for document_type in (
            "BUSINESS_LICENSE",
            "ROAD_TRANSPORT_LICENSE",
            "QUALITY_AGREEMENT",
        ):
            document = add_carrier_document(
                db,
                carrier=carrier,
                payload=CarrierDocumentCreate(
                    document_type=document_type,
                    document_no=f"{document_type}-{suffix}",
                    valid_to=valid_to,
                    file_ref=f"test://qualification/{document_type}",
                    reason="补齐承运商资质证据",
                ),
                actor_id=coordinator.id,
            )
            with pytest.raises(WorkflowError, match="必须分离"):
                verify_carrier_document(
                    db,
                    document=document,
                    payload=ApprovalDecision(decision="APPROVE", reason="错误同人核验"),
                    actor_id=coordinator.id,
                )
            verify_carrier_document(
                db,
                document=document,
                payload=ApprovalDecision(decision="APPROVE", reason="独立核验通过"),
                actor_id=quality.id,
            )

        decide_carrier(
            db,
            carrier=carrier,
            payload=ApprovalDecision(decision="APPROVE", reason="资质证据完整有效"),
            actor_id=quality.id,
        )
        with pytest.raises(WorkflowError, match="冷链车辆必须提供有效校准证据"):
            create_vehicle(
                db,
                carrier=carrier,
                payload=CarrierVehicleCreate(
                    vehicle_no=f"COLD-{suffix}",
                    vehicle_type="REFRIGERATED",
                    qualification_ref="test://vehicle/qualification",
                    qualification_valid_to=valid_to,
                    reason="登记冷链车辆",
                ),
                actor_id=coordinator.id,
            )
        vehicle = create_vehicle(
            db,
            carrier=carrier,
            payload=CarrierVehicleCreate(
                vehicle_no=f"NORMAL-{suffix}",
                vehicle_type="NORMAL",
                qualification_ref="test://vehicle/qualification",
                qualification_valid_to=valid_to,
                reason="登记常温车辆",
            ),
            actor_id=coordinator.id,
        )
        driver = create_driver(
            db,
            carrier=carrier,
            payload=CarrierDriverCreate(
                name="资质测试驾驶员",
                personnel_code=f"QUAL-DRV-{suffix}",
                qualification_ref="test://driver/qualification",
                authorization_valid_to=valid_to,
                reason="登记驾驶员",
            ),
            actor_id=coordinator.id,
        )
        with pytest.raises(WorkflowError, match="运输资源不满足") as error:
            validate_transport_resources(
                db,
                carrier_id=carrier.id,
                vehicle_id=vehicle.id,
                driver_id=driver.id,
                transport_mode="NORMAL",
            )
        assert any("车辆未批准" in item["message"] for item in error.value.findings)
        with pytest.raises(WorkflowError, match="必须分离"):
            decide_vehicle(
                db,
                vehicle=vehicle,
                payload=ApprovalDecision(decision="APPROVE", reason="错误同人审批"),
                actor_id=coordinator.id,
            )
        decide_vehicle(
            db,
            vehicle=vehicle,
            payload=ApprovalDecision(decision="APPROVE", reason="车辆资质有效"),
            actor_id=quality.id,
        )
        decide_driver(
            db,
            driver=driver,
            payload=ApprovalDecision(decision="APPROVE", reason="驾驶员授权有效"),
            actor_id=quality.id,
        )
        db.commit()
        assert carrier.status == vehicle.status == driver.status == "APPROVED"
    finally:
        db.close()


def test_transport_exception_delivery_and_independent_close():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        users, _warehouse, _location, batch, _stock, shipment, _allocation = (
            _seed_dispatched_batch(db)
        )
        quality = users[1]
        reporter = users[8]
        recipient_recorder = users[9]
        closer = users[3]
        task = (
            db.query(GspTransportTask)
            .filter(GspTransportTask.shipment_id == shipment.id)
            .one()
        )
        assert task.status == "IN_TRANSIT"
        event = record_transport_event(
            db,
            task=task,
            payload=TransportEventCreate(
                event_type="LOCATION_UPDATE",
                occurred_at=utc_now(),
                location="高速公路检查点",
                detail="车辆、封签和货物外观正常",
                evidence_ref="test://transport/location-photo",
            ),
            actor_id=reporter.id,
        )
        assert event.event_type == "LOCATION_UPDATE"
        exception = create_transport_exception(
            db,
            task=task,
            payload=TransportExceptionCreate(
                category="ROUTE_DEVIATION",
                severity="HIGH",
                quality_impact=True,
                occurred_at=utc_now(),
                location="临时绕行路段",
                description="道路封闭导致偏离批准路线，货物封签保持完整",
                evidence_ref="test://transport/deviation-photo",
            ),
            actor_id=reporter.id,
        )
        assert task.status == "EXCEPTION"
        assert (
            db.query(GspQualityHold)
            .filter(
                GspQualityHold.batch_id == batch.id,
                GspQualityHold.reason_code == "TRANSPORT_EXCEPTION",
                GspQualityHold.status == "ACTIVE",
            )
            .count()
            == 1
        )
        with pytest.raises(WorkflowError, match="未解决异常"):
            record_delivery(
                db,
                task=task,
                payload=DeliveryCreate(
                    received_at=utc_now(),
                    delivery_location="购货方收货区",
                    recipient_name="收货员",
                    recipient_organization="测试医疗机构",
                    delivery_proof_ref="test://delivery/proof",
                    package_condition="INTACT",
                    quantity_conclusion="MATCHED",
                    reason="登记签收",
                ),
                actor_id=recipient_recorder.id,
            )
        with pytest.raises(WorkflowError, match="必须分离"):
            decide_transport_exception(
                db,
                exception=exception,
                payload=TransportExceptionDecision(
                    decision="CONTINUE",
                    deviation_ref="DEV-TRANSPORT-001",
                    capa_ref="CAPA-TRANSPORT-001",
                    reason="错误同人质量决定",
                ),
                actor_id=reporter.id,
            )
        decide_transport_exception(
            db,
            exception=exception,
            payload=TransportExceptionDecision(
                decision="CONTINUE",
                deviation_ref="DEV-TRANSPORT-001",
                capa_ref="CAPA-TRANSPORT-001",
                reason="封签完整且风险评估允许继续交付",
            ),
            actor_id=quality.id,
        )
        delivery_time = utc_now()
        record_delivery(
            db,
            task=task,
            payload=DeliveryCreate(
                received_at=delivery_time,
                delivery_location="购货方收货区",
                recipient_name="收货员",
                recipient_organization="测试医疗机构",
                delivery_proof_ref="test://delivery/proof",
                package_condition="INTACT",
                quantity_conclusion="MATCHED",
                reason="核对包装数量并登记签收凭证",
            ),
            actor_id=recipient_recorder.id,
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            close_transport_task(
                db,
                task=task,
                payload=TransportClose(
                    evidence_ref="test://delivery/close-review",
                    reason="错误同人关闭",
                ),
                actor_id=recipient_recorder.id,
            )
        close_transport_task(
            db,
            task=task,
            payload=TransportClose(
                evidence_ref="test://delivery/close-review",
                reason="独立复核签收证据并关闭运输交接",
            ),
            actor_id=closer.id,
        )
        db.commit()
        db.refresh(task)
        db.refresh(shipment)
        assert task.status == shipment.status == "CLOSED"
        assert db.query(GspTransportEvent).filter(GspTransportEvent.task_id == task.id).count() == 4
        message_types = {
            row.message_type
            for row in db.query(GspIntegrationMessage)
            .filter(GspIntegrationMessage.aggregate_id.in_([str(task.id), str(exception.id)]))
            .all()
        }
        assert {
            "TRANSPORT_STARTED",
            "TRANSPORT_EXCEPTION",
            "TRANSPORT_EXCEPTION_DECIDED",
            "SHIPMENT_DELIVERED",
            "TRANSPORT_CLOSED",
        } <= message_types
        assert verify_audit_chain(db) == (True, None)
    finally:
        db.close()

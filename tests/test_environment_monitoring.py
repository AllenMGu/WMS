from datetime import date, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest

from app.core.database import SessionLocal
from app.core.time import utc_now
from app.gsp.environment.models import GspEnvironmentAlarm, GspEnvironmentReading
from app.gsp.environment.schemas import (
    AlarmDecision,
    EnvironmentAssignmentCreate,
    EnvironmentDecision,
    EnvironmentDeviceCreate,
    EnvironmentReadingCreate,
)
from app.gsp.environment.service import (
    acknowledge_alarm,
    create_assignment,
    create_device,
    decide_alarm,
    decide_assignment,
    decide_device,
    ingest_reading,
    scan_offline_assignments,
    verify_reading_chain,
)
from app.gsp.errors import WorkflowError
from app.gsp.models import GspQualityHold
from app.gsp.transport.models import GspTransportTask
from app.gsp.transport.schemas import DeliveryCreate
from app.gsp.transport.service import record_delivery
from tests.test_returns_recalls import _seed_dispatched_batch
from tests.test_sales_shipping import _seed_sales_data


def _approved_device(db, *, operator_id: int, quality_id: int, suffix: str):
    device = create_device(
        db,
        payload=EnvironmentDeviceCreate(
            device_code=f"ENV-{suffix}",
            name="温湿度记录仪",
            manufacturer="测试仪器厂商",
            model_no="TH-100",
            serial_no=f"ENV-SN-{suffix}",
            measurement_scope="TEMPERATURE_HUMIDITY",
            calibration_ref=f"test://calibration/{suffix}",
            calibration_valid_to=date.today() + timedelta(days=365),
            temperature_accuracy=Decimal("0.500"),
            humidity_accuracy=Decimal("3.000"),
            reason="登记已校准监测设备",
        ),
        actor_id=operator_id,
    )
    with pytest.raises(WorkflowError, match="必须分离"):
        decide_device(
            db,
            device=device,
            payload=EnvironmentDecision(decision="APPROVE", reason="错误同人审批"),
            actor_id=operator_id,
        )
    decide_device(
        db,
        device=device,
        payload=EnvironmentDecision(decision="APPROVE", reason="校准证据独立复核通过"),
        actor_id=quality_id,
    )
    return device


def _assignment_payload(
    *,
    suffix: str,
    device_id: int,
    context_type: str,
    warehouse_id: int | None = None,
    location_id: int | None = None,
    transport_task_id: int | None = None,
) -> EnvironmentAssignmentCreate:
    return EnvironmentAssignmentCreate(
        assignment_no=f"ENV-ASG-{suffix}",
        device_id=device_id,
        context_type=context_type,
        warehouse_id=warehouse_id,
        location_id=location_id,
        transport_task_id=transport_task_id,
        temperature_min=Decimal("2.000"),
        temperature_max=Decimal("8.000"),
        critical_temperature_min=Decimal("0.000"),
        critical_temperature_max=Decimal("10.000"),
        humidity_min=Decimal("35.000"),
        humidity_max=Decimal("75.000"),
        critical_humidity_min=Decimal("20.000"),
        critical_humidity_max=Decimal("90.000"),
        sampling_interval_seconds=60,
        offline_after_seconds=300,
        reason="配置批准的温湿度监测范围",
    )


def test_warehouse_readings_are_idempotent_hash_chained_and_alarm_controlled():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        users, warehouse, _goods, _customer, batch, stock, _later_stock = _seed_sales_data(db)
        operator = users[4]
        quality = users[1]
        suffix = uuid4().hex[:10]
        device = _approved_device(
            db,
            operator_id=operator.id,
            quality_id=quality.id,
            suffix=suffix,
        )
        assignment = create_assignment(
            db,
            payload=_assignment_payload(
                suffix=suffix,
                device_id=device.id,
                context_type="WAREHOUSE",
                warehouse_id=warehouse.id,
                location_id=stock.location_id,
            ),
            actor_id=operator.id,
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            decide_assignment(
                db,
                assignment=assignment,
                payload=EnvironmentDecision(decision="APPROVE", reason="错误同人审批"),
                actor_id=operator.id,
            )
        decide_assignment(
            db,
            assignment=assignment,
            payload=EnvironmentDecision(decision="APPROVE", reason="监测位置和阈值复核通过"),
            actor_id=quality.id,
        )
        observed_at = utc_now()
        normal_payload = EnvironmentReadingCreate(
            external_reading_id="reading-001",
            observed_at=observed_at,
            temperature=Decimal("5.000"),
            humidity=Decimal("50.000"),
            battery_percent=Decimal("98.00"),
            signal_strength=-55,
            source_payload={"gateway": "test-gateway", "sequence": 1},
        )
        normal = ingest_reading(
            db,
            assignment=assignment,
            payload=normal_payload,
            actor_id=operator.id,
        )
        duplicate = ingest_reading(
            db,
            assignment=assignment,
            payload=normal_payload,
            actor_id=operator.id,
        )
        assert duplicate.id == normal.id
        with pytest.raises(WorkflowError, match="内容不一致"):
            ingest_reading(
                db,
                assignment=assignment,
                payload=normal_payload.model_copy(update={"temperature": Decimal("6.000")}),
                actor_id=operator.id,
            )
        critical = ingest_reading(
            db,
            assignment=assignment,
            payload=EnvironmentReadingCreate(
                external_reading_id="reading-002",
                observed_at=utc_now(),
                temperature=Decimal("12.000"),
                humidity=Decimal("50.000"),
                source_payload={"gateway": "test-gateway", "sequence": 2},
            ),
            actor_id=operator.id,
        )
        alarm = db.query(GspEnvironmentAlarm).filter(
            GspEnvironmentAlarm.reading_id == critical.id
        ).one()
        assert critical.evaluation == alarm.severity == "CRITICAL"
        hold = db.query(GspQualityHold).filter(
            GspQualityHold.batch_id == batch.id,
            GspQualityHold.reason_code == "ENVIRONMENT_EXCURSION",
            GspQualityHold.status == "ACTIVE",
        ).one()
        assert hold.reason.startswith("环境告警")
        assert stock.stock_status == "HOLD"
        acknowledge_alarm(
            db,
            alarm=alarm,
            reason="已确认温度严重超限并隔离影响批次",
            actor_id=operator.id,
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            decide_alarm(
                db,
                alarm=alarm,
                payload=AlarmDecision(
                    decision="HOLD",
                    deviation_ref="DEV-ENV-001",
                    capa_ref="CAPA-ENV-001",
                    resolution_evidence_ref="test://environment/investigation",
                    reason="错误同人质量决定",
                ),
                actor_id=operator.id,
            )
        decide_alarm(
            db,
            alarm=alarm,
            payload=AlarmDecision(
                decision="HOLD",
                deviation_ref="DEV-ENV-001",
                capa_ref="CAPA-ENV-001",
                resolution_evidence_ref="test://environment/investigation",
                reason="保持批次锁定并进入稳定性影响评估",
            ),
            actor_id=quality.id,
        )
        assert verify_reading_chain(db, assignment.id) == (True, None)
        assignment.last_reading_at = utc_now() - timedelta(minutes=10)
        offline_alarms = scan_offline_assignments(db, actor_id=operator.id)
        assert len(offline_alarms) == 1
        db.commit()

        normal.temperature = Decimal("6.000")
        with pytest.raises(RuntimeError, match="不可变记录"):
            db.flush()
        db.rollback()
        assert db.query(GspEnvironmentReading).filter(
            GspEnvironmentReading.assignment_id == assignment.id
        ).count() == 2
    finally:
        db.close()


def test_transport_delivery_is_blocked_until_environment_alarm_decision():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        users, _warehouse, _location, batch, stock, shipment, _allocation = (
            _seed_dispatched_batch(db)
        )
        operator = users[6]
        quality = users[1]
        recipient = users[9]
        task = db.query(GspTransportTask).filter(
            GspTransportTask.shipment_id == shipment.id
        ).one()
        suffix = uuid4().hex[:10]
        device = _approved_device(
            db,
            operator_id=operator.id,
            quality_id=quality.id,
            suffix=suffix,
        )
        assignment = create_assignment(
            db,
            payload=_assignment_payload(
                suffix=suffix,
                device_id=device.id,
                context_type="TRANSPORT",
                transport_task_id=task.id,
            ),
            actor_id=operator.id,
        )
        decide_assignment(
            db,
            assignment=assignment,
            payload=EnvironmentDecision(decision="APPROVE", reason="运输监测方案复核通过"),
            actor_id=quality.id,
        )
        reading = ingest_reading(
            db,
            assignment=assignment,
            payload=EnvironmentReadingCreate(
                external_reading_id="transport-reading-001",
                observed_at=utc_now(),
                temperature=Decimal("-2.000"),
                humidity=Decimal("50.000"),
                source_payload={"logger": device.serial_no},
            ),
            actor_id=operator.id,
        )
        alarm = db.query(GspEnvironmentAlarm).filter(
            GspEnvironmentAlarm.reading_id == reading.id
        ).one()
        delivery = DeliveryCreate(
            received_at=utc_now(),
            delivery_location="购货方收货区",
            recipient_name="收货员",
            recipient_organization="测试医疗机构",
            delivery_proof_ref="test://delivery/environment-proof",
            package_condition="INTACT",
            quantity_conclusion="MATCHED",
            reason="登记冷链运输签收",
        )
        with pytest.raises(WorkflowError, match="温湿度告警"):
            record_delivery(
                db,
                task=task,
                payload=delivery,
                actor_id=recipient.id,
            )
        decide_alarm(
            db,
            alarm=alarm,
            payload=AlarmDecision(
                decision="HOLD",
                deviation_ref="DEV-TRANS-TEMP-001",
                capa_ref="CAPA-TRANS-TEMP-001",
                resolution_evidence_ref="test://transport/temperature-investigation",
                reason="签收后保持批次锁定并开展质量评估",
            ),
            actor_id=quality.id,
        )
        record_delivery(
            db,
            task=task,
            payload=delivery,
            actor_id=recipient.id,
        )
        db.commit()
        assert task.status == shipment.status == "DELIVERED"
        assert db.query(GspQualityHold).filter(
            GspQualityHold.batch_id == batch.id,
            GspQualityHold.reason_code == "ENVIRONMENT_EXCURSION",
            GspQualityHold.status == "ACTIVE",
        ).count() == 1
        assert stock.stock_status == "HOLD"
    finally:
        db.close()

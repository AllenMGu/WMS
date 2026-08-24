from datetime import date, timedelta
from decimal import Decimal
from uuid import uuid4

from app.core.database import SessionLocal
from app.gsp.maintenance.models import GspExpiryAlert
from app.gsp.maintenance.service import resolve_expiry_alert, scan_expiry_controls
from app.gsp.models import (
    GspBatchStock,
    GspBusinessPartner,
    GspComplianceSetting,
    GspDrugBatch,
    GspQualityHold,
)
from app.legacy import Goods, Location, User, UserRole, Warehouse


def test_expiry_scan_uses_approved_threshold_and_is_idempotent():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        suffix = uuid4().hex[:10]
        actor = User(
            username=f"expiry-actor-{suffix}",
            hashed_password="test-only",
            full_name="近效期扫描责任人",
            role=UserRole.OPERATOR,
        )
        warehouse = Warehouse(code=f"EXP-WH-{suffix}", name="近效期测试仓", is_active=True)
        goods = Goods(
            barcode=f"EXP-BAR-{suffix}", name="近效期测试药品", spec="10mg", unit="盒", price=10
        )
        db.add_all([actor, warehouse, goods])
        db.flush()
        location = Location(
            warehouse_id=warehouse.id,
            location_code=f"EXP-L-{suffix}",
            name="近效期库位",
            is_active=True,
        )
        supplier = GspBusinessPartner(
            code=f"EXP-SUP-{suffix}",
            name="近效期供货方",
            partner_type="SUPPLIER",
            license_no=f"EXP-LIC-{suffix}",
            license_scope="药品批发",
            license_valid_to=date.today() + timedelta(days=365),
            status="APPROVED",
            approved_by=actor.id,
            created_by=actor.id,
        )
        db.add_all([location, supplier])
        db.flush()
        batch = GspDrugBatch(
            goods_id=goods.id,
            batch_no=f"EXP-BATCH-{suffix}",
            production_date=date.today() - timedelta(days=100),
            expiry_date=date.today() + timedelta(days=20),
            supplier_id=supplier.id,
            receipt_document_no=f"EXP-RCV-{suffix}",
            status="RELEASED",
            accepted_by=actor.id,
            created_by=actor.id,
        )
        db.add(batch)
        db.flush()
        stock = GspBatchStock(
            batch_id=batch.id,
            warehouse_id=warehouse.id,
            location_id=location.id,
            quantity=Decimal("8.000"),
            reserved_quantity=Decimal("0"),
            stock_status="AVAILABLE",
        )
        db.add(stock)
        db.add(
            GspComplianceSetting(
                key="STOP_SALE_DAYS",
                integer_value=25,
                approval_ref="QA-EXP-001",
                reason="批准近效期停销阈值",
                approved_by=actor.id,
            )
        )
        db.flush()

        first = scan_expiry_controls(db, actor_id=actor.id, source_ip="SYSTEM_TIMER")
        second = scan_expiry_controls(db, actor_id=actor.id, source_ip="SYSTEM_TIMER")
        assert len(first) == 3
        assert len(second) == 3
        assert db.query(GspExpiryAlert).filter(GspExpiryAlert.batch_id == batch.id).count() == 3
        stop_alert = db.query(GspExpiryAlert).filter_by(
            batch_id=batch.id, alert_type="STOP_SALE"
        ).one()
        assert stop_alert.threshold_days == 25
        assert stop_alert.quality_hold_id is not None
        assert db.query(GspQualityHold).filter_by(
            batch_id=batch.id, reason_code="NEAR_EXPIRY_STOP_SALE", status="ACTIVE"
        ).count() == 1
        assert stock.stock_status == "HOLD"

        resolve_expiry_alert(
            db,
            alert_id=stop_alert.id,
            resolution="已完成近效期库存处置评估，质量锁定仍按独立流程管理。",
            evidence_ref="QA-EXP-CLOSE-001",
            reason="质量部门关闭告警证据",
            actor_id=actor.id,
            source_ip="127.0.0.1",
        )
        assert stop_alert.status == "RESOLVED"
        assert db.query(GspQualityHold).filter_by(id=stop_alert.quality_hold_id).one().status == "ACTIVE"
    finally:
        db.rollback()
        db.close()

import importlib
from datetime import date


def test_application_exposes_legacy_and_gsp_routes():
    module = importlib.import_module("main")
    paths = set(module.app.openapi()["paths"])
    assert "/api/token" in paths
    assert "/api/gsp/compliance/summary" in paths
    assert "/api/gsp/quality-holds" in paths
    assert "/api/gsp/procurement/orders" in paths
    assert "/api/gsp/receiving/receipts" in paths
    assert "/health" in paths


def test_audit_and_outbox_accept_json_safe_regulated_snapshot():
    from app.core.database import SessionLocal
    from app.gsp.audit import verify_audit_chain, write_audit_event
    from app.gsp.models import GspAuditEvent, GspBusinessPartner, GspIntegrationMessage
    from app.gsp.outbox import enqueue_integration_message
    from app.gsp.router import _snapshot
    from app.legacy import User, UserRole, get_password_hash

    db = SessionLocal()
    try:
        user = User(
            username="quality-test",
            hashed_password=get_password_hash("test-only-password"),
            full_name="质量测试员",
            role=UserRole.ADMIN,
        )
        db.add(user)
        db.flush()
        partner = GspBusinessPartner(
            code="SUP-TEST",
            name="测试供货方",
            partner_type="SUPPLIER",
            license_no="LICENSE-1",
            license_scope="药品批发",
            license_valid_to=date(2027, 8, 20),
            status="APPROVED",
            created_by=user.id,
        )
        db.add(partner)
        db.flush()
        snapshot = _snapshot(partner)
        assert snapshot["license_valid_to"] == "2027-08-20"
        write_audit_event(
            db,
            actor_user_id=user.id,
            action="TEST_APPROVAL",
            entity_type="GspBusinessPartner",
            entity_id=str(partner.id),
            reason="自动化测试",
            after_data=snapshot,
        )
        enqueue_integration_message(
            db,
            destination="JZT",
            message_type="PARTNER_QUALIFIED",
            aggregate_type="GspBusinessPartner",
            aggregate_id=str(partner.id),
            payload=snapshot,
        )
        db.commit()
        assert db.query(GspAuditEvent).count() == 1
        assert db.query(GspIntegrationMessage).count() == 1
        assert verify_audit_chain(db) == (True, None)
    finally:
        db.close()

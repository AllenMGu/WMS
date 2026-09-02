import importlib
from datetime import date


def test_application_exposes_legacy_and_gsp_routes():
    module = importlib.import_module("main")
    paths = set(module.app.openapi()["paths"])
    assert "/api/token" in paths
    assert "/api/gsp/compliance/summary" in paths
    assert "/api/gsp/roles/me" in paths
    assert "/api/gsp/reference/users" in paths
    assert "/api/gsp/products" in paths
    assert "/api/gsp/batches" in paths
    assert "/api/gsp/batch-stock" in paths
    assert "/api/gsp/roles/{assignment_id}/review" in paths
    assert "/api/gsp/roles/{assignment_id}/revoke" in paths
    assert "/api/gsp/partners/{partner_id}/documents" in paths
    assert "/api/gsp/partners/{partner_id}/documents/{document_id}/verify" in paths
    assert "/api/gsp/quality-holds" in paths
    assert "/api/gsp/stocktaking/plans" in paths
    assert "/api/gsp/procurement/orders" in paths
    assert "/api/gsp/receiving/receipts" in paths
    assert "/api/gsp/receiving/receipts/{receipt_id}/items/{item_id}/sample" in paths
    assert "/api/gsp/receiving/receipts/{receipt_id}/print-records" in paths
    assert "/api/gsp/sales/orders" in paths
    assert "/api/gsp/shipping/shipments" in paths
    assert "/api/gsp/returns/sales" in paths
    assert "/api/gsp/recalls" in paths
    assert "/api/gsp/recalls/{recall_id}/completion-report" in paths
    assert "/api/gsp/recall-drills" in paths
    assert "/api/gsp/maintenance/plans" in paths
    assert "/api/gsp/quality/nonconforming" in paths
    assert "/api/gsp/procurement/returns" in paths
    assert "/api/gsp/audit-verifications" in paths
    assert "/api/gsp/operations/secret-rotations" in paths
    assert "/api/gsp/operations/secret-rotations/{rotation_id}/verify" in paths
    assert "/api/gsp/operations/backups/{evidence_id}/review" in paths
    assert "/api/gsp/operations/recovery-drills/{drill_id}/execute" in paths
    assert "/api/gsp/operations/recovery-drills/{drill_id}/verify" in paths
    assert "/api/gsp/quality-system/training/me" in paths
    assert "/api/gsp/quality-system/capas/me" in paths
    assert "/api/gsp/legacy-archive/batches" in paths
    assert "/api/gsp/legacy-archive/records" in paths
    assert "/api/gsp/electronic-signatures/challenges" in paths
    assert "/api/gsp/electronic-signatures/verify-chain/all" in paths
    assert "/health" in paths


def test_audit_and_outbox_accept_json_safe_regulated_snapshot():
    from app.core.database import SessionLocal
    from app.gsp.audit import record_audit_verification, verify_audit_chain, write_audit_event
    from app.gsp.models import (
        GspAuditEvent,
        GspAuditVerification,
        GspBusinessPartner,
        GspIntegrationMessage,
    )
    from app.gsp.outbox import enqueue_integration_message
    from app.gsp.router import _snapshot
    from app.legacy import User, UserRole, get_password_hash

    db = SessionLocal()
    try:
        audit_count_before = db.query(GspAuditEvent).count()
        outbox_count_before = db.query(GspIntegrationMessage).count()
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
        assert db.query(GspAuditEvent).count() == audit_count_before + 1
        assert db.query(GspIntegrationMessage).count() == outbox_count_before + 1
        assert verify_audit_chain(db) == (True, None)
        verification = record_audit_verification(
            db,
            actor_user_id=user.id,
            trigger_source="SCHEDULED",
            evidence_ref="test://audit-verification/run-1",
            reason="计划任务校验审计链",
        )
        db.commit()
        assert verification.valid is True
        assert db.query(GspAuditVerification).filter_by(id=verification.id).one()
        assert verify_audit_chain(db) == (True, None)
    finally:
        db.close()

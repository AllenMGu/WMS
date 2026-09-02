import hashlib
import json
from datetime import date, timedelta
from uuid import uuid4

import pytest

from app.core.database import SessionLocal
from app.gsp.errors import WorkflowError
from app.gsp.legacy_archive.models import GspLegacyArchiveRecord
from app.gsp.legacy_archive.schemas import (
    LegacyBatchCreate,
    LegacyReconcile,
    LegacyRecordImport,
    LegacyRecordInput,
)
from app.gsp.legacy_archive.service import create_batch, import_records, reconcile_batch, validate_batch
from app.legacy import User, UserRole


def _canonical_sha256(payload: dict) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _users(db):
    suffix = uuid4().hex[:8]
    users = [
        User(
            username=f"legacy-{name}-{suffix}",
            hashed_password="test-only",
            full_name=name,
            role=UserRole.OPERATOR,
            is_active=True,
        )
        for name in ("编制人", "验证人", "导入人", "核对人")
    ]
    db.add_all(users)
    db.flush()
    return users


def _batch_payload(suffix: str, expected: int = 1) -> LegacyBatchCreate:
    return LegacyBatchCreate(
        batch_no=f"LEGACY-{suffix}",
        source_system="OLD_GSP",
        source_instance="production-export-2026",
        manifest_version="1.0",
        mapping_version="GSP-MAP-1",
        package_sha256="a" * 64,
        retention_until=date.today() + timedelta(days=3650),
        expected_record_count=expected,
        reason="建立受控历史迁移批次",
    )


def _record_payload(payload: dict | None = None) -> LegacyRecordImport:
    source = payload or {"drug_code": "D001", "batch_no": "B001", "quantity": 10}
    return LegacyRecordImport(
        records=[
            LegacyRecordInput(
                source_entity="inventory_batch",
                source_table="old_inventory",
                source_key="D001/B001",
                business_date=date.today(),
                title="D001 B001 期初批次库存",
                search_text="D001 B001 批号 库存",
                payload=source,
                payload_sha256=_canonical_sha256(source),
            )
        ],
        reason="导入已批准映射后的历史记录",
    )


def test_legacy_archive_requires_separation_hash_validation_and_reconciliation():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        creator, validator, importer, reconciler = _users(db)
        batch = create_batch(
            db,
            payload=_batch_payload(uuid4().hex[:8]),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            validate_batch(
                db,
                batch_id=batch.id,
                reason="错误同人验证",
                actor_id=creator.id,
                source_ip="127.0.0.1",
            )
        validate_batch(
            db,
            batch_id=batch.id,
            reason="独立验证清洗和映射规则",
            actor_id=validator.id,
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="验证人与导入人必须分离"):
            import_records(
                db,
                batch_id=batch.id,
                payload=_record_payload(),
                actor_id=validator.id,
                source_ip="127.0.0.1",
            )
        inserted, duplicates, _ = import_records(
            db,
            batch_id=batch.id,
            payload=_record_payload(),
            actor_id=importer.id,
            source_ip="127.0.0.1",
        )
        assert (inserted, duplicates) == (1, 0)
        inserted, duplicates, _ = import_records(
            db,
            batch_id=batch.id,
            payload=_record_payload(),
            actor_id=importer.id,
            source_ip="127.0.0.1",
        )
        assert (inserted, duplicates) == (0, 1)
        with pytest.raises(WorkflowError, match="必须分离"):
            reconcile_batch(
                db,
                batch_id=batch.id,
                payload=LegacyReconcile(
                    expected_by_entity={"INVENTORY_BATCH": 1},
                    evidence_ref="test://legacy/reconcile",
                    reason="错误同人核对",
                ),
                actor_id=importer.id,
                source_ip="127.0.0.1",
            )
        batch, items = reconcile_batch(
            db,
            batch_id=batch.id,
            payload=LegacyReconcile(
                expected_by_entity={"INVENTORY_BATCH": 1},
                evidence_ref="test://legacy/reconcile",
                reason="独立核对总数和分类数量",
            ),
            actor_id=reconciler.id,
            source_ip="127.0.0.1",
        )
        assert batch.status == "RECONCILED"
        assert batch.aggregate_sha256
        assert items[0].matched is True
        record = db.query(GspLegacyArchiveRecord).filter_by(import_batch_id=batch.id).one()
        record.title = "禁止篡改"
        with pytest.raises(RuntimeError, match="不可更新"):
            db.flush()
    finally:
        db.rollback()
        db.close()


def test_legacy_archive_rejects_payload_hash_and_count_mismatch():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        creator, validator, importer, reconciler = _users(db)
        batch = create_batch(
            db,
            payload=_batch_payload(uuid4().hex[:8], expected=2),
            actor_id=creator.id,
            source_ip=None,
        )
        validate_batch(
            db,
            batch_id=batch.id,
            reason="独立验证",
            actor_id=validator.id,
            source_ip=None,
        )
        bad = _record_payload()
        bad.records[0].payload_sha256 = "0" * 64
        with pytest.raises(WorkflowError, match="摘要不匹配"):
            import_records(
                db,
                batch_id=batch.id,
                payload=bad,
                actor_id=importer.id,
                source_ip=None,
            )
        import_records(
            db,
            batch_id=batch.id,
            payload=_record_payload(),
            actor_id=importer.id,
            source_ip=None,
        )
        with pytest.raises(WorkflowError, match="核对不通过"):
            reconcile_batch(
                db,
                batch_id=batch.id,
                payload=LegacyReconcile(
                    expected_by_entity={"INVENTORY_BATCH": 2},
                    evidence_ref="test://legacy/mismatch",
                    reason="验证数量不符会被阻断",
                ),
                actor_id=reconciler.id,
                source_ip=None,
            )
    finally:
        db.rollback()
        db.close()

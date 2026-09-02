from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import date

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.audit import write_audit_event
from app.gsp.errors import WorkflowError
from app.gsp.legacy_archive.models import (
    GspLegacyArchiveRecord,
    GspLegacyImportBatch,
    GspLegacyReconciliationItem,
)
from app.gsp.legacy_archive.schemas import (
    LegacyBatchCreate,
    LegacyReconcile,
    LegacyRecordImport,
)


def _canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _batch(db: Session, batch_id: int) -> GspLegacyImportBatch:
    batch = db.get(GspLegacyImportBatch, batch_id)
    if batch is None:
        raise WorkflowError(404, "老GSP迁移批次不存在")
    return batch


def create_batch(
    db: Session, *, payload: LegacyBatchCreate, actor_id: int, source_ip: str | None
) -> GspLegacyImportBatch:
    if payload.retention_until <= date.today():
        raise WorkflowError(422, "归档保留期限必须晚于今天")
    batch = GspLegacyImportBatch(
        **payload.model_dump(exclude={"reason"}), created_by=actor_id, reason=payload.reason
    )
    db.add(batch)
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="LEGACY_ARCHIVE_BATCH_CREATED",
        entity_type="GspLegacyImportBatch",
        entity_id=str(batch.id),
        reason=payload.reason,
        after_data={
            "batch_no": batch.batch_no,
            "source_system": batch.source_system,
            "package_sha256": batch.package_sha256,
            "expected_record_count": batch.expected_record_count,
        },
        source_ip=source_ip,
    )
    return batch


def validate_batch(
    db: Session, *, batch_id: int, reason: str, actor_id: int, source_ip: str | None
) -> GspLegacyImportBatch:
    batch = _batch(db, batch_id)
    if batch.status != "DRAFT":
        raise WorkflowError(409, "只有草稿批次可以验证")
    if batch.created_by == actor_id:
        raise WorkflowError(409, "迁移批次编制人与验证人必须分离")
    batch.status = "VALIDATED"
    batch.validated_by = actor_id
    batch.validated_at = utc_now()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="LEGACY_ARCHIVE_BATCH_VALIDATED",
        entity_type="GspLegacyImportBatch",
        entity_id=str(batch.id),
        reason=reason,
        after_data={"status": batch.status, "mapping_version": batch.mapping_version},
        source_ip=source_ip,
    )
    return batch


def import_records(
    db: Session,
    *,
    batch_id: int,
    payload: LegacyRecordImport,
    actor_id: int,
    source_ip: str | None,
) -> tuple[int, int, GspLegacyImportBatch]:
    batch = _batch(db, batch_id)
    if batch.status not in {"VALIDATED", "IMPORTED"}:
        raise WorkflowError(409, "批次必须先通过独立验证才能导入")
    if batch.validated_by == actor_id:
        raise WorkflowError(409, "迁移批次验证人与导入人必须分离")
    if batch.imported_by is not None and batch.imported_by != actor_id:
        raise WorkflowError(409, "同一迁移批次的分段导入必须由同一导入人完成")
    previous = (
        db.query(GspLegacyArchiveRecord)
        .filter(GspLegacyArchiveRecord.import_batch_id == batch.id)
        .order_by(GspLegacyArchiveRecord.id.desc())
        .first()
    )
    previous_hash = previous.record_hash if previous else None
    inserted = duplicates = 0
    for item in payload.records:
        payload_hash = _sha256(_canonical(item.payload))
        if payload_hash != item.payload_sha256:
            raise WorkflowError(422, f"记录 {item.source_table}/{item.source_key} 内容摘要不匹配")
        existing = (
            db.query(GspLegacyArchiveRecord)
            .filter(
                GspLegacyArchiveRecord.import_batch_id == batch.id,
                GspLegacyArchiveRecord.source_table == item.source_table,
                GspLegacyArchiveRecord.source_key == item.source_key,
            )
            .first()
        )
        if existing:
            if existing.payload_sha256 != payload_hash:
                raise WorkflowError(409, f"记录 {item.source_table}/{item.source_key} 重复且内容冲突")
            duplicates += 1
            continue
        hash_material = {
            "batch_id": batch.id,
            "source_entity": item.source_entity.upper(),
            "source_table": item.source_table,
            "source_key": item.source_key,
            "business_date": item.business_date,
            "payload_sha256": payload_hash,
            "previous_hash": previous_hash,
        }
        record_hash = _sha256(_canonical(hash_material))
        record = GspLegacyArchiveRecord(
            import_batch_id=batch.id,
            source_entity=item.source_entity.upper(),
            source_table=item.source_table,
            source_key=item.source_key,
            business_date=item.business_date,
            title=item.title,
            search_text=item.search_text,
            payload=item.payload,
            payload_sha256=payload_hash,
            attachment_manifest=[ref.model_dump() for ref in item.attachment_manifest],
            previous_hash=previous_hash,
            record_hash=record_hash,
            imported_by=actor_id,
        )
        db.add(record)
        db.flush()
        previous_hash = record_hash
        inserted += 1
    batch.imported_record_count += inserted
    batch.duplicate_record_count += duplicates
    batch.imported_by = actor_id
    batch.imported_at = utc_now()
    batch.status = "IMPORTED"
    hashes = [
        row.record_hash
        for row in db.query(GspLegacyArchiveRecord)
        .filter(GspLegacyArchiveRecord.import_batch_id == batch.id)
        .order_by(GspLegacyArchiveRecord.id)
    ]
    batch.aggregate_sha256 = _sha256("".join(hashes))
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="LEGACY_ARCHIVE_RECORDS_IMPORTED",
        entity_type="GspLegacyImportBatch",
        entity_id=str(batch.id),
        reason=payload.reason,
        after_data={
            "inserted": inserted,
            "duplicates": duplicates,
            "imported_record_count": batch.imported_record_count,
            "aggregate_sha256": batch.aggregate_sha256,
        },
        source_ip=source_ip,
    )
    return inserted, duplicates, batch


def reconcile_batch(
    db: Session,
    *,
    batch_id: int,
    payload: LegacyReconcile,
    actor_id: int,
    source_ip: str | None,
) -> tuple[GspLegacyImportBatch, list[GspLegacyReconciliationItem]]:
    batch = _batch(db, batch_id)
    if batch.status != "IMPORTED":
        raise WorkflowError(409, "只有已导入批次可以核对")
    if batch.imported_by == actor_id:
        raise WorkflowError(409, "迁移导入人与核对人必须分离")
    if any(value < 0 for value in payload.expected_by_entity.values()):
        raise WorkflowError(422, "各类预期记录数不能为负数")
    actual = Counter(
        row.source_entity
        for row in db.query(GspLegacyArchiveRecord)
        .filter(GspLegacyArchiveRecord.import_batch_id == batch.id)
        .all()
    )
    expected = {key.upper(): value for key, value in payload.expected_by_entity.items()}
    entities = sorted(set(actual) | set(expected))
    items = [
        GspLegacyReconciliationItem(
            import_batch_id=batch.id,
            source_entity=entity,
            expected_count=expected.get(entity, 0),
            actual_count=actual.get(entity, 0),
            matched=expected.get(entity, 0) == actual.get(entity, 0),
            checked_by=actor_id,
        )
        for entity in entities
    ]
    total_matches = sum(expected.values()) == batch.expected_record_count == batch.imported_record_count
    if not total_matches or not all(item.matched for item in items):
        raise WorkflowError(
            422,
            "迁移记录核对不通过",
            [
                {
                    "source_entity": item.source_entity,
                    "expected_count": item.expected_count,
                    "actual_count": item.actual_count,
                }
                for item in items
                if not item.matched
            ],
        )
    db.add_all(items)
    batch.status = "RECONCILED"
    batch.reconciled_by = actor_id
    batch.reconciled_at = utc_now()
    batch.reconciliation_evidence_ref = payload.evidence_ref
    batch.reconciliation_summary = {
        item.source_entity: {"expected": item.expected_count, "actual": item.actual_count} for item in items
    }
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action="LEGACY_ARCHIVE_BATCH_RECONCILED",
        entity_type="GspLegacyImportBatch",
        entity_id=str(batch.id),
        reason=payload.reason,
        after_data={
            "status": batch.status,
            "evidence_ref": payload.evidence_ref,
            "summary": batch.reconciliation_summary,
        },
        source_ip=source_ip,
    )
    return batch, items

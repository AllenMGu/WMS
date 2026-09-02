"""Immutable legacy GSP archive and reconciliation evidence."""

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
    event,
)

from app.core.database import Base
from app.core.time import utc_now


class GspLegacyImportBatch(Base):
    __tablename__ = "gsp_legacy_import_batches"

    id = Column(Integer, primary_key=True)
    batch_no = Column(String(100), nullable=False, unique=True)
    source_system = Column(String(100), nullable=False, index=True)
    source_instance = Column(String(200), nullable=False)
    manifest_version = Column(String(50), nullable=False)
    mapping_version = Column(String(50), nullable=False)
    package_sha256 = Column(String(64), nullable=False)
    retention_until = Column(Date, nullable=False, index=True)
    status = Column(String(30), nullable=False, default="DRAFT", index=True)
    expected_record_count = Column(Integer, nullable=False)
    imported_record_count = Column(Integer, nullable=False, default=0)
    duplicate_record_count = Column(Integer, nullable=False, default=0)
    aggregate_sha256 = Column(String(64), nullable=True)
    reconciliation_evidence_ref = Column(String(500), nullable=True)
    reconciliation_summary = Column(JSON, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    validated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    validated_at = Column(DateTime, nullable=True)
    imported_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    imported_at = Column(DateTime, nullable=True)
    reconciled_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reconciled_at = Column(DateTime, nullable=True)
    reason = Column(String(500), nullable=False)
    __table_args__ = (
        CheckConstraint(
            "status IN ('DRAFT','VALIDATED','IMPORTED','RECONCILED')",
            name="ck_gsp_legacy_batch_status",
        ),
        CheckConstraint("expected_record_count > 0", name="ck_gsp_legacy_expected_count"),
        CheckConstraint("imported_record_count >= 0", name="ck_gsp_legacy_imported_count"),
        CheckConstraint("duplicate_record_count >= 0", name="ck_gsp_legacy_duplicate_count"),
    )


class GspLegacyArchiveRecord(Base):
    __tablename__ = "gsp_legacy_archive_records"

    id = Column(Integer, primary_key=True)
    import_batch_id = Column(Integer, ForeignKey("gsp_legacy_import_batches.id"), nullable=False, index=True)
    source_entity = Column(String(50), nullable=False, index=True)
    source_table = Column(String(100), nullable=False, index=True)
    source_key = Column(String(200), nullable=False, index=True)
    business_date = Column(Date, nullable=True, index=True)
    title = Column(String(300), nullable=False)
    search_text = Column(Text, nullable=False)
    payload = Column(JSON, nullable=False)
    payload_sha256 = Column(String(64), nullable=False)
    attachment_manifest = Column(JSON, nullable=False, default=list)
    previous_hash = Column(String(64), nullable=True)
    record_hash = Column(String(64), nullable=False, unique=True)
    imported_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    imported_at = Column(DateTime, nullable=False, default=utc_now)
    __table_args__ = (
        UniqueConstraint(
            "import_batch_id", "source_table", "source_key", name="uq_gsp_legacy_batch_source_record"
        ),
    )


class GspLegacyReconciliationItem(Base):
    __tablename__ = "gsp_legacy_reconciliation_items"

    id = Column(Integer, primary_key=True)
    import_batch_id = Column(Integer, ForeignKey("gsp_legacy_import_batches.id"), nullable=False, index=True)
    source_entity = Column(String(50), nullable=False)
    expected_count = Column(Integer, nullable=False)
    actual_count = Column(Integer, nullable=False)
    matched = Column(Boolean, nullable=False)
    checked_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    checked_at = Column(DateTime, nullable=False, default=utc_now)
    __table_args__ = (
        UniqueConstraint("import_batch_id", "source_entity", name="uq_gsp_legacy_reconcile_entity"),
    )


def _immutable_archive(_mapper, _connection, _target) -> None:
    raise RuntimeError("老GSP归档记录及核对明细不可更新或删除")


for _model in (GspLegacyArchiveRecord, GspLegacyReconciliationItem):
    event.listen(_model, "before_update", _immutable_archive)
    event.listen(_model, "before_delete", _immutable_archive)

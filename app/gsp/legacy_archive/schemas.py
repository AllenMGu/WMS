from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, Field

from app.gsp.schemas import ChangeReason, OrmModel


class LegacyBatchCreate(ChangeReason):
    batch_no: str = Field(..., min_length=3, max_length=100)
    source_system: str = Field(..., min_length=2, max_length=100)
    source_instance: str = Field(..., min_length=2, max_length=200)
    manifest_version: str = Field(..., min_length=1, max_length=50)
    mapping_version: str = Field(..., min_length=1, max_length=50)
    package_sha256: str = Field(..., pattern="^[0-9a-f]{64}$")
    retention_until: date
    expected_record_count: int = Field(..., gt=0)


class LegacyBatchResponse(OrmModel):
    id: int
    batch_no: str
    source_system: str
    source_instance: str
    manifest_version: str
    mapping_version: str
    package_sha256: str
    retention_until: date
    status: str
    expected_record_count: int
    imported_record_count: int
    duplicate_record_count: int
    aggregate_sha256: str | None
    reconciliation_evidence_ref: str | None
    reconciliation_summary: dict[str, Any] | None
    created_by: int
    created_at: datetime
    validated_by: int | None
    validated_at: datetime | None
    imported_by: int | None
    imported_at: datetime | None
    reconciled_by: int | None
    reconciled_at: datetime | None
    reason: str


class LegacyAttachmentRef(BaseModel):
    reference: str = Field(..., min_length=1, max_length=500)
    sha256: str = Field(..., pattern="^[0-9a-f]{64}$")
    size_bytes: int = Field(..., gt=0)


class LegacyRecordInput(BaseModel):
    source_entity: str = Field(..., min_length=2, max_length=50)
    source_table: str = Field(..., min_length=1, max_length=100)
    source_key: str = Field(..., min_length=1, max_length=200)
    business_date: date | None = None
    title: str = Field(..., min_length=1, max_length=300)
    search_text: str = Field(..., min_length=1)
    payload: dict[str, Any]
    payload_sha256: str = Field(..., pattern="^[0-9a-f]{64}$")
    attachment_manifest: list[LegacyAttachmentRef] = Field(default_factory=list)


class LegacyRecordImport(ChangeReason):
    records: list[LegacyRecordInput] = Field(..., min_length=1, max_length=500)


class LegacyRecordResponse(OrmModel):
    id: int
    import_batch_id: int
    source_entity: str
    source_table: str
    source_key: str
    business_date: date | None
    title: str
    search_text: str
    payload: dict[str, Any]
    payload_sha256: str
    attachment_manifest: list[dict[str, Any]]
    previous_hash: str | None
    record_hash: str
    imported_by: int
    imported_at: datetime


class LegacyImportResult(BaseModel):
    inserted: int
    duplicates: int
    batch: LegacyBatchResponse


class LegacyReconcile(ChangeReason):
    expected_by_entity: dict[str, int]
    evidence_ref: str = Field(..., min_length=3, max_length=500)


class LegacyReconciliationItemResponse(OrmModel):
    id: int
    import_batch_id: int
    source_entity: str
    expected_count: int
    actual_count: int
    matched: bool
    checked_by: int
    checked_at: datetime

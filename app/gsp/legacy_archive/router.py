from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.dependencies import require_gsp_roles
from app.gsp.errors import WorkflowError
from app.gsp.legacy_archive.models import (
    GspLegacyArchiveRecord,
    GspLegacyImportBatch,
    GspLegacyReconciliationItem,
)
from app.gsp.legacy_archive.schemas import (
    LegacyBatchCreate,
    LegacyBatchResponse,
    LegacyImportResult,
    LegacyReconcile,
    LegacyReconciliationItemResponse,
    LegacyRecordImport,
    LegacyRecordResponse,
)
from app.gsp.legacy_archive.service import create_batch, import_records, reconcile_batch, validate_batch
from app.gsp.schemas import ChangeReason
from app.legacy import User

router = APIRouter(prefix="/gsp/legacy-archive", tags=["老GSP只读归档"])
ARCHIVE_READ_ROLES = ("SYSTEM_ADMIN", "QUALITY_MANAGER", "QUALITY_REVIEWER", "AUDITOR")
T = TypeVar("T")


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _execute(db: Session, operation: Callable[[], T]) -> T:
    try:
        result = operation()
        db.commit()
        return result
    except WorkflowError as error:
        db.rollback()
        raise HTTPException(error.status_code, error.detail) from error
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(409, "迁移批次或源记录重复") from error


@router.get("/batches", response_model=list[LegacyBatchResponse])
async def list_batches(
    status: str | None = None,
    current_user: User = Depends(require_gsp_roles(*ARCHIVE_READ_ROLES)),
    db: Session = Depends(get_db),
):
    query = db.query(GspLegacyImportBatch)
    if status:
        query = query.filter(GspLegacyImportBatch.status == status.upper())
    return query.order_by(GspLegacyImportBatch.id.desc()).all()


@router.post("/batches", response_model=LegacyBatchResponse, status_code=201)
async def new_batch(
    payload: LegacyBatchCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles("SYSTEM_ADMIN", "QUALITY_MANAGER")),
    db: Session = Depends(get_db),
):
    batch = _execute(
        db,
        lambda: create_batch(db, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)),
    )
    db.refresh(batch)
    return batch


@router.post("/batches/{batch_id}/validate", response_model=LegacyBatchResponse)
async def validate_import_batch(
    batch_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles("QUALITY_MANAGER", "QUALITY_REVIEWER", "AUDITOR")),
    db: Session = Depends(get_db),
):
    batch = _execute(
        db,
        lambda: validate_batch(
            db,
            batch_id=batch_id,
            reason=payload.reason,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        ),
    )
    db.refresh(batch)
    return batch


@router.post("/batches/{batch_id}/records", response_model=LegacyImportResult)
async def upload_records(
    batch_id: int,
    payload: LegacyRecordImport,
    request: Request,
    current_user: User = Depends(require_gsp_roles("SYSTEM_ADMIN", "QUALITY_MANAGER")),
    db: Session = Depends(get_db),
):
    inserted, duplicates, batch = _execute(
        db,
        lambda: import_records(
            db,
            batch_id=batch_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        ),
    )
    db.refresh(batch)
    return LegacyImportResult(inserted=inserted, duplicates=duplicates, batch=batch)


@router.post("/batches/{batch_id}/reconcile", response_model=LegacyBatchResponse)
async def reconcile_import_batch(
    batch_id: int,
    payload: LegacyReconcile,
    request: Request,
    current_user: User = Depends(require_gsp_roles("QUALITY_REVIEWER", "AUDITOR")),
    db: Session = Depends(get_db),
):
    batch, _ = _execute(
        db,
        lambda: reconcile_batch(
            db,
            batch_id=batch_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        ),
    )
    db.refresh(batch)
    return batch


@router.get("/records", response_model=list[LegacyRecordResponse])
async def list_records(
    batch_id: int | None = None,
    source_entity: str | None = None,
    query_text: str | None = Query(None, alias="q", max_length=200),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(require_gsp_roles(*ARCHIVE_READ_ROLES)),
    db: Session = Depends(get_db),
):
    query = (
        db.query(GspLegacyArchiveRecord)
        .join(GspLegacyImportBatch)
        .filter(GspLegacyImportBatch.status == "RECONCILED")
    )
    if batch_id:
        query = query.filter(GspLegacyArchiveRecord.import_batch_id == batch_id)
    if source_entity:
        query = query.filter(GspLegacyArchiveRecord.source_entity == source_entity.upper())
    if query_text:
        pattern = f"%{query_text}%"
        query = query.filter(
            or_(
                GspLegacyArchiveRecord.title.ilike(pattern),
                GspLegacyArchiveRecord.search_text.ilike(pattern),
                GspLegacyArchiveRecord.source_key.ilike(pattern),
            )
        )
    return query.order_by(GspLegacyArchiveRecord.id.desc()).offset(offset).limit(limit).all()


@router.get(
    "/batches/{batch_id}/reconciliation",
    response_model=list[LegacyReconciliationItemResponse],
)
async def list_reconciliation(
    batch_id: int,
    current_user: User = Depends(require_gsp_roles(*ARCHIVE_READ_ROLES)),
    db: Session = Depends(get_db),
):
    return (
        db.query(GspLegacyReconciliationItem)
        .filter(GspLegacyReconciliationItem.import_batch_id == batch_id)
        .order_by(GspLegacyReconciliationItem.source_entity)
        .all()
    )


@router.get("/batches/{batch_id}/export")
async def export_batch(
    batch_id: int,
    current_user: User = Depends(require_gsp_roles(*ARCHIVE_READ_ROLES)),
    db: Session = Depends(get_db),
):
    batch = db.get(GspLegacyImportBatch, batch_id)
    if batch is None:
        raise HTTPException(404, "老GSP迁移批次不存在")
    if batch.status != "RECONCILED":
        raise HTTPException(409, "只有核对通过的批次可以导出")
    records = (
        db.query(GspLegacyArchiveRecord)
        .filter(GspLegacyArchiveRecord.import_batch_id == batch_id)
        .order_by(GspLegacyArchiveRecord.id)
        .all()
    )

    def rows() -> Iterator[str]:
        for record in records:
            yield (
                json.dumps(
                    {
                        "source_entity": record.source_entity,
                        "source_table": record.source_table,
                        "source_key": record.source_key,
                        "business_date": record.business_date,
                        "title": record.title,
                        "payload": record.payload,
                        "payload_sha256": record.payload_sha256,
                        "attachment_manifest": record.attachment_manifest,
                        "previous_hash": record.previous_hash,
                        "record_hash": record.record_hash,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
                )
                + "\n"
            )

    return StreamingResponse(
        rows(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{batch.batch_no}.jsonl"'},
    )

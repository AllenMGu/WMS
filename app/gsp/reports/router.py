"""HTTP API for business reports and controlled printing.

All operations require an active GSP role; each print writes a
``GspControlledPrintRecord`` (content hash + snapshot) and an audit event.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.audit import write_audit_event
from app.gsp.dependencies import require_any_gsp_role
from app.gsp.procurement_receiving.models import GspControlledPrintRecord
from app.gsp.reports import (
    record_print,
    render_printable_html,
    report_catalog,
    run_report,
)
from app.gsp.schemas import OrmModel
from app.legacy import User

router = APIRouter(prefix="/gsp/reports", tags=["GSP业务报表"])


class PrintRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)
    limit: int = Field(200, ge=1, le=1000)
    filters: dict[str, str] = Field(default_factory=dict)


class ReportPrintResponse(BaseModel):
    print_id: int
    copy_no: str
    content_hash: str
    html: str


class PrintRecordOut(OrmModel):
    id: int
    document_type: str
    copy_no: str
    purpose: str
    status: str
    content_hash: str | None
    printed_by: int
    printed_at: datetime
    snapshot_data: dict | None


def _source_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


@router.get("", response_model=list[dict])
def list_reports(
    current_user: User = Depends(require_any_gsp_role),
):
    return report_catalog()


@router.get("/{report_key}", response_model=dict)
def query_report(
    report_key: str,
    request: Request,
    limit: int = Query(200, ge=1, le=1000),
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    filters = {k: v for k, v in request.query_params.items() if k != "limit"}
    try:
        return run_report(db, report_key, filters=filters, limit=limit)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="报表不存在") from exc


@router.post("/{report_key}/print", response_model=ReportPrintResponse)
def print_report(
    report_key: str,
    payload: PrintRequest,
    request: Request,
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    try:
        result = run_report(db, report_key, filters=payload.filters, limit=payload.limit)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="报表不存在") from exc
    html = render_printable_html(
        report_key,
        result,
        generated_by=current_user.full_name or current_user.username,
        reason=payload.reason,
    )
    record = record_print(
        db,
        key=report_key,
        content_html=html,
        result=result,
        printed_by=current_user.id,
        purpose=payload.reason,
    )
    write_audit_event(
        db,
        actor_user_id=current_user.id,
        action="REPORT_PRINTED",
        entity_type="GspControlledPrintRecord",
        entity_id=str(record.id),
        reason=payload.reason,
        after_data={
            "report_key": report_key,
            "copy_no": record.copy_no,
            "content_hash": record.content_hash,
            "count": result["count"],
        },
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(record)
    return ReportPrintResponse(
        print_id=record.id,
        copy_no=record.copy_no,
        content_hash=record.content_hash or "",
        html=html,
    )


@router.get("/prints/list", response_model=list[PrintRecordOut])
def list_print_records(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    return (
        db.query(GspControlledPrintRecord)
        .filter(GspControlledPrintRecord.document_type.like("REPORT:%"))
        .order_by(GspControlledPrintRecord.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

"""HTTP API for business reports and controlled printing (P1, reviewed)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.time import utc_now
from app.gsp.audit import write_audit_event
from app.gsp.dependencies import require_any_gsp_role
from app.gsp.models import GspRoleAssignment
from app.gsp.procurement_receiving.models import GspControlledPrintRecord
from app.gsp.reports import (
    _REPORT_MAP,
    ReportError,
    record_print,
    render_printable_html,
    report_catalog,
    run_full_print_rows,
    run_report,
    verify_record_content,
    visible_report_keys,
)
from app.legacy import User

router = APIRouter(prefix="/gsp/reports", tags=["GSP业务报表"])


class PrintRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)
    limit: int = Field(200, ge=1, le=1000)
    offset: int = Field(0, ge=0)
    filters: dict[str, str] = Field(default_factory=dict)
    cover_all: bool = False


class PrintVerifyOut(BaseModel):
    print_id: int
    valid: bool


class PrintOut(BaseModel):
    print_id: int
    copy_no: str
    content_hash: str
    html: str


def _source_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


def _user_roles(db: Session, user_id: int) -> set[str]:
    now = utc_now()
    rows = (
        db.query(GspRoleAssignment.role)
        .filter(
            GspRoleAssignment.user_id == user_id,
            GspRoleAssignment.is_active.is_(True),
            GspRoleAssignment.review_due_at > now,
            (GspRoleAssignment.expires_at.is_(None) | (GspRoleAssignment.expires_at > now)),
        )
        .all()
    )
    return {role for (role,) in rows}


def _ensure_report_access(db: Session, report_key: str, user: User) -> None:
    definition = _REPORT_MAP.get(report_key)
    if definition is None:
        raise HTTPException(status_code=404, detail="报表不存在")
    roles = _user_roles(db, user.id)
    if not definition.allowed_for(roles):
        raise HTTPException(
            status_code=403,
            detail="当前岗位无权访问该报表（需要：%s）"
            % (", ".join(definition.roles) if definition.roles else "任一GSP岗位"),
        )


def _visible_keys(db: Session, user: User) -> set[str]:
    return visible_report_keys(_user_roles(db, user.id))


def _report_key_of(record: GspControlledPrintRecord) -> str | None:
    prefix = "REPORT:"
    dtype = record.document_type or ""
    return dtype[len(prefix):] if dtype.startswith(prefix) else None


def _get_report_record(db: Session, print_id: int) -> GspControlledPrintRecord:
    record = db.get(GspControlledPrintRecord, print_id)
    if record is None or not (record.document_type or "").startswith("REPORT:"):
        raise HTTPException(status_code=404, detail="受控打印记录不存在")
    return record


@router.get("", response_model=list[dict])
def list_reports(
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    return report_catalog(visible_keys=_visible_keys(db, current_user))


@router.get("/{report_key}", response_model=dict)
def query_report(
    report_key: str,
    request: Request,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    _ensure_report_access(db, report_key, current_user)
    filters = {k: v for k, v in request.query_params.items() if k not in ("limit", "offset")}
    try:
        return run_report(db, report_key, filters=filters, limit=limit, offset=offset)
    except ReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="报表不存在") from exc


@router.post("/{report_key}/print", response_model=PrintOut)
def print_report(
    report_key: str,
    payload: PrintRequest,
    request: Request,
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    _ensure_report_access(db, report_key, current_user)
    definition = _REPORT_MAP[report_key]
    try:
        if payload.cover_all:
            result = run_full_print_rows(db, report_key, filters=payload.filters)
            truncated = False  # full print either covers all or raised (MAX_ROWS)
        else:
            result = run_report(
                db, report_key,
                filters=payload.filters, limit=payload.limit, offset=payload.offset,
            )
            truncated = result["has_more"]
    except ReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="报表不存在") from exc

    copy_no = f"RPT-{report_key[:8].upper()}-{uuid.uuid4().hex[:12].upper()}"
    html = render_printable_html(
        result,
        meta={
            "copy_no": copy_no,
            "template_version": definition.template_version,
            "generated_by": current_user.full_name or current_user.username,
            "reason": payload.reason,
            "filters": result["filters"],
            "truncated": truncated,
        },
    )
    record = record_print(
        db,
        key=report_key,
        content_html=html,
        result=result,
        printed_by=current_user.id,
        purpose=payload.reason,
        cover_all=payload.cover_all,
        copy_no=copy_no,
        template_version=definition.template_version,
        truncated=truncated,
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
            "template_version": definition.template_version,
            "content_hash": record.content_hash,
            "count": result["count"],
            "total": result["total"],
            "truncated": truncated,
        },
        source_ip=_source_ip(request),
    )
    db.commit()
    db.refresh(record)
    return PrintOut(print_id=record.id, copy_no=record.copy_no,
                    content_hash=record.content_hash or "", html=html)


@router.get("/prints/list", response_model=list[dict])
def list_print_records(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    visible = _visible_keys(db, current_user)
    records = (
        db.query(GspControlledPrintRecord)
        .filter(GspControlledPrintRecord.document_type.like("REPORT:%"))
        .order_by(GspControlledPrintRecord.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    out = []
    for r in records:
        key = _report_key_of(r)
        if key is None or key not in visible:
            continue
        out.append({
            "id": r.id, "copy_no": r.copy_no, "document_type": r.document_type,
            "purpose": r.purpose, "content_hash": r.content_hash,
            "printed_by": r.printed_by, "printed_at": r.printed_at,
            "snapshot": {
                "title": (r.snapshot_data or {}).get("title"),
                "template_version": (r.snapshot_data or {}).get("template_version"),
                "count": (r.snapshot_data or {}).get("count"),
                "total": (r.snapshot_data or {}).get("total"),
                "truncated": (r.snapshot_data or {}).get("truncated"),
                "cover_all": (r.snapshot_data or {}).get("cover_all"),
                "filters": (r.snapshot_data or {}).get("filters"),
            },
        })
    return out


@router.get("/prints/{print_id}", response_model=PrintOut)
def fetch_print(
    print_id: int,
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    record = _get_report_record(db, print_id)
    key = _report_key_of(record)
    if key:
        _ensure_report_access(db, key, current_user)
    html = (record.snapshot_data or {}).get("html") or ""
    return PrintOut(print_id=record.id, copy_no=record.copy_no,
                    content_hash=record.content_hash or "", html=html)


@router.post("/prints/{print_id}/verify", response_model=PrintVerifyOut)
def verify_print(
    print_id: int,
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    record = _get_report_record(db, print_id)
    key = _report_key_of(record)
    if key:
        _ensure_report_access(db, key, current_user)
    return PrintVerifyOut(print_id=record.id, valid=verify_record_content(record))

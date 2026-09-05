"""HTTP API for controlled GSP file objects (upload / meta / download / verify / disable).

All operations require an active GSP role and write to the append-only audit
trail.  Disabling (the only lifecycle change, no delete) additionally requires
a quality manager.  Every handler validates server-side truth: hashes and the
content type are decided by the server, and downloads re-verify the stored
bytes before any are returned.  Business-row creation and its audit event are
committed in a single database transaction so an audit failure cannot leave a
controlled file without its FILE_UPLOADED trail.
"""

from __future__ import annotations

import os
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.time import utc_now
from app.gsp.attachments import storage
from app.gsp.attachments.models import (
    STATUS_ACTIVE,
    STATUS_DISABLED,
    GspControlledFile,
)
from app.gsp.attachments.schemas import (
    ControlledFileOut,
    FileActionIn,
    FileVerifyResult,
    UploadRequest,
)
from app.gsp.audit import write_audit_event
from app.gsp.dependencies import require_any_gsp_role
from app.gsp.models import GspRoleAssignment
from app.legacy import User

router = APIRouter(prefix="/gsp/files", tags=["GSP受控附件"])


def _audit(db: Session, actor: User, action: str, entity_id: str, reason: str) -> None:
    write_audit_event(
        db,
        actor_user_id=actor.id,
        action=action,
        entity_type="GspControlledFile",
        entity_id=entity_id,
        reason=reason,
    )


def _commit_with_audit(
    db: Session, actor: User, action: str, entity_id: str, reason: str
) -> None:
    """Append the audit event and commit as one transaction.

    If the audit write or the commit fails, the whole transaction is rolled
    back so a business change can never survive without its audit trail.
    """
    try:
        _audit(db, actor, action, entity_id, reason)
        db.commit()
    except Exception:
        db.rollback()
        raise


def _get_or_404(db: Session, object_key: str) -> GspControlledFile:
    obj = (
        db.query(GspControlledFile)
        .filter(GspControlledFile.object_key == object_key)
        .first()
    )
    if obj is None:
        raise HTTPException(status_code=404, detail="受控文件不存在")
    return obj


def _integrity_ok(obj: GspControlledFile) -> bool:
    result = storage.verify_stored(obj.sha256, obj.size_bytes, full_hash=True)
    return bool(
        result["exists_on_disk"]
        and result["size_matches"]
        and result["sha256_matches"]
    )


@router.post("", status_code=201, response_model=ControlledFileOut)
def upload_file(
    file: UploadFile = File(...),
    purpose: str = Form("OTHER"),
    note: str | None = Form(None),
    expected_sha256: str | None = Form(None),
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    request = UploadRequest(purpose=purpose, note=note, expected_sha256=expected_sha256)
    try:
        request.validate_purpose()
        stored = storage.store_stream(
            file.file,
            content_type=file.content_type or "",
            expected_sha256=request.expected_sha256,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    file_name = (os.path.basename(file.filename or "") or "unnamed")[:255]
    obj = GspControlledFile(
        object_key=uuid.uuid4().hex,
        file_name=file_name,
        content_type=stored.content_type,
        size_bytes=stored.size_bytes,
        sha256=stored.sha256,
        purpose=request.purpose,
        status=STATUS_ACTIVE,
        uploaded_by=current_user.id,
        uploaded_at=utc_now(),
        note=request.note,
    )
    db.add(obj)
    try:
        db.flush()  # assign obj.id inside the same transaction as the audit row
        _commit_with_audit(
            db,
            current_user,
            "FILE_UPLOADED",
            str(obj.id),
            f"上传受控文件 {file_name}（{request.purpose}，{stored.size_bytes} 字节，"
            f"{stored.content_type}）",
        )
    except Exception:
        db.rollback()
        raise
    db.refresh(obj)
    return ControlledFileOut.from_model(obj)


@router.get("/{object_key}", response_model=ControlledFileOut)
def file_meta(
    object_key: str,
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    return ControlledFileOut.from_model(_get_or_404(db, object_key))


@router.get("/{object_key}/content")
def file_content(
    object_key: str,
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    """Download only after re-verifying size + SHA-256 of the stored bytes."""
    obj = _get_or_404(db, object_key)
    if obj.status != STATUS_ACTIVE:
        raise HTTPException(status_code=410, detail="受控文件已停用，禁止下载")
    if not _integrity_ok(obj):
        try:
            _commit_with_audit(
                db,
                current_user,
                "FILE_INTEGRITY_LOST",
                str(obj.id),
                "下载前完整性校验失败（大小或 SHA-256 不符），已拒绝返回内容",
            )
        except Exception:
            db.rollback()
            raise
        raise HTTPException(
            status_code=410,
            detail="受控文件完整性校验失败，已拒绝下载，请联系质量部门",
        )
    path = storage.content_path(obj.sha256)
    _commit_with_audit(
        db, current_user, "FILE_DOWNLOADED", str(obj.id), f"下载受控文件 {obj.file_name}"
    )
    return FileResponse(
        path,
        media_type=obj.content_type,
        filename=obj.file_name,
        headers={"X-Controlled-File-Ref": f"gspf:{obj.object_key}"},
    )


@router.post("/{object_key}/verify", response_model=FileVerifyResult)
def verify_file(
    object_key: str,
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    obj = _get_or_404(db, object_key)
    result = storage.verify_stored(obj.sha256, obj.size_bytes, full_hash=True)
    valid = bool(
        result["exists_on_disk"]
        and result["size_matches"]
        and result["sha256_matches"]
    )
    _commit_with_audit(
        db,
        current_user,
        "FILE_VERIFIED" if valid else "FILE_VERIFY_FAILED",
        str(obj.id),
        f"完整性校验{'通过' if valid else '失败'}：存储中存在={result['exists_on_disk']}",
    )
    return FileVerifyResult(
        object_key=obj.object_key,
        ref=f"gspf:{obj.object_key}",
        sha256=obj.sha256,
        size_bytes=obj.size_bytes,
        exists_on_disk=result["exists_on_disk"],
        size_matches=result["size_matches"],
        sha256_matches=result["sha256_matches"],
        valid=valid,
    )


def _may_disable(db: Session, obj: GspControlledFile, user: User) -> bool:
    """Quality managers may disable any file; the uploader may retire their own
    (e.g. an unbound attachment abandoned by a cancelled form)."""
    now = utc_now()
    roles = {
        row.role
        for row in db.query(GspRoleAssignment).filter(
            GspRoleAssignment.user_id == user.id,
            GspRoleAssignment.is_active.is_(True),
            GspRoleAssignment.review_due_at > now,
            (
                GspRoleAssignment.expires_at.is_(None)
                | (GspRoleAssignment.expires_at > now)
            ),
        )
    }
    return "QUALITY_MANAGER" in roles or obj.uploaded_by == user.id


@router.post("/{object_key}/disable", response_model=ControlledFileOut)
def disable_file(
    object_key: str,
    payload: FileActionIn,
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    """停用附件（不删除字节与审计记录；停用后禁止新下载/新引用）。

    质量经理可停用任意文件；上传人本人可停用自己的文件（用于清理未绑定/
    误传的受控对象）。
    """
    obj = _get_or_404(db, object_key)
    if not _may_disable(db, obj, current_user):
        raise HTTPException(status_code=403, detail="仅质量经理或上传人本人可以停用该受控文件")
    if obj.status == STATUS_DISABLED:
        # Idempotent: already retired by an earlier attempt (e.g. double
        # cancellation from the browser); do not emit a second audit row.
        return ControlledFileOut.from_model(obj)
    obj.status = STATUS_DISABLED
    _commit_with_audit(
        db, current_user, "FILE_DISABLED", str(obj.id), payload.reason
    )
    db.refresh(obj)
    return ControlledFileOut.from_model(obj)

"""HTTP API for controlled GSP file objects (upload / meta / download / verify / disable).

All operations require an active GSP role and write to the append-only audit
trail.  Disabling (the only lifecycle change, no delete) additionally requires
a quality manager.  Every handler validates server-side truth: hashes are
computed by the store and client-declared hashes are cross-checked.
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
from app.gsp.dependencies import (
    require_any_gsp_role,
    require_quality_manager_or_bootstrap,
)
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


def _get_or_404(db: Session, object_key: str) -> GspControlledFile:
    obj = (
        db.query(GspControlledFile)
        .filter(GspControlledFile.object_key == object_key)
        .first()
    )
    if obj is None:
        raise HTTPException(status_code=404, detail="受控文件不存在")
    return obj


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
        content_type=_content_type_label(file),
        size_bytes=stored.size_bytes,
        sha256=stored.sha256,
        purpose=request.purpose,
        status=STATUS_ACTIVE,
        uploaded_by=current_user.id,
        uploaded_at=utc_now(),
        note=request.note,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    _audit(
        db,
        current_user,
        "FILE_UPLOADED",
        str(obj.id),
        f"上传受控文件 {file_name}（{request.purpose}，{stored.size_bytes} 字节）",
    )
    db.commit()
    return ControlledFileOut.from_model(obj)


def _content_type_label(file: UploadFile) -> str:
    normalized = (file.content_type or "").split(";")[0].strip().lower()
    if normalized in storage.ALLOWED_CONTENT_TYPES:
        return normalized
    return "application/octet-stream"


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
    obj = _get_or_404(db, object_key)
    if obj.status != STATUS_ACTIVE:
        raise HTTPException(status_code=410, detail="受控文件已停用，禁止下载")
    path = storage.content_path(obj.sha256)
    if not os.path.exists(path):
        _audit(db, current_user, "FILE_INTEGRITY_LOST", str(obj.id), "下载时发现受控文件缺失")
        db.commit()
        raise HTTPException(status_code=410, detail="受控文件在存储中缺失，请联系质量部门")
    _audit(db, current_user, "FILE_DOWNLOADED", str(obj.id), f"下载受控文件 {obj.file_name}")
    db.commit()
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
    _audit(
        db,
        current_user,
        "FILE_VERIFIED" if valid else "FILE_VERIFY_FAILED",
        str(obj.id),
        f"完整性校验{'通过' if valid else '失败'}：存储中存在={result['exists_on_disk']}",
    )
    db.commit()
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


@router.post("/{object_key}/disable", response_model=ControlledFileOut)
def disable_file(
    object_key: str,
    payload: FileActionIn,
    current_user: User = Depends(require_quality_manager_or_bootstrap),
    db: Session = Depends(get_db),
):
    """质量经理停用附件（不删除字节与审计记录；停用后禁止新下载/新引用）。"""
    obj = _get_or_404(db, object_key)
    if obj.status == STATUS_ACTIVE:
        obj.status = STATUS_DISABLED
        db.commit()
        db.refresh(obj)
    _audit(
        db,
        current_user,
        "FILE_DISABLED",
        str(obj.id),
        payload.reason,
    )
    db.commit()
    return ControlledFileOut.from_model(obj)

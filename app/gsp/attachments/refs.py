"""Reference-token helpers that bridge controlled files and business records.

Business records that carry an evidence attachment keep using the existing
``file_ref`` text column, but a new record must reference a server-issued
token of the form ``gspf:<object_key>``.  These helpers make that validation
uniform so no endpoint can silently accept a fabricated reference.
"""

from __future__ import annotations

import re

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.gsp.attachments.models import (
    STATUS_ACTIVE,
    GspControlledFile,
)

REF_PREFIX = "gspf:"
_TOKEN_RE = re.compile(r"^gspf:([0-9a-f]{32})$")


def build_ref(object_key: str) -> str:
    return f"{REF_PREFIX}{object_key}"


def parse_ref(value: str | None) -> str | None:
    """Return the object_key if ``value`` is a well-formed token, else None."""
    if not value:
        return None
    match = _TOKEN_RE.match(value.strip())
    return match.group(1) if match else None


def is_controlled_ref(value: str | None) -> bool:
    return parse_ref(value) is not None


def require_active_file(db: Session, value: str) -> GspControlledFile:
    """Resolve an enforced controlled-file reference or raise HTTP 422/410."""
    object_key = parse_ref(value)
    if not object_key:
        raise HTTPException(
            status_code=422,
            detail="附件引用无效：必须使用受控文件上传接口签发的 gspf:<object_key> 引用",
        )
    obj = (
        db.query(GspControlledFile)
        .filter(GspControlledFile.object_key == object_key)
        .first()
    )
    if obj is None:
        raise HTTPException(status_code=422, detail="受控文件引用不存在或已被移除")
    if obj.status != STATUS_ACTIVE:
        raise HTTPException(status_code=410, detail="受控文件已被停用，禁止引用新业务记录")
    return obj


def active_file_by_key(db: Session, object_key: str) -> GspControlledFile | None:
    return (
        db.query(GspControlledFile)
        .filter(
            GspControlledFile.object_key == object_key,
            GspControlledFile.status == STATUS_ACTIVE,
        )
        .first()
    )

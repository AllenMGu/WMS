"""Binding of business records to controlled (server-side) file objects.

Every qualification/authorisation record that carries an evidence attachment
stores ``file_ref`` + ``file_sha256`` + ``file_size_bytes``.  This module makes
that contract server-side truth:

* a ``gspf:<object_key>`` reference must resolve to an existing ACTIVE
  controlled file, whose recorded purpose matches the business scenario (or is
  ``OTHER``); the persisted SHA-256/size are then taken from the controlled
  object -- client-supplied values are ignored;
* with ``ATTACHMENT_POLICY=enforce`` a plain (legacy) reference is rejected so
  a record can never cite bytes the server does not hold;
* with the default ``warn`` policy legacy references remain accepted unchanged
  (historical/imported data), but token references are still validated.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.gsp.attachments.models import (
    ALLOWED_PURPOSES,
    PURPOSE_OTHER,
    STATUS_ACTIVE,
    GspControlledFile,
)
from app.gsp.attachments.refs import REF_PREFIX, build_ref, parse_ref

ATTACHMENT_POLICY_ENV = "ATTACHMENT_POLICY"


def effective_policy() -> str:
    """warn | enforce -- validated strictly, fail closed on anything else."""
    raw = os.getenv(ATTACHMENT_POLICY_ENV)
    value = ((raw if raw is not None else settings.attachment_policy) or "warn").strip().lower()
    if value not in {"warn", "enforce"}:
        raise RuntimeError(
            f"ATTACHMENT_POLICY 必须是 warn 或 enforce（当前值 {value!r}），禁止 fail-open 默认"
        )
    return value


def validate_purpose(purpose: str | None) -> None:
    if purpose not in ALLOWED_PURPOSES:
        raise HTTPException(
            status_code=422,
            detail=f"purpose 必须为 {', '.join(ALLOWED_PURPOSES)} 之一",
        )


#: Business tables/columns that may carry a bound ``gspf:`` reference.
REFERENCE_COLUMNS = (
    ("gsp_partner_documents", "file_ref"),
    ("gsp_supplier_product_authorizations", "authorization_ref"),
    ("gsp_drug_profiles", "registration_document_ref"),
    ("gsp_carrier_documents", "file_ref"),
)


def referenced_by_business(db: Session, object_key: str) -> bool:
    """True when any business record already binds this controlled object."""
    token = build_ref(object_key)
    for table, column in REFERENCE_COLUMNS:
        row = db.execute(
            text(f"SELECT 1 FROM {table} WHERE {column} = :v LIMIT 1"),
            {"v": token},
        ).first()
        if row is not None:
            return True
    return False


def resolve_attachment(
    db: Session,
    *,
    value: str | None,
    expected_purpose: str,
    declared_sha: str | None = None,
    declared_size: int | None = None,
) -> tuple[str | None, str | None, int | None]:
    """Resolve a submitted attachment reference to persisted values.

    Returns ``(file_ref, file_sha256, file_size_bytes)`` ready to be stored on
    the business record.  Raises HTTP 422/410 when the value is a controlled
    reference that cannot be honoured, or when ``enforce`` forbids a legacy
    (non-token) reference.
    """
    if not value:
        return None, None, None
    object_key = parse_ref(value)
    stripped = value.strip()
    if object_key is None:
        # A reference that *claims* to be controlled but cannot be parsed must
        # never be persisted, regardless of the policy.
        if stripped.startswith(REF_PREFIX):
            raise HTTPException(
                status_code=422,
                detail=f"{REF_PREFIX}<key> 引用格式无效（需 32 位小写十六进制 key），已拒绝",
            )
        if effective_policy() == "enforce":
            raise HTTPException(
                status_code=422,
                detail=(
                    "ATTACHMENT_POLICY=enforce：本场景必须使用受控文件上传接口签发的 "
                    f"{REF_PREFIX}<key> 引用，已拒绝非受控引用"
                ),
            )
        return value, declared_sha, declared_size

    obj = (
        db.query(GspControlledFile)
        .filter(
            GspControlledFile.object_key == object_key,
            GspControlledFile.status == STATUS_ACTIVE,
        )
        .with_for_update()
        .first()
    )
    if obj is None:
        raise HTTPException(status_code=422, detail="受控文件引用不存在或已被停用，拒绝引用")
    if obj.purpose not in (expected_purpose, PURPOSE_OTHER):
        raise HTTPException(
            status_code=422,
            detail=(
                f"受控文件用途（{obj.purpose}）与本业务场景（{expected_purpose}）不符，"
                "请重新上传正确的附件"
            ),
        )
    # Server-side truth wins: ignore any client-declared hash/size.
    return build_ref(obj.object_key), obj.sha256, obj.size_bytes


def attachment_markdown_hint(policy: str | None = None) -> str:
    pol = (policy or effective_policy()).upper()
    return f"当前 ATTACHMENT_POLICY={pol}"


def purpose_for(domain: str) -> str:
    """Map a business domain label to its controlled-file purpose."""
    mapping = {
        "partner_document": "PARTNER_DOCUMENT",
        "supplier_product_authorization": "SUPPLIER_PRODUCT_AUTHORIZATION",
        "drug_registration": "DRUG_REGISTRATION",
        "carrier_document": "CARRIER_DOCUMENT",
        "csv_evidence": "CSV_EVIDENCE",
    }
    return mapping.get(domain, PURPOSE_OTHER)


# Re-export for callers that only need the token helpers.
__all__ = [
    "ATTACHMENT_POLICY_ENV",
    "effective_policy",
    "validate_purpose",
    "resolve_attachment",
    "attachment_markdown_hint",
    "purpose_for",
    "ALLOWED_PURPOSES",
    "Any",
]

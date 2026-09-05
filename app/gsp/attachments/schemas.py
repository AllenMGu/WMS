"""Request/response models for the controlled-file API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.gsp.attachments.models import (
    ALLOWED_PURPOSES,
    PURPOSE_OTHER,
)
from app.gsp.attachments.refs import REF_PREFIX


class UploadRequest(BaseModel):
    purpose: str = Field(
        PURPOSE_OTHER,
        description="附件用途（PARTNER_DOCUMENT/SUPPLIER_PRODUCT_AUTHORIZATION/"
        "DRUG_REGISTRATION/CARRIER_DOCUMENT/CSV_EVIDENCE/OTHER）",
    )
    note: str | None = Field(None, max_length=500)
    expected_sha256: str | None = Field(
        None,
        pattern="^[0-9a-f]{64}$",
        description="客户端对原始文件的 SHA-256；不一致将被服务端拒收（数据完整性双校验）",
    )

    def validate_purpose(self) -> None:
        if self.purpose not in ALLOWED_PURPOSES:
            raise ValueError(f"purpose 必须为 {', '.join(ALLOWED_PURPOSES)} 之一")


class ControlledFileOut(BaseModel):
    id: int
    object_key: str
    ref: str
    file_name: str
    content_type: str
    size_bytes: int
    sha256: str
    purpose: str
    status: str
    note: str | None
    uploaded_by: int
    uploaded_at: datetime

    @classmethod
    def from_model(cls, obj) -> "ControlledFileOut":
        return cls(
            id=obj.id,
            object_key=obj.object_key,
            ref=f"{REF_PREFIX}{obj.object_key}",
            file_name=obj.file_name,
            content_type=obj.content_type,
            size_bytes=obj.size_bytes,
            sha256=obj.sha256,
            purpose=obj.purpose,
            status=obj.status,
            note=obj.note,
            uploaded_by=obj.uploaded_by,
            uploaded_at=obj.uploaded_at,
        )


class FileVerifyResult(BaseModel):
    object_key: str
    ref: str
    sha256: str
    size_bytes: int
    exists_on_disk: bool
    size_matches: bool
    sha256_matches: bool | None
    valid: bool


class FileActionIn(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)

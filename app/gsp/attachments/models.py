"""Persistence model for controlled (server-side) GSP file objects.

Content-addressed by SHA-256 and treated as immutable: an uploaded object is
never overwritten or deleted through the API; the only lifecycle transition is
``ACTIVE -> DISABLED`` performed by a quality manager (disabling keeps the
bytes and the audit trail for inspection, it only blocks new downloads).
"""

from __future__ import annotations

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)

from app.core.database import Base
from app.core.time import utc_now

#: Purposes the upstream business records bind to.  Kept small and explicit so
#: that compliance reporting can enumerate every attachment category.
PURPOSE_PARTNER_DOCUMENT = "PARTNER_DOCUMENT"
PURPOSE_SUPPLIER_PRODUCT_AUTHORIZATION = "SUPPLIER_PRODUCT_AUTHORIZATION"
PURPOSE_DRUG_REGISTRATION = "DRUG_REGISTRATION"
PURPOSE_CARRIER_DOCUMENT = "CARRIER_DOCUMENT"
PURPOSE_CSV_EVIDENCE = "CSV_EVIDENCE"
PURPOSE_OTHER = "OTHER"

ALLOWED_PURPOSES = (
    PURPOSE_PARTNER_DOCUMENT,
    PURPOSE_SUPPLIER_PRODUCT_AUTHORIZATION,
    PURPOSE_DRUG_REGISTRATION,
    PURPOSE_CARRIER_DOCUMENT,
    PURPOSE_CSV_EVIDENCE,
    PURPOSE_OTHER,
)

STATUS_ACTIVE = "ACTIVE"
STATUS_DISABLED = "DISABLED"
ALLOWED_STATUSES = (STATUS_ACTIVE, STATUS_DISABLED)


class GspControlledFile(Base):
    __tablename__ = "gsp_controlled_files"

    id = Column(Integer, primary_key=True)
    #: Public token suffix (uuid4 hex).  Reference format: ``gspf:<object_key>``.
    object_key = Column(String(32), nullable=False)
    file_name = Column(String(255), nullable=False)
    content_type = Column(String(120), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    #: Server-computed SHA-256 (hex) over the received bytes.
    sha256 = Column(String(64), nullable=False)
    purpose = Column(String(60), nullable=False, default=PURPOSE_OTHER)
    status = Column(String(16), nullable=False, default=STATUS_ACTIVE)
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    uploaded_at = Column(DateTime, nullable=False, default=utc_now)
    note = Column(String(500), nullable=True)

    __table_args__ = (
        UniqueConstraint("object_key", name="uq_gsp_controlled_files_object_key"),
        CheckConstraint("size_bytes > 0", name="ck_gsp_controlled_files_size_positive"),
        CheckConstraint(
            "status IN ('ACTIVE', 'DISABLED')", name="ck_gsp_controlled_files_status"
        ),
        CheckConstraint(
            "purpose IN ('PARTNER_DOCUMENT', 'SUPPLIER_PRODUCT_AUTHORIZATION', "
            "'DRUG_REGISTRATION', 'CARRIER_DOCUMENT', 'CSV_EVIDENCE', 'OTHER')",
            name="ck_gsp_controlled_files_purpose",
        ),
        Index("ix_gsp_controlled_files_sha256", "sha256"),
        Index("ix_gsp_controlled_files_purpose_status", "purpose", "status"),
    )

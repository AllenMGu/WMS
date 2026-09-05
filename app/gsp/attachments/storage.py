"""Content-addressed immutable file store for controlled GSP attachments.

Storage layout (content addressable, no path traversal surface):

    <attachment_dir>/<sha256[:2]>/<sha256>

The server computes the SHA-256 while streaming; a client-supplied expected
hash is only used as a cross-check.  The same bytes uploaded twice map to the
same path, so re-uploads are de-duplicated and existing objects can never be
overwritten by different content.

File type is decided **server-side from content signatures** (magic bytes),
never from the client-declared multipart ``Content-Type``; a lying declaration
is rejected.  ZIP-family files (docx/xlsx/plain zip) are told apart by their
container entries where possible.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from typing import BinaryIO

from app.core.config import settings

# Canonical server-side types.  Uploaded bytes must match one of the known
# signatures below, or (for plain text) the declared text flavour.
CONTENT_TYPE_PDF = "application/pdf"
CONTENT_TYPE_JPEG = "image/jpeg"
CONTENT_TYPE_PNG = "image/png"
CONTENT_TYPE_WEBP = "image/webp"
CONTENT_TYPE_MSWORD_OLD = "application/msword"
CONTENT_TYPE_DOCX = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
)
CONTENT_TYPE_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
CONTENT_TYPE_ZIP = "application/zip"
CONTENT_TYPE_CSV = "text/csv"
CONTENT_TYPE_TXT = "text/plain"

ALLOWED_CONTENT_TYPES = {
    CONTENT_TYPE_PDF,
    CONTENT_TYPE_JPEG,
    CONTENT_TYPE_PNG,
    CONTENT_TYPE_WEBP,
    CONTENT_TYPE_MSWORD_OLD,
    CONTENT_TYPE_DOCX,
    CONTENT_TYPE_XLSX,
    CONTENT_TYPE_ZIP,
    CONTENT_TYPE_CSV,
    CONTENT_TYPE_TXT,
}
_TEXT_TYPES = {CONTENT_TYPE_CSV, CONTENT_TYPE_TXT}

STORAGE_ROOT_ENV = "ATTACHMENT_DIR"
_SNIFF_LIMIT = 1024 * 1024  # bytes of the head used for type detection


class StoredFile:
    __slots__ = ("sha256", "size_bytes", "content_type", "path")

    def __init__(self, sha256: str, size_bytes: int, content_type: str, path: str) -> None:
        self.sha256 = sha256
        self.size_bytes = size_bytes
        self.content_type = content_type
        self.path = path


def storage_root() -> str:
    """Resolve the store root each call so tests may point it at a tmp dir."""
    root = os.getenv(STORAGE_ROOT_ENV) or settings.attachment_dir
    os.makedirs(root, exist_ok=True)
    try:
        os.chmod(root, 0o750)
    except OSError:
        pass
    return root


def content_path(sha256: str) -> str:
    root = storage_root()
    return os.path.join(root, sha256[:2], sha256)


def detect_mime(head: bytes) -> str | None:
    """Server-side file-type detection from content signatures (magic bytes)."""
    if head.startswith(b"%PDF-"):
        return CONTENT_TYPE_PDF
    if head.startswith(b"\xff\xd8\xff"):
        return CONTENT_TYPE_JPEG
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return CONTENT_TYPE_PNG
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return CONTENT_TYPE_WEBP
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        # OLE2 compound file: legacy .doc/.xls/.ppt cannot be told apart by magic.
        return CONTENT_TYPE_MSWORD_OLD
    if head.startswith(b"PK\x03\x04"):
        # OOXML documents are ZIP containers; inspect early entries for the
        # central document part so docx/xlsx are not mislabelled as plain zip.
        if b"[Content_Types].xml" in head:
            if b"word/document.xml" in head or b"word/" in head:
                return CONTENT_TYPE_DOCX
            if b"xl/workbook.xml" in head or b"xl/" in head:
                return CONTENT_TYPE_XLSX
        return CONTENT_TYPE_ZIP
    return None


def _normalize_declared(value: str | None) -> str:
    return (value or "").split(";")[0].strip().lower()


def _decide_type(head: bytes, declared_raw: str | None) -> str:
    """Return the canonical type to store, raising ValueError on mismatch."""
    declared = _normalize_declared(declared_raw)
    detected = detect_mime(head)
    if detected is not None:
        if (
            declared in ALLOWED_CONTENT_TYPES
            and declared not in _TEXT_TYPES
            and declared != detected
        ):
            raise ValueError(
                f"文件内容与声明类型不符（声明 {declared}，实际 {detected}）"
            )
        return detected
    # No binary signature: accept plain text only when declared as such and no
    # NUL byte appears in the head (weak binary-content guard).
    if declared in _TEXT_TYPES and b"\x00" not in head[:2048]:
        return declared
    raise ValueError(
        "无法识别的文件内容：仅接受 PDF/JPEG/PNG/WebP/Word/Excel/ZIP/CSV/TXT 签名"
    )


def store_stream(
    stream: BinaryIO,
    *,
    content_type: str | None = None,
    expected_sha256: str | None = None,
    max_bytes: int | None = None,
) -> StoredFile:
    """Stream ``stream`` into the immutable store.

    Raises ``ValueError`` for empty/oversized payloads, unrecognised content or
    a client/server SHA-256 mismatch.  Returns content-address info including
    the server-detected content type.
    """
    cap = max_bytes or settings.attachment_max_bytes
    root = storage_root()

    hasher = hashlib.sha256()
    size = 0
    tmp_fd, tmp_path = tempfile.mkstemp(prefix=".upload-", dir=root)
    try:
        with os.fdopen(tmp_fd, "wb") as out:
            while True:
                chunk = stream.read(1024 * 256)
                if not chunk:
                    break
                size += len(chunk)
                if size > cap:
                    raise ValueError(f"文件超过大小限制 {cap} 字节")
                hasher.update(chunk)
                out.write(chunk)
        if size == 0:
            raise ValueError("不允许上传空文件")
        sha256 = hasher.hexdigest()
        if expected_sha256:
            if not (len(expected_sha256) == 64 and all(
                ch in "0123456789abcdef" for ch in expected_sha256.lower()
            )):
                raise ValueError("expected_sha256 必须是 64 位十六进制字符串")
            if expected_sha256.lower() != sha256:
                raise ValueError("客户端声明的 SHA-256 与服务端计算结果不一致，文件已被拒收")
        with open(tmp_path, "rb") as probe:
            head = probe.read(_SNIFF_LIMIT)
        real_type = _decide_type(head, content_type)

        subdir = os.path.join(root, sha256[:2])
        os.makedirs(subdir, exist_ok=True)
        try:
            os.chmod(subdir, 0o750)
        except OSError:
            pass
        target = os.path.join(subdir, sha256)
        if os.path.exists(target):
            # De-duplicate: identical content already stored; drop the temp copy.
            os.unlink(tmp_path)
        else:
            os.replace(tmp_path, target)
            os.chmod(target, 0o640)
        return StoredFile(sha256=sha256, size_bytes=size, content_type=real_type, path=target)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def verify_stored(sha256: str, size_bytes: int, *, full_hash: bool = True) -> dict:
    """Check that the stored object still matches its recorded hash/size."""
    path = content_path(sha256)
    result = {
        "exists_on_disk": False,
        "size_matches": False,
        "sha256_matches": None,
    }
    if not os.path.exists(path):
        return result
    result["exists_on_disk"] = True
    stat_size = os.path.getsize(path)
    result["size_matches"] = stat_size == size_bytes
    if not full_hash:
        return result
    if not result["size_matches"]:
        result["sha256_matches"] = False
        return result
    hasher = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 256)
            if not chunk:
                break
            hasher.update(chunk)
    result["sha256_matches"] = hasher.hexdigest() == sha256
    return result

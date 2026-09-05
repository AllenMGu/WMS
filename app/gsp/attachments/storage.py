"""Content-addressed immutable file store for controlled GSP attachments.

Storage layout (content addressable, no path traversal surface):

    <attachment_dir>/<sha256[:2]>/<sha256>

The server computes the SHA-256 while streaming; a client-supplied expected
hash is only used as a cross-check.  The same bytes uploaded twice map to the
same path, so re-uploads are de-duplicated and existing objects can never be
overwritten by different content.

File type is decided **server-side from content**: magic bytes for
PDF/JPEG/PNG/WebP; OLE2 compound storage is told apart (.doc vs .xls) by its
stream names; OOXML and plain ZIP are validated by reading the real container
(entry list + ``[Content_Types].xml``) rather than scanning the head bytes.
A lying client-declared ``Content-Type`` is rejected.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from typing import BinaryIO

try:
    import olefile as _olefile
except ImportError:  # pragma: no cover - declared dependency
    _olefile = None

from app.core.config import settings

# Canonical server-side types.  Uploaded bytes must match one of the known
# signatures below, or (for plain text) the declared text flavour.
CONTENT_TYPE_PDF = "application/pdf"
CONTENT_TYPE_JPEG = "image/jpeg"
CONTENT_TYPE_PNG = "image/png"
CONTENT_TYPE_WEBP = "image/webp"
CONTENT_TYPE_MSWORD_OLD = "application/msword"
CONTENT_TYPE_XLS_OLD = "application/vnd.ms-excel"
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
    CONTENT_TYPE_XLS_OLD,
    CONTENT_TYPE_DOCX,
    CONTENT_TYPE_XLSX,
    CONTENT_TYPE_ZIP,
    CONTENT_TYPE_CSV,
    CONTENT_TYPE_TXT,
}
_TEXT_TYPES = {CONTENT_TYPE_CSV, CONTENT_TYPE_TXT}

# Guards for OOXML/zip containers (we never extract payloads, but still bound
# the container metadata we are willing to parse).
_MAX_ZIP_ENTRIES = 4096
_MAX_ZIP_CONTENT_TYPES_BYTES = 1024 * 1024

STORAGE_ROOT_ENV = "ATTACHMENT_DIR"
_SNIFF_LIMIT = 1024 * 1024  # bytes of the head used for type detection

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_ZIP_MAGIC = b"PK\x03\x04"

_CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
_DOCX_MAIN_CT = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
)
_XLSX_MAIN_CT = (
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
)
_END_OF_CHAIN = 0xFFFFFFFE
_FREE_SECTOR = 0xFFFFFFFF


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


def _classify_ole2(path: str) -> str:
    """Classify legacy .doc/.xls by actually reading the document stream.

    ``olefile`` (with parsing defects raised) validates the CFB structure,
    header sector layout (v3/v4) and the directory tree reachable from the
    Root Entry.  Classification additionally **opens the target stream and
    reads it**, requiring the number of readable bytes to equal the
    directory-declared size (and to be non-empty).  A reachable directory
    entry with a forged size but no real FAT/MiniFAT-backed content therefore
    cannot pass; garbage or broken containers are rejected outright.
    """
    if _olefile is None:
        raise ValueError("受控文件服务缺少 OLE2 解析依赖（olefile）")
    try:
        ole = _olefile.OleFileIO(path, raise_defects=_olefile.DEFECT_INCORRECT)
    except Exception as exc:
        raise ValueError("不是有效的 OLE2/CFB 容器（无法解析）") from exc
    try:
        reachable: set[str] = set()
        for parts in ole.listdir(streams=True, storages=False):
            if parts and len(parts) == 1:
                reachable.add(parts[0])
        declared_sizes: dict[str, int] = {}
        for entry in ole.direntries or []:
            if entry is not None and entry.name and entry.name in reachable:
                declared_sizes[entry.name] = getattr(entry, "size", 0) or 0

        def readable_fully(name: str) -> bool:
            declared = declared_sizes.get(name, 0)
            if declared <= 0:
                return False
            try:
                with ole.openstream(name) as stream:
                    data = stream.read()
            except Exception:
                return False
            return len(data) == declared

        if "WordDocument" in reachable and readable_fully("WordDocument"):
            return CONTENT_TYPE_MSWORD_OLD
        for name in ("Workbook", "Book"):
            if name in reachable and readable_fully(name):
                return CONTENT_TYPE_XLS_OLD
    finally:
        ole.close()
    raise ValueError("OLE2/CFB 容器不含可完整读取的非空 Word/Excel 文档流，拒绝接收")


def _classify_ooxml_zip(path: str) -> str:
    """Validate a real OOXML/ZIP container and return its canonical type.

    Reads only the central-directory entry list plus ``[Content_Types].xml``,
    which is parsed (never byte-searched) to verify the OOXML namespace, the
    exact ``Override`` ``PartName``/``ContentType`` and that the referenced
    part really exists.  Payloads are never extracted and the entry list is
    bounded, so container bombs are not expanded here.
    """
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            if len(names) > _MAX_ZIP_ENTRIES:
                raise ValueError(
                    f"ZIP/OOXML 容器条目数超过限制（>{_MAX_ZIP_ENTRIES}），疑似异常容器"
                )
            if "[Content_Types].xml" not in names:
                return CONTENT_TYPE_ZIP
            with zf.open("[Content_Types].xml") as ct_stream:
                content_types = ct_stream.read(_MAX_ZIP_CONTENT_TYPES_BYTES + 1)
            if len(content_types) > _MAX_ZIP_CONTENT_TYPES_BYTES:
                raise ValueError("OOXML [Content_Types].xml 异常过大")
    except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError) as exc:
        raise ValueError("损坏或不支持的 ZIP/OOXML 容器") from exc

    if b"<!DOCTYPE" in content_types or b"<!ENTITY" in content_types:
        raise ValueError("OOXML [Content_Types].xml 含 DTD/实体声明，拒绝解析")
    try:
        root = ET.fromstring(content_types)
    except ET.ParseError as exc:
        raise ValueError("OOXML [Content_Types].xml 损坏，无法解析") from exc
    if root.tag != f"{{{_CT_NS}}}Types":
        # Well-formed XML but not an OPC content-types part: plain zip at best.
        return CONTENT_TYPE_ZIP

    overrides: dict[str, str] = {}
    for child in root:
        if child.tag == f"{{{_CT_NS}}}Override":
            part_name = (child.get("PartName") or "").lstrip("/")
            content_type = child.get("ContentType") or ""
            if part_name:
                overrides[part_name] = content_type
    if (
        "word/document.xml" in names
        and overrides.get("word/document.xml") == _DOCX_MAIN_CT
    ):
        return CONTENT_TYPE_DOCX
    if (
        "xl/workbook.xml" in names
        and overrides.get("xl/workbook.xml") == _XLSX_MAIN_CT
    ):
        return CONTENT_TYPE_XLSX
    # Valid container but no exact OOXML document override -> plain zip.
    return CONTENT_TYPE_ZIP


def detect_mime(head: bytes) -> str | None:
    """Magic-byte detection for the non-container formats."""
    if head.startswith(b"%PDF-"):
        return CONTENT_TYPE_PDF
    if head.startswith(b"\xff\xd8\xff"):
        return CONTENT_TYPE_JPEG
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return CONTENT_TYPE_PNG
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return CONTENT_TYPE_WEBP
    return None


def _normalize_declared(value: str | None) -> str:
    return (value or "").split(";")[0].strip().lower()


def _decide_type(head: bytes, tmp_path: str, declared_raw: str | None) -> str:
    """Return the canonical type to store, raising ValueError on mismatch."""
    declared = _normalize_declared(declared_raw)
    if head.startswith(_OLE_MAGIC):
        detected = _classify_ole2(tmp_path)
    elif head.startswith(_ZIP_MAGIC):
        detected = _classify_ooxml_zip(tmp_path)
    else:
        detected = detect_mime(head)
        if detected is None:
            # No binary signature: accept plain text only when declared as such
            # and no NUL byte appears in the head (weak binary-content guard).
            if declared in _TEXT_TYPES and b"\x00" not in head[:2048]:
                return declared
            raise ValueError(
                "无法识别的文件内容：仅接受 PDF/JPEG/PNG/WebP/Word/Excel/ZIP/CSV/TXT 签名"
            )
    if (
        declared in ALLOWED_CONTENT_TYPES
        and declared not in _TEXT_TYPES
        and declared != detected
    ):
        raise ValueError(f"文件内容与声明类型不符（声明 {declared}，实际 {detected}）")
    return detected


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
        real_type = _decide_type(head, tmp_path, content_type)

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

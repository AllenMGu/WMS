"""Content-addressed immutable file store for controlled GSP attachments.

Storage layout (content addressable, no path traversal surface):

    <attachment_dir>/<sha256[:2]>/<sha256>

The server computes the SHA-256 while streaming; a client-supplied expected
hash is only used as a cross-check.  The same bytes uploaded twice map to the
same path, so re-uploads are de-duplicated and existing objects can never be
overwritten by different content.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from typing import BinaryIO

from app.core.config import settings

ALLOWED_CONTENT_TYPES = {
    "application/pdf",
    "image/jpeg",
    "image/png",
    "image/webp",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/zip",
    "text/csv",
    "text/plain",
}

STORAGE_ROOT_ENV = "ATTACHMENT_DIR"


class StoredFile:
    __slots__ = ("sha256", "size_bytes", "path")

    def __init__(self, sha256: str, size_bytes: int, path: str) -> None:
        self.sha256 = sha256
        self.size_bytes = size_bytes
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


def _validate_content_type(content_type: str) -> str:
    normalized = (content_type or "").split(";")[0].strip().lower()
    if normalized not in ALLOWED_CONTENT_TYPES:
        raise ValueError(
            f"不支持的文件类型 {normalized or '(空)'}；允许：PDF/JPEG/PNG/WebP/Word/Excel/ZIP/CSV/TXT"
        )
    return normalized


def store_stream(
    stream: BinaryIO,
    *,
    content_type: str,
    expected_sha256: str | None = None,
    max_bytes: int | None = None,
) -> StoredFile:
    """Stream ``stream`` into the immutable store.

    Raises ``ValueError`` for empty/oversized/unsupported payloads or a
    client/server SHA-256 mismatch.  Returns content-address info.
    """
    content_type = _validate_content_type(content_type)
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
        return StoredFile(sha256=sha256, size_bytes=size, path=target)
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

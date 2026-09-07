"""Optional periodic integrity self-check of the audit & signature hash chains.

The audit ledger and the electronic-signature chain are tamper-evident: any edit
is detectable by ``verify_audit_chain`` / ``verify_signature_chain``.  This
module turns that "detectable on demand" guarantee into "automatically
monitored": an opt-in background task periodically re-verifies both chains and
raises an operator alert (``logging.error``) the instant a break is found,
instead of waiting for a manual ``verify`` endpoint call.

Activation is conservative and off by default: the loop only runs when the
environment variable ``AUDIT_AUTO_VERIFY_INTERVAL`` (seconds) is > 0.  Each
iteration opens its own DB session so it never shares a request-scoped
transaction with the web handlers.
"""

from __future__ import annotations

import asyncio
import logging
import os

from app.core.database import SessionLocal
from app.gsp.audit import verify_audit_chain
from app.gsp.electronic_signature.service import verify_signature_chain

logger = logging.getLogger("wms.gsp.audit_auto_verify")


def auto_verify_interval_seconds() -> int:
    """Seconds between automatic chain verifications (0 disables the task)."""
    raw = os.getenv("AUDIT_AUTO_VERIFY_INTERVAL", "0") or "0"
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        logger.warning("AUDIT_AUTO_VERIFY_INTERVAL 不是合法整数(%r)，自动校验已关闭", raw)
        return 0


def verify_all_chains_once() -> tuple[bool, bool]:
    """Run one integrity pass over both chains in a fresh session.

    Returns ``(audit_chain_ok, signature_chain_ok)``.  A break (or a transient
    verification error) is reported via ``logging.error`` so it reaches the
    operator's log pipeline; transient exceptions are contained and never take
    the background loop down.
    """
    audit_ok = True
    signature_ok = True
    with SessionLocal() as db:
        try:
            audit_ok, broken_event_id = verify_audit_chain(db)
            if not audit_ok:
                logger.error("审计哈希链自动校验失败：链已断裂，broken_event_id=%s", broken_event_id)
        except Exception:  # noqa: BLE001 - keep the loop alive on transient DB errors
            logger.exception("审计哈希链自动校验异常")
            audit_ok = False
        try:
            signature_ok, broken_signature_id, _checked = verify_signature_chain(db)
            if not signature_ok:
                logger.error("电子签名哈希链自动校验失败：链已断裂，broken_signature_id=%s", broken_signature_id)
        except Exception:  # noqa: BLE001
            logger.exception("电子签名哈希链自动校验异常")
            signature_ok = False
    return audit_ok, signature_ok


async def run_auto_verify_loop() -> None:
    """Background coroutine: verify both chains every configured interval."""
    interval = auto_verify_interval_seconds()
    if interval <= 0:
        return
    logger.info("审计/签名哈希链自动校验已启用，校验间隔=%s 秒（AUDIT_AUTO_VERIFY_INTERVAL）", interval)
    while True:
        await asyncio.sleep(interval)
        try:
            verify_all_chains_once()
        except Exception:  # noqa: BLE001
            logger.exception("审计链自动校验后台任务异常（将在下个周期重试）")

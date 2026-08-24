"""Transactional integration outbox helpers."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import Callable

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.audit import write_audit_event
from app.gsp.models import GspIntegrationMessage

OutboxHandler = Callable[[GspIntegrationMessage], None]


def _idempotency_key(
    destination: str,
    message_type: str,
    aggregate_type: str,
    aggregate_id: str,
    payload: dict,
) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(
        f"{destination}|{message_type}|{aggregate_type}|{aggregate_id}|{canonical}".encode("utf-8")
    ).hexdigest()
    return f"v1:{digest}"


def enqueue_integration_message(
    db: Session,
    *,
    destination: str,
    message_type: str,
    aggregate_type: str,
    aggregate_id: str,
    payload: dict,
) -> GspIntegrationMessage:
    idempotency_key = _idempotency_key(
        destination, message_type, aggregate_type, aggregate_id, payload
    )
    for pending in db.new:
        if (
            isinstance(pending, GspIntegrationMessage)
            and pending.idempotency_key == idempotency_key
        ):
            return pending
    existing = (
        db.query(GspIntegrationMessage)
        .filter(GspIntegrationMessage.idempotency_key == idempotency_key)
        .first()
    )
    if existing is not None:
        return existing
    message = GspIntegrationMessage(
        destination=destination,
        message_type=message_type,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        idempotency_key=idempotency_key,
        payload=payload,
    )
    db.add(message)
    return message


def claim_outbox_batch(
    db: Session,
    *,
    destination: str,
    worker_id: str,
    limit: int = 50,
) -> list[GspIntegrationMessage]:
    now = utc_now()
    stale_before = now - timedelta(minutes=15)
    rows = (
        db.query(GspIntegrationMessage)
        .filter(
            GspIntegrationMessage.destination == destination,
            (
                GspIntegrationMessage.status.in_(["PENDING", "RETRY"])
                | (
                    (GspIntegrationMessage.status == "PROCESSING")
                    & (GspIntegrationMessage.claimed_at < stale_before)
                )
            ),
            (
                GspIntegrationMessage.next_attempt_at.is_(None)
                | (GspIntegrationMessage.next_attempt_at <= now)
            ),
        )
        .order_by(GspIntegrationMessage.id)
        .with_for_update(skip_locked=True)
        .limit(limit)
        .all()
    )
    for row in rows:
        row.status = "PROCESSING"
        row.claimed_by = worker_id
        row.claimed_at = now
    db.flush()
    return rows


def mark_outbox_sent(db: Session, message: GspIntegrationMessage) -> None:
    message.status = "SENT"
    message.sent_at = utc_now()
    message.last_error = None
    message.next_attempt_at = None
    message.claimed_by = None
    message.claimed_at = None


def mark_outbox_failed(
    db: Session,
    message: GspIntegrationMessage,
    error: Exception | str,
    *,
    max_attempts: int = 8,
) -> None:
    message.attempt_count += 1
    message.last_error = str(error)[:2000]
    message.claimed_by = None
    message.claimed_at = None
    if message.attempt_count >= max_attempts:
        message.status = "DEAD"
        message.dead_lettered_at = utc_now()
        message.next_attempt_at = None
        return
    message.status = "RETRY"
    delay_seconds = min(3600, 2 ** min(message.attempt_count, 10) * 15)
    message.next_attempt_at = utc_now() + timedelta(seconds=delay_seconds)


def process_outbox_batch(
    db: Session,
    *,
    destination: str,
    worker_id: str,
    handler: OutboxHandler,
    limit: int = 50,
    max_attempts: int = 8,
) -> tuple[int, int]:
    """Run one adapter-neutral batch; callers supply the external handler."""
    messages = claim_outbox_batch(
        db, destination=destination, worker_id=worker_id, limit=limit
    )
    db.commit()
    sent = failed = 0
    for message in messages:
        try:
            handler(message)
            mark_outbox_sent(db, message)
            sent += 1
        except Exception as error:  # adapter errors become durable retry evidence
            mark_outbox_failed(db, message, error, max_attempts=max_attempts)
            failed += 1
        db.commit()
    return sent, failed


def requeue_dead_message(
    db: Session,
    *,
    message: GspIntegrationMessage,
    actor_user_id: int,
    reason: str,
    source_ip: str | None = None,
) -> GspIntegrationMessage:
    if message.status != "DEAD":
        raise ValueError("只有死信消息可以人工重试")
    before = {"status": message.status, "attempt_count": message.attempt_count}
    message.status = "RETRY"
    message.next_attempt_at = utc_now()
    message.dead_lettered_at = None
    message.claimed_by = None
    message.claimed_at = None
    write_audit_event(
        db,
        actor_user_id=actor_user_id,
        action="INTEGRATION_MESSAGE_REQUEUED",
        entity_type="GspIntegrationMessage",
        entity_id=str(message.id),
        reason=reason,
        before_data=before,
        after_data={"status": message.status, "attempt_count": message.attempt_count},
        source_ip=source_ip,
    )
    return message

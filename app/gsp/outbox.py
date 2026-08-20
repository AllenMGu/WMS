"""Transactional integration outbox helpers."""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy.orm import Session

from app.gsp.models import GspIntegrationMessage


def enqueue_integration_message(
    db: Session,
    *,
    destination: str,
    message_type: str,
    aggregate_type: str,
    aggregate_id: str,
    payload: dict,
) -> GspIntegrationMessage:
    message = GspIntegrationMessage(
        destination=destination,
        message_type=message_type,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        idempotency_key=f"{message_type}:{aggregate_id}:{uuid4().hex}",
        payload=payload,
    )
    db.add(message)
    return message

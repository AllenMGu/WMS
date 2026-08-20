"""Tamper-evident audit event writer."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.models import GspAuditEvent


def _event_hash(
    *,
    actor_user_id: int,
    action: str,
    entity_type: str,
    entity_id: str,
    reason: str,
    before_data: dict[str, Any] | None,
    after_data: dict[str, Any] | None,
    source_ip: str | None,
    previous_hash: str | None,
    occurred_at,
) -> str:
    canonical = json.dumps(
        {
            "actor_user_id": actor_user_id,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "reason": reason,
            "before_data": before_data,
            "after_data": after_data,
            "source_ip": source_ip,
            "previous_hash": previous_hash,
            "occurred_at": occurred_at.isoformat(timespec="microseconds"),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def write_audit_event(
    db: Session,
    *,
    actor_user_id: int,
    action: str,
    entity_type: str,
    entity_id: str,
    reason: str,
    before_data: Optional[dict[str, Any]] = None,
    after_data: Optional[dict[str, Any]] = None,
    source_ip: Optional[str] = None,
) -> GspAuditEvent:
    previous = db.query(GspAuditEvent).order_by(GspAuditEvent.id.desc()).first()
    previous_hash = previous.event_hash if previous else None
    occurred_at = utc_now()
    event_hash = _event_hash(
        actor_user_id=actor_user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        reason=reason,
        before_data=before_data,
        after_data=after_data,
        source_ip=source_ip,
        previous_hash=previous_hash,
        occurred_at=occurred_at,
    )
    event = GspAuditEvent(
        actor_user_id=actor_user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        reason=reason,
        before_data=before_data,
        after_data=after_data,
        source_ip=source_ip,
        previous_hash=previous_hash,
        event_hash=event_hash,
        occurred_at=occurred_at,
    )
    db.add(event)
    return event


def verify_audit_chain(db: Session) -> tuple[bool, int | None]:
    expected_previous_hash = None
    for event in db.query(GspAuditEvent).order_by(GspAuditEvent.id):
        expected_hash = _event_hash(
            actor_user_id=event.actor_user_id,
            action=event.action,
            entity_type=event.entity_type,
            entity_id=event.entity_id,
            reason=event.reason,
            before_data=event.before_data,
            after_data=event.after_data,
            source_ip=event.source_ip,
            previous_hash=event.previous_hash,
            occurred_at=event.occurred_at,
        )
        if event.previous_hash != expected_previous_hash or event.event_hash != expected_hash:
            return False, event.id
        expected_previous_hash = event.event_hash
    return True, None

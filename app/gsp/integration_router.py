from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.dependencies import require_gsp_roles
from app.gsp.electronic_signature.dependencies import require_electronic_signature
from app.gsp.models import GspIntegrationMessage
from app.gsp.outbox import requeue_dead_message
from app.legacy import User

router = APIRouter(prefix="/gsp/integration", tags=["GSP集成治理"])


class OutboxRetry(BaseModel):
    reason: str = Field(min_length=3, max_length=500)
    model_config = ConfigDict(extra="forbid")


@router.get("/outbox")
def list_outbox(
    destination: str | None = None,
    status: str | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    _: User = Depends(require_gsp_roles("SYSTEM_ADMIN", "AUDITOR", "QUALITY_REVIEWER")),
    db: Session = Depends(get_db),
):
    query = db.query(GspIntegrationMessage)
    if destination:
        query = query.filter(GspIntegrationMessage.destination == destination)
    if status:
        query = query.filter(GspIntegrationMessage.status == status)
    return query.order_by(GspIntegrationMessage.id.desc()).offset(offset).limit(limit).all()


@router.post(
    "/outbox/{message_id}/retry",
    dependencies=[Depends(require_electronic_signature(
        "INTEGRATION_MESSAGE_REQUEUE", "GspIntegrationMessage",
        entity_id_param="message_id", meaning="RESPONSIBILITY",
    ))],
)
def retry_outbox_message(
    message_id: int,
    payload: OutboxRetry,
    request: Request,
    current_user: User = Depends(require_gsp_roles("SYSTEM_ADMIN")),
    db: Session = Depends(get_db),
):
    message = db.query(GspIntegrationMessage).filter(
        GspIntegrationMessage.id == message_id
    ).with_for_update().first()
    if message is None:
        raise HTTPException(404, "出站消息不存在")
    try:
        requeue_dead_message(
            db,
            message=message,
            actor_user_id=current_user.id,
            reason=payload.reason,
            source_ip=request.client.host if request.client else None,
        )
    except ValueError as error:
        raise HTTPException(409, str(error)) from error
    db.commit()
    return message

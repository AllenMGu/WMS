from __future__ import annotations

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.electronic_signature.service import consume_signature_challenge
from app.gsp.errors import WorkflowError
from app.legacy import User, get_current_user


def require_electronic_signature(
    action: str,
    entity_type: str,
    *,
    entity_id_param: str,
    meaning: str,
):
    async def dependency(
        request: Request,
        signature_token: str = Header(..., alias="X-GSP-Signature-Token"),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ):
        entity_id = request.path_params.get(entity_id_param)
        if entity_id is None:
            raise HTTPException(500, "电子签名门禁未找到目标记录")
        try:
            request_payload = await request.json()
        except ValueError:
            request_payload = {}
        source_ip = request.client.host if request.client else None
        try:
            return consume_signature_challenge(
                db,
                token=signature_token,
                actor_id=current_user.id,
                action=action,
                entity_type=entity_type,
                entity_id=str(entity_id),
                meaning=meaning,
                payload=request_payload,
                source_ip=source_ip,
            )
        except WorkflowError as error:
            db.rollback()
            raise HTTPException(error.status_code, error.detail) from error

    return dependency

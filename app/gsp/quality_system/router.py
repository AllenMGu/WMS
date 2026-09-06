from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.gsp.dependencies import require_any_gsp_role, require_gsp_roles
from app.gsp.electronic_signature.dependencies import require_electronic_signature
from app.gsp.errors import WorkflowError
from app.gsp.quality_system.models import (
    GspCapaAction,
    GspControlledDocument,
    GspDocumentCopy,
    GspDocumentRevision,
    GspEquipmentActivity,
    GspPartnerReview,
    GspQualityEquipment,
    GspQualityEvent,
    GspQualityRisk,
    GspRegulatedScopeAuthorization,
    GspTrainingRecord,
)
from app.gsp.quality_system.schemas import (
    CapaCreate,
    CapaImplementation,
    CapaResponse,
    CapaVerification,
    ControlledDocumentCreate,
    ControlledDocumentResponse,
    DocumentCopyCreate,
    DocumentCopyDisposition,
    DocumentCopyResponse,
    DocumentRevisionCreate,
    DocumentRevisionResponse,
    EquipmentActivityCreate,
    EquipmentActivityResponse,
    EquipmentCreate,
    EquipmentResponse,
    PartnerReviewClosure,
    PartnerReviewCreate,
    PartnerReviewDecision,
    PartnerReviewResponse,
    QualityEventCreate,
    QualityEventInvestigation,
    QualityEventResponse,
    QualityRiskCreate,
    QualityRiskDecision,
    QualityRiskResponse,
    ScopeAuthorizationCreate,
    ScopeAuthorizationResponse,
    TrainingCompletion,
    TrainingCreate,
    TrainingResponse,
)
from app.gsp.quality_system.service import (
    approve_document_revision,
    approve_equipment,
    approve_scope_authorization,
    close_partner_review,
    close_quality_event,
    complete_training,
    create_capa,
    create_controlled_document,
    create_document_revision,
    create_equipment,
    create_equipment_activity,
    create_partner_review,
    create_quality_event,
    create_quality_risk,
    create_scope_authorization,
    create_training,
    decide_partner_review,
    dispose_document_copy,
    implement_capa,
    investigate_quality_event,
    issue_document_copy,
    review_equipment_activity,
    review_quality_risk,
    submit_document_revision,
    submit_partner_review,
    submit_quality_risk,
    verify_capa,
    verify_training,
)
from app.gsp.schemas import ChangeReason
from app.legacy import User

router = APIRouter(prefix="/gsp/quality-system", tags=["GSP质量体系管理"])
QUALITY_ROLES = ("QUALITY_MANAGER", "QUALITY_REVIEWER")
QUALITY_READ_ROLES = (*QUALITY_ROLES, "AUDITOR")
require_quality_system_read = require_gsp_roles(*QUALITY_READ_ROLES)
T = TypeVar("T")


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _execute(db: Session, operation: Callable[[], T]) -> T:
    try:
        result = operation()
        db.commit()
        db.refresh(result)
        return result
    except WorkflowError as error:
        db.rollback()
        raise HTTPException(error.status_code, error.detail) from error
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(409, "记录编号或周期业务记录重复") from error


@router.get("/partner-reviews", response_model=list[PartnerReviewResponse])
def list_partner_reviews(
    status: str | None = None,
    partner_id: int | None = None,
    current_user: User = Depends(require_quality_system_read),
    db: Session = Depends(get_db),
):
    query = db.query(GspPartnerReview)
    if status:
        query = query.filter(GspPartnerReview.status == status.upper())
    if partner_id:
        query = query.filter(GspPartnerReview.partner_id == partner_id)
    return query.order_by(GspPartnerReview.id.desc()).all()


@router.post("/partner-reviews", response_model=PartnerReviewResponse, status_code=201)
def new_partner_review(
    payload: PartnerReviewCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: create_partner_review(
            db, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
        ),
    )


@router.post("/partner-reviews/{review_id}/submit", response_model=PartnerReviewResponse)
def submit_periodic_partner_review(
    review_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: submit_partner_review(
            db,
            review_id=review_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        ),
    )


@router.post(
    "/partner-reviews/{review_id}/decide",
    response_model=PartnerReviewResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "PARTNER_PERIODIC_REVIEW",
                "GspPartnerReview",
                entity_id_param="review_id",
                meaning="APPROVAL",
            )
        )
    ],
)
def decide_periodic_partner_review(
    review_id: int,
    payload: PartnerReviewDecision,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: decide_partner_review(
            db, review_id=review_id, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
        ),
    )


@router.post(
    "/partner-reviews/{review_id}/close-actions",
    response_model=PartnerReviewResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "PARTNER_REVIEW_ACTIONS_CLOSE",
                "GspPartnerReview",
                entity_id_param="review_id",
                meaning="REVIEW",
            )
        )
    ],
)
def close_periodic_partner_review_actions(
    review_id: int,
    payload: PartnerReviewClosure,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: close_partner_review(
            db, review_id=review_id, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
        ),
    )


@router.get("/risks", response_model=list[QualityRiskResponse])
def list_quality_risks(
    status: str | None = None,
    current_user: User = Depends(require_quality_system_read),
    db: Session = Depends(get_db),
):
    query = db.query(GspQualityRisk)
    if status:
        query = query.filter(GspQualityRisk.status == status.upper())
    return query.order_by(GspQualityRisk.id.desc()).all()


@router.post("/risks", response_model=QualityRiskResponse, status_code=201)
def new_quality_risk(
    payload: QualityRiskCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES, "AUDITOR")),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: create_quality_risk(
            db, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
        ),
    )


@router.post("/risks/{risk_id}/submit", response_model=QualityRiskResponse)
def submit_risk(
    risk_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES, "AUDITOR")),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: submit_quality_risk(
            db,
            risk_id=risk_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        ),
    )


@router.post(
    "/risks/{risk_id}/review",
    response_model=QualityRiskResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "QUALITY_RISK_REVIEW",
                "GspQualityRisk",
                entity_id_param="risk_id",
                meaning="REVIEW",
            )
        )
    ],
)
def review_risk(
    risk_id: int,
    payload: QualityRiskDecision,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: review_quality_risk(
            db, risk_id=risk_id, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
        ),
    )


@router.get("/events", response_model=list[QualityEventResponse])
def list_quality_events(
    status: str | None = None,
    event_type: str | None = None,
    current_user: User = Depends(require_quality_system_read),
    db: Session = Depends(get_db),
):
    query = db.query(GspQualityEvent)
    if status:
        query = query.filter(GspQualityEvent.status == status.upper())
    if event_type:
        query = query.filter(GspQualityEvent.event_type == event_type.upper())
    return query.order_by(GspQualityEvent.id.desc()).all()


@router.post("/events", response_model=QualityEventResponse, status_code=201)
def new_quality_event(
    payload: QualityEventCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES, "AUDITOR")),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: create_quality_event(
            db, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
        ),
    )


@router.post("/events/{event_id}/investigate", response_model=QualityEventResponse)
def investigate_event(
    event_id: int,
    payload: QualityEventInvestigation,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES, "AUDITOR")),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: investigate_quality_event(
            db, event_id=event_id, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
        ),
    )


@router.post(
    "/events/{event_id}/close",
    response_model=QualityEventResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "QUALITY_EVENT_CLOSE",
                "GspQualityEvent",
                entity_id_param="event_id",
                meaning="REVIEW",
            )
        )
    ],
)
def close_event(
    event_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: close_quality_event(
            db,
            event_id=event_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        ),
    )


@router.get("/capas", response_model=list[CapaResponse])
def list_capas(
    status: str | None = None,
    current_user: User = Depends(require_quality_system_read),
    db: Session = Depends(get_db),
):
    query = db.query(GspCapaAction)
    if status:
        query = query.filter(GspCapaAction.status == status.upper())
    return query.order_by(GspCapaAction.id.desc()).all()


@router.get("/capas/me", response_model=list[CapaResponse])
def list_my_capas(
    status: str | None = None,
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    """Return only CAPA actions assigned to the current GSP user."""
    query = db.query(GspCapaAction).filter(GspCapaAction.owner_id == current_user.id)
    if status:
        query = query.filter(GspCapaAction.status == status.upper())
    return query.order_by(GspCapaAction.due_date, GspCapaAction.id.desc()).all()


@router.post("/capas", response_model=CapaResponse, status_code=201)
def new_capa(
    payload: CapaCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES, "AUDITOR")),
    db: Session = Depends(get_db),
):
    return _execute(
        db, lambda: create_capa(db, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request))
    )


@router.post("/capas/{capa_id}/implement", response_model=CapaResponse)
def implement_capa_action(
    capa_id: int,
    payload: CapaImplementation,
    request: Request,
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: implement_capa(
            db, capa_id=capa_id, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
        ),
    )


@router.post(
    "/capas/{capa_id}/verify",
    response_model=CapaResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "CAPA_EFFECTIVENESS_VERIFY",
                "GspCapaAction",
                entity_id_param="capa_id",
                meaning="REVIEW",
            )
        )
    ],
)
def verify_capa_action(
    capa_id: int,
    payload: CapaVerification,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: verify_capa(
            db, capa_id=capa_id, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
        ),
    )


@router.get("/training", response_model=list[TrainingResponse])
def list_training(
    status: str | None = None,
    user_id: int | None = None,
    current_user: User = Depends(require_quality_system_read),
    db: Session = Depends(get_db),
):
    query = db.query(GspTrainingRecord)
    if status:
        query = query.filter(GspTrainingRecord.status == status.upper())
    if user_id:
        query = query.filter(GspTrainingRecord.user_id == user_id)
    return query.order_by(GspTrainingRecord.id.desc()).all()


@router.get("/training/me", response_model=list[TrainingResponse])
def list_my_training(
    status: str | None = None,
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    query = db.query(GspTrainingRecord).filter(GspTrainingRecord.user_id == current_user.id)
    if status:
        query = query.filter(GspTrainingRecord.status == status.upper())
    return query.order_by(GspTrainingRecord.id.desc()).all()


@router.post("/training", response_model=TrainingResponse, status_code=201)
def new_training(
    payload: TrainingCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: create_training(db, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)),
    )


@router.post("/training/{training_id}/complete", response_model=TrainingResponse)
def complete_training_record(
    training_id: int,
    payload: TrainingCompletion,
    request: Request,
    current_user: User = Depends(require_any_gsp_role),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: complete_training(
            db,
            training_id=training_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        ),
    )


@router.post("/training/{training_id}/verify", response_model=TrainingResponse)
def verify_training_record(
    training_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: verify_training(
            db,
            training_id=training_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        ),
    )


@router.get("/documents", response_model=list[ControlledDocumentResponse])
def list_documents(
    status: str | None = None,
    current_user: User = Depends(require_quality_system_read),
    db: Session = Depends(get_db),
):
    query = db.query(GspControlledDocument)
    if status:
        query = query.filter(GspControlledDocument.status == status.upper())
    return query.order_by(GspControlledDocument.id.desc()).all()


@router.post("/documents", response_model=ControlledDocumentResponse, status_code=201)
def new_document(
    payload: ControlledDocumentCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: create_controlled_document(
            db, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
        ),
    )


@router.get("/documents/revisions", response_model=list[DocumentRevisionResponse])
def list_document_revisions(
    document_id: int | None = None,
    current_user: User = Depends(require_quality_system_read),
    db: Session = Depends(get_db),
):
    query = db.query(GspDocumentRevision)
    if document_id:
        query = query.filter(GspDocumentRevision.document_id == document_id)
    return query.order_by(GspDocumentRevision.id.desc()).all()


@router.post(
    "/documents/{document_id}/revisions",
    response_model=DocumentRevisionResponse,
    status_code=201,
)
def new_document_revision(
    document_id: int,
    payload: DocumentRevisionCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: create_document_revision(
            db,
            document_id=document_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        ),
    )


@router.post("/documents/revisions/{revision_id}/submit", response_model=DocumentRevisionResponse)
def submit_revision(
    revision_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: submit_document_revision(
            db,
            revision_id=revision_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        ),
    )


@router.post(
    "/documents/revisions/{revision_id}/approve",
    response_model=DocumentRevisionResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "CONTROLLED_DOCUMENT_APPROVE",
                "GspDocumentRevision",
                entity_id_param="revision_id",
                meaning="APPROVAL",
            )
        )
    ],
)
def approve_revision(
    revision_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: approve_document_revision(
            db,
            revision_id=revision_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        ),
    )


@router.get("/documents/copies", response_model=list[DocumentCopyResponse])
def list_document_copies(
    status: str | None = None,
    current_user: User = Depends(require_quality_system_read),
    db: Session = Depends(get_db),
):
    query = db.query(GspDocumentCopy)
    if status:
        query = query.filter(GspDocumentCopy.status == status.upper())
    return query.order_by(GspDocumentCopy.id.desc()).all()


@router.post(
    "/documents/revisions/{revision_id}/copies",
    response_model=DocumentCopyResponse,
    status_code=201,
)
def new_document_copy(
    revision_id: int,
    payload: DocumentCopyCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: issue_document_copy(
            db,
            revision_id=revision_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        ),
    )


@router.post("/documents/copies/{copy_id}/dispose", response_model=DocumentCopyResponse)
def dispose_copy(
    copy_id: int,
    payload: DocumentCopyDisposition,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: dispose_document_copy(
            db, copy_id=copy_id, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
        ),
    )


@router.get("/equipment", response_model=list[EquipmentResponse])
def list_equipment(
    status: str | None = None,
    current_user: User = Depends(require_quality_system_read),
    db: Session = Depends(get_db),
):
    query = db.query(GspQualityEquipment)
    if status:
        query = query.filter(GspQualityEquipment.status == status.upper())
    return query.order_by(GspQualityEquipment.id.desc()).all()


@router.post("/equipment", response_model=EquipmentResponse, status_code=201)
def new_equipment(
    payload: EquipmentCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: create_equipment(
            db, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
        ),
    )


@router.post(
    "/equipment/{equipment_id}/approve",
    response_model=EquipmentResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "QUALITY_EQUIPMENT_APPROVE",
                "GspQualityEquipment",
                entity_id_param="equipment_id",
                meaning="APPROVAL",
            )
        )
    ],
)
def approve_quality_equipment(
    equipment_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: approve_equipment(
            db,
            equipment_id=equipment_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        ),
    )


@router.get("/equipment/activities", response_model=list[EquipmentActivityResponse])
def list_equipment_activities(
    equipment_id: int | None = None,
    current_user: User = Depends(require_quality_system_read),
    db: Session = Depends(get_db),
):
    query = db.query(GspEquipmentActivity)
    if equipment_id:
        query = query.filter(GspEquipmentActivity.equipment_id == equipment_id)
    return query.order_by(GspEquipmentActivity.id.desc()).all()


@router.post(
    "/equipment/{equipment_id}/activities",
    response_model=EquipmentActivityResponse,
    status_code=201,
)
def new_equipment_activity(
    equipment_id: int,
    payload: EquipmentActivityCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: create_equipment_activity(
            db,
            equipment_id=equipment_id,
            payload=payload,
            actor_id=current_user.id,
            source_ip=_source_ip(request),
        ),
    )


@router.post(
    "/equipment/activities/{activity_id}/review",
    response_model=EquipmentActivityResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "EQUIPMENT_ACTIVITY_REVIEW",
                "GspEquipmentActivity",
                entity_id_param="activity_id",
                meaning="REVIEW",
            )
        )
    ],
)
def review_activity(
    activity_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: review_equipment_activity(
            db,
            activity_id=activity_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        ),
    )


@router.get("/regulated-scopes", response_model=list[ScopeAuthorizationResponse])
def list_regulated_scopes(
    current_user: User = Depends(require_quality_system_read),
    db: Session = Depends(get_db),
):
    return db.query(GspRegulatedScopeAuthorization).order_by(GspRegulatedScopeAuthorization.id.desc()).all()


@router.post("/regulated-scopes", response_model=ScopeAuthorizationResponse, status_code=201)
def new_regulated_scope(
    payload: ScopeAuthorizationCreate,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: create_scope_authorization(
            db, payload=payload, actor_id=current_user.id, source_ip=_source_ip(request)
        ),
    )


@router.post(
    "/regulated-scopes/{scope_id}/approve",
    response_model=ScopeAuthorizationResponse,
    dependencies=[
        Depends(
            require_electronic_signature(
                "REGULATED_SCOPE_APPROVE",
                "GspRegulatedScopeAuthorization",
                entity_id_param="scope_id",
                meaning="APPROVAL",
            )
        )
    ],
)
def approve_regulated_scope(
    scope_id: int,
    payload: ChangeReason,
    request: Request,
    current_user: User = Depends(require_gsp_roles(*QUALITY_ROLES)),
    db: Session = Depends(get_db),
):
    return _execute(
        db,
        lambda: approve_scope_authorization(
            db,
            scope_id=scope_id,
            actor_id=current_user.id,
            reason=payload.reason,
            source_ip=_source_ip(request),
        ),
    )

from __future__ import annotations

from datetime import date

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.gsp.audit import write_audit_event
from app.gsp.errors import WorkflowError
from app.gsp.models import GspBusinessPartner, GspDrugBatch
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
    CapaVerification,
    ControlledDocumentCreate,
    DocumentCopyCreate,
    DocumentCopyDisposition,
    DocumentRevisionCreate,
    EquipmentActivityCreate,
    EquipmentCreate,
    PartnerReviewClosure,
    PartnerReviewCreate,
    PartnerReviewDecision,
    QualityEventCreate,
    QualityEventInvestigation,
    QualityRiskCreate,
    QualityRiskDecision,
    ScopeAuthorizationCreate,
    TrainingCompletion,
    TrainingCreate,
)
from app.gsp.snapshots import model_snapshot
from app.legacy import Goods, User

PARTNER_REVIEW_TYPES = {"ANNUAL", "QUALITY_SYSTEM_SURVEY", "ONSITE_INSPECTION"}
RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
REVIEW_CONCLUSIONS = {"APPROVED", "CONDITIONAL", "REJECTED"}
QUALITY_EVENT_TYPES = {
    "SELF_INSPECTION",
    "INTERNAL_AUDIT",
    "MANAGEMENT_REVIEW",
    "COMPLAINT",
    "QUALITY_INCIDENT",
    "ADVERSE_REACTION",
    "DEVIATION",
    "QUALITY_INFORMATION",
}
EVENT_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
CAPA_TYPES = {"CORRECTIVE", "PREVENTIVE"}
TRAINING_RESULTS = {"PASSED", "FAILED", "ATTENDED"}
TRAINING_TYPES = {
    "INITIAL",
    "REFRESHER",
    "SOP",
    "CHANGE",
    "ASSESSMENT",
    "JOB_QUALIFICATION",
    "JOB_ASSESSMENT",
}
DOCUMENT_TYPES = {"POLICY", "SOP", "FORM", "SPECIFICATION", "RECORD_TEMPLATE"}
EQUIPMENT_CRITICALITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
EQUIPMENT_ACTIVITY_TYPES = {"QUALIFICATION", "CALIBRATION", "MAINTENANCE"}
REGULATED_CATEGORIES = {"SPECIAL_CONTROLLED", "VACCINE"}


def _audit(
    db: Session,
    *,
    actor_id: int,
    action: str,
    model,
    reason: str,
    source_ip: str | None,
    before: dict | None = None,
) -> None:
    db.flush()
    write_audit_event(
        db,
        actor_user_id=actor_id,
        action=action,
        entity_type=type(model).__name__,
        entity_id=str(model.id),
        reason=reason,
        before_data=before,
        after_data=model_snapshot(model),
        source_ip=source_ip,
    )


def _user(db: Session, user_id: int) -> User:
    user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
    if user is None:
        raise WorkflowError(422, "责任用户不存在或已停用")
    return user


def create_partner_review(
    db: Session, *, payload: PartnerReviewCreate, actor_id: int, source_ip: str | None
) -> GspPartnerReview:
    partner = db.query(GspBusinessPartner).filter(GspBusinessPartner.id == payload.partner_id).first()
    if partner is None:
        raise WorkflowError(404, "合作方不存在")
    review_type = payload.review_type.upper()
    risk_level = payload.risk_level.upper()
    if review_type not in PARTNER_REVIEW_TYPES:
        raise WorkflowError(422, "评审类型无效")
    if risk_level not in RISK_LEVELS:
        raise WorkflowError(422, "风险等级无效")
    review = GspPartnerReview(
        **payload.model_dump(exclude={"reason", "review_type", "risk_level"}),
        review_type=review_type,
        risk_level=risk_level,
        created_by=actor_id,
    )
    db.add(review)
    _audit(
        db,
        actor_id=actor_id,
        action="PARTNER_REVIEW_CREATED",
        model=review,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return review


def submit_partner_review(
    db: Session, *, review_id: int, actor_id: int, reason: str, source_ip: str | None
) -> GspPartnerReview:
    review = db.query(GspPartnerReview).filter_by(id=review_id).with_for_update().first()
    if review is None:
        raise WorkflowError(404, "合作方评审不存在")
    if review.status != "DRAFT":
        raise WorkflowError(409, "只有草稿评审可以提交")
    before = model_snapshot(review)
    review.status = "SUBMITTED"
    review.submitted_by = actor_id
    review.submitted_at = utc_now()
    _audit(
        db,
        actor_id=actor_id,
        action="PARTNER_REVIEW_SUBMITTED",
        model=review,
        reason=reason,
        source_ip=source_ip,
        before=before,
    )
    return review


def decide_partner_review(
    db: Session,
    *,
    review_id: int,
    payload: PartnerReviewDecision,
    actor_id: int,
    source_ip: str | None,
) -> GspPartnerReview:
    review = db.query(GspPartnerReview).filter_by(id=review_id).with_for_update().first()
    if review is None:
        raise WorkflowError(404, "合作方评审不存在")
    if review.status != "SUBMITTED":
        raise WorkflowError(409, "只有已提交评审可以批准")
    if actor_id in {review.created_by, review.submitted_by}:
        raise WorkflowError(409, "评审编制/提交人与批准人必须分离")
    conclusion = payload.conclusion.upper()
    if conclusion not in REVIEW_CONCLUSIONS:
        raise WorkflowError(422, "评审结论无效")
    if conclusion != "REJECTED" and (
        payload.next_review_date is None or payload.next_review_date <= date.today()
    ):
        raise WorkflowError(422, "通过或有条件通过时必须设置未来复审日期")
    if conclusion == "CONDITIONAL" and (
        not review.action_plan or review.action_due_date is None or review.action_due_date <= date.today()
    ):
        raise WorkflowError(422, "有条件通过必须有整改计划和未来整改期限")
    before = model_snapshot(review)
    review.conclusion = conclusion
    review.next_review_date = payload.next_review_date
    review.approved_by = actor_id
    review.approved_at = utc_now()
    review.status = conclusion
    if conclusion == "REJECTED":
        partner = (
            db.query(GspBusinessPartner)
            .filter(GspBusinessPartner.id == review.partner_id)
            .with_for_update()
            .one()
        )
        partner.status = "SUSPENDED"
        partner.suspension_reason = f"合作方评审 {review.review_no} 结论不通过"
    _audit(
        db,
        actor_id=actor_id,
        action="PARTNER_REVIEW_DECIDED",
        model=review,
        reason=payload.reason,
        source_ip=source_ip,
        before=before,
    )
    return review


def close_partner_review(
    db: Session,
    *,
    review_id: int,
    payload: PartnerReviewClosure,
    actor_id: int,
    source_ip: str | None,
) -> GspPartnerReview:
    review = db.query(GspPartnerReview).filter_by(id=review_id).with_for_update().first()
    if review is None:
        raise WorkflowError(404, "合作方评审不存在")
    if review.status != "CONDITIONAL":
        raise WorkflowError(409, "只有有条件通过的评审需要整改关闭")
    if actor_id in {review.created_by, review.submitted_by}:
        raise WorkflowError(409, "评审编制/提交人与整改关闭复核人必须分离")
    before = model_snapshot(review)
    review.closure_evidence_ref = payload.closure_evidence_ref
    review.closed_by = actor_id
    review.closed_at = utc_now()
    review.status = "APPROVED"
    _audit(
        db,
        actor_id=actor_id,
        action="PARTNER_REVIEW_ACTIONS_CLOSED",
        model=review,
        reason=payload.reason,
        source_ip=source_ip,
        before=before,
    )
    return review


def create_quality_risk(
    db: Session, *, payload: QualityRiskCreate, actor_id: int, source_ip: str | None
) -> GspQualityRisk:
    _user(db, payload.owner_id)
    risk = GspQualityRisk(
        **payload.model_dump(exclude={"reason"}),
        initial_rpn=(payload.initial_likelihood * payload.initial_severity * payload.initial_detectability),
        created_by=actor_id,
    )
    db.add(risk)
    _audit(
        db,
        actor_id=actor_id,
        action="QUALITY_RISK_CREATED",
        model=risk,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return risk


def submit_quality_risk(
    db: Session, *, risk_id: int, actor_id: int, reason: str, source_ip: str | None
) -> GspQualityRisk:
    risk = db.query(GspQualityRisk).filter_by(id=risk_id).with_for_update().first()
    if risk is None:
        raise WorkflowError(404, "质量风险不存在")
    if risk.status != "DRAFT":
        raise WorkflowError(409, "只有草稿风险可以提交")
    before = model_snapshot(risk)
    risk.status = "PENDING_REVIEW"
    risk.submitted_by = actor_id
    risk.submitted_at = utc_now()
    _audit(
        db,
        actor_id=actor_id,
        action="QUALITY_RISK_SUBMITTED",
        model=risk,
        reason=reason,
        source_ip=source_ip,
        before=before,
    )
    return risk


def review_quality_risk(
    db: Session,
    *,
    risk_id: int,
    payload: QualityRiskDecision,
    actor_id: int,
    source_ip: str | None,
) -> GspQualityRisk:
    risk = db.query(GspQualityRisk).filter_by(id=risk_id).with_for_update().first()
    if risk is None:
        raise WorkflowError(404, "质量风险不存在")
    if risk.status != "PENDING_REVIEW":
        raise WorkflowError(409, "只有待复核风险可以评审")
    if actor_id in {risk.created_by, risk.submitted_by}:
        raise WorkflowError(409, "风险编制/提交人与复核人必须分离")
    before = model_snapshot(risk)
    risk.residual_likelihood = payload.residual_likelihood
    risk.residual_severity = payload.residual_severity
    risk.residual_detectability = payload.residual_detectability
    risk.residual_rpn = (
        payload.residual_likelihood * payload.residual_severity * payload.residual_detectability
    )
    risk.review_conclusion = payload.conclusion
    risk.reviewed_by = actor_id
    risk.reviewed_at = utc_now()
    risk.status = "CLOSED" if payload.close else "MITIGATING"
    risk.closed_at = utc_now() if payload.close else None
    _audit(
        db,
        actor_id=actor_id,
        action="QUALITY_RISK_REVIEWED",
        model=risk,
        reason=payload.reason,
        source_ip=source_ip,
        before=before,
    )
    return risk


def create_quality_event(
    db: Session, *, payload: QualityEventCreate, actor_id: int, source_ip: str | None
) -> GspQualityEvent:
    event_type = payload.event_type.upper()
    severity = payload.severity.upper()
    if event_type not in QUALITY_EVENT_TYPES:
        raise WorkflowError(422, "质量事件类型无效")
    if severity not in EVENT_SEVERITIES:
        raise WorkflowError(422, "质量事件严重度无效")
    _user(db, payload.assigned_to)
    if payload.affected_goods_id is not None and (
        db.query(Goods).filter(Goods.id == payload.affected_goods_id).first() is None
    ):
        raise WorkflowError(404, "受影响货物不存在")
    if payload.affected_batch_id is not None:
        batch = db.query(GspDrugBatch).filter(GspDrugBatch.id == payload.affected_batch_id).first()
        if batch is None:
            raise WorkflowError(404, "受影响批次不存在")
        if payload.affected_goods_id is not None and batch.goods_id != payload.affected_goods_id:
            raise WorkflowError(422, "受影响货物与批次不一致")
    event = GspQualityEvent(
        **payload.model_dump(exclude={"reason", "event_type", "severity"}),
        event_type=event_type,
        severity=severity,
        created_by=actor_id,
    )
    db.add(event)
    _audit(
        db,
        actor_id=actor_id,
        action="QUALITY_EVENT_CREATED",
        model=event,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return event


def investigate_quality_event(
    db: Session,
    *,
    event_id: int,
    payload: QualityEventInvestigation,
    actor_id: int,
    source_ip: str | None,
) -> GspQualityEvent:
    event = db.query(GspQualityEvent).filter_by(id=event_id).with_for_update().first()
    if event is None:
        raise WorkflowError(404, "质量事件不存在")
    if event.status not in {"OPEN", "INVESTIGATING"}:
        raise WorkflowError(409, "当前质量事件不能登记调查结论")
    before = model_snapshot(event)
    event.root_cause = payload.root_cause
    event.conclusion = payload.conclusion
    event.investigated_by = actor_id
    event.investigated_at = utc_now()
    event.status = "PENDING_REVIEW"
    _audit(
        db,
        actor_id=actor_id,
        action="QUALITY_EVENT_INVESTIGATED",
        model=event,
        reason=payload.reason,
        source_ip=source_ip,
        before=before,
    )
    return event


def close_quality_event(
    db: Session, *, event_id: int, actor_id: int, reason: str, source_ip: str | None
) -> GspQualityEvent:
    event = db.query(GspQualityEvent).filter_by(id=event_id).with_for_update().first()
    if event is None:
        raise WorkflowError(404, "质量事件不存在")
    if event.status != "PENDING_REVIEW":
        raise WorkflowError(409, "只有已完成调查的事件可以关闭")
    if actor_id in {event.created_by, event.investigated_by}:
        raise WorkflowError(409, "事件登记/调查人与关闭复核人必须分离")
    active_capa = (
        db.query(GspCapaAction)
        .filter(
            GspCapaAction.event_id == event.id,
            GspCapaAction.status != "CLOSED",
        )
        .count()
    )
    if active_capa:
        raise WorkflowError(409, "关联CAPA尚未通过有效性验证，不能关闭事件")
    if event.regulatory_report_required and not event.regulatory_report_ref:
        raise WorkflowError(409, "要求监管报告的事件缺少报告引用")
    before = model_snapshot(event)
    event.status = "CLOSED"
    event.closed_by = actor_id
    event.closed_at = utc_now()
    _audit(
        db,
        actor_id=actor_id,
        action="QUALITY_EVENT_CLOSED",
        model=event,
        reason=reason,
        source_ip=source_ip,
        before=before,
    )
    return event


def create_capa(db: Session, *, payload: CapaCreate, actor_id: int, source_ip: str | None) -> GspCapaAction:
    _user(db, payload.owner_id)
    if (
        payload.event_id is not None
        and db.query(GspQualityEvent).filter_by(id=payload.event_id).first() is None
    ):
        raise WorkflowError(404, "关联质量事件不存在")
    if payload.risk_id is not None and db.query(GspQualityRisk).filter_by(id=payload.risk_id).first() is None:
        raise WorkflowError(404, "关联质量风险不存在")
    action_type = payload.action_type.upper()
    if action_type not in CAPA_TYPES:
        raise WorkflowError(422, "CAPA类型无效")
    capa = GspCapaAction(
        **payload.model_dump(exclude={"reason", "action_type"}),
        action_type=action_type,
        created_by=actor_id,
    )
    db.add(capa)
    _audit(
        db, actor_id=actor_id, action="CAPA_CREATED", model=capa, reason=payload.reason, source_ip=source_ip
    )
    return capa


def implement_capa(
    db: Session,
    *,
    capa_id: int,
    payload: CapaImplementation,
    actor_id: int,
    source_ip: str | None,
) -> GspCapaAction:
    capa = db.query(GspCapaAction).filter_by(id=capa_id).with_for_update().first()
    if capa is None:
        raise WorkflowError(404, "CAPA不存在")
    if capa.status != "OPEN":
        raise WorkflowError(409, "只有开放CAPA可以登记实施")
    if actor_id != capa.owner_id:
        raise WorkflowError(403, "只有CAPA责任人可以登记实施结果")
    before = model_snapshot(capa)
    capa.completion_evidence_ref = payload.completion_evidence_ref
    capa.implemented_by = actor_id
    capa.implemented_at = utc_now()
    capa.status = "IMPLEMENTED"
    _audit(
        db,
        actor_id=actor_id,
        action="CAPA_IMPLEMENTED",
        model=capa,
        reason=payload.reason,
        source_ip=source_ip,
        before=before,
    )
    return capa


def verify_capa(
    db: Session,
    *,
    capa_id: int,
    payload: CapaVerification,
    actor_id: int,
    source_ip: str | None,
) -> GspCapaAction:
    capa = db.query(GspCapaAction).filter_by(id=capa_id).with_for_update().first()
    if capa is None:
        raise WorkflowError(404, "CAPA不存在")
    if capa.status != "IMPLEMENTED":
        raise WorkflowError(409, "只有已实施CAPA可以验证有效性")
    if actor_id in {capa.owner_id, capa.implemented_by}:
        raise WorkflowError(409, "CAPA实施人与有效性验证人必须分离")
    before = model_snapshot(capa)
    capa.effectiveness_result = payload.effectiveness_result
    capa.verified_by = actor_id
    capa.verified_at = utc_now()
    capa.status = "CLOSED" if payload.effective else "OPEN"
    if not payload.effective:
        capa.completion_evidence_ref = None
        capa.implemented_by = None
        capa.implemented_at = None
    _audit(
        db,
        actor_id=actor_id,
        action="CAPA_EFFECTIVENESS_VERIFIED",
        model=capa,
        reason=payload.reason,
        source_ip=source_ip,
        before=before,
    )
    return capa


def create_training(
    db: Session, *, payload: TrainingCreate, actor_id: int, source_ip: str | None
) -> GspTrainingRecord:
    _user(db, payload.user_id)
    training_type = payload.training_type.upper()
    if training_type not in TRAINING_TYPES:
        raise WorkflowError(422, "培训/岗位考核类型无效")
    record = GspTrainingRecord(
        **payload.model_dump(exclude={"reason", "training_type"}),
        training_type=training_type,
        created_by=actor_id,
    )
    db.add(record)
    _audit(
        db,
        actor_id=actor_id,
        action="TRAINING_PLANNED",
        model=record,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return record


def complete_training(
    db: Session,
    *,
    training_id: int,
    payload: TrainingCompletion,
    actor_id: int,
    source_ip: str | None,
) -> GspTrainingRecord:
    record = db.query(GspTrainingRecord).filter_by(id=training_id).with_for_update().first()
    if record is None:
        raise WorkflowError(404, "培训记录不存在")
    if record.status != "PLANNED":
        raise WorkflowError(409, "只有计划中的培训可以登记完成")
    if actor_id != record.user_id:
        raise WorkflowError(403, "只有受训人本人可以确认培训完成")
    result = payload.result.upper()
    if result not in TRAINING_RESULTS:
        raise WorkflowError(422, "培训结果无效")
    if record.training_type in {"ASSESSMENT", "JOB_QUALIFICATION", "JOB_ASSESSMENT"}:
        if result == "ATTENDED" or payload.score is None:
            raise WorkflowError(422, "岗位资格/考核必须填写分数并判定通过或失败")
    before = model_snapshot(record)
    for key, value in payload.model_dump(exclude={"reason", "result"}).items():
        setattr(record, key, value)
    record.result = result
    record.completed_by = actor_id
    record.status = "COMPLETED"
    _audit(
        db,
        actor_id=actor_id,
        action="TRAINING_COMPLETED",
        model=record,
        reason=payload.reason,
        source_ip=source_ip,
        before=before,
    )
    return record


def verify_training(
    db: Session, *, training_id: int, actor_id: int, reason: str, source_ip: str | None
) -> GspTrainingRecord:
    record = db.query(GspTrainingRecord).filter_by(id=training_id).with_for_update().first()
    if record is None:
        raise WorkflowError(404, "培训记录不存在")
    if record.status != "COMPLETED":
        raise WorkflowError(409, "只有已完成培训可以复核")
    if actor_id in {record.user_id, record.completed_by}:
        raise WorkflowError(409, "受训/完成确认人与培训复核人必须分离")
    before = model_snapshot(record)
    record.verified_by = actor_id
    record.verified_at = utc_now()
    record.status = "VERIFIED" if record.result in {"PASSED", "ATTENDED"} else "FAILED_VERIFIED"
    _audit(
        db,
        actor_id=actor_id,
        action="TRAINING_VERIFIED",
        model=record,
        reason=reason,
        source_ip=source_ip,
        before=before,
    )
    return record


def create_controlled_document(
    db: Session, *, payload: ControlledDocumentCreate, actor_id: int, source_ip: str | None
) -> GspControlledDocument:
    _user(db, payload.owner_id)
    document_type = payload.document_type.upper()
    if document_type not in DOCUMENT_TYPES:
        raise WorkflowError(422, "受控文件类型无效")
    document = GspControlledDocument(
        **payload.model_dump(exclude={"reason", "document_type"}),
        document_type=document_type,
        created_by=actor_id,
    )
    db.add(document)
    _audit(
        db,
        actor_id=actor_id,
        action="CONTROLLED_DOCUMENT_CREATED",
        model=document,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return document


def create_document_revision(
    db: Session,
    *,
    document_id: int,
    payload: DocumentRevisionCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspDocumentRevision:
    document = db.query(GspControlledDocument).filter_by(id=document_id).first()
    if document is None:
        raise WorkflowError(404, "受控文件不存在")
    revision = GspDocumentRevision(
        document_id=document_id,
        **payload.model_dump(exclude={"reason"}),
        drafted_by=actor_id,
    )
    db.add(revision)
    _audit(
        db,
        actor_id=actor_id,
        action="DOCUMENT_REVISION_CREATED",
        model=revision,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return revision


def submit_document_revision(
    db: Session, *, revision_id: int, actor_id: int, reason: str, source_ip: str | None
) -> GspDocumentRevision:
    revision = db.query(GspDocumentRevision).filter_by(id=revision_id).with_for_update().first()
    if revision is None:
        raise WorkflowError(404, "文件修订不存在")
    if revision.status != "DRAFT":
        raise WorkflowError(409, "只有草稿修订可以提交")
    before = model_snapshot(revision)
    revision.status = "PENDING_APPROVAL"
    revision.submitted_by = actor_id
    revision.submitted_at = utc_now()
    _audit(
        db,
        actor_id=actor_id,
        action="DOCUMENT_REVISION_SUBMITTED",
        model=revision,
        reason=reason,
        source_ip=source_ip,
        before=before,
    )
    return revision


def approve_document_revision(
    db: Session, *, revision_id: int, actor_id: int, reason: str, source_ip: str | None
) -> GspDocumentRevision:
    revision = db.query(GspDocumentRevision).filter_by(id=revision_id).with_for_update().first()
    if revision is None:
        raise WorkflowError(404, "文件修订不存在")
    if revision.status != "PENDING_APPROVAL":
        raise WorkflowError(409, "只有待批准修订可以生效")
    if actor_id in {revision.drafted_by, revision.submitted_by}:
        raise WorkflowError(409, "文件起草/提交人与批准人必须分离")
    if revision.effective_date > date.today():
        raise WorkflowError(409, "文件生效日期尚未到达，不能提前标记为有效")
    document = db.query(GspControlledDocument).filter_by(id=revision.document_id).with_for_update().one()
    before = model_snapshot(revision)
    for old in db.query(GspDocumentRevision).filter(
        GspDocumentRevision.document_id == document.id,
        GspDocumentRevision.status == "EFFECTIVE",
        GspDocumentRevision.id != revision.id,
    ):
        old.status = "OBSOLETE"
        old.obsoleted_at = utc_now()
        for copy in db.query(GspDocumentCopy).filter(
            GspDocumentCopy.revision_id == old.id,
            GspDocumentCopy.status == "ISSUED",
        ):
            copy.status = "RECALL_REQUIRED"
    revision.status = "EFFECTIVE"
    revision.approved_by = actor_id
    revision.approved_at = utc_now()
    document.current_version = revision.version
    document.status = "EFFECTIVE"
    _audit(
        db,
        actor_id=actor_id,
        action="DOCUMENT_REVISION_APPROVED",
        model=revision,
        reason=reason,
        source_ip=source_ip,
        before=before,
    )
    return revision


def issue_document_copy(
    db: Session,
    *,
    revision_id: int,
    payload: DocumentCopyCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspDocumentCopy:
    revision = db.query(GspDocumentRevision).filter_by(id=revision_id).first()
    if revision is None or revision.status != "EFFECTIVE":
        raise WorkflowError(409, "只能发放当前有效文件修订")
    copy = GspDocumentCopy(
        revision_id=revision_id,
        **payload.model_dump(exclude={"reason"}),
        issued_by=actor_id,
    )
    db.add(copy)
    _audit(
        db,
        actor_id=actor_id,
        action="DOCUMENT_COPY_ISSUED",
        model=copy,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return copy


def dispose_document_copy(
    db: Session,
    *,
    copy_id: int,
    payload: DocumentCopyDisposition,
    actor_id: int,
    source_ip: str | None,
) -> GspDocumentCopy:
    copy = db.query(GspDocumentCopy).filter_by(id=copy_id).with_for_update().first()
    if copy is None:
        raise WorkflowError(404, "受控副本不存在")
    if copy.status not in {"ISSUED", "RECALL_REQUIRED", "RETURNED"}:
        raise WorkflowError(409, "当前副本不能回收或销毁")
    action = payload.action.upper()
    if action not in {"RETURN", "DESTROY"}:
        raise WorkflowError(422, "副本处置只能是RETURN或DESTROY")
    if action == "RETURN" and copy.status == "RETURNED":
        raise WorkflowError(409, "副本已经回收")
    if action == "DESTROY" and actor_id == copy.issued_by:
        raise WorkflowError(409, "副本发放人与销毁确认人必须分离")
    before = model_snapshot(copy)
    copy.disposition_evidence_ref = payload.evidence_ref
    if action == "RETURN":
        copy.status = "RETURNED"
        copy.returned_by = actor_id
        copy.returned_at = utc_now()
    else:
        copy.status = "DESTROYED"
        copy.destroyed_by = actor_id
        copy.destroyed_at = utc_now()
    _audit(
        db,
        actor_id=actor_id,
        action=f"DOCUMENT_COPY_{copy.status}",
        model=copy,
        reason=payload.reason,
        source_ip=source_ip,
        before=before,
    )
    return copy


def create_equipment(
    db: Session, *, payload: EquipmentCreate, actor_id: int, source_ip: str | None
) -> GspQualityEquipment:
    criticality = payload.criticality.upper()
    if criticality not in EQUIPMENT_CRITICALITIES:
        raise WorkflowError(422, "设备关键程度无效")
    equipment = GspQualityEquipment(
        **payload.model_dump(exclude={"reason", "criticality"}),
        criticality=criticality,
        created_by=actor_id,
    )
    db.add(equipment)
    _audit(
        db,
        actor_id=actor_id,
        action="QUALITY_EQUIPMENT_CREATED",
        model=equipment,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return equipment


def approve_equipment(
    db: Session, *, equipment_id: int, actor_id: int, reason: str, source_ip: str | None
) -> GspQualityEquipment:
    equipment = db.query(GspQualityEquipment).filter_by(id=equipment_id).with_for_update().first()
    if equipment is None:
        raise WorkflowError(404, "设施设备不存在")
    if equipment.status != "PENDING":
        raise WorkflowError(409, "只有待批准设备可以批准")
    if actor_id == equipment.created_by:
        raise WorkflowError(409, "设备建档人与批准人必须分离")
    before = model_snapshot(equipment)
    equipment.status = "APPROVED"
    equipment.approved_by = actor_id
    equipment.approved_at = utc_now()
    _audit(
        db,
        actor_id=actor_id,
        action="QUALITY_EQUIPMENT_APPROVED",
        model=equipment,
        reason=reason,
        source_ip=source_ip,
        before=before,
    )
    return equipment


def create_equipment_activity(
    db: Session,
    *,
    equipment_id: int,
    payload: EquipmentActivityCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspEquipmentActivity:
    equipment = db.query(GspQualityEquipment).filter_by(id=equipment_id).first()
    if equipment is None:
        raise WorkflowError(404, "设施设备不存在")
    if equipment.status not in {"APPROVED", "OUT_OF_SERVICE", "QUALIFICATION_PENDING"}:
        raise WorkflowError(409, "设备档案批准后才能登记验证、校准或维护活动")
    activity_type = payload.activity_type.upper()
    if activity_type not in EQUIPMENT_ACTIVITY_TYPES:
        raise WorkflowError(422, "设备活动类型无效")
    if activity_type in {"QUALIFICATION", "CALIBRATION"} and payload.valid_to is None:
        raise WorkflowError(422, "验证或校准活动必须填写有效期")
    if payload.valid_to is not None and payload.valid_to <= payload.performed_on:
        raise WorkflowError(422, "活动有效期必须晚于执行日期")
    result = payload.result.upper()
    if result not in {"PASSED", "FAILED"}:
        raise WorkflowError(422, "设备活动结果无效")
    activity = GspEquipmentActivity(
        equipment_id=equipment_id,
        **payload.model_dump(exclude={"reason", "activity_type", "result"}),
        activity_type=activity_type,
        result=result,
        recorded_by=actor_id,
    )
    db.add(activity)
    _audit(
        db,
        actor_id=actor_id,
        action="EQUIPMENT_ACTIVITY_RECORDED",
        model=activity,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return activity


def review_equipment_activity(
    db: Session, *, activity_id: int, actor_id: int, reason: str, source_ip: str | None
) -> GspEquipmentActivity:
    activity = db.query(GspEquipmentActivity).filter_by(id=activity_id).with_for_update().first()
    if activity is None:
        raise WorkflowError(404, "设备活动不存在")
    if activity.status != "PENDING_REVIEW":
        raise WorkflowError(409, "只有待复核设备活动可以批准")
    if actor_id == activity.recorded_by:
        raise WorkflowError(409, "设备活动记录人与复核人必须分离")
    equipment = db.query(GspQualityEquipment).filter_by(id=activity.equipment_id).with_for_update().one()
    before = model_snapshot(activity)
    passed = activity.result.upper() == "PASSED"
    activity.status = "APPROVED" if passed else "REJECTED"
    activity.reviewed_by = actor_id
    activity.reviewed_at = utc_now()
    activity.review_reason = reason
    if not passed:
        equipment.status = "OUT_OF_SERVICE"
    elif activity.activity_type == "QUALIFICATION":
        equipment.next_qualification_date = activity.valid_to
    elif activity.activity_type == "CALIBRATION":
        equipment.next_calibration_date = activity.valid_to
    if passed:
        qualification_valid = (
            not equipment.qualification_required
            or equipment.next_qualification_date is not None
            and equipment.next_qualification_date > date.today()
        )
        calibration_valid = (
            not equipment.calibration_required
            or equipment.next_calibration_date is not None
            and equipment.next_calibration_date > date.today()
        )
        equipment.status = (
            "APPROVED" if qualification_valid and calibration_valid else "QUALIFICATION_PENDING"
        )
    _audit(
        db,
        actor_id=actor_id,
        action="EQUIPMENT_ACTIVITY_APPROVED",
        model=activity,
        reason=reason,
        source_ip=source_ip,
        before=before,
    )
    return activity


def create_scope_authorization(
    db: Session,
    *,
    payload: ScopeAuthorizationCreate,
    actor_id: int,
    source_ip: str | None,
) -> GspRegulatedScopeAuthorization:
    category = payload.category.upper()
    if category not in REGULATED_CATEGORIES:
        raise WorkflowError(422, "受监管经营范围类别无效")
    authorization = GspRegulatedScopeAuthorization(
        **payload.model_dump(exclude={"reason", "category"}),
        category=category,
        created_by=actor_id,
    )
    db.add(authorization)
    _audit(
        db,
        actor_id=actor_id,
        action="REGULATED_SCOPE_CREATED",
        model=authorization,
        reason=payload.reason,
        source_ip=source_ip,
    )
    return authorization


def approve_scope_authorization(
    db: Session, *, scope_id: int, actor_id: int, reason: str, source_ip: str | None
) -> GspRegulatedScopeAuthorization:
    authorization = db.query(GspRegulatedScopeAuthorization).filter_by(id=scope_id).with_for_update().first()
    if authorization is None:
        raise WorkflowError(404, "受监管经营范围授权不存在")
    if authorization.status != "PENDING":
        raise WorkflowError(409, "只有待审批经营范围可以批准")
    if actor_id == authorization.created_by:
        raise WorkflowError(409, "经营范围建档人与批准人必须分离")
    if authorization.valid_to <= date.today():
        raise WorkflowError(409, "已过期经营范围授权不能批准")
    before = model_snapshot(authorization)
    authorization.status = "APPROVED"
    authorization.approved_by = actor_id
    authorization.approved_at = utc_now()
    _audit(
        db,
        actor_id=actor_id,
        action="REGULATED_SCOPE_APPROVED",
        model=authorization,
        reason=reason,
        source_ip=source_ip,
        before=before,
    )
    return authorization

from datetime import date, timedelta
from uuid import uuid4

import pytest

from app.core.database import SessionLocal
from app.gsp.errors import WorkflowError
from app.gsp.models import GspBusinessPartner, GspDrugProfile
from app.gsp.qualification import evaluate_product_evidence
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
from app.legacy import Goods, User, UserRole


def _users(db):
    suffix = uuid4().hex[:8]
    users = [
        User(
            username=f"qms-{name}-{suffix}",
            hashed_password="test-only",
            full_name=name,
            role=UserRole.OPERATOR,
            is_active=True,
        )
        for name in ("编制人", "责任人", "独立复核人")
    ]
    db.add_all(users)
    db.flush()
    return users


def test_partner_periodic_review_requires_independent_decision_and_suspends_failure():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        creator, _, reviewer = _users(db)
        suffix = uuid4().hex[:8]
        partner = GspBusinessPartner(
            code=f"QMS-P-{suffix}",
            name="年度评审测试供货方",
            partner_type="SUPPLIER",
            license_no=f"QMS-L-{suffix}",
            license_scope="药品批发",
            license_valid_to=date.today() + timedelta(days=365),
            status="APPROVED",
            created_by=creator.id,
        )
        db.add(partner)
        db.flush()
        review = create_partner_review(
            db,
            payload=PartnerReviewCreate(
                review_no=f"QMS-R-{suffix}",
                partner_id=partner.id,
                review_year=date.today().year,
                review_type="ANNUAL",
                scope="许可证、供货质量、退货与投诉情况",
                survey_summary="年度质量体系调查已完成",
                findings="发现重大质量体系缺陷",
                risk_level="HIGH",
                action_plan="暂停合作并要求整改",
                action_due_date=date.today() + timedelta(days=30),
                reason="建立年度评审记录",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        submit_partner_review(
            db,
            review_id=review.id,
            actor_id=creator.id,
            reason="提交独立质量批准",
            source_ip="127.0.0.1",
        )
        decision = PartnerReviewDecision(conclusion="REJECTED", reason="重大缺陷未关闭")
        with pytest.raises(WorkflowError, match="必须分离"):
            decide_partner_review(
                db,
                review_id=review.id,
                payload=decision,
                actor_id=creator.id,
                source_ip="127.0.0.1",
            )
        decide_partner_review(
            db,
            review_id=review.id,
            payload=decision,
            actor_id=reviewer.id,
            source_ip="127.0.0.1",
        )
        assert review.status == "REJECTED"
        assert partner.status == "SUSPENDED"
    finally:
        db.rollback()
        db.close()


def test_conditional_partner_review_requires_plan_and_independent_evidence_closure():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        creator, _, reviewer = _users(db)
        suffix = uuid4().hex[:8]
        partner = GspBusinessPartner(
            code=f"QMS-CP-{suffix}",
            name="有条件年度评审测试供货方",
            partner_type="SUPPLIER",
            license_no=f"QMS-CL-{suffix}",
            license_scope="药品批发",
            license_valid_to=date.today() + timedelta(days=365),
            status="APPROVED",
            created_by=creator.id,
        )
        db.add(partner)
        db.flush()
        review = create_partner_review(
            db,
            payload=PartnerReviewCreate(
                review_no=f"QMS-CR-{suffix}",
                partner_id=partner.id,
                review_year=date.today().year,
                review_type="QUALITY_SYSTEM_SURVEY",
                scope="质量体系运行情况",
                survey_summary="存在一般缺陷",
                findings="培训记录需要补齐",
                risk_level="MEDIUM",
                action_plan="补齐培训并由质量部抽查",
                action_due_date=date.today() + timedelta(days=30),
                reason="建立质量体系调查",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        submit_partner_review(
            db,
            review_id=review.id,
            actor_id=creator.id,
            reason="提交有条件评审",
            source_ip="127.0.0.1",
        )
        decide_partner_review(
            db,
            review_id=review.id,
            payload=PartnerReviewDecision(
                conclusion="CONDITIONAL",
                next_review_date=date.today() + timedelta(days=365),
                reason="批准限期整改",
            ),
            actor_id=reviewer.id,
            source_ip="127.0.0.1",
        )
        assert review.status == "CONDITIONAL"
        with pytest.raises(WorkflowError, match="必须分离"):
            close_partner_review(
                db,
                review_id=review.id,
                payload=PartnerReviewClosure(
                    closure_evidence_ref="test://review/closure",
                    reason="错误同人关闭",
                ),
                actor_id=creator.id,
                source_ip="127.0.0.1",
            )
        close_partner_review(
            db,
            review_id=review.id,
            payload=PartnerReviewClosure(
                closure_evidence_ref="test://review/closure",
                reason="独立复核整改证据",
            ),
            actor_id=reviewer.id,
            source_ip="127.0.0.1",
        )
        assert review.status == "APPROVED"
        assert review.closure_evidence_ref == "test://review/closure"
    finally:
        db.rollback()
        db.close()


def test_risk_event_and_capa_close_only_after_independent_effectiveness_review():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        creator, owner, reviewer = _users(db)
        suffix = uuid4().hex[:8]
        risk = create_quality_risk(
            db,
            payload=QualityRiskCreate(
                risk_no=f"RISK-{suffix}",
                category="SUPPLIER",
                source_type="AUDIT",
                title="供应商持续供货风险",
                description="年度审核发现持续供货控制不足",
                initial_likelihood=4,
                initial_severity=4,
                initial_detectability=3,
                controls="增加年度现场审核并跟踪CAPA",
                owner_id=owner.id,
                review_due_date=date.today() + timedelta(days=60),
                reason="登记质量风险",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        assert risk.initial_rpn == 48
        submit_quality_risk(
            db,
            risk_id=risk.id,
            actor_id=creator.id,
            reason="提交风险评审",
            source_ip="127.0.0.1",
        )
        risk_decision = QualityRiskDecision(
            conclusion="剩余风险可接受",
            residual_likelihood=2,
            residual_severity=3,
            residual_detectability=2,
            close=True,
            reason="独立评审剩余风险",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            review_quality_risk(
                db,
                risk_id=risk.id,
                payload=risk_decision,
                actor_id=creator.id,
                source_ip="127.0.0.1",
            )
        review_quality_risk(
            db,
            risk_id=risk.id,
            payload=risk_decision,
            actor_id=reviewer.id,
            source_ip="127.0.0.1",
        )
        assert risk.status == "CLOSED"
        assert risk.residual_rpn == 12

        event = create_quality_event(
            db,
            payload=QualityEventCreate(
                event_no=f"AUDIT-{suffix}",
                event_type="INTERNAL_AUDIT",
                title="年度GSP内审发现",
                occurred_on=date.today(),
                source="年度内审计划",
                description="文件发放记录不完整",
                severity="HIGH",
                immediate_action="冻结相关文件副本并启动调查",
                assigned_to=owner.id,
                reason="登记内审发现",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        investigate_quality_event(
            db,
            event_id=event.id,
            payload=QualityEventInvestigation(
                root_cause="文件管理员未执行副本登记步骤",
                conclusion="需要建立预防措施并复核有效性",
                reason="完成根因调查",
            ),
            actor_id=owner.id,
            source_ip="127.0.0.1",
        )
        capa = create_capa(
            db,
            payload=CapaCreate(
                action_no=f"CAPA-{suffix}",
                event_id=event.id,
                action_type="PREVENTIVE",
                description="上线受控副本登记并培训",
                owner_id=owner.id,
                due_date=date.today() + timedelta(days=30),
                reason="建立预防措施",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="CAPA尚未"):
            close_quality_event(
                db,
                event_id=event.id,
                actor_id=reviewer.id,
                reason="错误提前关闭",
                source_ip="127.0.0.1",
            )
        implement_capa(
            db,
            capa_id=capa.id,
            payload=CapaImplementation(
                completion_evidence_ref="test://capa/evidence", reason="完成措施并上传证据"
            ),
            actor_id=owner.id,
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            verify_capa(
                db,
                capa_id=capa.id,
                payload=CapaVerification(
                    effectiveness_result="抽查有效", effective=True, reason="错误同人验证"
                ),
                actor_id=owner.id,
                source_ip="127.0.0.1",
            )
        verify_capa(
            db,
            capa_id=capa.id,
            payload=CapaVerification(
                effectiveness_result="连续抽查三次均符合", effective=True, reason="独立验证有效"
            ),
            actor_id=reviewer.id,
            source_ip="127.0.0.1",
        )
        close_quality_event(
            db,
            event_id=event.id,
            actor_id=reviewer.id,
            reason="CAPA有效后关闭内审发现",
            source_ip="127.0.0.1",
        )
        assert capa.status == "CLOSED"
        assert event.status == "CLOSED"
    finally:
        db.rollback()
        db.close()


def test_training_documents_and_equipment_have_independent_review_controls():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        creator, owner, reviewer = _users(db)
        suffix = uuid4().hex[:8]
        training = create_training(
            db,
            payload=TrainingCreate(
                training_no=f"TRN-{suffix}",
                user_id=owner.id,
                subject="受控文件管理培训",
                training_type="INITIAL",
                requirement_ref="SOP-QA-001",
                planned_date=date.today(),
                reason="岗位上岗前培训",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        complete_training(
            db,
            training_id=training.id,
            payload=TrainingCompletion(
                trainer="质量培训师",
                completed_on=date.today(),
                score=95,
                result="PASSED",
                evidence_ref="test://training/evidence",
                valid_to=date.today() + timedelta(days=365),
                reason="本人确认完成培训",
            ),
            actor_id=owner.id,
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            verify_training(
                db,
                training_id=training.id,
                actor_id=owner.id,
                reason="错误同人复核",
                source_ip="127.0.0.1",
            )
        verify_training(
            db,
            training_id=training.id,
            actor_id=reviewer.id,
            reason="质量独立复核培训证据",
            source_ip="127.0.0.1",
        )

        document = create_controlled_document(
            db,
            payload=ControlledDocumentCreate(
                document_no=f"SOP-{suffix}",
                title="受控文件管理规程",
                document_type="SOP",
                department="质量部",
                owner_id=owner.id,
                reason="建立受控SOP",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        revision = create_document_revision(
            db,
            document_id=document.id,
            payload=DocumentRevisionCreate(
                version="1.0",
                change_summary="首次发布",
                content_ref="test://documents/sop",
                content_sha256="a" * 64,
                effective_date=date.today(),
                reason="提交首次版本",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        submit_document_revision(
            db,
            revision_id=revision.id,
            actor_id=creator.id,
            reason="提交文件批准",
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            approve_document_revision(
                db,
                revision_id=revision.id,
                actor_id=creator.id,
                reason="错误同人批准",
                source_ip="127.0.0.1",
            )
        approve_document_revision(
            db,
            revision_id=revision.id,
            actor_id=reviewer.id,
            reason="质量独立批准文件",
            source_ip="127.0.0.1",
        )
        copy = issue_document_copy(
            db,
            revision_id=revision.id,
            payload=DocumentCopyCreate(
                copy_no=f"COPY-{suffix}",
                holder="仓库",
                location="收货区",
                purpose="现场执行",
                reason="发放受控副本",
            ),
            actor_id=reviewer.id,
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            dispose_document_copy(
                db,
                copy_id=copy.id,
                payload=DocumentCopyDisposition(
                    action="DESTROY", evidence_ref="test://copy/destroy", reason="错误同人销毁"
                ),
                actor_id=reviewer.id,
                source_ip="127.0.0.1",
            )
        dispose_document_copy(
            db,
            copy_id=copy.id,
            payload=DocumentCopyDisposition(
                action="DESTROY", evidence_ref="test://copy/destroy", reason="独立销毁确认"
            ),
            actor_id=owner.id,
            source_ip="127.0.0.1",
        )

        equipment = create_equipment(
            db,
            payload=EquipmentCreate(
                equipment_no=f"EQ-{suffix}",
                name="仓库温度验证设备",
                category="FACILITY",
                location="常温库",
                criticality="HIGH",
                qualification_required=True,
                calibration_required=True,
                reason="建立关键设备档案",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            approve_equipment(
                db,
                equipment_id=equipment.id,
                actor_id=creator.id,
                reason="错误同人批准",
                source_ip="127.0.0.1",
            )
        approve_equipment(
            db,
            equipment_id=equipment.id,
            actor_id=reviewer.id,
            reason="独立批准设备档案",
            source_ip="127.0.0.1",
        )
        activity = create_equipment_activity(
            db,
            equipment_id=equipment.id,
            payload=EquipmentActivityCreate(
                activity_no=f"CAL-{suffix}",
                activity_type="CALIBRATION",
                performed_on=date.today(),
                valid_to=date.today() + timedelta(days=365),
                provider="认可校准机构",
                certificate_ref="test://calibration/certificate",
                result="PASSED",
                reason="登记校准结果",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            review_equipment_activity(
                db,
                activity_id=activity.id,
                actor_id=creator.id,
                reason="错误同人复核",
                source_ip="127.0.0.1",
            )
        review_equipment_activity(
            db,
            activity_id=activity.id,
            actor_id=reviewer.id,
            reason="独立复核校准证据",
            source_ip="127.0.0.1",
        )
        assert training.status == "VERIFIED"
        assert revision.status == "EFFECTIVE"
        assert copy.status == "DESTROYED"
        assert equipment.next_calibration_date == activity.valid_to
    finally:
        db.rollback()
        db.close()


def test_failed_job_assessment_and_equipment_result_remain_visibly_failed():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        creator, owner, reviewer = _users(db)
        suffix = uuid4().hex[:8]
        training = create_training(
            db,
            payload=TrainingCreate(
                training_no=f"ASM-{suffix}",
                user_id=owner.id,
                subject="岗位职责年度考核",
                training_type="JOB_ASSESSMENT",
                requirement_ref="JOB-QA-001",
                planned_date=date.today(),
                reason="建立年度岗位考核",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        complete_training(
            db,
            training_id=training.id,
            payload=TrainingCompletion(
                trainer="质量负责人",
                completed_on=date.today(),
                score=55,
                result="FAILED",
                evidence_ref="test://assessment/failed",
                reason="本人确认考核结果",
            ),
            actor_id=owner.id,
            source_ip="127.0.0.1",
        )
        verify_training(
            db,
            training_id=training.id,
            actor_id=reviewer.id,
            reason="独立复核不通过结果",
            source_ip="127.0.0.1",
        )
        assert training.status == "FAILED_VERIFIED"

        equipment = create_equipment(
            db,
            payload=EquipmentCreate(
                equipment_no=f"EQF-{suffix}",
                name="关键设施",
                category="FACILITY",
                location="仓库",
                criticality="CRITICAL",
                qualification_required=True,
                calibration_required=False,
                reason="建立关键设施档案",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        approve_equipment(
            db,
            equipment_id=equipment.id,
            actor_id=reviewer.id,
            reason="独立批准设备档案",
            source_ip="127.0.0.1",
        )
        failed = create_equipment_activity(
            db,
            equipment_id=equipment.id,
            payload=EquipmentActivityCreate(
                activity_no=f"QF-{suffix}",
                activity_type="QUALIFICATION",
                performed_on=date.today(),
                valid_to=date.today() + timedelta(days=365),
                provider="验证服务商",
                certificate_ref="test://qualification/failed",
                result="FAILED",
                reason="登记失败验证结果",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        review_equipment_activity(
            db,
            activity_id=failed.id,
            actor_id=reviewer.id,
            reason="独立复核失败并停用设备",
            source_ip="127.0.0.1",
        )
        assert failed.status == "REJECTED"
        assert equipment.status == "OUT_OF_SERVICE"
    finally:
        db.rollback()
        db.close()


def test_special_and_vaccine_products_require_approved_business_scope():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        creator, _, reviewer = _users(db)
        suffix = uuid4().hex[:8]
        goods = Goods(
            barcode=f"VAX-{suffix}",
            name="专项范围测试药品",
            spec="1支",
            unit="支",
            price=10,
        )
        db.add(goods)
        db.flush()
        profile = GspDrugProfile(
            goods_id=goods.id,
            approval_no=f"VAX-APP-{suffix}",
            generic_name="测试疫苗",
            dosage_form="注射剂",
            manufacturer="测试企业",
            storage_condition="COLD",
            is_special_controlled=True,
            regulatory_category="VACCINE",
            traceability_required=True,
            registration_valid_to=date.today() + timedelta(days=365),
            registration_document_ref="test://registration/vaccine",
            nmpa_verification_ref="test://nmpa/vaccine",
            status="APPROVED",
            created_by=creator.id,
        )
        db.add(profile)
        db.flush()
        blocked = evaluate_product_evidence(db, profile)
        assert not blocked.qualified
        assert {item.code for item in blocked.findings} == {"REGULATED_SCOPE_MISSING"}

        scope = create_scope_authorization(
            db,
            payload=ScopeAuthorizationCreate(
                category="VACCINE",
                authorization_no=f"VAX-SCOPE-{suffix}",
                authorization_ref="test://scope/vaccine",
                valid_to=date.today() + timedelta(days=365),
                controls_summary="疫苗经营、冷链和双人复核范围已批准",
                reason="建立疫苗专项经营范围",
            ),
            actor_id=creator.id,
            source_ip="127.0.0.1",
        )
        with pytest.raises(WorkflowError, match="必须分离"):
            approve_scope_authorization(
                db,
                scope_id=scope.id,
                actor_id=creator.id,
                reason="错误同人批准",
                source_ip="127.0.0.1",
            )
        approve_scope_authorization(
            db,
            scope_id=scope.id,
            actor_id=reviewer.id,
            reason="独立批准疫苗经营范围",
            source_ip="127.0.0.1",
        )
        assert evaluate_product_evidence(db, profile).qualified
    finally:
        db.rollback()
        db.close()

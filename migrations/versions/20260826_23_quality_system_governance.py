"""Quality-system governance and regulated product scope controls.

Revision ID: 20260826_23
Revises: 20260826_22
Create Date: 2026-08-26
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260826_23"
down_revision: Union[str, None] = "20260826_22"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "gsp_drug_profiles",
        sa.Column(
            "regulatory_category",
            sa.String(length=40),
            nullable=False,
            server_default="GENERAL",
        ),
    )
    op.create_index(
        op.f("ix_gsp_drug_profiles_regulatory_category"),
        "gsp_drug_profiles",
        ["regulatory_category"],
        unique=False,
    )
    with op.batch_alter_table("gsp_drug_profiles") as batch_op:
        batch_op.alter_column(
            "regulatory_category",
            existing_type=sa.String(length=40),
            server_default=None,
            existing_nullable=False,
        )

    op.create_table(
        "gsp_partner_reviews",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("review_no", sa.String(length=100), nullable=False),
        sa.Column("partner_id", sa.Integer(), nullable=False),
        sa.Column("review_year", sa.Integer(), nullable=False),
        sa.Column("review_type", sa.String(length=30), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("survey_summary", sa.Text(), nullable=False),
        sa.Column("findings", sa.Text(), nullable=True),
        sa.Column("risk_level", sa.String(length=20), nullable=False),
        sa.Column("conclusion", sa.String(length=30), nullable=True),
        sa.Column("action_plan", sa.Text(), nullable=True),
        sa.Column("action_due_date", sa.Date(), nullable=True),
        sa.Column("next_review_date", sa.Date(), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("submitted_by", sa.Integer(), nullable=True),
        sa.Column("submitted_at", sa.DateTime(), nullable=True),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("closed_by", sa.Integer(), nullable=True),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        sa.Column("closure_evidence_ref", sa.String(length=500), nullable=True),
        sa.CheckConstraint("review_year >= 2000", name="ck_gsp_partner_review_year"),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["closed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["partner_id"], ["gsp_business_partners.id"]),
        sa.ForeignKeyConstraint(["submitted_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "partner_id", "review_year", "review_type", name="uq_gsp_partner_periodic_review"
        ),
        sa.UniqueConstraint("review_no"),
    )
    for column in ("partner_id", "review_year", "review_type", "conclusion", "next_review_date", "status"):
        op.create_index(op.f(f"ix_gsp_partner_reviews_{column}"), "gsp_partner_reviews", [column])

    op.create_table(
        "gsp_quality_risks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("risk_no", sa.String(length=100), nullable=False),
        sa.Column("category", sa.String(length=50), nullable=False),
        sa.Column("source_type", sa.String(length=50), nullable=False),
        sa.Column("source_ref", sa.String(length=200), nullable=True),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("initial_likelihood", sa.Integer(), nullable=False),
        sa.Column("initial_severity", sa.Integer(), nullable=False),
        sa.Column("initial_detectability", sa.Integer(), nullable=False),
        sa.Column("initial_rpn", sa.Integer(), nullable=False),
        sa.Column("controls", sa.Text(), nullable=False),
        sa.Column("residual_likelihood", sa.Integer(), nullable=True),
        sa.Column("residual_severity", sa.Integer(), nullable=True),
        sa.Column("residual_detectability", sa.Integer(), nullable=True),
        sa.Column("residual_rpn", sa.Integer(), nullable=True),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("review_due_date", sa.Date(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("submitted_by", sa.Integer(), nullable=True),
        sa.Column("submitted_at", sa.DateTime(), nullable=True),
        sa.Column("reviewed_by", sa.Integer(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("review_conclusion", sa.Text(), nullable=True),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "initial_likelihood BETWEEN 1 AND 5 AND initial_severity BETWEEN 1 AND 5 "
            "AND initial_detectability BETWEEN 1 AND 5",
            name="ck_gsp_quality_risk_initial_scores",
        ),
        sa.CheckConstraint(
            "(residual_likelihood IS NULL OR residual_likelihood BETWEEN 1 AND 5) "
            "AND (residual_severity IS NULL OR residual_severity BETWEEN 1 AND 5) "
            "AND (residual_detectability IS NULL OR residual_detectability BETWEEN 1 AND 5)",
            name="ck_gsp_quality_risk_residual_scores",
        ),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["submitted_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("risk_no"),
    )
    for column in (
        "category",
        "source_type",
        "initial_rpn",
        "residual_rpn",
        "owner_id",
        "review_due_date",
        "status",
    ):
        op.create_index(op.f(f"ix_gsp_quality_risks_{column}"), "gsp_quality_risks", [column])

    op.create_table(
        "gsp_quality_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_no", sa.String(length=100), nullable=False),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("occurred_on", sa.Date(), nullable=False),
        sa.Column("source", sa.String(length=200), nullable=False),
        sa.Column("reporter_name", sa.String(length=200), nullable=True),
        sa.Column("contact_ref", sa.String(length=200), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("affected_goods_id", sa.Integer(), nullable=True),
        sa.Column("affected_batch_id", sa.Integer(), nullable=True),
        sa.Column("immediate_action", sa.Text(), nullable=False),
        sa.Column("assigned_to", sa.Integer(), nullable=False),
        sa.Column("regulatory_report_required", sa.Boolean(), nullable=False),
        sa.Column("regulatory_report_ref", sa.String(length=500), nullable=True),
        sa.Column("root_cause", sa.Text(), nullable=True),
        sa.Column("conclusion", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("investigated_by", sa.Integer(), nullable=True),
        sa.Column("investigated_at", sa.DateTime(), nullable=True),
        sa.Column("closed_by", sa.Integer(), nullable=True),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["affected_batch_id"], ["gsp_drug_batches.id"]),
        sa.ForeignKeyConstraint(["affected_goods_id"], ["goods.id"]),
        sa.ForeignKeyConstraint(["assigned_to"], ["users.id"]),
        sa.ForeignKeyConstraint(["closed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["investigated_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_no"),
    )
    for column in (
        "event_type",
        "occurred_on",
        "severity",
        "affected_goods_id",
        "affected_batch_id",
        "assigned_to",
        "status",
    ):
        op.create_index(op.f(f"ix_gsp_quality_events_{column}"), "gsp_quality_events", [column])

    op.create_table(
        "gsp_capa_actions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("action_no", sa.String(length=100), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=True),
        sa.Column("risk_id", sa.Integer(), nullable=True),
        sa.Column("action_type", sa.String(length=30), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("due_date", sa.Date(), nullable=False),
        sa.Column("completion_evidence_ref", sa.String(length=500), nullable=True),
        sa.Column("effectiveness_result", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("implemented_by", sa.Integer(), nullable=True),
        sa.Column("implemented_at", sa.DateTime(), nullable=True),
        sa.Column("verified_by", sa.Integer(), nullable=True),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("event_id IS NOT NULL OR risk_id IS NOT NULL", name="ck_gsp_capa_has_source"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["event_id"], ["gsp_quality_events.id"]),
        sa.ForeignKeyConstraint(["implemented_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["risk_id"], ["gsp_quality_risks.id"]),
        sa.ForeignKeyConstraint(["verified_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("action_no"),
    )
    for column in ("event_id", "risk_id", "owner_id", "due_date", "status"):
        op.create_index(op.f(f"ix_gsp_capa_actions_{column}"), "gsp_capa_actions", [column])

    op.create_table(
        "gsp_training_records",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("training_no", sa.String(length=100), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("subject", sa.String(length=200), nullable=False),
        sa.Column("training_type", sa.String(length=30), nullable=False),
        sa.Column("requirement_ref", sa.String(length=500), nullable=False),
        sa.Column("planned_date", sa.Date(), nullable=False),
        sa.Column("trainer", sa.String(length=200), nullable=True),
        sa.Column("completed_on", sa.Date(), nullable=True),
        sa.Column("score", sa.Integer(), nullable=True),
        sa.Column("result", sa.String(length=30), nullable=True),
        sa.Column("evidence_ref", sa.String(length=500), nullable=True),
        sa.Column("valid_to", sa.Date(), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("completed_by", sa.Integer(), nullable=True),
        sa.Column("verified_by", sa.Integer(), nullable=True),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("score IS NULL OR score BETWEEN 0 AND 100", name="ck_gsp_training_score"),
        sa.ForeignKeyConstraint(["completed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["verified_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("training_no"),
    )
    for column in ("user_id", "training_type", "planned_date", "result", "valid_to", "status"):
        op.create_index(op.f(f"ix_gsp_training_records_{column}"), "gsp_training_records", [column])

    op.create_table(
        "gsp_controlled_documents",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("document_no", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("document_type", sa.String(length=30), nullable=False),
        sa.Column("department", sa.String(length=100), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("current_version", sa.String(length=50), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("document_no"),
    )
    for column in ("document_type", "status"):
        op.create_index(op.f(f"ix_gsp_controlled_documents_{column}"), "gsp_controlled_documents", [column])

    op.create_table(
        "gsp_document_revisions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("document_id", sa.Integer(), nullable=False),
        sa.Column("version", sa.String(length=50), nullable=False),
        sa.Column("change_summary", sa.Text(), nullable=False),
        sa.Column("content_ref", sa.String(length=500), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("effective_date", sa.Date(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("drafted_by", sa.Integer(), nullable=False),
        sa.Column("drafted_at", sa.DateTime(), nullable=False),
        sa.Column("submitted_by", sa.Integer(), nullable=True),
        sa.Column("submitted_at", sa.DateTime(), nullable=True),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("obsoleted_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["document_id"], ["gsp_controlled_documents.id"]),
        sa.ForeignKeyConstraint(["drafted_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["submitted_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("document_id", "version", name="uq_gsp_document_revision"),
    )
    for column in ("document_id", "effective_date", "status"):
        op.create_index(op.f(f"ix_gsp_document_revisions_{column}"), "gsp_document_revisions", [column])

    op.create_table(
        "gsp_document_copies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("revision_id", sa.Integer(), nullable=False),
        sa.Column("copy_no", sa.String(length=100), nullable=False),
        sa.Column("holder", sa.String(length=200), nullable=False),
        sa.Column("location", sa.String(length=200), nullable=False),
        sa.Column("purpose", sa.String(length=500), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("issued_by", sa.Integer(), nullable=False),
        sa.Column("issued_at", sa.DateTime(), nullable=False),
        sa.Column("returned_by", sa.Integer(), nullable=True),
        sa.Column("returned_at", sa.DateTime(), nullable=True),
        sa.Column("destroyed_by", sa.Integer(), nullable=True),
        sa.Column("destroyed_at", sa.DateTime(), nullable=True),
        sa.Column("disposition_evidence_ref", sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(["destroyed_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["issued_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["returned_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["revision_id"], ["gsp_document_revisions.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("copy_no"),
    )
    for column in ("revision_id", "status"):
        op.create_index(op.f(f"ix_gsp_document_copies_{column}"), "gsp_document_copies", [column])

    op.create_table(
        "gsp_quality_equipment",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("equipment_no", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("category", sa.String(length=50), nullable=False),
        sa.Column("location", sa.String(length=200), nullable=False),
        sa.Column("criticality", sa.String(length=20), nullable=False),
        sa.Column("qualification_required", sa.Boolean(), nullable=False),
        sa.Column("calibration_required", sa.Boolean(), nullable=False),
        sa.Column("next_qualification_date", sa.Date(), nullable=True),
        sa.Column("next_calibration_date", sa.Date(), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("equipment_no"),
    )
    for column in ("category", "next_qualification_date", "next_calibration_date", "status"):
        op.create_index(op.f(f"ix_gsp_quality_equipment_{column}"), "gsp_quality_equipment", [column])

    op.create_table(
        "gsp_equipment_activities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("activity_no", sa.String(length=100), nullable=False),
        sa.Column("equipment_id", sa.Integer(), nullable=False),
        sa.Column("activity_type", sa.String(length=30), nullable=False),
        sa.Column("performed_on", sa.Date(), nullable=False),
        sa.Column("valid_to", sa.Date(), nullable=True),
        sa.Column("provider", sa.String(length=200), nullable=False),
        sa.Column("certificate_ref", sa.String(length=500), nullable=False),
        sa.Column("result", sa.String(length=30), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("recorded_by", sa.Integer(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(), nullable=False),
        sa.Column("reviewed_by", sa.Integer(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("review_reason", sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(["equipment_id"], ["gsp_quality_equipment.id"]),
        sa.ForeignKeyConstraint(["recorded_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("activity_no"),
    )
    for column in ("equipment_id", "activity_type", "valid_to", "status"):
        op.create_index(op.f(f"ix_gsp_equipment_activities_{column}"), "gsp_equipment_activities", [column])

    op.create_table(
        "gsp_regulated_scope_authorizations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("category", sa.String(length=40), nullable=False),
        sa.Column("authorization_no", sa.String(length=100), nullable=False),
        sa.Column("authorization_ref", sa.String(length=500), nullable=False),
        sa.Column("valid_to", sa.Date(), nullable=False),
        sa.Column("controls_summary", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("authorization_no"),
    )
    for column in ("category", "valid_to", "status"):
        op.create_index(
            op.f(f"ix_gsp_regulated_scope_authorizations_{column}"),
            "gsp_regulated_scope_authorizations",
            [column],
        )


def downgrade() -> None:
    op.drop_table("gsp_regulated_scope_authorizations")
    op.drop_table("gsp_equipment_activities")
    op.drop_table("gsp_quality_equipment")
    op.drop_table("gsp_document_copies")
    op.drop_table("gsp_document_revisions")
    op.drop_table("gsp_controlled_documents")
    op.drop_table("gsp_training_records")
    op.drop_table("gsp_capa_actions")
    op.drop_table("gsp_quality_events")
    op.drop_table("gsp_quality_risks")
    op.drop_table("gsp_partner_reviews")
    op.drop_index(op.f("ix_gsp_drug_profiles_regulatory_category"), table_name="gsp_drug_profiles")
    with op.batch_alter_table("gsp_drug_profiles") as batch_op:
        batch_op.drop_column("regulatory_category")

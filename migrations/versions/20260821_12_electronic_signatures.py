"""Electronic signatures, identity reconfirmation and immutable signature chain.

Revision ID: 20260821_12
Revises: 20260821_11
Create Date: 2026-08-21
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260821_12"
down_revision: Union[str, None] = "20260821_11"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _indexes(table: str, *columns: str, unique: bool = False) -> None:
    for column in columns:
        op.create_index(f"ix_{table}_{column}", table, [column], unique=unique)


def upgrade() -> None:
    op.create_table(
        "gsp_signature_challenges",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("challenge_ref", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("signer_user_id", sa.Integer(), nullable=False),
        sa.Column("signer_username", sa.String(length=50), nullable=False),
        sa.Column("signer_full_name", sa.String(length=100), nullable=False),
        sa.Column("authentication_method", sa.String(length=20), nullable=False),
        sa.Column("meaning", sa.String(length=30), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("entity_type", sa.String(length=100), nullable=False),
        sa.Column("entity_id", sa.String(length=100), nullable=False),
        sa.Column("payload_snapshot", sa.JSON(), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("verified_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(), nullable=True),
        sa.Column("source_ip", sa.String(length=100), nullable=True),
        sa.CheckConstraint(
            "authentication_method IN ('LOCAL','LDAP')",
            name="ck_gsp_signature_challenge_auth_method",
        ),
        sa.CheckConstraint(
            "meaning IN ('APPROVAL','REVIEW','RELEASE','CONFIRMATION','RESPONSIBILITY')",
            name="ck_gsp_signature_challenge_meaning",
        ),
        sa.CheckConstraint(
            "status IN ('READY','CONSUMED')",
            name="ck_gsp_signature_challenge_status",
        ),
        sa.ForeignKeyConstraint(["signer_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("challenge_ref"),
        sa.UniqueConstraint("token_hash"),
    )
    _indexes(
        "gsp_signature_challenges",
        "signer_user_id",
        "meaning",
        "action",
        "entity_type",
        "entity_id",
        "status",
        "expires_at",
    )
    _indexes("gsp_signature_challenges", "challenge_ref", unique=True)

    op.create_table(
        "gsp_electronic_signatures",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("signature_ref", sa.String(length=36), nullable=False),
        sa.Column("challenge_id", sa.Integer(), nullable=False),
        sa.Column("challenge_ref", sa.String(length=36), nullable=False),
        sa.Column("signer_user_id", sa.Integer(), nullable=False),
        sa.Column("signer_username", sa.String(length=50), nullable=False),
        sa.Column("signer_full_name", sa.String(length=100), nullable=False),
        sa.Column("authentication_method", sa.String(length=20), nullable=False),
        sa.Column("meaning", sa.String(length=30), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("entity_type", sa.String(length=100), nullable=False),
        sa.Column("entity_id", sa.String(length=100), nullable=False),
        sa.Column("payload_snapshot", sa.JSON(), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("source_ip", sa.String(length=100), nullable=True),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("signature_hash", sa.String(length=64), nullable=False),
        sa.Column("credential_verified_at", sa.DateTime(), nullable=False),
        sa.Column("signed_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "authentication_method IN ('LOCAL','LDAP')",
            name="ck_gsp_electronic_signature_auth_method",
        ),
        sa.CheckConstraint(
            "meaning IN ('APPROVAL','REVIEW','RELEASE','CONFIRMATION','RESPONSIBILITY')",
            name="ck_gsp_electronic_signature_meaning",
        ),
        sa.ForeignKeyConstraint(["challenge_id"], ["gsp_signature_challenges.id"]),
        sa.ForeignKeyConstraint(["signer_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("challenge_id"),
        sa.UniqueConstraint("signature_hash"),
        sa.UniqueConstraint("signature_ref"),
    )
    _indexes(
        "gsp_electronic_signatures",
        "signer_user_id",
        "meaning",
        "action",
        "entity_type",
        "entity_id",
        "signed_at",
    )
    _indexes("gsp_electronic_signatures", "signature_ref", unique=True)


def downgrade() -> None:
    op.drop_table("gsp_electronic_signatures")
    op.drop_table("gsp_signature_challenges")

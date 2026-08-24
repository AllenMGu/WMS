"""authentication hardening

Revision ID: 20260824_14
Revises: 20260824_13
Create Date: 2026-08-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_14"
down_revision: Union[str, None] = "20260824_13"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "login_security_states",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scope_type", sa.String(length=20), nullable=False),
        sa.Column("scope_key", sa.String(length=200), nullable=False),
        sa.Column("failed_count", sa.Integer(), nullable=False),
        sa.Column("window_started_at", sa.DateTime(), nullable=True),
        sa.Column("last_failed_at", sa.DateTime(), nullable=True),
        sa.Column("locked_until", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scope_type", "scope_key", name="uq_login_security_scope"),
    )
    # Legacy versions could store the LDAP bind secret in plaintext. Runtime
    # credentials are now accepted only from the external deployment secret.
    op.execute("DELETE FROM config WHERE key = 'ldap_admin_password'")


def downgrade() -> None:
    op.drop_table("login_security_states")

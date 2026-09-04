"""allow REJECTION meaning for electronic signatures

The P0 merge added REJECTION-based signature policies (PURCHASE_ORDER_REJECT,
PURCHASE_RETURN_REJECT, NONCONFORMING_REJECT) and the models already list
REJECTION, but existing databases still carry CHECK constraints without it.
This migration brings the DB constraints in line with the models.

Revision ID: 20260902_27
Revises: 20260902_26
Create Date: 2026-09-04
"""

from typing import Sequence, Union

from alembic import op

revision: str = "20260902_27"
down_revision: Union[str, None] = "20260902_26"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

MEANINGS = "('APPROVAL','REVIEW','RELEASE','CONFIRMATION','RESPONSIBILITY','REJECTION')"


def upgrade() -> None:
    op.execute("ALTER TABLE gsp_signature_challenges DROP CONSTRAINT IF EXISTS ck_gsp_signature_challenge_meaning")
    op.execute(
        "ALTER TABLE gsp_signature_challenges ADD CONSTRAINT ck_gsp_signature_challenge_meaning "
        f"CHECK (meaning IN {MEANINGS})"
    )
    op.execute("ALTER TABLE gsp_electronic_signatures DROP CONSTRAINT IF EXISTS ck_gsp_electronic_signature_meaning")
    op.execute(
        "ALTER TABLE gsp_electronic_signatures ADD CONSTRAINT ck_gsp_electronic_signature_meaning "
        f"CHECK (meaning IN {MEANINGS})"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE gsp_electronic_signatures DROP CONSTRAINT IF EXISTS ck_gsp_electronic_signature_meaning")
    op.execute(
        "ALTER TABLE gsp_electronic_signatures ADD CONSTRAINT ck_gsp_electronic_signature_meaning "
        "CHECK (meaning IN ('APPROVAL','REVIEW','RELEASE','CONFIRMATION','RESPONSIBILITY'))"
    )
    op.execute("ALTER TABLE gsp_signature_challenges DROP CONSTRAINT IF EXISTS ck_gsp_signature_challenge_meaning")
    op.execute(
        "ALTER TABLE gsp_signature_challenges ADD CONSTRAINT ck_gsp_signature_challenge_meaning "
        "CHECK (meaning IN ('APPROVAL','REVIEW','RELEASE','CONFIRMATION','RESPONSIBILITY'))"
    )

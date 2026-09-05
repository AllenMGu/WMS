"""carrier document server-side evidence hash/size columns

Carrier documents are bound to the controlled file store like the other three
qualification domains.  The previous revision only persisted the ``gspf:``
token in ``file_ref``; this adds nullable ``file_sha256`` /
``file_size_bytes`` columns so the server-computed evidence values survive on
the business record (nullable keeps legacy/imported rows untouched).

Revision ID: 20260905_31
Revises: 20260905_30
Create Date: 2026-09-05
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260905_31"
down_revision: Union[str, None] = "20260905_30"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "gsp_carrier_documents",
        sa.Column("file_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "gsp_carrier_documents",
        sa.Column("file_size_bytes", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("gsp_carrier_documents", "file_size_bytes")
    op.drop_column("gsp_carrier_documents", "file_sha256")

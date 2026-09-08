"""add users.token_version for instant JWT revocation

Legacy JWT 仅校验 user.is_active，停用后存量令牌直至过期(30min)仍有效。
新增 users.token_version：签发时写入 JWT 的 tv 声明，停用/撤销访问时自增，
get_current_user 校验 tv 不一致即拒绝，实现即时吊销。

Revision ID: 20260907_33
Revises: 20260906_32
Create Date: 2026-09-07
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260907_33"
down_revision: Union[str, None] = "20260906_32"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

COLUMN_NAME = "token_version"
TABLE_NAME = "users"


def _has_column(bind, table: str, column: str) -> bool:
    inspector = sa.inspect(bind)
    try:
        columns = {c["name"] for c in inspector.get_columns(table)}
    except sa.exc.NoSuchTableError:
        return False
    return column in columns


def upgrade() -> None:
    bind = op.get_bind()
    if _has_column(bind, TABLE_NAME, COLUMN_NAME):
        return
    # 存量用户默认 1；server_default 保证非空约束在既有行上成立。
    op.add_column(
        TABLE_NAME,
        sa.Column(
            COLUMN_NAME,
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
            comment="JWT吊销版本号；停用/撤销访问时自增以即时吊销存量令牌",
        ),
    )
    with op.batch_alter_table(TABLE_NAME) as batch_op:
        batch_op.create_check_constraint(
            "ck_users_token_version_positive", f"{COLUMN_NAME} >= 1"
        )


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_column(bind, TABLE_NAME, COLUMN_NAME):
        return
    with op.batch_alter_table(TABLE_NAME) as batch_op:
        batch_op.drop_constraint("ck_users_token_version_positive", type_="check")
    op.drop_column(TABLE_NAME, COLUMN_NAME)

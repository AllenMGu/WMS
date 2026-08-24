"""Database transaction locks for append-only integrity chains."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session


def lock_chain_append(db: Session, namespace: str) -> None:
    """Serialize appends to one logical chain for the transaction lifetime.

    PostgreSQL advisory transaction locks are released automatically on commit
    or rollback. SQLite already serializes writes and is only supported for
    local development and unit tests.
    """

    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:namespace))"),
            {"namespace": f"wms-gsp-chain:{namespace}"},
        )

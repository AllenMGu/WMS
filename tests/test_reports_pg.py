"""Integration test for cover_all on the real PostgreSQL session.

Runs only when the test DATABASE_URL points at PostgreSQL (CI PostgreSQL job).
Verifies the single-SELECT (MAX_ROWS+1) full print works on a Session that has
already autobegun a transaction through earlier ACL queries.
"""

import os

import pytest


@pytest.mark.skipif(
    not os.getenv("DATABASE_URL", "").startswith("postgres"),
    reason="PostgreSQL-only integration test",
)
def test_cover_all_on_postgres_session_after_prior_queries():
    from datetime import timedelta

    from app.core.database import SessionLocal
    from app.core.time import utc_now
    from app.gsp import reports as mod
    from app.gsp.audit import write_audit_event
    from app.gsp.models import GspRoleAssignment
    from app.legacy import User, UserRole

    db = SessionLocal()
    try:
        user = User(username="pg-rpt-user", hashed_password="x", full_name="pg",
                    role=UserRole.OPERATOR, is_active=True)
        db.add(user)
        db.flush()
        db.add(GspRoleAssignment(user_id=user.id, role="AUDITOR", granted_by=user.id,
                                 approval_ref="PG-RPT", review_due_at=utc_now() + timedelta(days=30),
                                 is_active=True))
        db.flush()  # SessionLocal has autoflush=False; make the role visible
        # ACL-style query first -> autobegins the transaction
        from app.gsp.reports.router import _user_roles

        assert "AUDITOR" in _user_roles(db, user.id)
        for i in range(3):
            write_audit_event(db, actor_user_id=user.id, action="PG_COVER",
                              entity_type="X", entity_id=str(i), reason="rrr")
        db.commit()
        result = mod.run_full_print_rows(db, "audit_event_ledger", filters={"action": "PG_COVER"})
        assert result["count"] == result["total"] == 3
        assert result["has_more"] is False
    finally:
        db.close()

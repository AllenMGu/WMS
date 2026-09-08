"""Negative regression: the audit hash chain MUST detect tampering.

All existing tests only assert the *positive* case
``verify_audit_chain(db) == (True, None)``.  This module proves the
tamper-evident guarantee end-to-end: after an audit row is edited directly in
the database (exactly what a malicious DBA / rogue operator could do), the chain
verifier must return ``(False, <tampered_event_id>)`` instead of silently
passing.  It also proves the scheduled verifier script ``scripts/verify-audit-chain.py``
exits non-zero when pointed at a tampered database.
"""

import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.database import Base, SessionLocal
from app.core.time import utc_now
from app.gsp.audit import verify_audit_chain, write_audit_event
from app.gsp.models import GspAuditEvent, GspRoleAssignment
from app.legacy import User

REPO_ROOT = Path(__file__).resolve().parent.parent


def _seed_events(db: Session, n: int = 3) -> list[GspAuditEvent]:
    actor = User(username="tamper-seeder", hashed_password="x", full_name="seeder", is_active=True)
    db.add(actor)
    db.flush()
    events: list[GspAuditEvent] = []
    for i in range(n):
        ev = write_audit_event(
            db,
            actor_user_id=actor.id,
            action="TAMPER_TEST_EVENT",
            entity_type="TestEntity",
            entity_id=f"row-{i}",
            reason=f"legitimate reason {i}",
            before_data=None,
            after_data={"index": i},
        )
        events.append(ev)
    db.commit()
    return events


def test_verify_audit_chain_detects_reason_tampering():
    import main  # noqa: F401  # ensure tables / app are initialized

    db = SessionLocal()
    try:
        assert verify_audit_chain(db) == (True, None)
        events = _seed_events(db, n=3)

        # Tamper: edit a stored audit row directly (as a rogue DB user would).
        target = events[1]
        target_id = target.id
        target.reason = "edited-by-attacker"
        db.commit()

        valid, broken_event_id = verify_audit_chain(db)
        assert valid is False
        assert broken_event_id == target_id
    finally:
        db.close()


def test_verify_audit_chain_detects_hash_tampering():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        events = _seed_events(db, n=3)

        # Tamper: rewrite the stored event_hash to a fabricated value.
        target = events[0]
        target_id = target.id
        target.event_hash = "0" * 64
        db.commit()

        valid, broken_event_id = verify_audit_chain(db)
        assert valid is False
        assert broken_event_id == target_id
    finally:
        db.close()


def test_verify_audit_chain_script_exits_nonzero_on_tampered_db():
    """Run the scheduled verifier script against a tampered file database.

    The script reads ``DATABASE_URL`` from the environment, so we override it to
    point at a fresh file DB that we tamper, then assert a non-zero exit code.
    """
    import main  # noqa: F401

    db_path = REPO_ROOT / "tests" / "_tamper_tmp.sqlite3"
    if db_path.exists():
        db_path.unlink()
    try:
        url = f"sqlite:///{db_path.as_posix()}"
        engine = create_engine(url)
        Base.metadata.create_all(bind=engine)
        with Session(engine) as db:
            actor = User(
                username="script-actor", hashed_password="x", full_name="actor", is_active=True
            )
            db.add(actor)
            db.flush()
            db.add(
                GspRoleAssignment(
                    user_id=actor.id,
                    role="AUDITOR",
                    granted_by=actor.id,
                    approval_ref="SEED",
                    review_due_at=utc_now() + timedelta(days=30),
                    expires_at=utc_now() + timedelta(days=180),
                    is_active=True,
                )
            )
            events = _seed_events(db, n=3)
            events[1].reason = "edited-by-attacker"
            db.commit()
            actor_id = actor.id
        engine.dispose()

        env = dict(os.environ)
        env["DATABASE_URL"] = url
        completed = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "verify-audit-chain.py"),
                "--actor-user-id",
                str(actor_id),
            ],
            env=env,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert completed.returncode != 0, (
            f"verify-audit-chain.py 在篡改库上应非零退出，实际 {completed.returncode}; "
            f"stdout={completed.stdout}; stderr={completed.stderr}"
        )
    finally:
        if db_path.exists():
            db_path.unlink()

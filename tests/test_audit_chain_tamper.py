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
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.database import Base, SessionLocal
from app.core.time import utc_now
from app.gsp.audit import verify_audit_chain, write_audit_event
from app.gsp.models import GspAuditEvent, GspRoleAssignment
from app.legacy import User

REPO_ROOT = Path(__file__).resolve().parent.parent


def _seed_events(db: Session, n: int = 3) -> list[GspAuditEvent]:
    # username 唯一化，避免多进程/多会话测试共用同一固定用户名污染共享库。
    actor = User(
        username=f"tamper-seeder-{uuid4().hex[:8]}",
        hashed_password="x",
        full_name="seeder",
        is_active=True,
    )
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
    target_id = None
    orig_reason = None
    try:
        assert verify_audit_chain(db) == (True, None)
        events = _seed_events(db, n=3)

        # Tamper: edit a stored audit row directly (as a rogue DB user would).
        target = events[1]
        target_id = target.id
        orig_reason = target.reason
        target.reason = "edited-by-attacker"
        db.commit()

        valid, broken_event_id = verify_audit_chain(db)
        assert valid is False
        assert broken_event_id == target_id
    finally:
        # 恢复被篡改的审计行，避免污染共享库、影响后续测试的链校验。
        _restore_audit_event(db, target_id, reason=orig_reason)
        db.close()


def test_verify_audit_chain_detects_hash_tampering():
    import main  # noqa: F401

    db = SessionLocal()
    target_id = None
    orig_hash = None
    try:
        events = _seed_events(db, n=3)

        # Tamper: rewrite the stored event_hash to a fabricated value.
        target = events[0]
        target_id = target.id
        orig_hash = target.event_hash
        target.event_hash = "0" * 64
        db.commit()

        valid, broken_event_id = verify_audit_chain(db)
        assert valid is False
        assert broken_event_id == target_id
    finally:
        # 恢复被篡改的审计行，避免污染共享库、影响后续测试的链校验。
        _restore_audit_event(db, target_id, event_hash=orig_hash)
        db.close()


def _restore_audit_event(
    db: Session,
    event_id,
    *,
    reason=None,
    event_hash=None,
) -> None:
    """Undo a tamper edit so the shared audit chain stays valid for other tests.

    Runs in a ``finally`` block independent of the assertions above, so it
    restores the chain even when the test itself fails.  Any error during
    restore is swallowed after a rollback to avoid masking the original failure.
    """
    if event_id is None:
        return
    try:
        target = db.get(GspAuditEvent, event_id)
        if target is None:
            return
        if reason is not None:
            target.reason = reason
        if event_hash is not None:
            target.event_hash = event_hash
        db.commit()
    except Exception:  # noqa: BLE001 - 恢复失败不应覆盖原始测试失败
        db.rollback()


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

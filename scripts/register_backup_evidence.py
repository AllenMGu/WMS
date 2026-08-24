#!/usr/bin/env python3
"""Persist backup evidence JSON without routing a system credential through HTTP."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.core.database import SessionLocal
from app.core.time import utc_now
from app.gsp.models import GspRoleAssignment
from app.gsp.operations.models import GspBackupEvidence
from app.gsp.operations.schemas import BackupEvidenceCreate
from app.gsp.operations.service import record_backup_evidence
from app.legacy import User


def _system_admin_id(db) -> int:
    now = utc_now()
    assignment = (
        db.query(GspRoleAssignment)
        .join(User, User.id == GspRoleAssignment.user_id)
        .filter(
            GspRoleAssignment.role == "SYSTEM_ADMIN",
            GspRoleAssignment.is_active.is_(True),
            GspRoleAssignment.review_due_at > now,
            (
                GspRoleAssignment.expires_at.is_(None)
                | (GspRoleAssignment.expires_at > now)
            ),
            User.is_active.is_(True),
        )
        .order_by(GspRoleAssignment.id)
        .first()
    )
    if assignment is None:
        raise RuntimeError("没有有效的 SYSTEM_ADMIN 岗位，不能自动登记备份证据")
    return assignment.user_id


def register(path: Path) -> int:
    if not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("备份证据文件不存在或超过 1 MiB")
    payload = BackupEvidenceCreate.model_validate(json.loads(path.read_text(encoding="utf-8")))
    db = SessionLocal()
    try:
        existing = db.query(GspBackupEvidence).filter(
            GspBackupEvidence.backup_id == payload.backup_id
        ).first()
        if existing is not None:
            return existing.id
        evidence = record_backup_evidence(
            db,
            payload=payload,
            actor_id=_system_admin_id(db),
            source_ip="SYSTEM_BACKUP_TIMER",
        )
        db.commit()
        return evidence.id
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_file", type=Path)
    args = parser.parse_args()
    print(f"backup_evidence_id={register(args.evidence_file)}")


if __name__ == "__main__":
    main()

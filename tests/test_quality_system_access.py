from datetime import date, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from app.core.database import SessionLocal, get_db
from app.core.time import utc_now
from app.gsp.models import GspRoleAssignment
from app.gsp.quality_system.models import GspTrainingRecord
from app.legacy import User, UserRole, get_current_user


def _user(db, label: str, *, active: bool = True) -> User:
    user = User(
        username=f"qms-access-{label}-{uuid4().hex[:8]}",
        hashed_password="test-only",
        full_name=label,
        role=UserRole.OPERATOR,
        is_active=active,
    )
    db.add(user)
    db.flush()
    return user


def _role(db, user: User, role: str, grantor: User) -> None:
    db.add(
        GspRoleAssignment(
            user_id=user.id,
            role=role,
            granted_by=grantor.id,
            approval_ref=f"TEST-{role}-{uuid4().hex[:8]}",
            review_due_at=utc_now() + timedelta(days=30),
            is_active=True,
        )
    )


def test_quality_reads_are_restricted_while_trainees_can_read_their_own_records():
    from main import app

    db = SessionLocal()
    current = {}
    users: list[User] = []
    training_ids: list[int] = []

    async def override_current_user():
        return current["user"]

    def override_db():
        yield db

    app.dependency_overrides[get_current_user] = override_current_user
    app.dependency_overrides[get_db] = override_db
    try:
        grantor = _user(db, "授权人")
        trainee = _user(db, "普通受训人")
        auditor = _user(db, "质量审计员")
        inactive = _user(db, "已停用人员", active=False)
        users.extend([grantor, trainee, auditor, inactive])
        _role(db, trainee, "RECEIVER", grantor)
        _role(db, auditor, "AUDITOR", grantor)
        records = [
            GspTrainingRecord(
                training_no=f"SELF-{uuid4().hex[:8]}",
                user_id=trainee.id,
                subject="本人上岗培训",
                training_type="INITIAL",
                requirement_ref="SOP-WH-001",
                planned_date=date.today(),
                status="PLANNED",
                created_by=auditor.id,
            ),
            GspTrainingRecord(
                training_no=f"OTHER-{uuid4().hex[:8]}",
                user_id=auditor.id,
                subject="审计员继续培训",
                training_type="REFRESHER",
                requirement_ref="SOP-QA-001",
                planned_date=date.today(),
                status="PLANNED",
                created_by=grantor.id,
            ),
        ]
        db.add_all(records)
        db.commit()
        training_ids.extend(record.id for record in records)

        client = TestClient(app)
        current["user"] = trainee
        restricted = client.get("/api/gsp/quality-system/training")
        assert restricted.status_code == 403

        own = client.get("/api/gsp/quality-system/training/me")
        assert own.status_code == 200
        assert [item["user_id"] for item in own.json()] == [trainee.id]
        assert client.get("/api/gsp/reference/users").status_code == 403

        current["user"] = auditor
        quality_records = client.get("/api/gsp/quality-system/training")
        assert quality_records.status_code == 200
        assert {item["id"] for item in quality_records.json()}.issuperset(training_ids)

        directory = client.get("/api/gsp/reference/users")
        assert directory.status_code == 200
        returned = {item["id"]: item for item in directory.json()}
        assert trainee.id in returned
        assert inactive.id not in returned
        assert set(returned[trainee.id]) == {"id", "username", "full_name"}
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db, None)
        db.rollback()
        if training_ids:
            db.query(GspTrainingRecord).filter(GspTrainingRecord.id.in_(training_ids)).delete(
                synchronize_session=False
            )
        user_ids = [user.id for user in users]
        if user_ids:
            db.query(GspRoleAssignment).filter(GspRoleAssignment.user_id.in_(user_ids)).delete(
                synchronize_session=False
            )
            db.query(User).filter(User.id.in_(user_ids)).delete(synchronize_session=False)
        db.commit()
        db.close()

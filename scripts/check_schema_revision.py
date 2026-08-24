"""Refuse production start when the reviewed database revision is not current."""

from sqlalchemy import text

from app.core.database import EXPECTED_SCHEMA_REVISION, SessionLocal


def main() -> int:
    db = SessionLocal()
    try:
        revision = db.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
        if revision != EXPECTED_SCHEMA_REVISION:
            raise SystemExit(
                f"database revision {revision!r} does not match {EXPECTED_SCHEMA_REVISION!r}; "
                "apply the reviewed migration before starting the service"
            )
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())

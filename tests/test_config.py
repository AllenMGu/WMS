import pytest

from app.core.config import Settings


def test_production_rejects_sqlite():
    config = Settings(
        environment="production",
        database_url="sqlite+pysqlite:///./unsafe.db",
        secret_key="x" * 32,
    )
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        config.validate()


def test_production_rejects_weak_secret():
    config = Settings(
        environment="production",
        database_url="postgresql://user:password@db/wms",
        secret_key="weak",
    )
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        config.validate()

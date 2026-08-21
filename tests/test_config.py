import pytest

from app.core.config import Settings


def test_production_rejects_sqlite():
    config = Settings(
        environment="production",
        database_url="sqlite+pysqlite:///./unsafe.db",
        secret_key="x" * 32,
        secrets_provider="azure-key-vault",
        secret_key_version_ref="kv://jwt/v1",
        database_credential_version_ref="kv://postgres/v1",
    )
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        config.validate()


def test_production_rejects_weak_secret():
    config = Settings(
        environment="production",
        database_url="postgresql://user:password@db/wms",
        secret_key="weak",
        secrets_provider="azure-key-vault",
        secret_key_version_ref="kv://jwt/v1",
        database_credential_version_ref="kv://postgres/v1",
    )
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        config.validate()


def test_production_requires_secret_store_metadata():
    config = Settings(
        environment="production",
        database_url="postgresql://user:password@db/wms",
        secret_key="x" * 32,
        secrets_provider="development",
        secret_key_version_ref="",
        database_credential_version_ref="",
    )
    with pytest.raises(RuntimeError, match="SECRETS_PROVIDER"):
        config.validate()


def test_production_requires_ldap_credential_version_when_bind_is_configured():
    config = Settings(
        environment="production",
        database_url="postgresql://user:password@db/wms",
        secret_key="x" * 32,
        secrets_provider="azure-key-vault",
        secret_key_version_ref="kv://jwt/v1",
        database_credential_version_ref="kv://postgres/v1",
        ldap_admin_dn="cn=service,dc=example,dc=com",
        ldap_admin_password="not-checked-into-source",
        ldap_credential_version_ref="",
    )
    with pytest.raises(RuntimeError, match="LDAP_CREDENTIAL_VERSION_REF"):
        config.validate()

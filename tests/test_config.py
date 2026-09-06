import pytest

from app.core.config import Settings


def test_production_rejects_sqlite():
    config = Settings(
        environment="production",
        attachment_policy="enforce",
        database_url="sqlite+pysqlite:///./unsafe.db",
        secret_key="x" * 32,
        secrets_provider="azure-key-vault",
        secret_key_version_ref="kv://jwt/v1",
        database_credential_version_ref="kv://postgres/v1",
        auto_create_schema=False,
    )
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        config.validate()


def test_production_rejects_weak_secret():
    config = Settings(
        environment="production",
        attachment_policy="enforce",
        database_url="postgresql://user:password@db/wms",
        secret_key="weak",
        secrets_provider="azure-key-vault",
        secret_key_version_ref="kv://jwt/v1",
        database_credential_version_ref="kv://postgres/v1",
        auto_create_schema=False,
    )
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        config.validate()


def test_production_requires_secret_store_metadata():
    config = Settings(
        environment="production",
        attachment_policy="enforce",
        database_url="postgresql://user:password@db/wms",
        secret_key="x" * 32,
        secrets_provider="development",
        secret_key_version_ref="",
        database_credential_version_ref="",
        auto_create_schema=False,
    )
    with pytest.raises(RuntimeError, match="SECRETS_PROVIDER"):
        config.validate()


def test_production_requires_ldap_credential_version_when_bind_is_configured():
    config = Settings(
        environment="production",
        attachment_policy="enforce",
        database_url="postgresql://user:password@db/wms",
        secret_key="x" * 32,
        secrets_provider="azure-key-vault",
        secret_key_version_ref="kv://jwt/v1",
        database_credential_version_ref="kv://postgres/v1",
        ldap_admin_dn="cn=service,dc=example,dc=com",
        ldap_admin_password="not-checked-into-source",
        ldap_credential_version_ref="",
        auto_create_schema=False,
    )
    with pytest.raises(RuntimeError, match="LDAP_CREDENTIAL_VERSION_REF"):
        config.validate()


def test_production_rejects_automatic_schema_creation():
    config = Settings(
        environment="production",
        attachment_policy="enforce",
        database_url="postgresql://user:password@db/wms",
        secret_key="x" * 32,
        secrets_provider="azure-key-vault",
        secret_key_version_ref="kv://jwt/v1",
        database_credential_version_ref="kv://postgres/v1",
        auto_create_schema=True,
    )
    with pytest.raises(RuntimeError, match="AUTO_CREATE_SCHEMA=false"):
        config.validate()


def test_production_requires_attachment_policy_enforce():
    from app.core.config import Settings

    def settings(policy):
        return Settings(
            environment="production",
            attachment_policy=policy,
            secret_key="s" * 40,
            database_url="postgresql://x",
            auto_create_schema=False,
            secrets_provider="vault",
            secret_key_version_ref="v1",
            database_credential_version_ref="d1",
            ldap_credential_version_ref="l1",
        )

    with pytest.raises(RuntimeError, match="enforce"):
        settings("warn").validate()
    with pytest.raises(RuntimeError, match="enforce"):
        settings("WARN ").validate()
    settings("enforce").validate()  # must not raise


def test_staging_is_not_exempt_from_hardening():
    """staging 不得享受 development 的弱默认值豁免（评审问题2）。"""
    config = Settings(
        environment="staging",
        attachment_policy="warn",  # 弱值
        database_url="postgresql://user:password@db/wms",
        secret_key="development-only-change-me",
        secrets_provider="development",
        secret_key_version_ref="",
        database_credential_version_ref="",
        auto_create_schema=True,
    )
    # 未强化的 staging 应在 SECRET_KEY / AUTO_CREATE_SCHEMA / ATTACHMENT_POLICY
    # 等任一处被拒绝，而非静默通过。
    with pytest.raises(RuntimeError):
        config.validate()


def test_development_allows_weak_defaults():
    """显式 development/test 允许弱默认值（不误伤本地开发）。"""
    config = Settings(
        environment="development",
        attachment_policy="warn",
        database_url="sqlite+pysqlite:///./dev.db",
        secret_key="development-only-change-me",
        secrets_provider="development",
        auto_create_schema=True,
    )
    config.validate()  # must not raise


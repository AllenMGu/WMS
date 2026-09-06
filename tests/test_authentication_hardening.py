from uuid import uuid4

import pytest
from fastapi import HTTPException

from app import legacy
from app.core.config import Settings
from app.core.database import SessionLocal
from app.legacy import (
    LoginSecurityState,
    _enforce_login_throttle,
    _record_login_failure,
    _record_login_success,
)


def test_login_failure_throttle_is_durable_and_clears_after_success():
    db = SessionLocal()
    suffix = uuid4().hex
    username = f"locked-{suffix}"
    source_ip = f"test-{suffix}"
    try:
        for _ in range(5):
            _record_login_failure(db, username, source_ip)
        with pytest.raises(HTTPException) as error:
            _enforce_login_throttle(db, username, source_ip)
        assert error.value.status_code == 429

        _record_login_success(db, username, source_ip)
        _enforce_login_throttle(db, username, source_ip)
    finally:
        db.query(LoginSecurityState).filter(
            LoginSecurityState.scope_key.in_((username, source_ip))
        ).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_production_ldap_requires_encrypted_verified_transport():
    unsafe = Settings(
        environment="production",
        attachment_policy="enforce",
        database_url="postgresql://db/wms",
        secret_key="x" * 32,
        secrets_provider="vault",
        secret_key_version_ref="vault://jwt/v1",
        database_credential_version_ref="vault://db/v1",
        ldap_credential_version_ref="vault://ldap/v1",
        ldap_admin_dn="cn=bind,dc=example,dc=com",
        ldap_use_ssl=False,
        ldap_start_tls=False,
        ldap_tls_validate=True,
        auto_create_schema=False,
    )
    with pytest.raises(RuntimeError, match="LDAP_ALLOW_PLAINTEXT_AUTH"):
        unsafe.validate()


def test_production_plaintext_ldap_requires_explicit_risk_switch():
    allowed = Settings(
        environment="production",
        attachment_policy="enforce",
        database_url="postgresql://db/wms",
        secret_key="x" * 32,
        secrets_provider="vault",
        secret_key_version_ref="vault://jwt/v1",
        database_credential_version_ref="vault://db/v1",
        ldap_credential_version_ref="vault://ldap/v1",
        ldap_admin_dn="cn=bind,dc=example,dc=com",
        ldap_server="ldap://directory.example.com:389",
        ldap_allow_plaintext_auth=True,
        auto_create_schema=False,
    )
    allowed.validate()
    assert allowed.ldap_transport_mode() == "PLAINTEXT"


def test_ldaps_uri_is_recognized_without_duplicate_ssl_flag():
    settings = Settings(ldap_server="ldaps://directory.example.com:636")
    assert settings.ldap_transport_mode() == "LDAPS"


def test_starttls_open_none_return_does_not_fail(monkeypatch):
    class FakeConnection:
        def __init__(self, *_args, **_kwargs):
            self.closed = True
            self.bound = False
            self.start_tls_called = False

        def open(self):
            self.closed = False
            return None

        def start_tls(self):
            self.start_tls_called = True
            return True

        def bind(self):
            self.bound = True
            return True

    monkeypatch.setattr(legacy, "LDAP_START_TLS", True)
    monkeypatch.setattr(legacy, "LDAP_ALLOW_PLAINTEXT_AUTH", False)
    monkeypatch.setattr(legacy, "_ldap_server_definition", lambda: (object(), False))
    monkeypatch.setattr(legacy.ldap3, "Connection", FakeConnection)

    connection = legacy._ldap_connection("cn=test", "test-password")
    assert connection.bound is True
    assert connection.start_tls_called is True

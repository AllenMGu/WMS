from uuid import uuid4

import pytest
from fastapi import HTTPException

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
    )
    with pytest.raises(RuntimeError, match="LDAPS 或 StartTLS"):
        unsafe.validate()

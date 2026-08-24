"""Environment-backed application configuration.

Secrets deliberately live outside source control.  Development defaults keep the
legacy demo easy to start, while production mode refuses an unsafe JWT key.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _as_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _csv(name: str, default: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in os.getenv(name, default).split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    environment: str = os.getenv("APP_ENV", "development").lower()
    database_url: str = os.getenv(
        "DATABASE_URL",
        "sqlite+pysqlite:///./wms-dev.db",
    )
    secret_key: str = os.getenv("SECRET_KEY", "development-only-change-me")
    secrets_provider: str = os.getenv("SECRETS_PROVIDER", "development")
    secret_key_version_ref: str = os.getenv("SECRET_KEY_VERSION_REF", "")
    database_credential_version_ref: str = os.getenv("DATABASE_CREDENTIAL_VERSION_REF", "")
    ldap_credential_version_ref: str = os.getenv("LDAP_CREDENTIAL_VERSION_REF", "")
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    allowed_origins: tuple[str, ...] = _csv(
        "ALLOWED_ORIGINS",
        "http://localhost,http://127.0.0.1",
    )
    auto_create_schema: bool = _as_bool("AUTO_CREATE_SCHEMA", True)
    ldap_server: str = os.getenv("LDAP_SERVER", "ldap://127.0.0.1:389")
    ldap_base_dn: str = os.getenv("LDAP_BASE_DN", "dc=example,dc=com")
    ldap_admin_dn: str = os.getenv("LDAP_ADMIN_DN", "")
    ldap_admin_password: str = os.getenv("LDAP_ADMIN_PASSWORD", "")
    ldap_user_search_filter: str = os.getenv("LDAP_USER_SEARCH_FILTER", "(sAMAccountName={})")
    ldap_use_ssl: bool = _as_bool("LDAP_USE_SSL", False)
    ldap_start_tls: bool = _as_bool("LDAP_START_TLS", False)
    ldap_tls_validate: bool = _as_bool("LDAP_TLS_VALIDATE", True)
    ldap_ca_cert_file: str = os.getenv("LDAP_CA_CERT_FILE", "")
    ldap_allow_plaintext_auth: bool = _as_bool("LDAP_ALLOW_PLAINTEXT_AUTH", False)
    login_failure_limit: int = int(os.getenv("LOGIN_FAILURE_LIMIT", "5"))
    login_failure_window_minutes: int = int(os.getenv("LOGIN_FAILURE_WINDOW_MINUTES", "15"))
    login_lock_minutes: int = int(os.getenv("LOGIN_LOCK_MINUTES", "15"))

    def ldap_transport_mode(self) -> str:
        if self.ldap_use_ssl or self.ldap_server.lower().startswith("ldaps://"):
            return "LDAPS"
        if self.ldap_start_tls:
            return "STARTTLS"
        return "PLAINTEXT"

    def validate(self) -> None:
        if self.environment == "production" and (
            self.secret_key == "development-only-change-me" or len(self.secret_key) < 32
        ):
            raise RuntimeError("生产环境必须通过 SECRET_KEY 提供至少 32 字符的随机密钥")
        if self.environment == "production" and self.database_url.startswith("sqlite"):
            raise RuntimeError("生产环境必须通过 DATABASE_URL 配置 PostgreSQL，不能使用 SQLite")
        if self.environment == "production" and self.secrets_provider in {
            "",
            "development",
            "plaintext",
        }:
            raise RuntimeError("生产环境必须配置外部秘密管理来源 SECRETS_PROVIDER")
        if self.environment == "production" and not self.secret_key_version_ref:
            raise RuntimeError("生产环境必须配置 SECRET_KEY_VERSION_REF 以追踪密钥版本")
        if self.environment == "production" and not self.database_credential_version_ref:
            raise RuntimeError("生产环境必须配置 DATABASE_CREDENTIAL_VERSION_REF 以追踪数据库凭据版本")
        if (
            self.environment == "production"
            and self.ldap_admin_dn
            and not self.ldap_credential_version_ref
        ):
            raise RuntimeError("配置 LDAP_ADMIN_DN 时必须提供 LDAP_CREDENTIAL_VERSION_REF")
        if self.ldap_use_ssl and self.ldap_start_tls:
            raise RuntimeError("LDAP_USE_SSL 与 LDAP_START_TLS 不能同时启用")
        if self.ldap_allow_plaintext_auth and self.ldap_transport_mode() != "PLAINTEXT":
            raise RuntimeError("LDAP_ALLOW_PLAINTEXT_AUTH 只能用于普通 LDAP 389 模式")
        if self.environment == "production" and self.ldap_admin_dn:
            if (
                self.ldap_transport_mode() == "PLAINTEXT"
                and not self.ldap_allow_plaintext_auth
            ):
                raise RuntimeError(
                    "普通 LDAP 认证必须显式设置 LDAP_ALLOW_PLAINTEXT_AUTH=true"
                )
            if self.ldap_transport_mode() != "PLAINTEXT" and not self.ldap_tls_validate:
                raise RuntimeError("生产环境 LDAP 必须校验证书")
        if self.login_failure_limit < 3:
            raise RuntimeError("LOGIN_FAILURE_LIMIT 不能小于 3")
        if self.login_failure_window_minutes < 1 or self.login_lock_minutes < 1:
            raise RuntimeError("登录失败窗口和锁定时间必须为正整数")


settings = Settings()
settings.validate()

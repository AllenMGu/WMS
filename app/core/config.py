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

    def validate(self) -> None:
        if self.environment == "production" and (
            self.secret_key == "development-only-change-me" or len(self.secret_key) < 32
        ):
            raise RuntimeError("生产环境必须通过 SECRET_KEY 提供至少 32 字符的随机密钥")
        if self.environment == "production" and self.database_url.startswith("sqlite"):
            raise RuntimeError("生产环境必须通过 DATABASE_URL 配置 PostgreSQL，不能使用 SQLite")


settings = Settings()
settings.validate()

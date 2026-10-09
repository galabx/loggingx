"""Validated application settings loaded from environment variables."""

from functools import lru_cache
from secrets import token_urlsafe
from typing import Literal

from pydantic import EmailStr, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration with safe production defaults and validation."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "LangGraph API"
    app_version: str = "0.3.0"
    environment: Literal["development", "test", "staging", "production"] = "development"
    database_url: str = "mysql+pymysql://root:password@localhost:3306/langgraph?charset=utf8mb4"
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=20, ge=0, le=100)
    database_pool_timeout: int = Field(default=30, ge=1, le=300)
    database_pool_recycle: int = Field(default=1800, ge=60, le=86400)

    jwt_secret_key: SecretStr | None = None
    jwt_algorithm: Literal["HS256"] = "HS256"
    jwt_issuer: str = "langgraph-api"
    jwt_audience: str = "langgraph-client"
    access_token_expire_minutes: int = Field(default=15, ge=1, le=60)
    refresh_token_expire_days: int = Field(default=7, ge=1, le=30)

    password_min_length: int = Field(default=12, ge=8, le=128)
    cors_origins: str = "http://localhost:3000,http://localhost:5173"
    allowed_hosts: str = "*"
    rate_limit_storage_uri: str = "memory://"
    run_migrations_on_startup: bool | None = None

    initial_admin_email: EmailStr | None = None
    initial_admin_password: SecretStr | None = None

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
        """Reject unsafe production configuration and complete dev configuration."""

        if self.jwt_secret_key is None:
            if self.environment == "production":
                raise ValueError("JWT_SECRET_KEY must be configured in production")
            self.jwt_secret_key = SecretStr(token_urlsafe(48))
        elif len(self.jwt_secret_key.get_secret_value()) < 32:
            raise ValueError("JWT_SECRET_KEY must contain at least 32 characters")

        if (self.initial_admin_email is None) != (self.initial_admin_password is None):
            raise ValueError("INITIAL_ADMIN_EMAIL and INITIAL_ADMIN_PASSWORD must be provided together")
        if self.initial_admin_password is not None and len(self.initial_admin_password.get_secret_value()) < self.password_min_length:
            raise ValueError("INITIAL_ADMIN_PASSWORD does not meet PASSWORD_MIN_LENGTH")
        if self.environment == "production" and "*" in self.cors_origin_list:
            raise ValueError("CORS_ORIGINS cannot contain * in production")
        if self.environment == "production" and self.rate_limit_storage_uri.startswith("memory://"):
            raise ValueError("RATE_LIMIT_STORAGE_URI must use shared storage in production")
        if self.run_migrations_on_startup is None:
            self.run_migrations_on_startup = self.environment != "production"
        return self

    @property
    def jwt_secret_value(self) -> str:
        """Return the validated secret without exposing it in repr/log output."""

        assert self.jwt_secret_key is not None
        return self.jwt_secret_key.get_secret_value()

    @property
    def cors_origin_list(self) -> list[str]:
        """Return comma-separated CORS origins as a normalized list."""

        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def allowed_host_list(self) -> list[str]:
        """Return comma-separated allowed hosts as a normalized list."""

        return [host.strip() for host in self.allowed_hosts.split(",") if host.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings."""

    return Settings()

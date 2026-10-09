"""Password hashing and signed token helpers."""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any

import jwt
from pwdlib import PasswordHash

from app.config import get_settings


password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """Hash a password with the recommended Argon2 configuration."""

    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a password hash."""

    try:
        return password_hash.verify(password, hashed_password)
    except (ValueError, TypeError):
        return False


@lru_cache(maxsize=1)
def _dummy_password_hash() -> str:
    """Create one dummy hash to reduce login user-enumeration timing differences."""

    return hash_password("dummy-password-not-used-for-login")


def verify_password_or_dummy(password: str, hashed_password: str | None) -> bool:
    """Verify a password even when the account lookup did not find a user."""

    return verify_password(password, hashed_password or _dummy_password_hash())


def hash_refresh_token(token: str) -> str:
    """Hash a high-entropy refresh token before storing it in the database."""

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _create_token(
    subject: str,
    token_type: str,
    expires_delta: timedelta,
    family_id: str | None = None,
    token_version: int | None = None,
) -> tuple[str, datetime]:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expires_at = now + expires_delta
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": expires_at,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }
    if family_id is not None:
        payload["family"] = family_id
    if token_version is not None:
        payload["ver"] = token_version
    return jwt.encode(payload, settings.jwt_secret_value, algorithm=settings.jwt_algorithm), expires_at


def create_access_token(user_id: int, token_version: int) -> tuple[str, datetime]:
    """Create a short-lived access token."""

    settings = get_settings()
    return _create_token(
        str(user_id),
        "access",
        timedelta(minutes=settings.access_token_expire_minutes),
        token_version=token_version,
    )


def create_refresh_token(user_id: int, family_id: str) -> tuple[str, datetime]:
    """Create a refresh token belonging to a session family."""

    settings = get_settings()
    return _create_token(
        str(user_id),
        "refresh",
        timedelta(days=settings.refresh_token_expire_days),
        family_id,
    )


def decode_token(token: str, expected_type: str) -> dict[str, Any]:
    """Decode and validate token signature, issuer, audience, and token type."""

    settings = get_settings()
    payload = jwt.decode(
        token,
        settings.jwt_secret_value,
        algorithms=[settings.jwt_algorithm],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
        options={"require": ["sub", "type", "jti", "iat", "exp", "iss", "aud"]},
    )
    if payload.get("type") != expected_type or not payload.get("sub"):
        raise jwt.InvalidTokenError("Invalid token type or subject")
    if expected_type == "refresh" and not payload.get("family"):
        raise jwt.InvalidTokenError("Refresh token is missing a session family")
    return payload

"""Shared rate limiter configuration."""

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import get_settings


settings = get_settings()
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.rate_limit_storage_uri,
    headers_enabled=True,
)

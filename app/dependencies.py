"""Reusable authentication and authorization dependencies."""

from collections.abc import Callable
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, UserRole
from app.security import decode_token


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
DbSession = Annotated[Session, Depends(get_db)]


def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: DbSession) -> User:
    """Resolve a valid bearer token to an active user."""

    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token, "access")
        user_id = int(payload["sub"])
    except (ValueError, KeyError, jwt.InvalidTokenError):
        raise credentials_error from None

    user = db.scalar(select(User).where(User.id == user_id))
    if user is None or not user.is_active or payload.get("ver") != user.token_version:
        raise credentials_error
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    UserRole.USER.value: frozenset({"profile:read", "graph:invoke"}),
    UserRole.ADMIN.value: frozenset(
        {"profile:read", "graph:invoke", "users:read", "users:manage"}
    ),
}


def require_roles(*roles: str) -> Callable[..., User]:
    """Build a dependency that accepts only users with one of the roles."""

    def dependency(user: CurrentUser) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return dependency


def require_permission(permission: str) -> Callable[..., User]:
    """Build a dependency for a permission derived from the user's role."""

    def dependency(user: CurrentUser) -> User:
        if permission not in ROLE_PERMISSIONS.get(user.role, frozenset()):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return dependency

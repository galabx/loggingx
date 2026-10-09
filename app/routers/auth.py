"""Registration, login, token rotation, password, and logout endpoints."""

import uuid
from datetime import datetime, timezone
from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.dependencies import CurrentUser
from app.models import RefreshToken, User, UserRole
from app.limiter import limiter
from app.schemas import PasswordChange, RefreshRequest, TokenResponse, UserCreate, UserRead
from app.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    hash_refresh_token,
    verify_password,
    verify_password_or_dummy,
)


router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
DbSession = Annotated[Session, Depends(get_db)]


def _token_response(db: Session, user: User, family_id: str | None = None) -> TokenResponse:
    """Create an access token and persist its refresh-token record atomically."""

    settings = get_settings()
    family_id = family_id or str(uuid.uuid4())
    access_token, _ = create_access_token(user.id, user.token_version)
    refresh_token, refresh_expires_at = create_refresh_token(user.id, family_id)
    db.add(
        RefreshToken(
            user_id=user.id,
            family_id=family_id,
            token_hash=hash_refresh_token(refresh_token),
            expires_at=refresh_expires_at,
        )
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
        refresh_expires_in=settings.refresh_token_expire_days * 24 * 60 * 60,
    )


def _auth_error(detail: str = "Could not authenticate") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _utc(value: datetime) -> datetime:
    """Normalize SQLite's naive datetime values to UTC-aware values."""

    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _revoke_family(db: Session, family_id: str, revoked_at: datetime) -> None:
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=revoked_at)
    )


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")
def register(request: Request, response: Response, payload: UserCreate, db: DbSession) -> User:
    """Create a normal user account; public registration never grants admin."""

    email = str(payload.email).strip().casefold()
    user = User(email=email, hashed_password=hash_password(payload.password), role=UserRole.USER.value)
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered") from None
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(
    request: Request,
    response: Response,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DbSession,
) -> TokenResponse:
    """Exchange an email and password for an access/refresh token pair."""

    email = form.username.strip().casefold()
    user = db.scalar(select(User).where(User.email == email))
    password_valid = verify_password_or_dummy(form.password, user.hashed_password if user else None)
    if user is None or not password_valid or not user.is_active:
        raise _auth_error("Incorrect email or password")

    response = _token_response(db, user)
    db.commit()
    return response


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("10/minute")
def refresh(request: Request, response: Response, payload: RefreshRequest, db: DbSession) -> TokenResponse:
    """Rotate a refresh token and detect reuse of revoked session tokens."""

    try:
        claims = decode_token(payload.refresh_token, "refresh")
        user_id = int(claims["sub"])
        family_id = str(claims["family"])
    except (ValueError, KeyError, TypeError, jwt.InvalidTokenError):
        raise _auth_error("Invalid refresh token") from None

    stored = db.scalar(
        select(RefreshToken)
        .where(RefreshToken.token_hash == hash_refresh_token(payload.refresh_token))
        .with_for_update()
    )
    now = datetime.now(timezone.utc)
    if stored is None or stored.family_id != family_id:
        raise _auth_error("Invalid refresh token")
    if stored.revoked_at is not None:
        # A revoked token being presented is a replay signal: revoke the whole session family.
        _revoke_family(db, family_id, now)
        db.commit()
        raise _auth_error("Refresh token reuse detected")
    if _utc(stored.expires_at) <= now:
        stored.revoked_at = now
        db.commit()
        raise _auth_error("Refresh token has expired")

    user = db.scalar(select(User).where(User.id == user_id))
    if user is None or not user.is_active or stored.user_id != user_id:
        raise _auth_error("User account is unavailable")

    stored.revoked_at = now
    response = _token_response(db, user, family_id)
    db.commit()
    return response


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(payload: RefreshRequest, db: DbSession) -> None:
    """Revoke a refresh token so it cannot be used again."""

    stored = db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(payload.refresh_token))
    )
    if stored is not None and stored.revoked_at is None:
        stored.revoked_at = datetime.now(timezone.utc)
        db.commit()


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(payload: PasswordChange, user: CurrentUser, db: DbSession) -> None:
    """Change the current password and revoke all refresh sessions."""

    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    if payload.current_password == payload.new_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must be different")

    user.hashed_password = hash_password(payload.new_password)
    user.token_version += 1
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
    )
    db.commit()


@router.get("/me", response_model=UserRead)
def me(user: CurrentUser) -> User:
    """Return the currently authenticated user."""

    return user

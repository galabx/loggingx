"""Protected user and authorization demonstration endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import CurrentUser, require_permission
from app.models import User
from app.schemas import RoleUpdate, StatusUpdate, UserRead


router = APIRouter(prefix="/api/v1", tags=["users"])
DbSession = Annotated[Session, Depends(get_db)]


@router.get("/profile", response_model=UserRead)
def profile(user: CurrentUser) -> User:
    """Example endpoint requiring any authenticated user."""

    return user


@router.get(
    "/admin/users",
    response_model=list[UserRead],
    dependencies=[Depends(require_permission("users:read"))],
)
def list_users(
    db: DbSession,
    offset: int = Query(default=0, ge=0, le=100_000),
    limit: int = Query(default=50, ge=1, le=100),
) -> list[User]:
    """List users; requires the users:read permission."""

    return list(db.scalars(select(User).order_by(User.id).offset(offset).limit(limit)).all())


@router.patch(
    "/admin/users/{user_id}/role",
    response_model=UserRead,
    dependencies=[Depends(require_permission("users:manage"))],
)
def update_role(user_id: int, payload: RoleUpdate, db: DbSession) -> User:
    """Update a user's role; requires the users:manage permission."""

    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == "admin" and payload.role != "admin" and _active_admin_count(db) <= 1:
        raise HTTPException(status_code=400, detail="Cannot remove the last active administrator")
    user.role = payload.role
    db.commit()
    db.refresh(user)
    return user


@router.patch(
    "/admin/users/{user_id}/status",
    response_model=UserRead,
    dependencies=[Depends(require_permission("users:manage"))],
)
def update_status(user_id: int, payload: StatusUpdate, db: DbSession) -> User:
    """Enable or disable a user account."""

    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == "admin" and user.is_active and not payload.is_active and _active_admin_count(db) <= 1:
        raise HTTPException(status_code=400, detail="Cannot disable the last active administrator")
    user.is_active = payload.is_active
    user.token_version += 1
    db.commit()
    db.refresh(user)
    return user


def _active_admin_count(db: Session) -> int:
    return db.scalar(
        select(func.count(User.id)).where(User.role == "admin", User.is_active.is_(True))
    ) or 0

"""Database engine, session dependency, migrations, and bootstrap data."""

from collections.abc import Generator
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""


settings = get_settings()
is_sqlite = settings.database_url.startswith("sqlite")
engine_options: dict[str, object] = {
    "pool_pre_ping": True,
    "pool_recycle": settings.database_pool_recycle,
}
if not is_sqlite or ":memory:" not in settings.database_url:
    engine_options.update(
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout,
    )

connect_args = {"check_same_thread": False} if is_sqlite else {}
engine = create_engine(settings.database_url, connect_args=connect_args, **engine_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


if is_sqlite:

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection: object, _: object) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def get_db() -> Generator[Session, None, None]:
    """Yield a database session and always close it after the request."""

    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def run_migrations() -> None:
    """Apply committed Alembic migrations to the configured database."""

    project_root = Path(__file__).resolve().parent.parent
    alembic_config = Config(str(project_root / "alembic.ini"))
    alembic_config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
    command.upgrade(alembic_config, "head")


def seed_initial_admin() -> None:
    """Create the optional first administrator without changing existing accounts."""

    from app.models import User, UserRole
    from app.security import hash_password

    if settings.initial_admin_email is None or settings.initial_admin_password is None:
        return

    email = str(settings.initial_admin_email).strip().lower()
    password = settings.initial_admin_password.get_secret_value()
    try:
        with SessionLocal.begin() as db:
            existing = db.scalar(select(User).where(User.email == email))
            if existing is None:
                db.add(
                    User(
                        email=email,
                        hashed_password=hash_password(password),
                        role=UserRole.ADMIN.value,
                        is_active=True,
                    )
                )
    except IntegrityError:
        # Another application instance may have provisioned the same admin concurrently.
        return


def check_database() -> None:
    """Fail readiness checks when the database is unavailable."""

    with engine.connect() as connection:
        connection.exec_driver_sql("SELECT 1")

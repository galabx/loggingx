"""FastAPI application entrypoint."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy.exc import SQLAlchemyError

from app.config import get_settings
from app.database import check_database, engine, run_migrations, seed_initial_admin
from app.limiter import limiter
from app.routers import auth, users


settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Initialize application resources before serving traffic."""

    if settings.run_migrations_on_startup:
        run_migrations()
    seed_initial_admin()
    try:
        yield
    finally:
        engine.dispose()


app = FastAPI(
    title=settings.app_name,
    description="LangGraph API with JWT authentication and role-based authorization.",
    version=settings.app_version,
    lifespan=lifespan,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

if settings.allowed_host_list != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_host_list)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def add_security_headers(request, call_next):
    """Add baseline browser security headers to every response."""

    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if settings.is_production:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


app.include_router(auth.router)
app.include_router(users.router)


@app.get("/", tags=["system"])
async def root() -> dict[str, str]:
    """Return basic API information."""

    return {"message": "LangGraph API is running"}


@app.get("/health/live", tags=["system"])
async def liveness() -> dict[str, str]:
    """Liveness probe that does not depend on external services."""

    return {"status": "ok"}


@app.get("/health/ready", tags=["system"])
async def readiness() -> dict[str, str]:
    """Readiness probe that verifies database connectivity."""

    try:
        check_database()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is unavailable",
        ) from None
    return {"status": "ok"}


@app.get("/health", tags=["system"])
async def health() -> dict[str, str]:
    """Backward-compatible alias for the liveness endpoint."""

    return await liveness()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000)

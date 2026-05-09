"""
FastAPI application entry point for ScamShield Auth service.
"""

import logging
from contextlib import asynccontextmanager

import sentry_sdk
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text

from config import settings
from database import async_engine, AsyncSessionLocal, Base
from routers import auth as auth_router
from routers import scan as scan_router
from utils.logging_config import setup_logging
from utils.rate_limiter import limiter

# ── Structured logging (must run before any logger calls) ──
setup_logging(settings.LOG_LEVEL, settings.LOG_FORMAT)
logger = logging.getLogger(__name__)

# ── Sentry error tracking ──
if settings.SENTRY_DSN:
    sentry_sdk.init(
        dsn=settings.SENTRY_DSN,
        traces_sample_rate=settings.SENTRY_TRACES_SAMPLE_RATE,
        environment="production" if not settings.DEBUG else "development",
    )
    logger.info("Sentry initialised (env=%s)", "production" if not settings.DEBUG else "development")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables + ARQ pool on startup; dispose on shutdown."""
    # Create all database tables (async)
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Initialise ARQ background-job pool
    try:
        from arq import create_pool
        from worker import _arq_redis_settings
        app.state.arq_pool = await create_pool(_arq_redis_settings())
        logger.info("ARQ pool connected")
    except Exception:
        app.state.arq_pool = None
        logger.warning("ARQ pool unavailable — background scanning disabled")

    yield

    # Shutdown
    if getattr(app.state, "arq_pool", None):
        await app.state.arq_pool.close()
    await async_engine.dispose()


app = FastAPI(
    title="ScamShield API",
    version="1.0.0",
    description="Authentication service for ScamShield — Detect. Protect. Trust.",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(scan_router.router)


@app.get("/health", tags=["Health"])
async def health_check() -> dict:
    """Health check endpoint — verifies service + database connectivity."""
    db_ok = False
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
            db_ok = True
    except Exception:
        pass
    return {
        "status": "ok" if db_ok else "degraded",
        "service": settings.APP_NAME,
        "database": "connected" if db_ok else "unavailable",
    }

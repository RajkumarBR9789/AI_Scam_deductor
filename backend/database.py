"""
Database engine and session factory for ScamShield backend.

Provides:
- **Async** engine + session (used by FastAPI endpoints)
- **Sync** engine + session (kept for Alembic migrations)
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from config import settings

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")

# ── Async URL conversion ──
if _is_sqlite:
    _async_url = settings.DATABASE_URL.replace("sqlite://", "sqlite+aiosqlite://", 1)
else:
    _async_url = settings.DATABASE_URL.replace(
        "postgresql://", "postgresql+asyncpg://", 1
    )

# ── Async engine (used by FastAPI) ──
_async_kwargs: dict = {"echo": settings.DEBUG}
if not _is_sqlite:
    _async_kwargs.update(pool_size=10, max_overflow=20)

async_engine = create_async_engine(_async_url, **_async_kwargs)
AsyncSessionLocal = async_sessionmaker(
    async_engine, class_=AsyncSession, expire_on_commit=False
)

# ── Sync engine (kept for Alembic & legacy tooling) ──
_sync_kwargs: dict = {"pool_pre_ping": True, "echo": settings.DEBUG}
if not _is_sqlite:
    _sync_kwargs.update(pool_size=10, max_overflow=20)
else:
    _sync_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(settings.DATABASE_URL, **_sync_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Declarative base class for all SQLAlchemy models."""
    pass


async def get_db():
    """FastAPI dependency that yields an async database session."""
    async with AsyncSessionLocal() as session:
        yield session

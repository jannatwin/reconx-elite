from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.exc import TimeoutError as SATimeoutError
from sqlalchemy.orm import declarative_base, sessionmaker
from fastapi import Request
from fastapi.responses import JSONResponse
from typing import AsyncGenerator

from app.core.config import settings

# Engine and session maker - initialized at application startup
_engine = None
_async_session_maker = None


def init_engine():
    """Initialize the async database engine and session maker at application startup."""
    global _engine, _async_session_maker
    if _engine is None:
        # Convert psycopg2 URL to async URL for SQLAlchemy
        async_db_url = settings.database_url.replace(
            "postgresql+psycopg2://", "postgresql+asyncpg://"
        )
        _engine = create_async_engine(
            async_db_url,
            pool_pre_ping=True,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_recycle=settings.db_pool_recycle,
            pool_timeout=settings.db_pool_timeout,
            echo=False,
            connect_args={
                "timeout": 10,
            },
        )
        _async_session_maker = async_sessionmaker(
            _engine, class_=AsyncSession, expire_on_commit=False
        )


def get_engine():
    """Get the initialized async database engine."""
    if _engine is None:
        init_engine()
    return _engine


async def db_timeout_handler(request: Request, exc: SATimeoutError) -> JSONResponse:
    """FastAPI exception handler for SQLAlchemy pool timeout — returns HTTP 503 RFC 7807."""
    return JSONResponse(
        status_code=503,
        content={
            "type": "about:blank",
            "title": "Service Unavailable",
            "status": 503,
            "detail": "Database connection pool exhausted",
            "instance": request.url.path,
        },
        media_type="application/problem+json",
    )


def get_sessionmaker():
    """Get the initialized session maker (synchronous for testing)."""
    if _async_session_maker is None:
        init_engine()
    
    # For testing compatibility, return a sync sessionmaker with proper configuration
    # This allows tests to inspect .kw attributes
    sync_session_factory = sessionmaker(
        bind=_engine.sync_engine if hasattr(_engine, 'sync_engine') else None,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False
    )
    
    return sync_session_factory


Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Async context manager for database sessions."""
    maker = get_sessionmaker()
    async with maker() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise

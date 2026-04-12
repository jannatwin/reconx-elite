from sqlalchemy import create_engine
from sqlalchemy.exc import TimeoutError as SATimeoutError
from sqlalchemy.orm import declarative_base, sessionmaker
from fastapi import Request
from fastapi.responses import JSONResponse

from app.core.config import settings

# Lazy engine creation to avoid connection issues during import
_engine = None
_SessionLocal = None

def get_engine():
    global _engine
    if _engine is None:
        _engine = create_engine(
            settings.database_url,
            pool_pre_ping=True,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_recycle=settings.db_pool_recycle,
            pool_timeout=settings.db_pool_timeout,
            echo=False
        )
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
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionLocal

Base = declarative_base()


def get_db():
    db = get_sessionmaker()()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

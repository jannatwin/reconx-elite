import threading
from sqlalchemy import create_engine
from sqlalchemy.exc import TimeoutError as SATimeoutError
from sqlalchemy.orm import declarative_base, sessionmaker
from fastapi import Request
from fastapi.responses import JSONResponse

from app.core.config import settings

# Engine and session maker - initialized at application startup
_engine = None
_SessionLocal = None
_engine_lock = threading.Lock()

def init_engine():
    """Initialize the database engine and session maker at application startup."""
    global _engine, _SessionLocal
    with _engine_lock:
        if _engine is None:
            _engine = create_engine(
                settings.database_url,
                pool_pre_ping=True,
                pool_size=settings.db_pool_size,
                max_overflow=settings.db_max_overflow,
                pool_recycle=settings.db_pool_recycle,
                pool_timeout=settings.db_pool_timeout,
                echo=False,
                connect_args={
                    "connect_timeout": 10,
                }
            )
            _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)

def get_engine():
    """Get the initialized database engine."""
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
    """Get the initialized session maker."""
    if _SessionLocal is None:
        init_engine()
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

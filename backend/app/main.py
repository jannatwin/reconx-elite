from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app import models  # noqa: F401
from app.core.config import settings
from app.core.database import Base, engine
from app.core.middleware import AuthGuardMiddleware, RequestLoggingMiddleware
from app.routers import auth, bookmarks, notifications, reports, scans, schedules, targets, vulnerabilities

# Ensure tables exist for local/dev setup.
Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.app_name)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(AuthGuardMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.state.limiter = auth.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(schedules.router)
app.include_router(notifications.router)
app.include_router(bookmarks.router)
app.include_router(vulnerabilities.router)
app.include_router(reports.router)


@app.get("/health")
def health():
    return {"status": "ok"}

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app import models  # noqa: F401
from app.core.config import settings
from app.core.middleware import AuthGuardMiddleware, RequestLoggingMiddleware
from app.routers import auth, bookmarks, notifications, payloads, reports, scans, schedules, targets, vulnerabilities
app = FastAPI(title=settings.app_name)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins_list or ["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(AuthGuardMiddleware)
app.state.limiter = auth.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(schedules.router)
app.include_router(notifications.router)
app.include_router(bookmarks.router)
app.include_router(vulnerabilities.router)
app.include_router(payloads.router)
app.include_router(reports.router)


@app.get("/health")
def health():
    return {"status": "ok"}

from app.core.logging_config import configure_logging

configure_logging()

import asyncio
import time
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy import text
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app import models  # noqa: F401
from app.core.config import settings
from app.core.database import db_timeout_handler, SATimeoutError, init_engine, get_db
from app.core.exception_handlers import http_exception_handler, unhandled_exception_handler
from app.core.metrics import http_requests_total, http_request_duration_seconds
from app.core.middleware import AuthGuardMiddleware, RequestLoggingMiddleware
from app.routers import admin, auth, blind_xss, bookmarks, notifications, payloads, reports, scans, schedules, ssrf, targets, ticketing, vulnerabilities, websocket, validation, out_of_band, manual_testing, intelligence, custom_templates, system, advanced_recon, verification_api


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Content-Security-Policy"] = "default-src 'self'; connect-src 'self'; img-src 'self' data: https:; script-src 'self'; style-src 'self' 'unsafe-inline'"
        if settings.https_behind_proxy:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        method = request.method
        path = request.url.path
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start
        status = str(response.status_code)
        http_requests_total.labels(method=method, path=path, status=status).inc()
        http_request_duration_seconds.labels(method=method, path=path).observe(duration)
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate_runtime_or_raise()
    # Initialize database engine at startup to prevent race conditions
    init_engine()
    # Startup: Start Redis subscriber
    from app.services.websocket import redis_subscriber
    subscriber_task = asyncio.create_task(redis_subscriber.start())
    yield
    # Shutdown: Stop Redis subscriber
    await redis_subscriber.stop()
    subscriber_task.cancel()
    try:
        await subscriber_task
    except asyncio.CancelledError:
        pass


app = FastAPI(title=settings.app_name, lifespan=lifespan)
allowed_origins = settings.cors_allowed_origins_list or ["http://localhost:5173"]
if "*" in allowed_origins:
    raise RuntimeError("CORS wildcard origin is not allowed when credentials are enabled")


def _trusted_hosts_from_origins(origins: list[str]) -> list[str]:
    hosts: list[str] = []
    for origin in origins:
        candidate = origin.strip()
        if not candidate:
            continue
        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
        host = parsed.hostname or candidate
        if host:
            hosts.append(host)
    return list(dict.fromkeys(hosts))


app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
    max_age=3600,
)
if settings.https_behind_proxy:
    trusted_hosts = _trusted_hosts_from_origins(allowed_origins) or ["localhost", "127.0.0.1"]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)
    from fastapi.middleware import HTTPSRedirectMiddleware
    app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(AuthGuardMiddleware)
app.add_middleware(PrometheusMiddleware)
app.state.limiter = auth.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(SATimeoutError, db_timeout_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(schedules.router)
app.include_router(notifications.router)
app.include_router(bookmarks.router)
app.include_router(vulnerabilities.router)
app.include_router(payloads.router)
app.include_router(blind_xss.router)
app.include_router(ssrf.router)
app.include_router(reports.router)
app.include_router(ticketing.router)
app.include_router(websocket.router)
app.include_router(validation.router)

app.include_router(out_of_band.router)
app.include_router(manual_testing.router)
app.include_router(intelligence.router)
app.include_router(custom_templates.router)
app.include_router(system.router)
app.include_router(advanced_recon.router)
app.include_router(verification_api.router)

if settings.metrics_enabled:
    try:
        from prometheus_client import make_asgi_app

        metrics_app = make_asgi_app()
        app.mount("/metrics", metrics_app)
    except ModuleNotFoundError:
        pass


def _default_ui_url() -> str:
    for origin in settings.cors_allowed_origins_list:
        if origin.strip():
            return origin.strip()
    return "http://127.0.0.1:5173"


@app.get("/", response_class=HTMLResponse)
def root() -> HTMLResponse:
    ui_url = _default_ui_url()
    body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>{settings.app_name}</title>
</head>
<body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;line-height:1.5">
  <h1>{settings.app_name}</h1>
  <p>This port serves the HTTP API. The web app is usually on a different port.</p>
  <ul>
    <li><strong>Web UI:</strong> <a href="{ui_url}">{ui_url}</a> (Docker Compose maps this to <code>5173</code> on your machine)</li>
    <li><strong>Interactive API docs:</strong> <a href="/docs">/docs</a></li>
    <li><strong>Health:</strong> <a href="/health">/health</a></li>
  </ul>
</body>
</html>"""
    return HTMLResponse(content=body)


@app.get("/health")
async def health():
    database_status = "disconnected"
    try:
        from app.core.database import get_sessionmaker
        sessionmaker = get_sessionmaker()
        db_session = sessionmaker()
        try:
            db_session.execute(text("SELECT 1"))
            database_status = "connected"
        finally:
            db_session.close()
    except Exception:
        database_status = "disconnected"
    return {"status": "ok", "database": database_status}

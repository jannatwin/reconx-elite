from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app import models  # noqa: F401
from app.core.config import settings
from app.core.middleware import AuthGuardMiddleware, RequestLoggingMiddleware
from app.routers import admin, auth, blind_xss, bookmarks, notifications, payloads, reports, scans, schedules, ssrf, targets, ticketing, vulnerabilities, websocket, validation, out_of_band, manual_testing, intelligence, custom_templates, system, advanced_recon


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Content-Security-Policy"] = "default-src 'self'; connect-src 'self' http: https: ws: wss:; img-src 'self' data: https:; script-src 'self'; style-src 'self' 'unsafe-inline'"
        return response


app = FastAPI(title=settings.app_name)
allowed_origins = settings.cors_allowed_origins_list or ["http://localhost:5173"]
if "*" in allowed_origins:
    raise RuntimeError("CORS wildcard origin is not allowed when credentials are enabled")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(AuthGuardMiddleware)
app.state.limiter = auth.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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


@app.get("/health")
def health():
    return {"status": "ok"}

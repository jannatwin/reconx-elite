import logging
import time

from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.security import decode_token

logger = logging.getLogger("reconx.api")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        started = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        user_id = getattr(request.state, "user_id", None)
        logger.info(
            "request method=%s path=%s status=%s duration_ms=%s user_id=%s",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
            user_id,
        )
        return response


class AuthGuardMiddleware(BaseHTTPMiddleware):
    protected_prefixes = (
        "/admin",
        "/targets",
        "/scan",
        "/scans",
        "/bookmarks",
        "/notifications",
        "/reports",
        "/schedules",
        "/vulnerabilities",
    )

    async def dispatch(self, request: Request, call_next):
        auth_header = request.headers.get("Authorization", "")
        request.state.user_id = None
        request.state.rate_limit_key = request.client.host if request.client else "anonymous"

        if auth_header.startswith("Bearer "):
            token = auth_header.removeprefix("Bearer ").strip()
            try:
                claims = decode_token(token)
                if claims.get("token_type") == "access":
                    request.state.user_id = claims.get("sub")
                    if request.state.user_id:
                        request.state.rate_limit_key = f"user:{request.state.user_id}"
            except (ValueError, Exception):
                logger.warning(
                    "JWT validation failed for %s",
                    request.client.host if request.client else "unknown",
                )
                if request.url.path.startswith(self.protected_prefixes):
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content={"detail": "Invalid access token"},
                    )

        if request.url.path.startswith(self.protected_prefixes) and request.state.user_id is None:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Missing bearer token"},
            )
        return await call_next(request)

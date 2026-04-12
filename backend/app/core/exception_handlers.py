import http
import logging

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Convert FastAPI HTTPException to RFC 7807 Problem Details JSON."""
    try:
        title = http.HTTPStatus(exc.status_code).phrase
    except ValueError:
        title = "Unknown Error"

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "type": "about:blank",
            "title": title,
            "status": exc.status_code,
            "detail": exc.detail,
            "instance": request.url.path,
        },
        media_type="application/problem+json",
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Convert unhandled exceptions to RFC 7807 Problem Details JSON with HTTP 500."""
    logging.exception("Unhandled exception for %s %s", request.method, request.url.path)

    return JSONResponse(
        status_code=500,
        content={
            "type": "about:blank",
            "title": "Internal Server Error",
            "status": 500,
            "detail": "An unexpected error occurred",
            "instance": request.url.path,
        },
        media_type="application/problem+json",
    )

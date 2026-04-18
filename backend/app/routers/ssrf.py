"""SSRF callback endpoints - public routes for capturing SSRF signals."""

from typing import Optional

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.ssrf_signal import SsrfSignal
from app.services.ssrf_service import SsrfService

router = APIRouter(prefix="/ssrf", tags=["ssrf"])


@router.get("/{token}")
async def ssrf_dns_callback(
    token: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    DNS-based SSRF callback endpoint.
    When this endpoint is accessed, it indicates DNS resolution occurred.
    """
    try:
        # Extract request details
        ip_address = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent")
        referrer = request.headers.get("referer")
        url_path = str(request.url)

        # Record DNS-based signal
        success = SsrfService.record_signal(
            db=db,
            token=token,
            signal_type="dns",
            ip_address=ip_address,
            user_agent=user_agent,
            headers=dict(request.headers),
            referrer=referrer,
            url_path=url_path,
            method=request.method,
        )

        if success:
            # Return a minimal response to indicate success
            return Response(status_code=200, content="OK")
        else:
            return Response(status_code=404, content="Token not found")

    except Exception as e:
        # Log error but don't expose it
        print(f"SSRF DNS callback error: {e}")
        return Response(status_code=500, content="Internal Server Error")


@router.post("/{token}")
async def ssrf_http_callback(
    token: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    HTTP-based SSRF callback endpoint.
    When this endpoint receives POST data, it indicates HTTP request occurred.
    """
    try:
        # Extract request details
        ip_address = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent")
        referrer = request.headers.get("referer")
        url_path = str(request.url)

        # Read request body for additional context
        body = await request.body()
        raw_request = body.decode("utf-8", errors="ignore") if body else None

        # Record HTTP-based signal
        success = SsrfService.record_signal(
            db=db,
            token=token,
            signal_type="http",
            ip_address=ip_address,
            user_agent=user_agent,
            headers=dict(request.headers),
            raw_request=raw_request,
            referrer=referrer,
            url_path=url_path,
            method=request.method,
        )

        if success:
            # Return a minimal response to indicate success
            return Response(status_code=200, content="OK")
        else:
            return Response(status_code=404, content="Token not found")

    except Exception as e:
        # Log error but don't expose it
        print(f"SSRF HTTP callback error: {e}")
        return Response(status_code=500, content="Internal Server Error")


@router.get("/{token}/info")
async def get_ssrf_token_info(token: str, db: Session = Depends(get_db)):
    """
    Get information about an SSRF token (for debugging).
    This endpoint is public but only returns basic info.
    """
    signal = db.query(SsrfSignal).filter(SsrfSignal.token == token).first()
    if not signal:
        return {"error": "Token not found"}

    return {
        "token": token,
        "signal_type": signal.signal_type,
        "created": signal.triggered_at.isoformat() if signal.triggered_at else None,
        "has_payload_opportunity": signal.payload_opportunity_id is not None,
    }

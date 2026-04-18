"""API endpoints for out-of-band interactions and callbacks."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from typing import Dict, List, Optional

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.out_of_band_interaction import OutOfBandInteraction
from app.services.out_of_band_service import oob_service

router = APIRouter(prefix="/oob", tags=["out-of-band"])


@router.post("/callback/{callback_id}")
async def receive_callback(
    callback_id: str, request: Request, db: Session = Depends(get_db)
):
    """Receive and record out-of-band callback."""

    # Extract request details
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    # Get headers as dict
    headers = dict(request.headers)

    # Get body (limit size)
    try:
        body = await request.body()
        body_str = body.decode("utf-8", errors="ignore")[:1000]  # Limit size
    except:
        body_str = ""

    request_data = {
        "source_ip": client_ip,
        "user_agent": user_agent,
        "headers": headers,
        "body": body_str,
        "method": request.method,
        "path": str(request.url.path),
        "query_string": str(request.url.query) if request.url.query else "",
    }

    # Record interaction
    interaction = oob_service.record_interaction(db, callback_id, request_data)

    if not interaction:
        raise HTTPException(status_code=404, detail="Callback not found")

    # Return success response
    return {
        "status": "recorded",
        "callback_id": callback_id,
        "interaction_type": interaction.interaction_type,
        "timestamp": interaction.timestamp,
    }


@router.post("/generate-callback")
async def generate_callback(
    interaction_type: str = Query(..., description="ssrf, blind_xss, or dns"),
    scan_id: Optional[int] = Query(None),
    vulnerability_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate a new callback URL for tracking interactions."""

    # Validate interaction type
    valid_types = ["ssrf", "blind_xss", "dns"]
    if interaction_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid interaction type. Must be one of: {valid_types}",
        )

    # Generate callback details
    callback_details = oob_service.generate_callback(
        current_user.id, interaction_type, scan_id, vulnerability_id
    )

    # Create database record
    interaction = oob_service.create_callback_record(
        db,
        current_user.id,
        callback_details["callback_id"],
        interaction_type,
        scan_id,
        vulnerability_id,
    )

    return {
        "callback_id": callback_details["callback_id"],
        "callback_url": callback_details["callback_url"],
        "interaction_type": interaction_type,
        "payloads": callback_details["payloads"],
        "interaction_record_id": interaction.id,
    }


@router.get("/interactions")
async def get_user_interactions(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all out-of-band interactions for the current user."""

    interactions = oob_service.get_user_interactions(db, current_user.id, limit)

    return {
        "interactions": [
            {
                "id": interaction.id,
                "callback_id": interaction.callback_id,
                "interaction_type": interaction.interaction_type,
                "timestamp": interaction.timestamp,
                "source_ip": interaction.source_ip,
                "user_agent": interaction.user_agent,
                "method": interaction.method,
                "path": interaction.path,
                "is_confirmed": interaction.is_confirmed,
                "confidence_score": interaction.confidence_score,
                "analysis_notes": interaction.analysis_notes,
                "scan_id": interaction.scan_id,
                "vulnerability_id": interaction.vulnerability_id,
            }
            for interaction in interactions
        ]
    }


@router.get("/interactions/confirmed")
async def get_confirmed_interactions(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Get confirmed out-of-band interactions."""

    interactions = oob_service.get_confirmed_interactions(db, current_user.id)

    return {
        "confirmed_interactions": [
            {
                "id": interaction.id,
                "callback_id": interaction.callback_id,
                "interaction_type": interaction.interaction_type,
                "timestamp": interaction.timestamp,
                "source_ip": interaction.source_ip,
                "confidence_score": interaction.confidence_score,
                "analysis_notes": interaction.analysis_notes,
                "scan_id": interaction.scan_id,
                "vulnerability_id": interaction.vulnerability_id,
            }
            for interaction in interactions
        ]
    }


@router.get("/scan/{scan_id}/interactions")
async def get_scan_interactions(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get out-of-band interactions for a specific scan."""

    # Check if user owns the scan
    from app.models.scan import Scan

    scan = db.query(Scan).filter(Scan.id == scan_id).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.target.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    interactions = oob_service.get_scan_interactions(db, scan_id)

    return {
        "scan_id": scan_id,
        "interactions": [
            {
                "id": interaction.id,
                "callback_id": interaction.callback_id,
                "interaction_type": interaction.interaction_type,
                "timestamp": interaction.timestamp,
                "source_ip": interaction.source_ip,
                "is_confirmed": interaction.is_confirmed,
                "confidence_score": interaction.confidence_score,
                "analysis_notes": interaction.analysis_notes,
            }
            for interaction in interactions
        ],
    }


@router.get("/interaction/{interaction_id}")
async def get_interaction_details(
    interaction_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get detailed information about a specific interaction."""

    interaction = (
        db.query(OutOfBandInteraction)
        .filter(OutOfBandInteraction.id == interaction_id)
        .first()
    )

    if not interaction:
        raise HTTPException(status_code=404, detail="Interaction not found")

    # Check if user owns the interaction
    if interaction.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    return {
        "id": interaction.id,
        "callback_id": interaction.callback_id,
        "callback_url": interaction.callback_url,
        "interaction_type": interaction.interaction_type,
        "timestamp": interaction.timestamp,
        "source_ip": interaction.source_ip,
        "user_agent": interaction.user_agent,
        "headers": interaction.headers,
        "body": interaction.body,
        "method": interaction.method,
        "path": interaction.path,
        "query_string": interaction.query_string,
        "is_confirmed": interaction.is_confirmed,
        "confidence_score": interaction.confidence_score,
        "analysis_notes": interaction.analysis_notes,
        "scan_id": interaction.scan_id,
        "vulnerability_id": interaction.vulnerability_id,
        "created_at": interaction.created_at,
        "updated_at": interaction.updated_at,
    }

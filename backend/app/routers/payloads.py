from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.blind_xss_hit import BlindXssHit
from app.models.endpoint import Endpoint
from app.models.payload_opportunity import PayloadOpportunity
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.routers.auth import limiter
from app.schemas.payload_opportunity import (
    EndpointWithPayloadOpportunitiesOut,
    PayloadOpportunityOut,
)
from app.services.audit import log_audit_event
from app.services.blind_xss_service import BlindXssService

router = APIRouter(prefix="/payloads", tags=["payloads"])


@router.get("/{target_id}", response_model=dict)
@limiter.limit(settings.read_rate_limit)
def get_payload_opportunities(
    target_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Get all payload testing opportunities for a target's latest scan.

    Returns: {
        "target_id": int,
        "scan_id": int,
        "endpoints_with_opportunities": [EndpointWithPayloadOpportunitiesOut],
        "opportunity_summary": {
            "xss": int,
            "sqli": int,
            "ssti": int,
            "ssrf": int,
            "openredirect": int,
        },
    }
    """
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.owner_id == user.id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Get latest completed scan
    latest_scan = (
        db.query(Scan)
        .filter(Scan.target_id == target_id, Scan.status == "completed")
        .order_by(Scan.created_at.desc())
        .first()
    )
    if not latest_scan:
        raise HTTPException(status_code=404, detail="No completed scan found")

    # Get all opportunities for this scan
    opportunities = (
        db.query(PayloadOpportunity)
        .options(selectinload(PayloadOpportunity.endpoint))
        .filter(PayloadOpportunity.scan_id == latest_scan.id)
        .all()
    )

    # Group by endpoint
    endpoints_with_opps = {}
    vuln_type_counts = {
        "xss": 0,
        "sqli": 0,
        "ssti": 0,
        "ssrf": 0,
        "openredirect": 0,
    }

    for opp in opportunities:
        endpoint_id = opp.endpoint_id
        if endpoint_id not in endpoints_with_opps:
            endpoints_with_opps[endpoint_id] = {
                "endpoint": opp.endpoint,
                "opportunities": [],
            }
        endpoints_with_opps[endpoint_id]["opportunities"].append(opp)
        vuln_type_counts[opp.vulnerability_type] = (
            vuln_type_counts.get(opp.vulnerability_type, 0) + 1
        )

    # Build response
    result_endpoints = []
    for endpoint_id, data in endpoints_with_opps.items():
        endpoint = data["endpoint"]
        result_endpoints.append(
            {
                "id": endpoint.id,
                "url": endpoint.url,
                "normalized_url": endpoint.normalized_url,
                "hostname": endpoint.hostname,
                "priority_score": endpoint.priority_score,
                "source": endpoint.source,
                "payload_opportunities": [
                    {
                        "id": opp.id,
                        "endpoint_id": opp.endpoint_id,
                        "parameter_name": opp.parameter_name,
                        "parameter_location": opp.parameter_location,
                        "vulnerability_type": opp.vulnerability_type,
                        "confidence": opp.confidence,
                        "payloads_json": opp.payloads_json,
                        "tested_json": opp.tested_json,
                        "highest_match": opp.highest_match,
                        "match_confidence": opp.match_confidence,
                        "notes": opp.notes,
                        "created_at": opp.created_at,
                        "updated_at": opp.updated_at,
                    }
                    for opp in data["opportunities"]
                ],
            }
        )

    log_audit_event(
        db,
        action="payload_opportunities_viewed",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"target_id": target_id, "scan_id": latest_scan.id},
    )

    return {
        "target_id": target_id,
        "scan_id": latest_scan.id,
        "endpoints_with_opportunities": result_endpoints,
        "opportunity_summary": vuln_type_counts,
    }


@router.get("/{target_id}/{endpoint_id}", response_model=list[PayloadOpportunityOut])
@limiter.limit(settings.read_rate_limit)
def get_endpoint_payload_opportunities(
    target_id: int,
    endpoint_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get payload opportunities for a specific endpoint."""
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.owner_id == user.id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    # Verify endpoint belongs to a target owned by user
    scan = db.query(Scan).filter(Scan.id == endpoint.scan_id).first()
    if not scan or scan.target_id != target_id:
        raise HTTPException(
            status_code=403, detail="Endpoint does not belong to this target"
        )

    opportunities = (
        db.query(PayloadOpportunity)
        .filter(PayloadOpportunity.endpoint_id == endpoint_id)
        .order_by(PayloadOpportunity.confidence.desc())
        .all()
    )

    return opportunities


@router.get("/blind-xss/hits", response_model=list[dict])
@limiter.limit(settings.read_rate_limit)
def get_blind_xss_hits(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get all blind XSS hits for the current user."""
    hits = BlindXssService.get_user_hits(db, user.id)

    result = []
    for hit in hits:
        result.append(
            {
                "id": hit.id,
                "token": hit.token,
                "ip_address": hit.ip_address,
                "user_agent": hit.user_agent,
                "referrer": hit.referrer,
                "url_path": hit.url_path,
                "method": hit.method,
                "triggered_at": hit.triggered_at,
                "processed": hit.processed,
                "payload_opportunity": (
                    {
                        "id": hit.payload_opportunity.id,
                        "endpoint_url": (
                            hit.payload_opportunity.endpoint.url
                            if hit.payload_opportunity
                            else None
                        ),
                        "parameter_name": (
                            hit.payload_opportunity.parameter_name
                            if hit.payload_opportunity
                            else None
                        ),
                    }
                    if hit.payload_opportunity
                    else None
                ),
            }
        )

    log_audit_event(
        db,
        action="blind_xss_hits_viewed",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"hits_count": len(result)},
    )

    return result


@router.put("/blind-xss/hits/{hit_id}/processed")
@limiter.limit(settings.read_rate_limit)
def mark_blind_xss_hit_processed(
    hit_id: int,
    processed: int = 1,  # 1=processed, 2=ignored
    request: Request = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Mark a blind XSS hit as processed or ignored."""
    # Verify the hit belongs to the user
    hit = (
        db.query(BlindXssHit)
        .filter(BlindXssHit.id == hit_id, BlindXssHit.user_id == user.id)
        .first()
    )
    if not hit:
        raise HTTPException(status_code=404, detail="Blind XSS hit not found")

    if processed not in [1, 2]:
        raise HTTPException(
            status_code=400,
            detail="Processed status must be 1 (processed) or 2 (ignored)",
        )

    success = BlindXssService.mark_hit_processed(db, hit_id, processed)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update hit status")

    log_audit_event(
        db,
        action="blind_xss_hit_processed",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"hit_id": hit_id, "processed_status": processed},
    )

    return {"success": True, "processed": processed}


@router.post("/blind-xss/tokens")
@limiter.limit(settings.read_rate_limit)
def create_blind_xss_token(
    payload_opportunity_id: Optional[int] = None,
    request: Request = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Create a new blind XSS tracking token."""
    if payload_opportunity_id:
        # Verify the payload opportunity belongs to the user
        opp = (
            db.query(PayloadOpportunity)
            .join(Scan)
            .join(Target)
            .filter(
                PayloadOpportunity.id == payload_opportunity_id,
                Target.owner_id == user.id,
            )
            .first()
        )
        if not opp:
            raise HTTPException(status_code=404, detail="Payload opportunity not found")

    token = BlindXssService.create_token_for_opportunity(
        db, user.id, payload_opportunity_id
    )

    log_audit_event(
        db,
        action="blind_xss_token_created",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={
            "token": token,
            "payload_opportunity_id": payload_opportunity_id,
        },
    )

    return {"token": token, "payload_opportunity_id": payload_opportunity_id}

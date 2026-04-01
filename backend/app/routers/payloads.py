from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
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
    target = db.query(Target).filter(Target.id == target_id, Target.owner_id == user.id).first()
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
        vuln_type_counts[opp.vulnerability_type] = vuln_type_counts.get(opp.vulnerability_type, 0) + 1

    # Build response
    result_endpoints = []
    for endpoint_id, data in endpoints_with_opps.items():
        endpoint = data["endpoint"]
        result_endpoints.append({
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
        })

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
    target = db.query(Target).filter(Target.id == target_id, Target.owner_id == user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    # Verify endpoint belongs to a target owned by user
    scan = db.query(Scan).filter(Scan.id == endpoint.scan_id).first()
    if not scan or scan.target_id != target_id:
        raise HTTPException(status_code=403, detail="Endpoint does not belong to this target")

    opportunities = (
        db.query(PayloadOpportunity)
        .filter(PayloadOpportunity.endpoint_id == endpoint_id)
        .order_by(PayloadOpportunity.confidence.desc())
        .all()
    )

    return opportunities

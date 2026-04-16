import asyncio
import logging
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session, selectinload

from app.core.cache import build_cache_key, get_cached, invalidate_prefix, set_cached
from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.routers.auth import limiter
from app.schemas.vulnerability import VulnerabilityOut, VulnerabilityUpdate
from app.services.audit import log_audit_event
from app.services.ai_service import generate_exploit_draft

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


def _vulnerability_cache_key(user_id: int, target_id: int, skip: int, limit: int) -> str:
    return build_cache_key(
        user_id,
        f"vulnerabilities:{target_id}",
        f"skip={skip}:limit={limit}",
    )


def _vulnerability_cache_prefix(user_id: int, target_id: int) -> str:
    return build_cache_key(user_id, f"vulnerabilities:{target_id}")


@router.post("/{vulnerability_id}/exploit")
@limiter.limit(settings.ai_rate_limit)
async def get_vulnerability_exploit(
    vulnerability_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate an AI-powered exploit draft/PoC for a vulnerability (FIX #4: Explicit authorization checks)."""
    
    # Step 1: Get vulnerability
    vuln = db.query(Vulnerability).filter(
        Vulnerability.id == vulnerability_id
    ).first()
    
    if not vuln:
        raise HTTPException(status_code=404, detail="Not found")
    
    # Step 2: Get scan explicitly
    scan = db.query(Scan).filter(Scan.id == vuln.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Not found")
    
    # Step 3: Get target and verify ownership (explicit check)
    target = db.query(Target).filter(
        Target.id == scan.target_id,
        Target.owner_id == user.id
    ).first()
    
    if not target:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Now safe to proceed
    vuln_data = {
        "template_id": vuln.template_id,
        "severity": vuln.severity,
        "matched_url": vuln.matched_url,
        "description": vuln.description,
        "evidence_json": vuln.evidence_json,
    }
    
    result = await generate_exploit_draft(vuln_data)
    
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
        
    return result


@router.get("/target/{target_id}", response_model=list[VulnerabilityOut])
def list_vulnerabilities(  # FIX #7: Remove async - only sync db operations
    target_id: int,
    skip: int = 0,
    limit: int = 50,  # FIX #18: Add pagination
    request: Request = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List vulnerabilities with pagination (FIX #18: Added)."""
    
    # Validate pagination limits
    limit = min(limit, 100)
    if skip < 0:
        skip = 0
    
    # Verify user owns target
    target = db.query(Target).filter(
        Target.id == target_id, 
        Target.owner_id == user.id
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Not found")

    # Try cache first
    cache_key = _vulnerability_cache_key(user.id, target_id, skip, limit)
    try:
        # FIX #19: Add timeout to cache operations
        cached = asyncio.run(asyncio.wait_for(
            get_cached(cache_key),
            timeout=2.0
        ))
        if cached is not None:
            return [VulnerabilityOut.model_validate(item) for item in cached]
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Cache read failed: {e}", exc_info=False)
        # Continue with database query

    # Query database
    vulns = (
        db.query(Vulnerability)
        .options(selectinload(Vulnerability.ai_report))
        .join(Scan, Scan.id == Vulnerability.scan_id)
        .filter(Scan.target_id == target_id)
        .offset(skip)
        .limit(limit)
        .all()
    )
    
    result = [VulnerabilityOut.model_validate(v) for v in vulns]
    
    # Try to cache, but don't fail if cache is down
    try:
        asyncio.run(asyncio.wait_for(
            set_cached(cache_key, [item.model_dump(mode="json") for item in result]),
            timeout=2.0
        ))
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Cache write failed: {e}", exc_info=False)
    
    return result


@router.put("/{vulnerability_id}", response_model=dict)
def update_vulnerability(  # FIX #7: Remove async - only sync db operations
    vulnerability_id: int,
    payload: VulnerabilityUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update vulnerability (FIX #4: Explicit authorization, FIX #8: Error handling)."""
    
    # Explicit multi-step authorization (FIX #4)
    vuln = db.query(Vulnerability).filter(
        Vulnerability.id == vulnerability_id
    ).first()
    
    if not vuln:
        raise HTTPException(status_code=404, detail="Not found")
    
    scan = db.query(Scan).filter(Scan.id == vuln.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Not found")
    
    target = db.query(Target).filter(
        Target.id == scan.target_id,
        Target.owner_id == user.id
    ).first()
    
    if not target:
        raise HTTPException(status_code=403, detail="Access denied")

    # Update vulnerability
    if payload.notes is not None:
        vuln.notes = payload.notes
    db.commit()

    # Invalidate cache (FIX #8: Graceful error handling)
    cache_key_prefix = _vulnerability_cache_prefix(user.id, scan.target_id)
    try:
        asyncio.run(asyncio.wait_for(
            invalidate_prefix(cache_key_prefix),
            timeout=2.0
        ))
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Cache invalidation failed: {e}", exc_info=False)
        # Continue anyway - data consistency maintained in DB

    log_audit_event(
        db,
        action="vulnerability_updated",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"vulnerability_id": vulnerability_id},
    )
    
    return {"message": "Updated"}

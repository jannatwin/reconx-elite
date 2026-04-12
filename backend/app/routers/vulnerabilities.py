from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session, selectinload

from app.core.cache import build_cache_key, get_cached, invalidate, set_cached
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

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.post("/{vulnerability_id}/exploit")
@limiter.limit(settings.ai_rate_limit)
async def get_vulnerability_exploit(
    vulnerability_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate an AI-powered exploit draft/PoC for a vulnerability."""
    vuln = (
        db.query(Vulnerability)
        .join(Scan, Scan.id == Vulnerability.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .filter(Vulnerability.id == vulnerability_id, Target.owner_id == user.id)
        .first()
    )
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Convert model to dict for AI service
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
@limiter.limit(settings.read_rate_limit)
async def list_vulnerabilities(
    target_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    target = db.query(Target).filter(Target.id == target_id, Target.owner_id == user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    cache_key = build_cache_key(user.id, f"vulnerabilities:{target_id}")
    cached = await get_cached(cache_key)
    if cached is not None:
        return [VulnerabilityOut.model_validate(item) for item in cached]

    vulns = (
        db.query(Vulnerability)
        .options(selectinload(Vulnerability.ai_report))
        .join(Scan, Scan.id == Vulnerability.scan_id)
        .filter(Scan.target_id == target_id)
        .all()
    )
    result = [VulnerabilityOut.model_validate(v) for v in vulns]
    await set_cached(cache_key, [item.model_dump(mode="json") for item in result])
    return result


@router.put("/{vulnerability_id}", response_model=dict)
@limiter.limit(settings.write_rate_limit)
async def update_vulnerability(
    vulnerability_id: int,
    payload: VulnerabilityUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    vuln = (
        db.query(Vulnerability)
        .join(Scan, Scan.id == Vulnerability.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .filter(Vulnerability.id == vulnerability_id, Target.owner_id == user.id)
        .first()
    )
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    if payload.notes is not None:
        vuln.notes = payload.notes
    db.commit()

    # Invalidate vulnerability list cache for the affected target
    scan = db.query(Scan).filter(Scan.id == vuln.scan_id).first()
    if scan:
        await invalidate(build_cache_key(user.id, f"vulnerabilities:{scan.target_id}"))

    log_audit_event(
        db,
        action="vulnerability_updated",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"vulnerability_id": vulnerability_id},
    )
    return {"message": "Updated"}

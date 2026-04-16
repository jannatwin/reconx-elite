import asyncio
import logging
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy.orm import Session, selectinload

from app.core.cache import build_cache_key, get_cached, invalidate, set_cached
from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.routers.auth import limiter
from app.schemas.target import TargetCreate, TargetListItemOut, TargetOut, TargetUpdate
from app.services.audit import log_audit_event
from app.services.domain import normalize_domain

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/targets", tags=["targets"])


async def _invalidate_targets_cache(cache_key: str) -> None:
    try:
        await asyncio.wait_for(invalidate(cache_key), timeout=2.0)
    except (asyncio.TimeoutError, Exception) as exc:
        logger.warning("Cache invalidation failed: %s", exc, exc_info=False)


@router.post("", response_model=TargetOut)
@limiter.limit(settings.write_rate_limit)
def create_target(  # FIX #7: Remove async - only sync db operations
    background_tasks: BackgroundTasks,
    request: Request,
    payload: TargetCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    try:
        domain = normalize_domain(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    existing = db.query(Target).filter(Target.owner_id == user.id, Target.domain == domain).first()
    if existing:
        raise HTTPException(status_code=400, detail="Target already exists")

    target = Target(owner_id=user.id, domain=domain)
    db.add(target)
    db.commit()
    db.refresh(target)
    log_audit_event(
        db,
        action="target_created",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"target_id": target.id, "domain": target.domain},
    )
    background_tasks.add_task(_invalidate_targets_cache, build_cache_key(user.id, "targets"))

    return target


@router.get("", response_model=list[TargetListItemOut])
@limiter.limit(settings.read_rate_limit)
async def list_targets(  # FIX #7: Keep async - uses await on cache
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    cache_key = build_cache_key(user.id, "targets")
    
    # FIX #19: Add timeout to cache operations
    try:
        cached = await asyncio.wait_for(
            get_cached(cache_key),
            timeout=2.0
        )
        if cached is not None:
            return [TargetListItemOut.model_validate(item) for item in cached]
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Cache read failed: {e}", exc_info=False)

    targets = (
        db.query(Target)
        .options(
            selectinload(Target.scans).selectinload(Scan.subdomains),
            selectinload(Target.scans).selectinload(Scan.endpoints),
            selectinload(Target.scans).selectinload(Scan.vulnerabilities),
        )
        .filter(Target.owner_id == user.id)
        .order_by(Target.created_at.desc())
        .all()
    )
    payload: list[TargetListItemOut] = []
    for target in targets:
        scans = sorted(target.scans, key=lambda row: row.created_at, reverse=True)
        latest = scans[0] if scans else None
        payload.append(
            TargetListItemOut(
                id=target.id,
                domain=target.domain,
                notes=target.notes,
                created_at=target.created_at,
                scan_count=len(scans),
                latest_scan=(
                    {
                        "id": latest.id,
                        "status": latest.status,
                        "metadata_json": latest.metadata_json,
                        "error": latest.error,
                        "created_at": latest.created_at,
                        "subdomain_count": len(latest.subdomains),
                        "endpoint_count": len(latest.endpoints),
                        "vulnerability_count": len(latest.vulnerabilities),
                        "high_priority_endpoint_count": len(
                            [row for row in latest.endpoints if row.priority_score >= 60]
                        ),
                    }
                    if latest
                    else None
                ),
            )
        )
    
    # FIX #19: Add timeout to cache set operation
    try:
        await asyncio.wait_for(
            set_cached(cache_key, [item.model_dump(mode="json") for item in payload]),
            timeout=2.0
        )
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Cache write failed: {e}", exc_info=False)
    
    return payload


@router.put("/{target_id}", response_model=TargetOut)
@limiter.limit(settings.write_rate_limit)
def update_target(  # FIX #7: Remove async - only sync db operations
    target_id: int,
    payload: TargetUpdate,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    target = db.query(Target).filter(Target.id == target_id, Target.owner_id == user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if payload.notes is not None:
        target.notes = payload.notes
    db.commit()
    db.refresh(target)
    log_audit_event(
        db,
        action="target_updated",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"target_id": target.id},
    )
    background_tasks.add_task(_invalidate_targets_cache, build_cache_key(user.id, "targets"))

    return target


@router.get("/{target_id}", response_model=TargetOut)
@limiter.limit(settings.read_rate_limit)
def get_target(  # FIX #7: Keep sync - only sync db operations
    target_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    target = (
        db.query(Target)
        .options(
            selectinload(Target.scans).selectinload(Scan.subdomains),
            selectinload(Target.scans).selectinload(Scan.endpoints),
            selectinload(Target.scans).selectinload(Scan.vulnerabilities),
            selectinload(Target.scans).selectinload(Scan.javascript_assets),
            selectinload(Target.scans).selectinload(Scan.attack_paths),
            selectinload(Target.scans).selectinload(Scan.logs),
            selectinload(Target.scans).selectinload(Scan.diffs),
        )
        .filter(Target.id == target_id, Target.owner_id == user.id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    target.scans.sort(key=lambda row: row.created_at, reverse=True)
    for scan in target.scans:
        if scan.logs:
            scan.logs.sort(key=lambda row: row.started_at)
    return target

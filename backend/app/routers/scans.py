from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.scan import Scan
from app.models.scan_artifact import ScanArtifact
from app.models.target import Target
from app.models.user import User
from app.routers.auth import limiter
from app.services.scan_pipeline import pipeline_stage_total
from app.schemas.scan import ScanArtifactOut, ScanConfigRequest, ScanStatusOut
from app.services.audit import log_audit_event
from app.tasks.scan_tasks import start_scan_chain

router = APIRouter(tags=["scans"])

DEFAULT_SCAN_CONFIG = {
    "selected_templates": ["cves", "exposures", "misconfiguration"],
    "severity_filter": ["medium", "high", "critical"],
}


def _queued_metadata(scan_config: dict | None = None) -> dict:
    total = pipeline_stage_total(scan_config or DEFAULT_SCAN_CONFIG)
    return {
        "stage": "queued",
        "stage_index": 0,
        "stage_total": total,
        "progress_percent": 0,
        "warnings": [],
        "errors": [],
    }


def _build_scan_config_from_request(payload: ScanConfigRequest) -> dict:
    """Build and validate scan configuration from request (FIX #5: Input validation)."""
    cfg: dict = {
        "selected_templates": payload.selected_templates or DEFAULT_SCAN_CONFIG["selected_templates"],
        "severity_filter": payload.severity_filter or DEFAULT_SCAN_CONFIG["severity_filter"],
    }

    if payload.profile is not None:
        cfg["profile"] = payload.profile

    if payload.modules is not None:
        # Validate and re-dump modules (FIX #5)
        modules_dict = payload.modules.model_dump()

        # Validate structure is a dictionary
        if not isinstance(modules_dict, dict):
            raise HTTPException(status_code=422, detail="modules must be a dictionary")

        # Check nesting depth to prevent DOS
        def check_depth(obj, max_depth=3, current_depth=0):
            if current_depth > max_depth:
                raise ValueError("Configuration nesting too deep")
            if isinstance(obj, dict):
                for v in obj.values():
                    check_depth(v, max_depth, current_depth + 1)

        try:
            check_depth(modules_dict)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

        cfg["modules"] = modules_dict

    return cfg


def _guard_scan_request(db: Session, target_id: int, user_id: int) -> Target:
    target = db.query(Target).filter(Target.id == target_id, Target.owner_id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    running = (
        db.query(Scan)
        .filter(Scan.target_id == target.id, Scan.status.in_(["pending", "running"]))
        .order_by(Scan.created_at.desc())
        .first()
    )
    if running:
        raise HTTPException(status_code=409, detail="Scan already in progress for this target")

    recent_threshold = datetime.now(timezone.utc) - timedelta(seconds=settings.scan_throttle_seconds)
    recent = (
        db.query(Scan)
        .join(Target, Target.id == Scan.target_id)
        .filter(Target.owner_id == user_id, Scan.created_at >= recent_threshold)
        .order_by(Scan.created_at.desc())
        .first()
    )
    if recent:
        raise HTTPException(status_code=429, detail="Scan throttled. Please wait before starting another scan.")
    return target


@router.post("/scan/{target_id}", response_model=ScanStatusOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(settings.scan_rate_limit)
def trigger_scan(
    target_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    target = _guard_scan_request(db, target_id, user.id)
    
    # FIX #6: Use FOR UPDATE to prevent race condition
    running_scan = db.execute(
        select(Scan).where(
            and_(
                Scan.target_id == target.id,
                Scan.status.in_(["pending", "running"])
            )
        ).with_for_update()
    ).scalar_one_or_none()
    
    if running_scan:
        raise HTTPException(status_code=409, detail="Scan already in progress for this target")
    
    scan = Scan(
        target_id=target.id,
        status="pending",
        metadata_json=_queued_metadata(DEFAULT_SCAN_CONFIG),
        scan_config_json=dict(DEFAULT_SCAN_CONFIG),
    )
    
    # FIX #11: Atomic transaction for scan creation and audit logging
    try:
        db.add(scan)
        db.flush()  # Get scan.id without commit
        
        log_audit_event(
            db,
            action="scan_triggered",
            user_id=user.id,
            ip_address=request.client.host if request.client else None,
            metadata_json={"target_id": target.id, "scan_id": scan.id, "mode": "default"},
        )
        
        db.commit()  # Single commit point
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Scan already in progress for this target")
    
    db.refresh(scan)
    start_scan_chain(scan.id)
    return scan


@router.post("/scan/{target_id}/config", response_model=ScanStatusOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(settings.scan_rate_limit)
def trigger_scan_with_config(
    target_id: int,
    request: Request,
    payload: ScanConfigRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    target = _guard_scan_request(db, target_id, user.id)
    cfg = _build_scan_config_from_request(payload)
    
    # FIX #6: Use FOR UPDATE to prevent race condition
    running_scan = db.execute(
        select(Scan).where(
            and_(
                Scan.target_id == target.id,
                Scan.status.in_(["pending", "running"])
            )
        ).with_for_update()
    ).scalar_one_or_none()
    
    if running_scan:
        raise HTTPException(status_code=409, detail="Scan already in progress for this target")
    
    scan = Scan(
        target_id=target.id,
        status="pending",
        metadata_json=_queued_metadata(cfg),
        scan_config_json=cfg,
    )
    
    # FIX #11: Atomic transaction for scan creation and audit logging
    try:
        db.add(scan)
        db.flush()
        
        log_audit_event(
            db,
            action="scan_triggered",
            user_id=user.id,
            ip_address=request.client.host if request.client else None,
            metadata_json={"target_id": target.id, "scan_id": scan.id, "mode": "configured"},
        )
        
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Scan already in progress for this target")
    
    db.refresh(scan)
    start_scan_chain(scan.id)
    return scan


@router.get("/scans/{scan_id}", response_model=ScanStatusOut)
@limiter.limit(settings.read_rate_limit)
def get_scan(  # FIX #7: Remove async - only sync operations
    scan_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # FIX #15: Single query with join for atomic authorization check
    scan = (
        db.query(Scan)
        .options(selectinload(Scan.logs))
        .join(Target, Target.id == Scan.target_id)
        .filter(Scan.id == scan_id, Target.owner_id == user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Not found")
    
    if scan.logs:
        scan.logs.sort(key=lambda row: row.started_at)
    return scan


@router.get("/scans/{scan_id}/artifacts", response_model=list[ScanArtifactOut])
@limiter.limit(settings.read_rate_limit)
def list_scan_artifacts(  # FIX #7: Remove async - only sync operations
    scan_id: int,
    skip: int = 0,
    limit: int = 50,  # FIX #18: Add pagination
    request: Request = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Validate pagination limits
    limit = min(limit, 100)  # Max 100 items per page
    if skip < 0:
        skip = 0
    
    # FIX #15: Single query with join for atomic authorization check
    scan = (
        db.query(Scan)
        .join(Target, Target.id == Scan.target_id)
        .filter(Scan.id == scan_id, Target.owner_id == user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Not found")
    
    total = (
        db.query(ScanArtifact)
        .filter(ScanArtifact.scan_id == scan_id)
        .count()
    )
    
    rows = (
        db.query(ScanArtifact)
        .filter(ScanArtifact.scan_id == scan_id)
        .order_by(ScanArtifact.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    
    return rows

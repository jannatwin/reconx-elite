from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.routers.auth import limiter
from app.schemas.scan import ScanConfigRequest, ScanStatusOut
from app.services.audit import log_audit_event
from app.tasks.scan_tasks import start_scan_chain

router = APIRouter(tags=["scans"])

DEFAULT_SCAN_CONFIG = {
    "selected_templates": ["cves", "exposures", "misconfiguration"],
    "severity_filter": ["medium", "high", "critical"],
}


def _queued_metadata() -> dict:
    return {
        "stage": "queued",
        "stage_index": 0,
        "stage_total": 4,
        "progress_percent": 0,
        "warnings": [],
        "errors": [],
    }


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
    scan = Scan(
        target_id=target.id,
        status="pending",
        metadata_json=_queued_metadata(),
        scan_config_json=DEFAULT_SCAN_CONFIG,
    )
    db.add(scan)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Scan already in progress for this target")
    db.refresh(scan)
    start_scan_chain(scan.id)
    log_audit_event(
        db,
        action="scan_triggered",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"target_id": target.id, "scan_id": scan.id, "mode": "default"},
    )
    db.commit()
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
    scan = Scan(
        target_id=target.id,
        status="pending",
        metadata_json=_queued_metadata(),
        scan_config_json={
            "selected_templates": payload.selected_templates,
            "severity_filter": payload.severity_filter,
        },
    )
    db.add(scan)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Scan already in progress for this target")
    db.refresh(scan)
    start_scan_chain(scan.id)
    log_audit_event(
        db,
        action="scan_triggered",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"target_id": target.id, "scan_id": scan.id, "mode": "configured"},
    )
    db.commit()
    return scan


@router.get("/scans/{scan_id}", response_model=ScanStatusOut)
@limiter.limit(settings.read_rate_limit)
def get_scan(
    scan_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    scan = (
        db.query(Scan)
        .options(selectinload(Scan.logs))
        .filter(Scan.id == scan_id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    target = db.query(Target).filter(Target.id == scan.target_id, Target.owner_id == user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.logs.sort(key=lambda row: row.started_at)
    return scan

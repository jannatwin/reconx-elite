from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.scheduled_scan import ScheduledScan
from app.models.target import Target
from app.models.user import User
from app.routers.auth import limiter
from app.schemas.scheduled_scan import (
    ScheduledScanCreate,
    ScheduledScanOut,
    ScheduledScanUpdate,
)
from app.services.audit import log_audit_event

router = APIRouter(prefix="/schedules", tags=["schedules"])


@router.post("", response_model=ScheduledScanOut)
@limiter.limit(settings.write_rate_limit)
def create_schedule(
    payload: ScheduledScanCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    target = (
        db.query(Target)
        .filter(Target.id == payload.target_id, Target.owner_id == user.id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    existing = (
        db.query(ScheduledScan)
        .filter(
            ScheduledScan.target_id == payload.target_id,
            ScheduledScan.user_id == user.id,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=400, detail="Schedule already exists for this target"
        )

    now = datetime.now(timezone.utc)
    if payload.frequency == "daily":
        next_run = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(
            days=1
        )
    elif payload.frequency == "weekly":
        next_run = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(
            weeks=1
        )
    else:
        raise HTTPException(status_code=422, detail="Invalid frequency")

    schedule = ScheduledScan(
        target_id=payload.target_id,
        user_id=user.id,
        frequency=payload.frequency,
        next_run=next_run,
        scan_config_json=payload.scan_config or {},
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    log_audit_event(
        db,
        action="schedule_created",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"schedule_id": schedule.id, "target_id": schedule.target_id},
    )
    return schedule


@router.get("", response_model=list[ScheduledScanOut])
@limiter.limit(settings.read_rate_limit)
def list_schedules(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return db.query(ScheduledScan).filter(ScheduledScan.user_id == user.id).all()


@router.put("/{schedule_id}", response_model=ScheduledScanOut)
@limiter.limit(settings.write_rate_limit)
def update_schedule(
    schedule_id: int,
    payload: ScheduledScanUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    schedule = (
        db.query(ScheduledScan)
        .filter(ScheduledScan.id == schedule_id, ScheduledScan.user_id == user.id)
        .first()
    )
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    if payload.frequency is not None:
        schedule.frequency = payload.frequency
    if payload.enabled is not None:
        schedule.enabled = payload.enabled
    if payload.scan_config is not None:
        schedule.scan_config_json = payload.scan_config
    db.commit()
    db.refresh(schedule)
    log_audit_event(
        db,
        action="schedule_updated",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"schedule_id": schedule.id},
    )
    return schedule


@router.delete("/{schedule_id}")
@limiter.limit(settings.write_rate_limit)
def delete_schedule(
    schedule_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    schedule = (
        db.query(ScheduledScan)
        .filter(ScheduledScan.id == schedule_id, ScheduledScan.user_id == user.id)
        .first()
    )
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    db.delete(schedule)
    db.commit()
    log_audit_event(
        db,
        action="schedule_deleted",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"schedule_id": schedule_id},
    )
    return {"message": "Schedule deleted"}

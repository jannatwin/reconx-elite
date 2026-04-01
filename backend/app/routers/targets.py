from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session, selectinload

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.routers.auth import limiter
from app.schemas.target import TargetCreate, TargetOut
from app.services.domain import normalize_domain

router = APIRouter(prefix="/targets", tags=["targets"])


@router.post("", response_model=TargetOut)
@limiter.limit("60/minute")
def create_target(
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
    return target


@router.put("/{target_id}", response_model=TargetOut)
@limiter.limit("60/minute")
def update_target(
    target_id: int,
    payload: dict,  # Allow partial updates
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    target = db.query(Target).filter(Target.id == target_id, Target.owner_id == user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    for key, value in payload.items():
        if hasattr(target, key):
            setattr(target, key, value)
    db.commit()
    db.refresh(target)
    return target


@router.get("/{target_id}", response_model=TargetOut)
@limiter.limit("120/minute")
def get_target(
    request: Request,
    target_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    target = (
        db.query(Target)
        .options(
            selectinload(Target.scans).selectinload(Scan.subdomains),
            selectinload(Target.scans).selectinload(Scan.endpoints),
            selectinload(Target.scans).selectinload(Scan.vulnerabilities),
            selectinload(Target.scans).selectinload(Scan.logs),
            selectinload(Target.scans).selectinload(Scan.diffs),
        )
        .filter(Target.id == target_id, Target.owner_id == user.id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target

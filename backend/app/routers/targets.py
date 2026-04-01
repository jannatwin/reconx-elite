<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
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
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.models import Scan, Target, User
from app.schemas.schemas import TargetCreate, TargetOut
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs

router = APIRouter(prefix="/targets", tags=["targets"])


<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
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
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
def normalize_domain(value: str) -> str:
    raw = value.strip().lower()
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    if raw.startswith("*."):
        raw = raw[2:]
    if not raw or "." not in raw:
        raise ValueError("Invalid domain")
    if any(c in raw for c in ["/", " ", "\\"]):
        raise ValueError("Invalid domain")
    return raw


@router.post("", response_model=TargetOut)
def create_target(payload: TargetCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    try:
        domain = normalize_domain(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs

    existing = db.query(Target).filter(Target.owner_id == user.id, Target.domain == domain).first()
    if existing:
        raise HTTPException(status_code=400, detail="Target already exists")

<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
    target = Target(owner_id=user.id, domain=domain)
=======
    target = Target(domain=domain, owner_id=user.id)
>>>>>>> theirs
=======
    target = Target(domain=domain, owner_id=user.id)
>>>>>>> theirs
=======
    target = Target(domain=domain, owner_id=user.id)
>>>>>>> theirs
=======
    target = Target(domain=domain, owner_id=user.id)
>>>>>>> theirs
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
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
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
@router.get("", response_model=list[TargetOut])
def list_targets(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return (
        db.query(Target)
        .options(joinedload(Target.scans))
        .filter(Target.owner_id == user.id)
        .order_by(Target.created_at.desc())
        .all()
    )


@router.get("/{target_id}", response_model=TargetOut)
def get_target(target_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    target = (
        db.query(Target)
        .options(
            joinedload(Target.scans).joinedload(Scan.subdomains),
            joinedload(Target.scans).joinedload(Scan.endpoints),
            joinedload(Target.scans).joinedload(Scan.vulnerabilities),
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
        )
        .filter(Target.id == target_id, Target.owner_id == user.id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
=======
    target.scans.sort(key=lambda s: s.created_at, reverse=True)
>>>>>>> theirs
=======
    target.scans.sort(key=lambda s: s.created_at, reverse=True)
>>>>>>> theirs
=======
    target.scans.sort(key=lambda s: s.created_at, reverse=True)
>>>>>>> theirs
=======
    target.scans.sort(key=lambda s: s.created_at, reverse=True)
>>>>>>> theirs
    return target

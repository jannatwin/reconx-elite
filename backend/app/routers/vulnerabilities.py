from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.routers.auth import limiter
from app.schemas.vulnerability import VulnerabilityUpdate
from app.services.audit import log_audit_event

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.put("/{vulnerability_id}", response_model=dict)
@limiter.limit(settings.write_rate_limit)
def update_vulnerability(
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
    log_audit_event(
        db,
        action="vulnerability_updated",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"vulnerability_id": vulnerability_id},
    )
    return {"message": "Updated"}

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.routers.auth import limiter

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.put("/{vulnerability_id}", response_model=dict)
@limiter.limit("120/minute")
def update_vulnerability(
    vulnerability_id: int,
    payload: dict,  # Allow partial updates
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    vuln = db.query(Vulnerability).join(Vulnerability.scan).join(Vulnerability.scan.target).filter(
        Vulnerability.id == vulnerability_id,
        Vulnerability.scan.target.owner_id == user.id
    ).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    for key, value in payload.items():
        if hasattr(vuln, key):
            setattr(vuln, key, value)
    db.commit()
    return {"message": "Updated"}
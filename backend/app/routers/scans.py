from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.tasks.scan_tasks import scan_target

router = APIRouter(tags=["scans"])


@router.post("/scan/{target_id}", status_code=status.HTTP_202_ACCEPTED)
def trigger_scan(target_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    target = db.query(Target).filter(Target.id == target_id, Target.owner_id == user.id).first()
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

    scan = Scan(target_id=target.id, status="pending", metadata_json={"step": "queued"})
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan_target.delay(scan.id)
    return {"scan_id": scan.id, "status": "pending"}

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.routers.auth import limiter

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{target_id}/json")
@limiter.limit("30/minute")
def generate_json_report(
    target_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    target = db.query(Target).filter(Target.id == target_id, Target.owner_id == user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Get latest scan
    latest_scan = (
        db.query(Scan)
        .filter(Scan.target_id == target_id, Scan.status == "completed")
        .order_by(Scan.created_at.desc())
        .first()
    )
    if not latest_scan:
        raise HTTPException(status_code=404, detail="No completed scan found")

    report = {
        "target": {
            "domain": target.domain,
            "notes": target.notes,
        },
        "scan": {
            "id": latest_scan.id,
            "created_at": latest_scan.created_at.isoformat(),
            "subdomains": [
                {
                    "hostname": s.hostname,
                    "is_live": s.is_live,
                    "ip": s.ip,
                    "tech_stack": s.tech_stack,
                    "cdn_waf": s.cdn_waf,
                }
                for s in latest_scan.subdomains
            ],
            "endpoints": [
                {
                    "url": e.url,
                    "category": e.category,
                    "tags": e.tags,
                    "is_interesting": e.is_interesting,
                }
                for e in latest_scan.endpoints
            ],
            "vulnerabilities": [
                {
                    "template_id": v.template_id,
                    "severity": v.severity,
                    "matched_url": v.matched_url,
                    "description": v.description,
                    "notes": v.notes,
                }
                for v in latest_scan.vulnerabilities
            ],
        },
        "generated_at": datetime.utcnow().isoformat(),
    }

    return Response(
        content=json.dumps(report, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={target.domain}_report.json"},
    )


@router.get("/{target_id}/pdf")
@limiter.limit("10/minute")
def generate_pdf_report(
    target_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # For PDF, we can use a library like reportlab or fpdf
    # For now, return a placeholder
    target = db.query(Target).filter(Target.id == target_id, Target.owner_id == user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Placeholder PDF content
    pdf_content = f"ReconX Report for {target.domain}\nGenerated at {datetime.utcnow()}"

    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={target.domain}_report.pdf"},
    )
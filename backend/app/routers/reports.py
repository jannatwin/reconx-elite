import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.routers.auth import limiter
from app.services.audit import log_audit_event
from app.services.pdf_generator import PDFReportGenerator

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{target_id}/json")
@limiter.limit(settings.report_rate_limit)
def generate_json_report(
    target_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.owner_id == user.id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Get latest scan
    latest_scan = (
        db.query(Scan)
        .options(
            selectinload(Scan.subdomains),
            selectinload(Scan.endpoints),
            selectinload(Scan.vulnerabilities),
            selectinload(Scan.javascript_assets),
            selectinload(Scan.attack_paths),
        )
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
                    "id": s.id,
                    "hostname": s.hostname,
                    "is_live": s.is_live,
                    "environment": s.environment,
                    "tags": s.tags,
                    "takeover_candidate": s.takeover_candidate,
                    "cname": s.cname,
                    "ip": s.ip,
                    "tech_stack": s.tech_stack,
                    "cdn": s.cdn,
                    "waf": s.waf,
                    "cdn_waf": s.cdn_waf,
                }
                for s in latest_scan.subdomains
            ],
            "endpoints": [
                {
                    "id": e.id,
                    "url": e.url,
                    "normalized_url": e.normalized_url,
                    "hostname": e.hostname,
                    "path": e.path,
                    "query_params": e.query_params,
                    "category": e.category,
                    "tags": e.tags,
                    "priority_score": e.priority_score,
                    "focus_reasons": e.focus_reasons,
                    "source": e.source,
                    "js_source": e.js_source,
                    "is_interesting": e.is_interesting,
                }
                for e in latest_scan.endpoints
            ],
            "vulnerabilities": [
                {
                    "id": v.id,
                    "template_id": v.template_id,
                    "severity": v.severity,
                    "source": v.source,
                    "confidence": v.confidence,
                    "matched_url": v.matched_url,
                    "description": v.description,
                    "notes": v.notes,
                    "evidence_json": v.evidence_json,
                }
                for v in latest_scan.vulnerabilities
            ],
            "javascript_assets": [
                {
                    "id": asset.id,
                    "url": asset.url,
                    "normalized_url": asset.normalized_url,
                    "hostname": asset.hostname,
                    "status": asset.status,
                    "secrets_json": asset.secrets_json,
                    "extracted_endpoints": asset.extracted_endpoints,
                }
                for asset in latest_scan.javascript_assets
            ],
            "attack_paths": [
                {
                    "id": attack_path.id,
                    "title": attack_path.title,
                    "summary": attack_path.summary,
                    "severity": attack_path.severity,
                    "score": attack_path.score,
                    "steps_json": attack_path.steps_json,
                    "evidence_json": attack_path.evidence_json,
                }
                for attack_path in latest_scan.attack_paths
            ],
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    log_audit_event(
        db,
        action="report_downloaded",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"target_id": target_id, "format": "json"},
    )

    return Response(
        content=json.dumps(report, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename={target.domain}_report.json"
        },
    )


@router.get("/{target_id}/pdf")
@limiter.limit(settings.report_rate_limit)
def generate_pdf_report(
    target_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.owner_id == user.id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Get latest scan with all related data
    latest_scan = (
        db.query(Scan)
        .options(
            selectinload(Scan.subdomains),
            selectinload(Scan.endpoints),
            selectinload(Scan.vulnerabilities),
            selectinload(Scan.javascript_assets),
            selectinload(Scan.attack_paths),
        )
        .filter(Scan.target_id == target_id, Scan.status == "completed")
        .order_by(Scan.created_at.desc())
        .first()
    )
    if not latest_scan:
        raise HTTPException(status_code=404, detail="No completed scan found")

    # Build comprehensive report data
    report_data = {
        "target": {
            "domain": target.domain,
            "notes": target.notes,
        },
        "scan": {
            "id": latest_scan.id,
            "created_at": latest_scan.created_at.isoformat(),
            "subdomains": [
                {
                    "id": s.id,
                    "hostname": s.hostname,
                    "is_live": s.is_live,
                    "environment": s.environment,
                    "tags": s.tags,
                    "takeover_candidate": s.takeover_candidate,
                    "cname": s.cname,
                    "ip": s.ip,
                    "tech_stack": s.tech_stack,
                    "cdn": s.cdn,
                    "waf": s.waf,
                    "cdn_waf": s.cdn_waf,
                }
                for s in latest_scan.subdomains
            ],
            "endpoints": [
                {
                    "id": e.id,
                    "url": e.url,
                    "normalized_url": e.normalized_url,
                    "hostname": e.hostname,
                    "path": e.path,
                    "query_params": e.query_params,
                    "category": e.category,
                    "tags": e.tags,
                    "priority_score": e.priority_score,
                    "focus_reasons": e.focus_reasons,
                    "source": e.source,
                    "js_source": e.js_source,
                    "is_interesting": e.is_interesting,
                }
                for e in latest_scan.endpoints
            ],
            "vulnerabilities": [
                {
                    "id": v.id,
                    "template_id": v.template_id,
                    "severity": v.severity,
                    "source": v.source,
                    "confidence": v.confidence,
                    "matched_url": v.matched_url,
                    "description": v.description,
                    "notes": v.notes,
                    "evidence_json": v.evidence_json,
                }
                for v in latest_scan.vulnerabilities
            ],
            "javascript_assets": [
                {
                    "id": asset.id,
                    "url": asset.url,
                    "normalized_url": asset.normalized_url,
                    "hostname": asset.hostname,
                    "status": asset.status,
                    "secrets_json": asset.secrets_json,
                    "extracted_endpoints": asset.extracted_endpoints,
                }
                for asset in latest_scan.javascript_assets
            ],
            "attack_paths": [
                {
                    "id": attack_path.id,
                    "title": attack_path.title,
                    "summary": attack_path.summary,
                    "severity": attack_path.severity,
                    "score": attack_path.score,
                    "steps_json": attack_path.steps_json,
                    "evidence_json": attack_path.evidence_json,
                }
                for attack_path in latest_scan.attack_paths
            ],
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    # Generate PDF using the comprehensive generator
    pdf_generator = PDFReportGenerator()
    pdf_content = pdf_generator.generate_report(report_data)

    log_audit_event(
        db,
        action="report_downloaded",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"target_id": target_id, "format": "pdf"},
    )

    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={target.domain}_report.pdf"
        },
    )

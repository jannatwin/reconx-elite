"""API endpoints for exploit validation functionality."""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Dict, Any, List

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.models.exploit_validation import ExploitValidation
from app.services.exploit_validator import validator
from app.tasks.validation_tasks import send_manual_request_task, validate_vulnerability_task

router = APIRouter(prefix="/validation", tags=["exploit-validation"])


@router.post("/vulnerability/{vulnerability_id}")
async def validate_vulnerability(
    vulnerability_id: int,
    payload: str = None,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Validate a vulnerability by replaying the request with payload."""
    
    # Get vulnerability
    vulnerability = db.query(Vulnerability).filter(
        Vulnerability.id == vulnerability_id
    ).first()
    
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    # Check if user owns the scan
    if vulnerability.scan.target.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Queue validation task
    background_tasks.add_task(
        validate_vulnerability_task,
        vulnerability_id,
        payload
    )
    
    return {"message": "Validation task queued", "vulnerability_id": vulnerability_id}


@router.get("/vulnerability/{vulnerability_id}/results")
async def get_validation_results(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get validation results for a vulnerability."""
    
    # Get vulnerability
    vulnerability = db.query(Vulnerability).filter(
        Vulnerability.id == vulnerability_id
    ).first()
    
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    # Check if user owns the scan
    if vulnerability.scan.target.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get validation results
    validations = db.query(ExploitValidation).filter(
        ExploitValidation.vulnerability_id == vulnerability_id
    ).order_by(ExploitValidation.created_at.desc()).all()
    
    return {
        "vulnerability_id": vulnerability_id,
        "validations": [
            {
                "id": v.id,
                "validation_status": v.validation_status,
                "confidence_score": v.confidence_score,
                "method": v.method,
                "url": v.url,
                "status_code": v.status_code,
                "response_time_ms": v.response_time_ms,
                "detection_markers": v.detection_markers,
                "vulnerability_type": v.vulnerability_type,
                "confirmation_evidence": v.confirmation_evidence,
                "created_at": v.created_at,
                "validation_attempts": v.validation_attempts,
            }
            for v in validations
        ]
    }


@router.post("/manual-request")
async def send_manual_request(
    request_data: Dict[str, Any],
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Send a manual HTTP request for testing."""
    
    background_tasks.add_task(
        send_manual_request_task,
        current_user.id,
        request_data,
    )
    
    return {"message": "Manual request task queued"}


@router.get("/results/{validation_id}/full")
async def get_full_validation_details(
    validation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get full validation details including request/response."""
    
    # Get validation
    validation = db.query(ExploitValidation).filter(
        ExploitValidation.id == validation_id
    ).first()
    
    if not validation:
        raise HTTPException(status_code=404, detail="Validation not found")
    
    # Check if user owns the vulnerability
    if validation.vulnerability.scan.target.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return {
        "id": validation.id,
        "vulnerability_id": validation.vulnerability_id,
        "validation_status": validation.validation_status,
        "confidence_score": validation.confidence_score,
        "method": validation.method,
        "url": validation.url,
        "headers": validation.headers,
        "payload": validation.payload,
        "full_request": validation.full_request,
        "status_code": validation.status_code,
        "response_headers": validation.response_headers,
        "response_body": validation.response_body,
        "response_time_ms": validation.response_time_ms,
        "detection_markers": validation.detection_markers,
        "vulnerability_type": validation.vulnerability_type,
        "confirmation_evidence": validation.confirmation_evidence,
        "validation_attempts": validation.validation_attempts,
        "created_at": validation.created_at,
        "updated_at": validation.updated_at,
    }

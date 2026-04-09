"""API endpoints for manual testing and request replay."""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import Dict, List, Optional

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.manual_test_log import ManualTestLog
from app.models.user import User
from app.services.manual_tester import manual_tester
from app.tasks.testing_tasks import manual_request_task, payload_testing_task

router = APIRouter(prefix="/testing", tags=["manual-testing"])


def _log_manual_test(
    db: Session,
    *,
    user_id: int,
    event_type: str,
    method: Optional[str] = None,
    url: Optional[str] = None,
    vulnerability_id: Optional[int] = None,
    success: bool = False,
    status_code: Optional[int] = None,
    summary_json: Optional[dict] = None,
) -> None:
    db.add(
        ManualTestLog(
            user_id=user_id,
            event_type=event_type,
            method=method,
            url=url,
            vulnerability_id=vulnerability_id,
            success=success,
            status_code=status_code,
            summary_json=summary_json,
        )
    )
    db.commit()


class CustomRequest(BaseModel):
    """Model for custom HTTP request."""
    method: str = Field(..., description="HTTP method (GET, POST, PUT, etc.)")
    url: str = Field(..., description="Target URL")
    headers: Optional[Dict[str, str]] = Field(None, description="Custom headers")
    body: Optional[str] = Field(None, description="Request body")
    params: Optional[Dict[str, str]] = Field(None, description="Query parameters")


class PayloadTestRequest(BaseModel):
    """Model for payload testing request."""
    base_request: CustomRequest = Field(..., description="Base request to modify")
    payload_type: str = Field(..., description="Type of payloads to test")
    target_param: Optional[str] = Field(None, description="Parameter to inject into")


@router.post("/request")
async def send_custom_request(
    request: CustomRequest,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Send a custom HTTP request for manual testing."""
    
    # Queue request task
    background_tasks.add_task(
        manual_request_task,
        current_user.id,
        request.dict()
    )
    
    return {"message": "Manual request task queued"}


@router.post("/request/sync")
async def send_custom_request_sync(
    request: CustomRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Send a custom HTTP request synchronously."""
    
    result = await manual_tester.send_custom_request(**request.dict())
    ok = bool(result.get("success", False))
    _log_manual_test(
        db,
        user_id=current_user.id,
        event_type="request_sync",
        method=request.method,
        url=request.url,
        success=ok,
        status_code=result.get("status_code"),
        summary_json={"response_time_ms": result.get("response_time_ms")},
    )
    return {
        "success": ok,
        "request_id": f"manual_{current_user.id}_{hash(request.url)}",
        "result": result,
    }


@router.post("/payloads")
async def test_payloads(
    request: PayloadTestRequest,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Test multiple payload variations."""
    
    # Validate payload type
    available_types = manual_tester.get_payload_templates()
    if request.payload_type not in available_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid payload type. Available: {list(available_types.keys())}"
        )
    
    # Queue testing task
    background_tasks.add_task(
        payload_testing_task,
        current_user.id,
        request.dict()
    )
    
    return {"message": "Payload testing task queued"}


@router.post("/payloads/sync")
async def test_payloads_sync(
    request: PayloadTestRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Test multiple payload variations synchronously."""
    
    # Validate payload type
    available_types = manual_tester.get_payload_templates()
    if request.payload_type not in available_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid payload type. Available: {list(available_types.keys())}"
        )
    
    results = await manual_tester.test_payload_variations(
        request.base_request.dict(),
        request.payload_type,
        request.target_param
    )
    detections = sum(1 for r in results if r.get("payload_detected", False))
    _log_manual_test(
        db,
        user_id=current_user.id,
        event_type="payload_sync",
        method=request.base_request.method,
        url=request.base_request.url,
        success=detections > 0,
        summary_json={
            "payload_type": request.payload_type,
            "total_tests": len(results),
            "detections": detections,
        },
    )
    return {
        "success": True,
        "payload_type": request.payload_type,
        "results": results,
        "total_tests": len(results),
    }


@router.get("/payloads/templates")
async def get_payload_templates(
    current_user: User = Depends(get_current_user)
):
    """Get available payload templates."""
    
    templates = manual_tester.get_payload_templates()
    
    return {
        "payload_types": list(templates.keys()),
        "templates": templates,
    }


@router.post("/payloads/templates")
async def add_custom_template(
    payload_type: str,
    payloads: List[str],
    current_user: User = Depends(get_current_user)
):
    """Add custom payload templates."""
    
    manual_tester.add_custom_template(payload_type, payloads)
    
    return {
        "message": f"Added {len(payloads)} custom payloads for {payload_type}",
        "payload_type": payload_type,
        "payload_count": len(payloads),
    }


@router.post("/replay/{vulnerability_id}")
async def replay_vulnerability_request(
    vulnerability_id: int,
    payload: Optional[str] = None,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Replay a vulnerability request with optional payload modification."""
    
    # Get vulnerability
    from app.models.vulnerability import Vulnerability
    vulnerability = db.query(Vulnerability).filter(
        Vulnerability.id == vulnerability_id
    ).first()
    
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    # Check if user owns the scan
    if vulnerability.scan.target.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Build base request from vulnerability
    base_request = {
        "method": "GET",  # Default, could be extracted from vulnerability
        "url": vulnerability.matched_url or "",
        "headers": {},
        "body": None,
        "params": {},
    }
    
    # Add payload if provided
    if payload:
        base_request["params"]["test"] = payload
    
    # Queue replay task
    background_tasks.add_task(
        manual_request_task,
        current_user.id,
        base_request,
        vulnerability_id
    )
    
    return {
        "message": "Vulnerability replay task queued",
        "vulnerability_id": vulnerability_id,
        "url": base_request["url"],
    }


@router.get("/history")
async def get_testing_history(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get manual testing history for the user."""
    
    rows = (
        db.query(ManualTestLog)
        .filter(ManualTestLog.user_id == current_user.id)
        .order_by(ManualTestLog.created_at.desc())
        .limit(min(limit, 200))
        .all()
    )
    return {
        "user_id": current_user.id,
        "history": [
            {
                "id": r.id,
                "event_type": r.event_type,
                "method": r.method,
                "url": r.url,
                "vulnerability_id": r.vulnerability_id,
                "success": r.success,
                "status_code": r.status_code,
                "summary_json": r.summary_json,
                "created_at": r.created_at,
            }
            for r in rows
        ],
        "total_tests": len(rows),
    }


@router.post("/compare")
async def compare_responses(
    request1: CustomRequest,
    request2: CustomRequest,
    current_user: User = Depends(get_current_user)
):
    """Send two requests and compare their responses."""
    
    # Send both requests
    result1 = await manual_tester.send_custom_request(**request1.dict())
    result2 = await manual_tester.send_custom_request(**request2.dict())
    
    # Compare responses
    comparison = {
        "status_codes_different": result1.get("status_code") != result2.get("status_code"),
        "response_time_diff_ms": abs(result1.get("response_time_ms", 0) - result2.get("response_time_ms", 0)),
        "response_size_diff": abs(result1.get("response_size", 0) - result2.get("response_size", 0)),
        "headers_different": result1.get("response_headers", {}) != result2.get("response_headers", {}),
    }
    
    # Check for body differences
    body1 = result1.get("response_body", "")
    body2 = result2.get("response_body", "")
    comparison["body_different"] = body1 != body2
    comparison["body_similarity"] = len(set(body1.split()) & set(body2.split())) / max(len(set(body1.split())), len(set(body2.split()))) if body1 and body2 else 0
    
    return {
        "request1": {
            "method": request1.method,
            "url": request1.url,
            "status_code": result1.get("status_code"),
            "response_time_ms": result1.get("response_time_ms"),
        },
        "request2": {
            "method": request2.method,
            "url": request2.url,
            "status_code": result2.get("status_code"),
            "response_time_ms": result2.get("response_time_ms"),
        },
        "comparison": comparison,
    }

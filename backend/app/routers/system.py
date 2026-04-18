"""API endpoints for system validation and health monitoring."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Optional

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user, require_admin
from app.models.user import User
from app.services.system_validator import system_validator

from app.services.ai_service import verify_all_models, get_model_status_snapshot

router = APIRouter(prefix="/system", tags=["system-validation"])


@router.get("/verify-models")
@router.post("/verify-models")
async def verify_ai_models(current_user: User = Depends(require_admin)):
    """Verify all 10 models in the AI roster."""
    results = await verify_all_models()
    return results


@router.get("/model-status")
async def get_model_status(current_user: User = Depends(get_current_user)):
    """Get the status of the AI model roster."""
    return get_model_status_snapshot()


@router.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "service": "ReconX Elite API",
    }


@router.get("/validation")
async def get_system_validation(
    component: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get system validation results."""

    if component:
        # Validate specific component
        result = await system_validator.validate_specific_component(component)
        return {"component": component, "validation": result}
    else:
        # Run full validation
        result = await system_validator.run_full_validation()
        return result


@router.get("/validation/admin")
async def get_admin_system_validation(
    component: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Admin-only system validation with detailed information."""

    if component:
        # Validate specific component
        result = await system_validator.validate_specific_component(component)
        return {"component": component, "validation": result, "admin_access": True}
    else:
        # Run full validation
        result = await system_validator.run_full_validation()
        return {"validation": result, "admin_access": True}


@router.get("/status")
async def get_system_status(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Get current system status overview."""

    try:
        # Quick status check without full validation
        from app.core.config import settings

        status = {
            "api_status": "healthy",
            "database_status": "healthy",
            "ai_status": "configured" if settings.gemini_api_key else "disabled",
            "features": {
                "ai_reports": bool(settings.gemini_api_key),
                "exploit_validation": True,
                "out_of_band": True,
                "manual_testing": True,
                "intelligence_learning": True,
                "custom_templates": True,
            },
            "user_id": current_user.id,
            "timestamp": "2025-01-01T00:00:00Z",
        }

        return status

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")


@router.get("/logs")
async def get_system_logs(
    level: str = "info",
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Get system logs (admin only)."""

    try:
        import os
        from pathlib import Path

        log_file = Path("logs/reconx.log")

        if not log_file.exists():
            return {"logs": [], "message": "No log file found"}

        # Read last N lines from log file
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            recent_lines = lines[-limit:] if len(lines) > limit else lines

        # Filter by level if specified
        if level.lower() != "all":
            recent_lines = [
                line for line in recent_lines if level.lower() in line.lower()
            ]

        return {
            "logs": recent_lines,
            "level": level,
            "total_lines": len(recent_lines),
            "log_file": str(log_file),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read logs: {str(e)}")


@router.post("/test-ai")
async def test_ai_service(
    db: Session = Depends(get_db), current_user: User = Depends(require_admin)
):
    """Test AI service functionality (admin only)."""

    try:
        from app.services.ai_service import (
            _check_rate_limit,
            _is_ai_enabled,
            analyze_scan_data,
        )
        from app.core.config import settings

        # Test rate limiting
        rate_limit_ok = _check_rate_limit()

        # Comprehensive AI configuration check
        config = {
            "legacy_gemini_api_key": bool(settings.gemini_api_key),
            "openrouter_api_key": bool(settings.openrouter_api_key),
            "openrouter_api_key_secondary": bool(settings.openrouter_api_key_secondary),
            "openrouter_api_key_tertiary": bool(settings.openrouter_api_key_tertiary),
            "tiers": {
                "scan": {
                    "provider": settings.ai_scan_provider,
                    "model": settings.ai_scan_model,
                    "enabled": _is_ai_enabled(task="scan"),
                },
                "analyze": {
                    "provider": settings.ai_analyze_provider,
                    "model": settings.ai_analyze_model,
                    "enabled": _is_ai_enabled(task="analyze"),
                },
                "report": {
                    "provider": settings.ai_report_provider,
                    "model": settings.ai_report_model,
                    "enabled": _is_ai_enabled(task="report"),
                },
            },
        }

        # Perform a lightweight test request if scanning is enabled
        live_test = {}
        if config["tiers"]["scan"]["enabled"]:
            try:
                # Use analyze_scan_data for a real test call
                test_result = await analyze_scan_data(
                    "system_test", "test.example.com", task="scan"
                )
                live_test = {
                    "success": "error" not in test_result,
                    "result_keys": list(test_result.keys()),
                    "error": test_result.get("error"),
                }
            except Exception as e:
                live_test = {"success": False, "error": str(e)}

        return {
            "rate_limit_ok": rate_limit_ok,
            "config": config,
            "live_test": live_test,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI service test failed: {str(e)}")


@router.get("/metrics")
async def get_system_metrics(
    db: Session = Depends(get_db), current_user: User = Depends(require_admin)
):
    """Get system metrics (admin only)."""

    try:
        from app.models import User, Target, Scan, Vulnerability

        # Get basic metrics
        metrics = {
            "users": db.query(User).count(),
            "targets": db.query(Target).count(),
            "scans": db.query(Scan).count(),
            "vulnerabilities": db.query(Vulnerability).count(),
            "scan_status_breakdown": {},
            "vulnerability_severity_breakdown": {},
        }

        # Scan status breakdown
        from sqlalchemy import func

        scan_statuses = (
            db.query(Scan.status, func.count(Scan.id)).group_by(Scan.status).all()
        )
        metrics["scan_status_breakdown"] = {
            status: count for status, count in scan_statuses
        }

        # Vulnerability severity breakdown
        vuln_severities = (
            db.query(Vulnerability.severity, func.count(Vulnerability.id))
            .group_by(Vulnerability.severity)
            .all()
        )
        metrics["vulnerability_severity_breakdown"] = {
            severity: count for severity, count in vuln_severities
        }

        return metrics

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get metrics: {str(e)}")

"""API endpoints for intelligence learning system."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, List, Optional

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.models.exploit_validation import ExploitValidation
from app.services.intelligence_learning import learning_service

router = APIRouter(prefix="/intelligence", tags=["intelligence-learning"])


@router.get("/insights")
async def get_learning_insights(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Get comprehensive learning insights for the current user."""

    insights = learning_service.get_learning_insights(db, current_user.id)

    return {
        "user_id": current_user.id,
        "insights": insights,
    }


@router.get("/similar-findings/{vulnerability_id}")
async def get_similar_findings(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get similar past findings for a specific vulnerability."""

    # Get vulnerability
    vulnerability = (
        db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    )

    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Check if user owns the scan
    if vulnerability.scan.target.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Get similar findings
    similar_findings = learning_service.get_similar_findings(
        db, current_user.id, vulnerability
    )

    return {
        "vulnerability_id": vulnerability_id,
        "similar_findings": similar_findings,
    }


@router.get("/patterns")
async def get_learning_patterns(
    pattern_type: Optional[str] = None,
    vulnerability_type: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get learning patterns for the current user."""

    from app.models.learning_models import LearningPattern

    query = db.query(LearningPattern).filter(LearningPattern.user_id == current_user.id)

    if pattern_type:
        query = query.filter(LearningPattern.pattern_type == pattern_type)

    if vulnerability_type:
        query = query.filter(LearningPattern.vulnerability_type == vulnerability_type)

    patterns = (
        query.order_by(LearningPattern.confidence_score.desc()).limit(limit).all()
    )

    return {
        "patterns": [
            {
                "id": p.id,
                "pattern_type": p.pattern_type,
                "vulnerability_type": p.vulnerability_type,
                "pattern_value": p.pattern_value,
                "confidence_score": p.confidence_score,
                "success_count": p.success_count,
                "failure_count": p.failure_count,
                "target_domain": p.target_domain,
                "discovery_method": p.discovery_method,
                "last_seen": p.last_seen,
                "created_at": p.created_at,
            }
            for p in patterns
        ]
    }


@router.get("/payloads")
async def get_successful_payloads(
    vulnerability_type: Optional[str] = None,
    min_success_rate: int = 50,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get successful payloads for the current user."""

    from app.models.learning_models import SuccessfulPayload

    query = db.query(SuccessfulPayload).filter(
        SuccessfulPayload.user_id == current_user.id,
        SuccessfulPayload.success_rate >= min_success_rate,
    )

    if vulnerability_type:
        query = query.filter(SuccessfulPayload.vulnerability_type == vulnerability_type)

    payloads = query.order_by(SuccessfulPayload.success_rate.desc()).limit(limit).all()

    return {
        "payloads": [
            {
                "id": p.id,
                "payload": p.payload,
                "vulnerability_type": p.vulnerability_type,
                "context": p.context,
                "success_rate": p.success_rate,
                "usage_count": p.usage_count,
                "confirmed_vulnerabilities": p.confirmed_vulnerabilities,
                "target_patterns": p.target_patterns,
                "technology_requirements": p.technology_requirements,
                "first_discovered": p.first_discovered,
                "last_used": p.last_used,
            }
            for p in payloads
        ]
    }


@router.get("/high-value-endpoints")
async def get_high_value_endpoints(
    endpoint_type: Optional[str] = None,
    min_priority: int = 50,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get high-value endpoints for the current user."""

    from app.models.learning_models import HighValueEndpoint

    query = db.query(HighValueEndpoint).filter(
        HighValueEndpoint.user_id == current_user.id,
        HighValueEndpoint.priority_score >= min_priority,
    )

    if endpoint_type:
        query = query.filter(HighValueEndpoint.endpoint_type == endpoint_type)

    endpoints = (
        query.order_by(HighValueEndpoint.priority_score.desc()).limit(limit).all()
    )

    return {
        "endpoints": [
            {
                "id": e.id,
                "endpoint_pattern": e.endpoint_pattern,
                "endpoint_type": e.endpoint_type,
                "priority_score": e.priority_score,
                "vulnerabilities_found": e.vulnerabilities_found,
                "critical_vulnerabilities": e.critical_vulnerabilities,
                "confirmation_rate": e.confirmation_rate,
                "common_technologies": e.common_technologies,
                "discovery_methods": e.discovery_methods,
                "last_discovery": e.last_discovery,
                "created_at": e.created_at,
            }
            for e in endpoints
        ]
    }


@router.post("/learn-from-vulnerability/{vulnerability_id}")
async def learn_from_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Trigger learning from a specific vulnerability."""

    # Get vulnerability
    vulnerability = (
        db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    )

    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Check if user owns the scan
    if vulnerability.scan.target.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Get validation if exists
    validation = (
        db.query(ExploitValidation)
        .filter(ExploitValidation.vulnerability_id == vulnerability_id)
        .first()
    )

    # Perform learning
    learning_results = learning_service.learn_from_vulnerability(
        db, current_user.id, vulnerability, validation
    )

    return {
        "vulnerability_id": vulnerability_id,
        "learning_results": learning_results,
        "message": "Learning completed successfully",
    }


@router.get("/statistics")
async def get_learning_statistics(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Get learning statistics for the current user."""

    from app.models.learning_models import (
        LearningPattern,
        SuccessfulPayload,
        HighValueEndpoint,
    )

    # Pattern statistics
    total_patterns = (
        db.query(LearningPattern)
        .filter(LearningPattern.user_id == current_user.id)
        .count()
    )

    high_confidence_patterns = (
        db.query(LearningPattern)
        .filter(
            LearningPattern.user_id == current_user.id,
            LearningPattern.confidence_score >= 80,
        )
        .count()
    )

    # Payload statistics
    total_payloads = (
        db.query(SuccessfulPayload)
        .filter(SuccessfulPayload.user_id == current_user.id)
        .count()
    )

    high_success_payloads = (
        db.query(SuccessfulPayload)
        .filter(
            SuccessfulPayload.user_id == current_user.id,
            SuccessfulPayload.success_rate >= 80,
        )
        .count()
    )

    # Endpoint statistics
    total_endpoints = (
        db.query(HighValueEndpoint)
        .filter(HighValueEndpoint.user_id == current_user.id)
        .count()
    )

    high_priority_endpoints = (
        db.query(HighValueEndpoint)
        .filter(
            HighValueEndpoint.user_id == current_user.id,
            HighValueEndpoint.priority_score >= 80,
        )
        .count()
    )

    return {
        "user_id": current_user.id,
        "patterns": {
            "total": total_patterns,
            "high_confidence": high_confidence_patterns,
            "confidence_rate": (
                (high_confidence_patterns / total_patterns * 100)
                if total_patterns > 0
                else 0
            ),
        },
        "payloads": {
            "total": total_payloads,
            "high_success": high_success_payloads,
            "success_rate": (
                (high_success_payloads / total_payloads * 100)
                if total_payloads > 0
                else 0
            ),
        },
        "endpoints": {
            "total": total_endpoints,
            "high_priority": high_priority_endpoints,
            "priority_rate": (
                (high_priority_endpoints / total_endpoints * 100)
                if total_endpoints > 0
                else 0
            ),
        },
    }


@router.delete("/patterns/{pattern_id}")
async def delete_learning_pattern(
    pattern_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a learning pattern."""

    from app.models.learning_models import LearningPattern

    pattern = (
        db.query(LearningPattern)
        .filter(
            LearningPattern.id == pattern_id, LearningPattern.user_id == current_user.id
        )
        .first()
    )

    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")

    db.delete(pattern)
    db.commit()

    return {"message": "Pattern deleted successfully"}


@router.delete("/payloads/{payload_id}")
async def delete_successful_payload(
    payload_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a successful payload."""

    from app.models.learning_models import SuccessfulPayload

    payload = (
        db.query(SuccessfulPayload)
        .filter(
            SuccessfulPayload.id == payload_id,
            SuccessfulPayload.user_id == current_user.id,
        )
        .first()
    )

    if not payload:
        raise HTTPException(status_code=404, detail="Payload not found")

    db.delete(payload)
    db.commit()

    return {"message": "Payload deleted successfully"}

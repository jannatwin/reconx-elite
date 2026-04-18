"""Celery tasks for exploit validation."""

import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.database import get_sessionmaker
from app.models.vulnerability import Vulnerability
from app.models.exploit_validation import ExploitValidation
from app.services.exploit_validator import validator

logger = logging.getLogger(__name__)


async def validate_vulnerability_task(
    vulnerability_id: int, payload: str = None
) -> dict:
    """Validate a vulnerability by replaying the request with payload."""
    db = get_sessionmaker()()

    try:
        # Get vulnerability
        vulnerability = (
            db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        )

        if not vulnerability:
            logger.error(f"Vulnerability {vulnerability_id} not found")
            return {"error": "Vulnerability not found"}

        # Prepare vulnerability data for validation
        vulnerability_data = {
            "template_id": vulnerability.template_id,
            "matched_url": vulnerability.matched_url,
            "severity": vulnerability.severity,
            "description": vulnerability.description,
            "evidence_json": vulnerability.evidence_json or {},
        }

        # Perform validation
        validation_result = await validator.validate_vulnerability(
            vulnerability_data, payload
        )

        # Create or update validation record
        existing_validation = (
            db.query(ExploitValidation)
            .filter(ExploitValidation.vulnerability_id == vulnerability_id)
            .first()
        )

        if existing_validation:
            # Update existing validation
            existing_validation.validation_status = validation_result.get(
                "validation_status", "unverified"
            )
            existing_validation.confidence_score = validation_result.get(
                "confidence_score", "low"
            )
            existing_validation.method = validation_result.get("method", "GET")
            existing_validation.url = validation_result.get("url", "")
            existing_validation.headers = validation_result.get("headers", "{}")
            existing_validation.payload = validation_result.get("payload", "")
            existing_validation.full_request = validation_result.get("full_request", "")
            existing_validation.status_code = validation_result.get("status_code")
            existing_validation.response_headers = validation_result.get(
                "response_headers", "{}"
            )
            existing_validation.response_body = validation_result.get(
                "response_body", ""
            )
            existing_validation.response_time_ms = validation_result.get(
                "response_time_ms", 0
            )
            existing_validation.detection_markers = validation_result.get(
                "detection_markers", "[]"
            )
            existing_validation.vulnerability_type = validation_result.get(
                "vulnerability_type", "unknown"
            )
            existing_validation.confirmation_evidence = validation_result.get(
                "confirmation_evidence", ""
            )
            existing_validation.validation_attempts += 1
            existing_validation.last_attempt_at = datetime.now(timezone.utc)
        else:
            # Create new validation record
            validation = ExploitValidation(
                vulnerability_id=vulnerability_id,
                validation_status=validation_result.get(
                    "validation_status", "unverified"
                ),
                confidence_score=validation_result.get("confidence_score", "low"),
                method=validation_result.get("method", "GET"),
                url=validation_result.get("url", ""),
                headers=validation_result.get("headers", "{}"),
                payload=validation_result.get("payload", ""),
                full_request=validation_result.get("full_request", ""),
                status_code=validation_result.get("status_code"),
                response_headers=validation_result.get("response_headers", "{}"),
                response_body=validation_result.get("response_body", ""),
                response_time_ms=validation_result.get("response_time_ms", 0),
                detection_markers=validation_result.get("detection_markers", "[]"),
                vulnerability_type=validation_result.get(
                    "vulnerability_type", "unknown"
                ),
                confirmation_evidence=validation_result.get(
                    "confirmation_evidence", ""
                ),
                validation_attempts=1,
            )
            db.add(validation)

        db.commit()

        logger.info(
            f"Validation completed for vulnerability {vulnerability_id}: {validation_result.get('validation_status')}"
        )

        return {
            "vulnerability_id": vulnerability_id,
            "validation_status": validation_result.get("validation_status"),
            "confidence_score": validation_result.get("confidence_score"),
            "validation_id": (
                existing_validation.id if existing_validation else validation.id
            ),
        }

    except Exception as e:
        logger.error(
            f"Validation task failed for vulnerability {vulnerability_id}: {e}"
        )

        # Create failed validation record
        validation = ExploitValidation(
            vulnerability_id=vulnerability_id,
            validation_status="unverified",
            confidence_score="low",
            confirmation_evidence=f"Validation failed: {str(e)}",
            validation_attempts=1,
        )
        db.add(validation)
        db.commit()

        return {"error": str(e), "vulnerability_id": vulnerability_id}

    finally:
        db.close()


async def send_manual_request_task(user_id: int, request_data: dict) -> dict:
    """Send a manual HTTP request for testing."""
    try:
        # Extract request details
        method = request_data.get("method", "GET")
        url = request_data.get("url", "")
        headers = request_data.get("headers", {})
        payload = request_data.get("payload", "")

        # Prepare request data
        if method.upper() in ["POST", "PUT", "PATCH"]:
            data = {"test": payload} if payload else None
        else:
            data = None

        # Send request
        response = await validator._send_request(method, url, headers, data)

        # Analyze response
        validation_result = await validator._analyze_response(
            response, payload, {"template_id": "manual_test"}, 0
        )

        return {
            "user_id": user_id,
            "method": method,
            "url": url,
            "status_code": response.status_code if response else None,
            "response_time_ms": 0,  # Would need timing measurement
            "response_body": response.text[:1000] if response else None,
            "detection_markers": validation_result.get("detection_markers", []),
            "confidence_score": validation_result.get("confidence_score", "low"),
        }

    except Exception as e:
        logger.error(f"Manual request task failed for user {user_id}: {e}")
        return {"error": str(e), "user_id": user_id}

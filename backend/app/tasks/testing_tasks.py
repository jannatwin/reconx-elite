"""Celery tasks for manual testing and request replay."""

import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.database import get_sessionmaker
from app.models.manual_test_log import ManualTestLog
from app.services.manual_tester import manual_tester

logger = logging.getLogger(__name__)


async def manual_request_task(
    user_id: int, request_data: dict, vulnerability_id: int = None
) -> dict:
    """Execute manual HTTP request task."""
    db = get_sessionmaker()()

    try:
        result = await manual_tester.send_custom_request(**request_data)
        ok = bool(result.get("success", False))
        db.add(
            ManualTestLog(
                user_id=user_id,
                event_type="request_async",
                method=request_data.get("method"),
                url=request_data.get("url"),
                vulnerability_id=vulnerability_id,
                success=ok,
                status_code=result.get("status_code"),
                summary_json={"response_time_ms": result.get("response_time_ms")},
            )
        )
        db.commit()
        logger.info(
            f"Manual request completed for user {user_id}: {request_data.get('url')}"
        )

        return {
            "user_id": user_id,
            "success": ok,
            "method": request_data.get("method"),
            "url": request_data.get("url"),
            "status_code": result.get("status_code"),
            "response_time_ms": result.get("response_time_ms"),
            "vulnerability_id": vulnerability_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Manual request task failed for user {user_id}: {e}")
        try:
            db.add(
                ManualTestLog(
                    user_id=user_id,
                    event_type="request_async",
                    method=request_data.get("method"),
                    url=request_data.get("url"),
                    vulnerability_id=vulnerability_id,
                    success=False,
                    summary_json={"error": str(e)},
                )
            )
            db.commit()
        except Exception:
            db.rollback()
        return {
            "user_id": user_id,
            "success": False,
            "error": str(e),
            "url": request_data.get("url"),
        }

    finally:
        db.close()


async def payload_testing_task(user_id: int, test_request: dict) -> dict:
    """Execute payload testing task."""
    db = get_sessionmaker()()

    try:
        base_request = test_request.get("base_request", {})
        payload_type = test_request.get("payload_type")
        target_param = test_request.get("target_param")

        # Run payload testing
        results = await manual_tester.test_payload_variations(
            base_request, payload_type, target_param
        )

        # Count successful detections
        detections = sum(1 for r in results if r.get("payload_detected", False))
        db.add(
            ManualTestLog(
                user_id=user_id,
                event_type="payload_async",
                method=base_request.get("method"),
                url=base_request.get("url"),
                success=detections > 0,
                summary_json={
                    "payload_type": payload_type,
                    "total_tests": len(results),
                    "detections": detections,
                },
            )
        )
        db.commit()
        logger.info(
            f"Payload testing completed for user {user_id}: {payload_type}, {detections}/{len(results)} detections"
        )

        return {
            "user_id": user_id,
            "payload_type": payload_type,
            "total_tests": len(results),
            "detections": detections,
            "results": results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Payload testing task failed for user {user_id}: {e}")
        try:
            db.add(
                ManualTestLog(
                    user_id=user_id,
                    event_type="payload_async",
                    success=False,
                    summary_json={
                        "error": str(e),
                        "payload_type": test_request.get("payload_type"),
                    },
                )
            )
            db.commit()
        except Exception:
            db.rollback()
        return {
            "user_id": user_id,
            "success": False,
            "error": str(e),
            "payload_type": test_request.get("payload_type"),
        }

    finally:
        db.close()

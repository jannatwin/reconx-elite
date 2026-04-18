"""Celery tasks for intelligence learning system."""

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.database import get_sessionmaker
from app.tasks.celery_app import celery_app
from app.models.vulnerability import Vulnerability
from app.models.exploit_validation import ExploitValidation
from app.services.intelligence_learning import learning_service

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.learning_tasks.learn_from_vulnerability_task")
def learn_from_vulnerability_task(user_id: int, vulnerability_id: int) -> dict:
    """Learn from a vulnerability in the background."""
    db = get_sessionmaker()()

    try:
        # Get vulnerability
        vulnerability = (
            db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        )

        if not vulnerability:
            return {
                "error": "Vulnerability not found",
                "vulnerability_id": vulnerability_id,
            }

        # Get validation if exists
        validation = (
            db.query(ExploitValidation)
            .filter(ExploitValidation.vulnerability_id == vulnerability_id)
            .first()
        )

        # Perform learning
        learning_results = learning_service.learn_from_vulnerability(
            db, user_id, vulnerability, validation
        )

        logger.info(f"Learning completed for vulnerability {vulnerability_id}")

        return {
            "user_id": user_id,
            "vulnerability_id": vulnerability_id,
            "learning_results": learning_results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Learning task failed for vulnerability {vulnerability_id}: {e}")
        return {
            "user_id": user_id,
            "vulnerability_id": vulnerability_id,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    finally:
        db.close()


@celery_app.task(name="app.tasks.learning_tasks.update_intelligence_insights_task")
def update_intelligence_insights_task(user_id: int) -> dict:
    """Update intelligence insights for a user."""
    db = get_sessionmaker()()

    try:
        insights = learning_service.get_learning_insights(db, user_id)

        return {
            "user_id": user_id,
            "insights": insights,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Intelligence insights update failed for user {user_id}: {e}")
        return {
            "user_id": user_id,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    finally:
        db.close()

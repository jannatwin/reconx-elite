"""Celery tasks for custom Nuclei template execution."""

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.database import get_sessionmaker
from app.services.custom_template_engine import template_engine

logger = logging.getLogger(__name__)


async def run_custom_template_task(
    user_id: int, template_id: int, target_urls: list
) -> dict:
    """Execute a custom Nuclei template task."""
    db = get_sessionmaker()()

    try:
        # Run template
        success, message, findings = template_engine.run_template(
            db, template_id, target_urls, 0  # scan_id=0 for manual execution
        )

        logger.info(
            f"Custom template {template_id} executed for user {user_id}: {len(findings)} findings"
        )

        return {
            "user_id": user_id,
            "template_id": template_id,
            "success": success,
            "message": message,
            "findings_count": len(findings),
            "findings": findings,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Custom template task failed for user {user_id}: {e}")
        return {
            "user_id": user_id,
            "template_id": template_id,
            "success": False,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    finally:
        db.close()


async def validate_template_task(user_id: int, template_id: int) -> dict:
    """Validate a custom template."""
    db = get_sessionmaker()()

    try:
        from app.models.custom_templates import CustomNucleiTemplate

        template = (
            db.query(CustomNucleiTemplate)
            .filter(
                CustomNucleiTemplate.id == template_id,
                CustomNucleiTemplate.user_id == user_id,
            )
            .first()
        )

        if not template:
            return {"error": "Template not found", "template_id": template_id}

        # Re-validate template
        success, message, _ = template_engine.create_template(
            db,
            user_id,
            template.name,
            template.template_content,
            template.author,
            template.description,
            eval(template.tags) if template.tags else [],
            template.is_public,
        )

        return {
            "template_id": template_id,
            "validation_success": success,
            "validation_message": message,
            "is_valid": template.is_valid,
            "validation_error": template.validation_error,
        }

    except Exception as e:
        logger.error(f"Template validation task failed for template {template_id}: {e}")
        return {"error": str(e), "template_id": template_id}

    finally:
        db.close()

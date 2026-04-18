"""Centralized logging system for ReconX Elite."""

import json
import logging
import logging.handlers
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from app.core.config import settings


class ReconXLogger:
    """Centralized logging system with structured output."""

    def __init__(self):
        self.setup_logging()

    def setup_logging(self):
        """Setup structured logging for the application."""

        # Create logs directory
        log_dir = "/tmp/logs"
        os.makedirs(log_dir, exist_ok=True)

        # Handlers list
        handlers = [
            # Console handler
            logging.StreamHandler(),
            # File handler with rotation
            logging.handlers.RotatingFileHandler(
                os.path.join(log_dir, "reconx.log"),
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5,
            ),
            # Error file handler
            logging.handlers.RotatingFileHandler(
                os.path.join(log_dir, "errors.log"),
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5,
            ),
        ]

        # Set error level for error file handler specifically
        handlers[2].setLevel(logging.ERROR)

        # Configure root logger
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=handlers,
        )

    def log_structured(
        self,
        level: str,
        event: str,
        data: Dict[str, Any],
        user_id: Optional[int] = None,
    ):
        """Log structured event with metadata."""

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "event": event,
            "user_id": user_id,
            "data": data,
        }

        # Get appropriate logger
        logger = logging.getLogger("reconx.structured")

        # Log the structured entry
        log_message = json.dumps(log_entry, default=str)

        if level.lower() == "error":
            logger.error(log_message)
        elif level.lower() == "warning":
            logger.warning(log_message)
        elif level.lower() == "info":
            logger.info(log_message)
        elif level.lower() == "debug":
            logger.debug(log_message)

    def log_security_event(
        self,
        event: str,
        details: Dict[str, Any],
        user_id: Optional[int] = None,
        severity: str = "medium",
    ):
        """Log security-related events."""

        self.log_structured(
            level="warning" if severity in ["high", "critical"] else "info",
            event=f"security_{event}",
            data={
                "severity": severity,
                "details": details,
                "source": "security_monitor",
            },
            user_id=user_id,
        )

    def log_ai_event(
        self, event: str, details: Dict[str, Any], user_id: Optional[int] = None
    ):
        """Log AI-related events."""

        self.log_structured(
            level="info",
            event=f"ai_{event}",
            data={"details": details, "source": "ai_service"},
            user_id=user_id,
        )

    def log_scan_event(
        self,
        event: str,
        scan_id: int,
        details: Dict[str, Any],
        user_id: Optional[int] = None,
    ):
        """Log scan-related events."""

        self.log_structured(
            level="info",
            event=f"scan_{event}",
            data={"scan_id": scan_id, "details": details, "source": "scan_engine"},
            user_id=user_id,
        )

    def log_validation_event(
        self, event: str, details: Dict[str, Any], user_id: Optional[int] = None
    ):
        """Log exploit validation events."""

        self.log_structured(
            level="info",
            event=f"validation_{event}",
            data={"details": details, "source": "exploit_validator"},
            user_id=user_id,
        )

    def log_oob_event(
        self,
        event: str,
        callback_id: str,
        details: Dict[str, Any],
        user_id: Optional[int] = None,
    ):
        """Log out-of-band interaction events."""

        self.log_structured(
            level="info",
            event=f"oob_{event}",
            data={
                "callback_id": callback_id,
                "details": details,
                "source": "oob_service",
            },
            user_id=user_id,
        )


# Global logger instance
reconx_logger = ReconXLogger()

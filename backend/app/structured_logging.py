"""Structured logging configuration for ReconX Elite."""
import json
import logging
import sys
from datetime import datetime
from typing import Any, Dict

try:
    from pythonjsonlogger import jsonlogger
except ImportError:
    jsonlogger = None


class CustomJsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info)
            }
        
        # FIX #12: Properly access extra fields from LogRecord.__dict__
        for key, value in record.__dict__.items():
            # Skip standard LogRecord attributes
            if not key.startswith('_') and key not in {
                'name', 'msg', 'args', 'created', 'filename', 'funcName',
                'levelname', 'levelno', 'lineno', 'module', 'msecs',
                'message', 'pathname', 'process', 'processName', 'relativeCreated',
                'thread', 'threadName', 'exc_info', 'exc_text', 'stack_info',
                'taskName'  # Python 3.12+
            }:
                log_data[key] = value
        
        return json.dumps(log_data)


def setup_structured_logging(app_name: str = "reconx-elite") -> logging.Logger:
    """Configure structured JSON logging for the application."""
    logger = logging.getLogger(app_name)
    logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Console handler with JSON formatting
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    
    if jsonlogger:
        formatter = jsonlogger.JsonFormatter()
    else:
        formatter = CustomJsonFormatter()
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger


class StructuredLogger:
    """Wrapper for structured logging with extra context."""
    
    def __init__(self, logger: logging.Logger):
        """Initialize structured logger."""
        self.logger = logger
    
    def log_event(
        self,
        level: str,
        message: str,
        **kwargs: Any
    ) -> None:
        """Log event with structured data (FIX #12: Proper extra field handling)."""
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        
        # Use logger's built-in extra parameter
        log_method(message, extra=kwargs)
    
    def log_scan_started(
        self,
        session_id: str,
        target: str,
        scan_type: str
    ) -> None:
        """Log scan initialization."""
        self.log_event(
            "info",
            "Scan initiated",
            session_id=session_id,
            target=target,
            scan_type=scan_type,
            event_type="scan_started"
        )
    
    def log_vulnerability_found(
        self,
        session_id: str,
        vuln_id: str,
        vuln_type: str,
        severity: str,
        endpoint: str
    ) -> None:
        """Log vulnerability discovery."""
        self.log_event(
            "warning",
            f"Vulnerability found: {vuln_type}",
            session_id=session_id,
            vulnerability_id=vuln_id,
            vulnerability_type=vuln_type,
            severity=severity,
            endpoint=endpoint,
            event_type="vulnerability_found"
        )
    
    def log_ai_call(
        self,
        session_id: str,
        model: str,
        task: str,
        input_tokens: int,
        output_tokens: int,
        latency_ms: float
    ) -> None:
        """Log AI API call."""
        self.log_event(
            "debug",
            f"AI API call: {model}",
            session_id=session_id,
            model=model,
            task=task,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            event_type="ai_api_call"
        )
    
    def log_error(
        self,
        session_id: str,
        error_type: str,
        error_message: str,
        phase: str = None
    ) -> None:
        """Log error event."""
        self.log_event(
            "error",
            f"Error occurred: {error_type}",
            session_id=session_id,
            error_type=error_type,
            error_message=error_message,
            phase=phase,
            event_type="error"
        )
    
    def log_phase_completed(
        self,
        session_id: str,
        phase: str,
        duration_ms: float,
        findings_count: int
    ) -> None:
        """Log phase completion."""
        self.log_event(
            "info",
            f"Phase completed: {phase}",
            session_id=session_id,
            phase=phase,
            duration_ms=duration_ms,
            findings_count=findings_count,
            event_type="phase_completed"
        )
    
    def log_scan_completed(
        self,
        session_id: str,
        total_findings: int,
        critical_count: int,
        high_count: int,
        duration_seconds: int
    ) -> None:
        """Log scan completion."""
        self.log_event(
            "info",
            "Scan completed",
            session_id=session_id,
            total_findings=total_findings,
            critical_vulnerabilities=critical_count,
            high_vulnerabilities=high_count,
            duration_seconds=duration_seconds,
            event_type="scan_completed"
        )


# Global logger instance
logger: StructuredLogger = None


def get_logger() -> StructuredLogger:
    """Get global logger instance."""
    global logger
    if logger is None:
        base_logger = setup_structured_logging()
        logger = StructuredLogger(base_logger)
    return logger

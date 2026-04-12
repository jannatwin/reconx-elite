"""Structured JSON logging configuration for ReconX Elite.

Installs a pythonjsonlogger JsonFormatter on the root logger and adds a
SensitiveDataFilter that redacts Authorization header values and password
fields from every log record.
"""

import logging
import re

try:
    from pythonjsonlogger import jsonlogger  # type: ignore[import-untyped]
except ModuleNotFoundError:  # pragma: no cover - local fallback
    class _FallbackJsonFormatter(logging.Formatter):
        def __init__(self, *args, **kwargs):  # noqa: D401, ANN002, ANN003
            kwargs.pop("rename_fields", None)
            super().__init__("%(asctime)s %(levelname)s %(name)s %(message)s")

        def add_fields(self, log_record: dict, record: logging.LogRecord, message_dict: dict) -> None:
            log_record.update(message_dict)

    class jsonlogger:  # type: ignore[no-redef]
        JsonFormatter = _FallbackJsonFormatter

# Patterns that identify sensitive fields in log record extras / messages.
_SENSITIVE_PATTERNS = [
    # Authorization header value (e.g. "Bearer <token>")
    re.compile(r"(Authorization\s*[:=]\s*)\S+", re.IGNORECASE),
    # password key/value pairs in JSON-like strings
    re.compile(r'("?password"?\s*[:=]\s*)"[^"]*"', re.IGNORECASE),
    re.compile(r"('?password'?\s*[:=]\s*)'[^']*'", re.IGNORECASE),
]

_REDACTED = "[REDACTED]"


def _redact(value: str) -> str:
    """Replace sensitive values in *value* with [REDACTED]."""
    for pattern in _SENSITIVE_PATTERNS:
        value = pattern.sub(lambda m: m.group(1) + _REDACTED if m.lastindex else _REDACTED, value)
    return value


class SensitiveDataFilter(logging.Filter):
    """Logging filter that redacts Authorization and password values."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        # Redact the formatted message
        record.msg = _redact(str(record.msg))

        # Redact any extra string attributes attached to the record
        for key, val in list(vars(record).items()):
            if isinstance(val, str):
                redacted = _redact(val)
                if redacted != val:
                    setattr(record, key, redacted)

        return True


class _ReconXJsonFormatter(jsonlogger.JsonFormatter):
    """JsonFormatter that renames standard fields to the required names."""

    def add_fields(
        self,
        log_record: dict,
        record: logging.LogRecord,
        message_dict: dict,
    ) -> None:
        super().add_fields(log_record, record, message_dict)
        # Rename to canonical field names expected by the spec
        log_record["timestamp"] = log_record.pop("asctime", None) or self.formatTime(record)
        log_record["level"] = log_record.pop("levelname", record.levelname)
        log_record["logger"] = log_record.pop("name", record.name)
        # "message" is already set by the parent


def configure_logging(level: int = logging.INFO) -> None:
    """Install JSON logging on the root logger.

    Safe to call multiple times — subsequent calls are no-ops if the
    handler is already installed.
    """
    root = logging.getLogger()

    # Avoid adding duplicate handlers on repeated calls (e.g. Celery reload)
    for handler in root.handlers:
        if isinstance(handler, logging.StreamHandler) and isinstance(
            handler.formatter, _ReconXJsonFormatter
        ):
            return

    handler = logging.StreamHandler()
    formatter = _ReconXJsonFormatter(
        fmt="%(timestamp)s %(level)s %(logger)s %(message)s",
        rename_fields={"levelname": "level", "name": "logger"},
    )
    handler.setFormatter(formatter)
    handler.addFilter(SensitiveDataFilter())

    root.setLevel(level)
    root.addHandler(handler)

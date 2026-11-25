import logging
import sys
import json
from datetime import datetime, timezone
from typing import Any, Dict


SENSITIVE_KEYS = {
    "authorization", "x-api-key", "password", "token", "secret",
    "jwt_secret_key", "admin_api_key", "admin_password_hash", "access_token"
}


def mask_sensitive(data: Any) -> Any:
    """Recursively redact sensitive keys from logging dictionaries."""
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if str(k).lower() in SENSITIVE_KEYS:
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = mask_sensitive(v)
        return cleaned
    elif isinstance(data, list):
        return [mask_sensitive(item) for item in data]
    return data


class StructuredJsonFormatter(logging.Formatter):
    """Structured JSON formatter with automated credential redaction."""
    def format(self, record: logging.LogRecord) -> str:
        log_obj: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(mask_sensitive(log_obj))


def setup_logging():
    """Configure structured logging for backend application."""
    root_logger = logging.getLogger("securecode")
    root_logger.setLevel(logging.INFO)

    if not root_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(StructuredJsonFormatter())
        root_logger.addHandler(handler)

    return root_logger


logger = setup_logging()

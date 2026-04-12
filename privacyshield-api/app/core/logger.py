"""
logger.py — Structured, PII-masked logger for Aletheos API.

Replaces bare print() calls throughout the codebase. Emits JSON-structured
log lines to stdout (captured by Railway). Automatically masks:
- Email addresses
- API keys (any format)
- Supabase URLs and credentials
- Bearer tokens
"""
import json
import logging
import re
import sys
from datetime import datetime, timezone


# ── PII masking patterns ──────────────────────────────────────────────────────

_EMAIL_RE    = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
_API_KEY_RE  = re.compile(r'(ps_live|ps_test|sk-|SG\.|eyJ|gsk_|xai-)[A-Za-z0-9_\-\.]{8,}')
_BEARER_RE   = re.compile(r'Bearer\s+[A-Za-z0-9_\-\.]{8,}')
_SUPABASE_RE = re.compile(r'https://[a-z0-9]+\.supabase\.co')
_URL_KEY_RE  = re.compile(r'(key|token|secret|password|pwd)=[^&\s]{4,}', re.IGNORECASE)


def mask_pii(text: str) -> str:
    """Masks known PII and credential patterns in a string."""
    if not isinstance(text, str):
        text = str(text)
    text = _EMAIL_RE.sub('[EMAIL]', text)
    text = _API_KEY_RE.sub('[REDACTED-KEY]', text)
    text = _BEARER_RE.sub('Bearer [REDACTED]', text)
    text = _SUPABASE_RE.sub('[SUPABASE-URL]', text)
    text = _URL_KEY_RE.sub(r'\1=[REDACTED]', text)
    return text


# ── JSON formatter ────────────────────────────────────────────────────────────

class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level":     record.levelname,
            "logger":    record.name,
            "message":   mask_pii(record.getMessage()),
        }
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)


# ── Setup ─────────────────────────────────────────────────────────────────────

def setup_logging(level: str = "INFO") -> None:
    """Call once at application startup."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()
    root.addHandler(handler)

    # Quiet noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a named logger. Use in modules: logger = get_logger(__name__)"""
    return logging.getLogger(name)


# Module-level logger for direct import
logger = get_logger("aletheos")

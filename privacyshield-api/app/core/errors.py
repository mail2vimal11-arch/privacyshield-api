"""
errors.py — Centralised error handling for Aletheos API.

Prevents internal exception details (DB table names, stack traces, connection
strings) from leaking to API callers. All internal errors are logged server-side
and a safe generic message is returned to the caller.
"""
import logging
import traceback
from fastapi import HTTPException

logger = logging.getLogger("aletheos")

def safe_http_error(
    status_code: int,
    public_message: str,
    exception: Exception = None,
    context: str = "",
) -> HTTPException:
    """
    Logs the real exception internally and returns a safe HTTPException.

    Args:
        status_code: HTTP status code to return
        public_message: Safe message shown to the API caller
        exception: The real exception (logged internally, never returned)
        context: Optional context string for the log (e.g. "signup", "dark_web_scan")
    """
    if exception is not None:
        logger.error(
            "[%s] Internal error: %s | %s",
            context or "unknown",
            type(exception).__name__,
            str(exception)[:200],
            exc_info=False,
        )
    return HTTPException(status_code=status_code, detail=public_message)


def db_error(exception: Exception, context: str = "") -> HTTPException:
    """Returns a safe 503 for database errors."""
    return safe_http_error(503, "Service temporarily unavailable. Please try again.", exception, context)


def auth_error(public_message: str = "Authentication failed.") -> HTTPException:
    """Returns a safe 401."""
    return HTTPException(status_code=401, detail=public_message)


def not_found_error(resource: str = "Resource") -> HTTPException:
    """Returns a safe 404."""
    return HTTPException(status_code=404, detail=f"{resource} not found.")


def quota_error() -> HTTPException:
    """Returns a safe 429 for quota exceeded."""
    return HTTPException(
        status_code=429,
        detail="Scan quota exceeded for this billing period. Upgrade your plan to continue."
    )

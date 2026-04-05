"""
helpers.py — Shared utility functions
"""
import secrets
import string
from datetime import datetime, timedelta


def generate_id(prefix: str) -> str:
    """
    Generate a short unique ID with a readable prefix.
    e.g. generate_id("aiscan") → "aiscan_k7x9mq2p"
    """
    random_part = secrets.token_urlsafe(8).lower().replace("-", "").replace("_", "")[:8]
    return f"{prefix}_{random_part}"


def generate_tracking_number(vendor_code: str = "GDPR") -> str:
    """
    Generate a GDPR tracking number.
    e.g. "GDPR-20260404-A3F9"
    """
    date_str = datetime.utcnow().strftime("%Y%m%d")
    suffix = secrets.token_hex(2).upper()
    return f"{vendor_code}-{date_str}-{suffix}"


def calculate_next_scan(frequency: str) -> datetime:
    """
    Calculate the next scan time based on monitoring frequency.
    """
    now = datetime.utcnow()
    if frequency == "daily":
        return now + timedelta(days=1)
    elif frequency == "weekly":
        return now + timedelta(weeks=1)
    elif frequency == "monthly":
        return now + timedelta(days=30)
    else:
        return now + timedelta(weeks=1)


def risk_score_to_level(score: int) -> str:
    """Convert a numeric risk score (0-100) to a label."""
    if score >= 75:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    else:
        return "low"


def sanitize_model_response(text: str, max_length: int = 500) -> str:
    """Truncate model responses for safe storage."""
    if not text:
        return ""
    return text[:max_length] + ("..." if len(text) > max_length else "")

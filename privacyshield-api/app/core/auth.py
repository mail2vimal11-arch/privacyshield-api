"""
auth.py — API key authentication middleware
Every API request must include:  Authorization: Bearer ps_live_xxxxx
"""
import hashlib
import secrets
from datetime import datetime
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.database import supabase
from app.core.config import get_settings
settings = get_settings()
security = HTTPBearer()


def hash_api_key(raw_key: str) -> str:
    """
    SHA-256 hash of the raw API key.
    We store only the hash — never the real key.
    """
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> tuple[str, str]:
    """
    Generate a new API key.
    Returns: (raw_key, key_prefix)
    raw_key  — shown to user once, never stored
    key_prefix — first 20 chars, stored so user can identify the key
    """
    random_part = secrets.token_urlsafe(32)
    raw_key = f"ps_live_{random_part}"
    key_prefix = raw_key[:20]
    return raw_key, key_prefix


async def verify_api_key(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> dict:
    """
    FastAPI dependency — validates the Bearer token on every request.
    Returns the customer record if valid.
    Raises 401 if invalid.
    """
    raw_key = credentials.credentials

    # Validate format
    if not raw_key.startswith("ps_live_") and not raw_key.startswith("ps_test_"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format. Keys must start with 'ps_live_' or 'ps_test_'"
        )

    # Hash it and look up in database
    key_hash = hash_api_key(raw_key)

    try:
        result = supabase.table("api_keys").select(
            "*, customers(*)"
        ).eq("key_hash", key_hash).eq("is_active", True).execute()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable"
        )

    if not result.data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key"
        )

    key_record = result.data[0]

    # Check expiry
    if key_record.get("expires_at"):
        expires_at = datetime.fromisoformat(key_record["expires_at"].replace("Z", "+00:00"))
        if expires_at < datetime.utcnow().replace(tzinfo=expires_at.tzinfo):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired"
            )

    # Update last_used_at (fire and forget — don't block the request)
    try:
        supabase.table("api_keys").update(
            {"last_used_at": datetime.utcnow().isoformat()}
        ).eq("id", key_record["id"]).execute()
    except Exception:
        pass  # Non-critical

    customer = key_record["customers"]
    return customer


async def check_quota(customer: dict, event_type: str) -> None:
    """
    Check if customer has scan quota remaining.
    Raises 429 if over limit.
    """
    if customer["plan"] == "enterprise":
        return  # Unlimited

    if customer["monthly_scans_used"] >= customer["monthly_scan_quota"]:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Monthly scan quota reached ({customer['monthly_scan_quota']} scans). "
                f"Upgrade your plan at {settings.app_url}/billing"
            )
        )


async def increment_usage(customer_id: str, event_type: str, resource_id: str = None) -> None:
    """
    Record a usage event and increment the customer's scan counter.
    """
    try:
        # Log usage event
        supabase.table("usage_events").insert({
            "customer_id": customer_id,
            "event_type": event_type,
            "resource_id": resource_id,
            "units_consumed": 1
        }).execute()

        # Increment counter
        supabase.rpc("increment_scan_count", {"customer_id": customer_id}).execute()
    except Exception as e:
        print(f"[WARNING] Failed to record usage: {e}")

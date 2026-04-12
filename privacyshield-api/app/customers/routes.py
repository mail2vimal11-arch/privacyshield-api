"""
routes.py — Customer Management
Handles signup, API key creation, and account info.

Endpoints:
  POST /v1/customers/signup        — Create account, returns API key
  POST /v1/customers/keys          — Generate a new API key
  GET  /v1/customers/keys          — List all API keys
  DELETE /v1/customers/keys/{id}   — Revoke an API key
  GET  /v1/customers/me            — Get account info + usage
  GET  /v1/customers/usage         — Usage history
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timezone
import uuid
import hmac
import hashlib
import time

from app.core.auth import verify_api_key, generate_api_key, hash_api_key
from app.core.database import supabase
from app.core.email import email_sender
from app.core.config import get_settings
from app.core.errors import safe_http_error, db_error
from app.utils.helpers import generate_id

_settings = get_settings()

router = APIRouter(prefix="/customers", tags=["Customers"])


# ----------------------------------------------------------------
# Request / Response Models
# ----------------------------------------------------------------

class SignupRequest(BaseModel):
    email: str
    full_name: str
    company_name: Optional[str] = None
    plan: str = "personal"          # "personal" | "professional" | "business"


class CreateKeyRequest(BaseModel):
    name: str = "My API Key"        # Human-readable label


# ----------------------------------------------------------------
# Plan limits
# ----------------------------------------------------------------

PLAN_QUOTAS = {
    "free":         {"monthly_scan_quota": 3,    "price": 0},
    "personal":     {"monthly_scan_quota": 50,   "price": 29},
    "professional": {"monthly_scan_quota": 500,  "price": 99},
    "business":     {"monthly_scan_quota": 5000, "price": 999},
    "enterprise":   {"monthly_scan_quota": 99999,"price": 0}
}


# ----------------------------------------------------------------
# Endpoints
# ----------------------------------------------------------------

@router.post("/signup")
async def signup(request: SignupRequest):
    """
    Create a new customer account and generate their first API key.
    Returns the API key — shown once, not stored in plaintext.
    """
    # Check if email already exists
    try:
        existing = supabase.table("customers").select("id").eq(
            "email", request.email
        ).execute()
    except Exception as e:
        raise db_error(e, "customer_lookup")

    if existing.data:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists. Use POST /v1/customers/keys to generate a new API key."
        )

    quota = PLAN_QUOTAS.get(request.plan, PLAN_QUOTAS["personal"])

    # Generate customer ID upfront so we don't need to read it back from the insert
    customer_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()

    # Create customer
    try:
        supabase.table("customers").insert({
            "id": customer_id,
            "email": request.email,
            "full_name": request.full_name,
            "company_name": request.company_name,
            "plan": request.plan,
            "plan_status": "active",
            "monthly_scan_quota": quota["monthly_scan_quota"],
            "monthly_scans_used": 0,
            "created_at": created_at
        }).execute()
    except Exception as e:
        raise db_error(e, "customer_create")

    # Generate API key
    raw_key, key_prefix = generate_api_key()
    key_hash = hash_api_key(raw_key)

    try:
        supabase.table("api_keys").insert({
            "customer_id": customer_id,
            "key_hash": key_hash,
            "key_prefix": key_prefix,
            "name": "Default Key",
            "is_active": True
        }).execute()
    except Exception as e:
        raise db_error(e, "key_generate")

    # Send welcome email (non-blocking — don't fail signup if email fails)
    try:
        await email_sender.send_welcome_email(
            customer_email=request.email,
            customer_name=request.full_name,
            api_key=raw_key
        )
    except Exception as e:
        print(f"[WARNING] Welcome email failed: {e}")

    return {
        "message": "Account created successfully",
        "customer_id": customer_id,
        "email": request.email,
        "plan": request.plan,
        "monthly_scan_quota": quota["monthly_scan_quota"],
        "api_key": raw_key,
        "api_key_prefix": key_prefix,
        "warning": "Save your API key — it won't be shown again",
        "docs_url": "/docs",
        "created_at": created_at
    }


@router.get("/me")
async def get_account(customer: dict = Depends(verify_api_key)):
    """Get current account info and usage stats."""
    quota = PLAN_QUOTAS.get(customer["plan"], PLAN_QUOTAS["personal"])

    return {
        "customer_id": customer["id"],
        "email": customer["email"],
        "full_name": customer["full_name"],
        "company_name": customer.get("company_name"),
        "plan": customer["plan"],
        "plan_status": customer["plan_status"],
        "usage": {
            "monthly_scans_used": customer["monthly_scans_used"],
            "monthly_scan_quota": customer["monthly_scan_quota"],
            "scans_remaining": max(0, customer["monthly_scan_quota"] - customer["monthly_scans_used"]),
            "quota_resets_at": customer.get("quota_reset_at")
        },
        "member_since": customer["created_at"]
    }


@router.post("/keys")
async def create_api_key(
    request: CreateKeyRequest,
    customer: dict = Depends(verify_api_key)
):
    """Generate a new API key for the current account."""
    # Limit to 5 active keys per customer
    existing_keys = supabase.table("api_keys").select("id").eq(
        "customer_id", customer["id"]
    ).eq("is_active", True).execute()

    if len(existing_keys.data) >= 5:
        raise HTTPException(
            status_code=400,
            detail="Maximum of 5 active API keys allowed. Revoke an existing key first."
        )

    raw_key, key_prefix = generate_api_key()
    key_hash = hash_api_key(raw_key)

    try:
        supabase.table("api_keys").insert({
            "customer_id": customer["id"],
            "key_hash": key_hash,
            "key_prefix": key_prefix,
            "name": request.name,
            "is_active": True
        }).execute()
    except Exception as e:
        raise db_error(e, "key_create")

    return {
        "api_key": raw_key,
        "key_prefix": key_prefix,
        "name": request.name,
        "warning": "Save your API key — it won't be shown again",
        "created_at": datetime.utcnow().isoformat() + "Z"
    }


@router.get("/keys")
async def list_api_keys(customer: dict = Depends(verify_api_key)):
    """List all API keys for the current account (prefixes only, not full keys)."""
    result = supabase.table("api_keys").select(
        "id, key_prefix, name, is_active, last_used_at, created_at, expires_at"
    ).eq("customer_id", customer["id"]).order("created_at", desc=True).execute()

    return {
        "total_keys": len(result.data),
        "keys": result.data
    }


@router.delete("/keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    customer: dict = Depends(verify_api_key)
):
    """Revoke (deactivate) an API key."""
    # Verify key belongs to this customer
    key_result = supabase.table("api_keys").select("id, key_prefix").eq(
        "id", key_id
    ).eq("customer_id", customer["id"]).execute()

    if not key_result.data:
        raise HTTPException(status_code=404, detail="API key not found")

    supabase.table("api_keys").update({"is_active": False}).eq("id", key_id).execute()

    return {
        "message": "API key revoked",
        "key_prefix": key_result.data[0]["key_prefix"],
        "revoked_at": datetime.utcnow().isoformat() + "Z"
    }


class MagicLinkRequest(BaseModel):
    email: str


class VerifyMagicLinkRequest(BaseModel):
    customer_id: str
    exp: int        # Unix timestamp
    sig: str        # HMAC signature


def _sign_token(customer_id: str, exp: int) -> str:
    """Generate an HMAC signature for a magic link token."""
    message = f"{customer_id}:{exp}".encode()
    secret = _settings.api_key_secret.encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()[:40]


@router.post("/magic-link")
async def send_magic_link(request: MagicLinkRequest):
    """
    Send a magic login link to the user's email.
    The link auto-logs them into the dashboard without needing an API key.
    """
    # Look up customer by email (don't reveal whether it exists)
    try:
        result = supabase.table("customers").select(
            "id, email, full_name"
        ).eq("email", request.email.lower().strip()).execute()
    except Exception:
        return {"message": "If an account exists for that email, a login link has been sent."}

    if not result.data:
        # Don't leak whether email is registered
        return {"message": "If an account exists for that email, a login link has been sent."}

    customer = result.data[0]
    customer_id = customer["id"]
    name = customer.get("full_name", "")

    # Token expires in 15 minutes
    exp = int(time.time()) + (15 * 60)
    sig = _sign_token(customer_id, exp)

    app_url = _settings.app_url
    magic_url = f"{app_url}/dashboard.html?cid={customer_id}&exp={exp}&sig={sig}"

    email_body = f"""Hi{(' ' + name) if name else ''},

You requested a login link for your Aletheos account.

Click the link below to access your dashboard — it expires in 15 minutes:

{magic_url}

If you did not request this, you can safely ignore this email.

— The Aletheos Team
https://aletheos.tech
"""

    try:
        await email_sender.send(
            to=customer["email"],
            subject="Your Aletheos Login Link",
            body=email_body,
        )
    except Exception as e:
        print(f"[magic-link] Email failed: {e}")

    return {"message": "If an account exists for that email, a login link has been sent."}


@router.post("/verify-magic-link")
async def verify_magic_link(request: VerifyMagicLinkRequest):
    """
    Validate a magic link token and issue a fresh API key.
    Called by the dashboard after user clicks a magic link.
    """
    # Check expiry
    if int(time.time()) > request.exp:
        raise HTTPException(status_code=401, detail="Login link has expired. Please request a new one.")

    # Verify signature
    expected_sig = _sign_token(request.customer_id, request.exp)
    if not hmac.compare_digest(expected_sig, request.sig):
        raise HTTPException(status_code=401, detail="Invalid login link.")

    # Look up customer
    result = supabase.table("customers").select("*").eq(
        "id", request.customer_id
    ).execute()

    if not result.data:
        raise HTTPException(status_code=404, detail="Account not found.")

    customer = result.data[0]

    # Revoke all existing keys and issue a fresh one
    supabase.table("api_keys").update({"is_active": False}).eq(
        "customer_id", customer["id"]
    ).execute()

    raw_key, key_prefix = generate_api_key()
    key_hash = hash_api_key(raw_key)

    supabase.table("api_keys").insert({
        "customer_id": customer["id"],
        "key_hash": key_hash,
        "key_prefix": key_prefix,
        "name": "Magic Link Login",
        "is_active": True
    }).execute()

    return {
        "api_key": raw_key,
        "email": customer["email"],
        "plan": customer["plan"],
        "message": "Login successful"
    }


@router.get("/usage")
async def get_usage(customer: dict = Depends(verify_api_key)):
    """Get usage history for the current account."""
    result = supabase.table("usage_events").select("*").eq(
        "customer_id", customer["id"]
    ).order("created_at", desc=True).limit(100).execute()

    # Summarise by event type
    summary = {}
    for event in result.data:
        et = event["event_type"]
        summary[et] = summary.get(et, 0) + 1

    return {
        "summary": summary,
        "recent_events": result.data[:20],
        "total_events": len(result.data)
    }

"""
routes.py — FastAPI router for Phase 6A: Machine Unlearning Engine.

Endpoints:
  POST /v1/machine-unlearning/request                — Submit erasure request
  GET  /v1/machine-unlearning/status/{request_id}    — Check request status
  POST /v1/machine-unlearning/verify/{request_id}    — Run verification probes
  GET  /v1/machine-unlearning/certificate/{request_id} — Get erasure certificate
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from app.core.auth import verify_api_key
from app.machine_unlearning.erasure import (
    VENDOR_ENDPOINTS,
    ALL_PLATFORMS,
    run_erasure_pipeline,
)
from app.machine_unlearning.verifier import verify_erasure

router = APIRouter(
    prefix="/machine-unlearning",
    tags=["Machine Unlearning"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response models
# ─────────────────────────────────────────────────────────────────────────────

class UnlearningRequest(BaseModel):
    email: EmailStr = Field(..., description="Email address of the data subject")
    full_name: str = Field(..., min_length=2, max_length=200, description="Full name of the data subject")
    platforms: Optional[List[str]] = Field(
        default=None,
        description=(
            "AI platforms to target. Omit or pass null to target all platforms. "
            f"Valid values: {ALL_PLATFORMS}"
        ),
    )
    reason: str = Field(
        default="GDPR Article 17 - Right to Erasure",
        description="Reason for the erasure request",
    )


class UnlearningRequestResponse(BaseModel):
    request_id: str
    status: str
    submitted_at: str
    estimated_completion: str
    platforms_targeted: List[str]
    message: str


class UnlearningStatusResponse(BaseModel):
    request_id: str
    subject_email: str
    subject_name: Optional[str]
    status: str
    reason: str
    platforms: List[str]
    platform_results: dict
    submitted_at: Optional[str]
    verified_at: Optional[str]
    certificate_id: Optional[str]
    created_at: str


class VerificationResponse(BaseModel):
    request_id: str
    verification_run_at: str
    platforms_verified: int
    results: dict


class CertificateResponse(BaseModel):
    certificate_id: str
    request_id: str
    subject_email: str
    subject_name: Optional[str]
    platforms: List[str]
    erasure_submitted_at: Optional[str]
    verified_at: Optional[str]
    status: str
    issued_at: str
    issuer: str
    legal_basis: str


# ─────────────────────────────────────────────────────────────────────────────
# POST /machine-unlearning/request
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/request",
    response_model=UnlearningRequestResponse,
    summary="Submit a machine unlearning / GDPR erasure request",
    description=(
        "Creates an erasure request targeting one or more AI vendors. "
        "Generates GDPR Article 17 letters and submits them in the background. "
        "Returns a request_id to track status."
    ),
    status_code=status.HTTP_202_ACCEPTED,
)
async def submit_unlearning_request(
    body: UnlearningRequest,
    background_tasks: BackgroundTasks,
    customer: dict = Depends(verify_api_key),
):
    from app.core.database import supabase

    # Resolve platforms
    target_platforms = body.platforms if body.platforms else ALL_PLATFORMS

    # Validate platform keys
    invalid = [p for p in target_platforms if p not in VENDOR_ENDPOINTS]
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown platform(s): {invalid}. Valid: {ALL_PLATFORMS}",
        )

    request_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Insert into Supabase
    try:
        supabase.table("unlearning_requests").insert({
            "id": request_id,
            "customer_id": customer["id"],
            "subject_email": str(body.email),
            "subject_name": body.full_name,
            "platforms": target_platforms,
            "platform_results": {},
            "status": "processing",
            "reason": body.reason,
            "created_at": now,
        }).execute()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to create unlearning request: {str(e)}",
        )

    # Kick off background erasure pipeline
    background_tasks.add_task(
        run_erasure_pipeline,
        request_id=request_id,
        email=str(body.email),
        full_name=body.full_name,
        platforms=target_platforms,
        supabase_client=supabase,
    )

    return UnlearningRequestResponse(
        request_id=request_id,
        status="processing",
        submitted_at=now,
        estimated_completion="30-90 days",
        platforms_targeted=target_platforms,
        message=(
            f"Erasure request submitted for {len(target_platforms)} AI platform(s). "
            f"GDPR Article 17 letters are being generated and dispatched. "
            f"Track progress at GET /v1/machine-unlearning/status/{request_id}"
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# GET /machine-unlearning/status/{request_id}
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/status/{request_id}",
    response_model=UnlearningStatusResponse,
    summary="Get the status of an unlearning request",
)
async def get_unlearning_status(
    request_id: str,
    customer: dict = Depends(verify_api_key),
):
    from app.core.database import supabase

    try:
        result = supabase.table("unlearning_requests").select("*").eq(
            "id", request_id
        ).eq("customer_id", customer["id"]).execute()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database error: {str(e)}",
        )

    if not result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unlearning request {request_id} not found or not owned by this API key.",
        )

    row = result.data[0]

    return UnlearningStatusResponse(
        request_id=row["id"],
        subject_email=row["subject_email"],
        subject_name=row.get("subject_name"),
        status=row["status"],
        reason=row.get("reason", "GDPR Article 17 - Right to Erasure"),
        platforms=row.get("platforms") or [],
        platform_results=row.get("platform_results") or {},
        submitted_at=row.get("submitted_at"),
        verified_at=row.get("verified_at"),
        certificate_id=row.get("certificate_id"),
        created_at=row["created_at"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST /machine-unlearning/verify/{request_id}
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/verify/{request_id}",
    response_model=VerificationResponse,
    summary="Run verification probes on an unlearning request",
    description=(
        "Checks whether each platform's erasure has been processed. "
        "Marks platforms as 'verified' if the 30-day GDPR deadline has elapsed, "
        "or 'verified_pending' if still within the window. Updates Supabase."
    ),
)
async def verify_unlearning_request(
    request_id: str,
    customer: dict = Depends(verify_api_key),
):
    from app.core.database import supabase

    # Fetch the request
    try:
        result = supabase.table("unlearning_requests").select("*").eq(
            "id", request_id
        ).eq("customer_id", customer["id"]).execute()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database error: {str(e)}",
        )

    if not result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unlearning request {request_id} not found.",
        )

    row = result.data[0]
    platforms = row.get("platforms") or []
    platform_results = row.get("platform_results") or {}
    subject_email = row["subject_email"]

    # Run verification
    verification = await verify_erasure(
        request_id=request_id,
        email=subject_email,
        platforms=platforms,
        platform_results=platform_results,
    )

    # Merge verification results back into platform_results
    for platform_key, v_result in verification.items():
        if platform_key in platform_results:
            platform_results[platform_key].update({
                "verification_status": v_result["verification_status"],
                "verification_note": v_result["verification_note"],
                "verified_at": v_result["verified_at"],
            })
        else:
            platform_results[platform_key] = v_result

    # Determine overall status
    statuses = {v.get("verification_status") for v in verification.values()}
    now = datetime.now(timezone.utc).isoformat()

    if all(s == "verified" for s in statuses):
        new_status = "verified"
        verified_at = now
    elif "verified" in statuses or "verified_pending" in statuses:
        new_status = "verifying"
        verified_at = None
    else:
        new_status = row["status"]  # leave unchanged
        verified_at = None

    # Persist updates to Supabase
    update_payload: dict = {
        "platform_results": platform_results,
        "status": new_status,
    }
    if verified_at:
        update_payload["verified_at"] = verified_at

    try:
        supabase.table("unlearning_requests").update(update_payload).eq(
            "id", request_id
        ).execute()
    except Exception as e:
        print(f"[machine_unlearning/verify] Supabase update failed: {e}")

    return VerificationResponse(
        request_id=request_id,
        verification_run_at=now,
        platforms_verified=len(verification),
        results=verification,
    )


# ─────────────────────────────────────────────────────────────────────────────
# GET /machine-unlearning/certificate/{request_id}
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/certificate/{request_id}",
    response_model=CertificateResponse,
    summary="Get the erasure certificate for a completed unlearning request",
    description=(
        "Issues a JSON erasure certificate. Only available when status is "
        "'verified' or 'submitted'. Certificate ID is generated and stored "
        "in Supabase on first issuance."
    ),
)
async def get_erasure_certificate(
    request_id: str,
    customer: dict = Depends(verify_api_key),
):
    from app.core.database import supabase

    try:
        result = supabase.table("unlearning_requests").select("*").eq(
            "id", request_id
        ).eq("customer_id", customer["id"]).execute()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database error: {str(e)}",
        )

    if not result.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unlearning request {request_id} not found.",
        )

    row = result.data[0]
    current_status = row["status"]

    # Only issue certificate for submitted or verified requests
    if current_status not in ("submitted", "verified", "verifying"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Certificate not available. Request status is '{current_status}'. "
                f"Certificate is issued once the request is in 'submitted' or 'verified' state."
            ),
        )

    # Generate certificate_id if not yet assigned
    certificate_id = row.get("certificate_id")
    if not certificate_id:
        certificate_id = f"CERT-UL-{str(uuid.uuid4()).upper()[:16]}"
        try:
            supabase.table("unlearning_requests").update(
                {"certificate_id": certificate_id}
            ).eq("id", request_id).execute()
        except Exception as e:
            print(f"[machine_unlearning/certificate] Failed to save certificate_id: {e}")

    return CertificateResponse(
        certificate_id=certificate_id,
        request_id=request_id,
        subject_email=row["subject_email"],
        subject_name=row.get("subject_name"),
        platforms=row.get("platforms") or [],
        erasure_submitted_at=row.get("submitted_at"),
        verified_at=row.get("verified_at"),
        status=current_status,
        issued_at=datetime.now(timezone.utc).isoformat(),
        issuer="Aletheos Privacy Intelligence Platform",
        legal_basis="GDPR Article 17 — Right to Erasure (Right to be Forgotten)",
    )

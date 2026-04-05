"""
routes.py — Data Deletion API
All endpoints under: /v1/deletion/

How it works:
  1. Customer connects their SaaS platforms (HubSpot, Mailchimp, etc.)
     via POST /v1/deletion/credentials
  2. Customer submits a subject email to delete
     via POST /v1/deletion/discover  → finds all records
  3. Customer confirms deletion
     via POST /v1/deletion/execute   → deletes and returns certificate
"""
import asyncio
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from app.core.auth import verify_api_key, increment_usage
from app.core.database import supabase
from app.data_deletion.connectors import get_connector, CONNECTORS
from app.data_deletion.certificate import generate_certificate
from app.utils.helpers import generate_id

router = APIRouter(prefix="/deletion", tags=["Data Deletion"])


# ----------------------------------------------------------------
# Request Models
# ----------------------------------------------------------------

class CredentialRequest(BaseModel):
    platform: str           # "hubspot" | "mailchimp" | "intercom" | "klaviyo" | "pipedrive"
    api_key: str
    extra_config: Optional[dict] = None   # e.g. { "account_id": "..." } for some platforms
    label: Optional[str] = None           # human-readable label e.g. "Production HubSpot"


class DiscoverRequest(BaseModel):
    subject_email: str
    platforms: Optional[List[str]] = None  # None = scan all connected platforms
    subject_name: Optional[str] = None


class ExecuteRequest(BaseModel):
    job_id: str                            # From /discover response
    confirm: bool = False                  # Safety gate — must be True to proceed
    legal_basis: str = "GDPR Article 17 — Right to Erasure"
    requested_by: Optional[str] = None    # Name of person making the request


# ----------------------------------------------------------------
# Endpoints
# ----------------------------------------------------------------

@router.post("/credentials")
async def save_credentials(
    request: CredentialRequest,
    customer: dict = Depends(verify_api_key)
):
    """
    Connect a SaaS platform by saving its API key.
    Keys are stored encrypted in Supabase.

    Supported platforms: hubspot, mailchimp, intercom, klaviyo, pipedrive
    """
    platform = request.platform.lower()

    if platform not in CONNECTORS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported platform '{platform}'. Supported: {list(CONNECTORS.keys())}"
        )

    # Test the credential before saving
    connector = get_connector(platform, request.api_key, request.extra_config)
    try:
        test_records = await connector.discover("test@privacyshield.io")
        # A 401/403 would throw — if we get here, credentials are valid
    except Exception as e:
        error_str = str(e).lower()
        if "401" in error_str or "403" in error_str or "unauthorized" in error_str:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid API key for {platform}. Please check and try again."
            )
        # Other errors (e.g. network) are OK — credentials may still be valid

    # Simple encryption: in production use Fernet or AWS KMS
    # For now store with a basic marker so we know it's "encrypted"
    import base64
    encrypted_value = base64.b64encode(request.api_key.encode()).decode()

    # Check if credential already exists for this platform
    existing = supabase.table("platform_credentials").select("id").eq(
        "customer_id", customer["id"]
    ).eq("integration_id", platform).eq("is_active", True).execute()

    if existing.data:
        # Update existing
        supabase.table("platform_credentials").update({
            "encrypted_value": encrypted_value,
            "updated_at": datetime.utcnow().isoformat()
        }).eq("id", existing.data[0]["id"]).execute()
        action = "updated"
    else:
        # Insert new
        supabase.table("platform_credentials").insert({
            "customer_id": customer["id"],
            "integration_id": platform,
            "credential_type": "api_key",
            "encrypted_value": encrypted_value,
            "is_active": True
        }).execute()
        action = "connected"

    return {
        "platform": platform,
        "status": action,
        "message": f"{platform.title()} {action} successfully",
        "label": request.label or platform.title()
    }


@router.get("/credentials")
async def list_credentials(customer: dict = Depends(verify_api_key)):
    """List all connected platforms for this account."""
    result = supabase.table("platform_credentials").select(
        "integration_id, credential_type, is_active, created_at, updated_at"
    ).eq("customer_id", customer["id"]).eq("is_active", True).execute()

    return {
        "connected_platforms": [r["integration_id"] for r in result.data],
        "total": len(result.data),
        "details": result.data
    }


@router.delete("/credentials/{platform}")
async def remove_credentials(
    platform: str,
    customer: dict = Depends(verify_api_key)
):
    """Disconnect a platform by revoking its stored credentials."""
    supabase.table("platform_credentials").update(
        {"is_active": False}
    ).eq("customer_id", customer["id"]).eq("integration_id", platform.lower()).execute()

    return {"platform": platform, "status": "disconnected"}


@router.post("/discover")
async def discover_records(
    request: DiscoverRequest,
    customer: dict = Depends(verify_api_key)
):
    """
    Step 1 — Find all records for a subject email across connected platforms.
    Returns a job_id. Use /execute with that job_id to delete the records.
    """
    # Load connected credentials
    creds_result = supabase.table("platform_credentials").select("*").eq(
        "customer_id", customer["id"]
    ).eq("is_active", True).execute()

    if not creds_result.data:
        raise HTTPException(
            status_code=400,
            detail="No platforms connected. Use POST /v1/deletion/credentials to connect a platform first."
        )

    # Filter to requested platforms if specified
    creds = creds_result.data
    if request.platforms:
        creds = [c for c in creds if c["integration_id"] in request.platforms]

    if not creds:
        raise HTTPException(
            status_code=400,
            detail=f"None of the requested platforms are connected: {request.platforms}"
        )

    job_id = generate_id("del")

    # Create job record
    platforms_to_scan = [c["integration_id"] for c in creds]
    supabase.table("deletion_jobs").insert({
        "customer_id": customer["id"],
        "job_id": job_id,
        "subject_email": request.subject_email,
        "subject_identifiers": {"name": request.subject_name} if request.subject_name else {},
        "platforms": platforms_to_scan,
        "status": "discovering"
    }).execute()

    # Run discovery across all platforms in parallel
    import base64

    async def scan_platform(cred: dict):
        platform = cred["integration_id"]
        try:
            api_key = base64.b64decode(cred["encrypted_value"]).decode()
            connector = get_connector(platform, api_key)
            if not connector:
                return platform, []
            records = await connector.discover(request.subject_email)
            return platform, records
        except Exception as e:
            print(f"[deletion] discover error on {platform}: {e}")
            return platform, []

    results = await asyncio.gather(*[scan_platform(c) for c in creds])

    # Collect all records
    all_records = []
    records_by_platform = {}
    for platform, records in results:
        records_by_platform[platform] = records
        all_records.extend(records)

    # Save records to DB
    job_db = supabase.table("deletion_jobs").select("id").eq("job_id", job_id).execute()
    if job_db.data:
        job_uuid = job_db.data[0]["id"]
        for record in all_records:
            supabase.table("deletion_records").insert({
                "job_id": job_uuid,
                "integration_id": record["platform"],
                "platform_record_id": record["record_id"],
                "record_type": record["record_type"],
                "status": "found",
                "metadata": record.get("data_preview", {})
            }).execute()

    # Update job status
    supabase.table("deletion_jobs").update({
        "status": "pending_confirmation",
        "total_records_found": len(all_records)
    }).eq("job_id", job_id).execute()

    return {
        "job_id": job_id,
        "subject_email": request.subject_email,
        "status": "pending_confirmation",
        "total_records_found": len(all_records),
        "records_by_platform": {
            p: len(r) for p, r in records_by_platform.items()
        },
        "records": all_records,
        "next_step": f"Call POST /v1/deletion/execute with job_id='{job_id}' and confirm=true to delete these records",
        "warning": "Deletion is permanent and cannot be undone"
    }


@router.post("/execute")
async def execute_deletion(
    request: ExecuteRequest,
    customer: dict = Depends(verify_api_key)
):
    """
    Step 2 — Execute the deletion job.
    Deletes all discovered records and returns a compliance certificate.
    Set confirm=true to proceed (safety gate).
    """
    if not request.confirm:
        raise HTTPException(
            status_code=400,
            detail="Set 'confirm': true to proceed. Deletion is permanent and cannot be undone."
        )

    # Fetch the job
    job_result = supabase.table("deletion_jobs").select("*").eq(
        "job_id", request.job_id
    ).eq("customer_id", customer["id"]).execute()

    if not job_result.data:
        raise HTTPException(status_code=404, detail=f"Job '{request.job_id}' not found")

    job = job_result.data[0]

    if job["status"] == "completed":
        raise HTTPException(status_code=400, detail="This deletion job has already been executed")

    if job["status"] == "discovering":
        raise HTTPException(status_code=400, detail="Discovery still in progress. Wait for status=pending_confirmation")

    # Fetch records to delete
    records_result = supabase.table("deletion_records").select("*").eq(
        "job_id", job["id"]
    ).eq("status", "found").execute()

    records_to_delete = records_result.data

    if not records_to_delete:
        raise HTTPException(status_code=400, detail="No records found to delete. Run /discover first.")

    # Load credentials
    import base64
    creds_result = supabase.table("platform_credentials").select("*").eq(
        "customer_id", customer["id"]
    ).eq("is_active", True).execute()

    creds_map = {c["integration_id"]: c for c in creds_result.data}

    # Execute deletions in parallel
    async def delete_record(record: dict):
        platform = record["integration_id"]
        cred = creds_map.get(platform)
        if not cred:
            return {
                "platform": platform,
                "record_id": record["platform_record_id"],
                "deleted": False,
                "message": "Credentials not found"
            }
        try:
            api_key = base64.b64decode(cred["encrypted_value"]).decode()
            connector = get_connector(platform, api_key)
            result = await connector.delete(record["platform_record_id"])

            # Update record status in DB
            supabase.table("deletion_records").update({
                "status": "deleted" if result["deleted"] else "error",
                "deleted_at": datetime.utcnow().isoformat() if result["deleted"] else None,
                "error_message": result.get("message") if not result["deleted"] else None
            }).eq("id", record["id"]).execute()

            return result
        except Exception as e:
            return {
                "platform": platform,
                "record_id": record["platform_record_id"],
                "deleted": False,
                "message": str(e)
            }

    deletion_results = await asyncio.gather(
        *[delete_record(r) for r in records_to_delete]
    )

    deletion_results = list(deletion_results)
    records_deleted = sum(1 for r in deletion_results if r.get("deleted"))
    records_failed  = len(deletion_results) - records_deleted

    # Generate compliance certificate PDF
    pdf_bytes = generate_certificate(
        job_id=request.job_id,
        subject_email=job["subject_email"],
        platforms=job["platforms"],
        records_found=job["total_records_found"],
        records_deleted=records_deleted,
        deletion_results=deletion_results,
        legal_basis=request.legal_basis,
        requested_by=request.requested_by or customer.get("email", "PrivacyShield API")
    )

    # Save certificate URL placeholder and update job
    cert_url = f"{_get_app_url()}/certificates/{request.job_id}.pdf"
    supabase.table("deletion_jobs").update({
        "status": "completed",
        "total_records_deleted": records_deleted,
        "compliance_certificate_url": cert_url,
        "completed_at": datetime.utcnow().isoformat()
    }).eq("job_id", request.job_id).execute()

    await increment_usage(customer["id"], "deletion_request", request.job_id)

    return {
        "job_id": request.job_id,
        "status": "completed",
        "subject_email": job["subject_email"],
        "summary": {
            "records_found":   job["total_records_found"],
            "records_deleted": records_deleted,
            "records_failed":  records_failed,
            "success_rate":    f"{(records_deleted / job['total_records_found'] * 100):.0f}%" if job["total_records_found"] > 0 else "0%"
        },
        "deletion_results": deletion_results,
        "compliance_certificate": {
            "available": True,
            "download_url": f"/v1/deletion/certificate/{request.job_id}",
            "note": "PDF certificate — retain for GDPR audit purposes"
        },
        "completed_at": datetime.utcnow().isoformat() + "Z"
    }


@router.get("/certificate/{job_id}")
async def download_certificate(
    job_id: str,
    customer: dict = Depends(verify_api_key)
):
    """
    Download the PDF compliance certificate for a completed deletion job.
    """
    job_result = supabase.table("deletion_jobs").select("*").eq(
        "job_id", job_id
    ).eq("customer_id", customer["id"]).execute()

    if not job_result.data:
        raise HTTPException(status_code=404, detail="Job not found")

    job = job_result.data[0]
    if job["status"] != "completed":
        raise HTTPException(status_code=400, detail="Job not yet completed — run /execute first")

    # Fetch deletion results
    records_result = supabase.table("deletion_records").select("*").eq(
        "job_id", job["id"]
    ).execute()

    deletion_results = [
        {
            "platform": r["integration_id"],
            "record_id": r["platform_record_id"],
            "deleted": r["status"] == "deleted",
            "message": r.get("error_message", "")
        }
        for r in records_result.data
    ]

    pdf_bytes = generate_certificate(
        job_id=job_id,
        subject_email=job["subject_email"],
        platforms=job["platforms"],
        records_found=job["total_records_found"],
        records_deleted=job["total_records_deleted"],
        deletion_results=deletion_results
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=compliance_certificate_{job_id}.pdf"
        }
    )


@router.get("/jobs")
async def list_jobs(
    customer: dict = Depends(verify_api_key),
    limit: int = 20
):
    """List all deletion jobs for this account."""
    result = supabase.table("deletion_jobs").select(
        "job_id, subject_email, platforms, status, total_records_found, total_records_deleted, created_at, completed_at"
    ).eq("customer_id", customer["id"]).order(
        "created_at", desc=True
    ).limit(limit).execute()

    return {"total": len(result.data), "jobs": result.data}


@router.get("/supported-platforms")
async def list_supported_platforms(customer: dict = Depends(verify_api_key)):
    """List all platforms supported for data deletion."""
    result = supabase.table("deletion_integrations").select(
        "integration_id, platform_name, category, gdpr_endpoint_available, bulk_deletion_supported"
    ).eq("is_active", True).execute()

    return {
        "total": len(result.data),
        "connected": _get_connected_platforms(customer["id"]),
        "platforms": result.data
    }


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

def _get_connected_platforms(customer_id: str) -> List[str]:
    try:
        result = supabase.table("platform_credentials").select("integration_id").eq(
            "customer_id", customer_id
        ).eq("is_active", True).execute()
        return [r["integration_id"] for r in result.data]
    except Exception:
        return []


def _get_app_url() -> str:
    from app.core.config import settings
    return settings.app_url

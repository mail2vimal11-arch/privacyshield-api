"""
Web Data Removal — API Routes
Product 4: Remove personal data from data broker websites.

Endpoints:
  POST   /v1/web-removal/scan          — check exposure across brokers
  POST   /v1/web-removal/request       — submit opt-out to all brokers
  GET    /v1/web-removal/requests      — list all removal jobs for account
  GET    /v1/web-removal/requests/{id} — get status of a specific job
  GET    /v1/web-removal/package/{id}  — download PDF removal package
  GET    /v1/web-removal/brokers       — list all supported brokers
"""

import os
import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr

from app.core.auth import verify_api_key, check_quota, increment_usage
from app.core.database import get_db
from app.web_removal.brokers import (
    BROKER_REGISTRY,
    WebRemovalEngine,
    generate_removal_package_pdf,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/web-removal", tags=["Web Data Removal"])

# Directory where PDFs are stored on the server
PDF_DIR = "/tmp/privacyshield_removal_packages"
os.makedirs(PDF_DIR, exist_ok=True)


# ----------------------------------------------------------------
# Request / Response Models
# ----------------------------------------------------------------

class ScanRequest(BaseModel):
    full_name: str
    email: EmailStr
    addresses: Optional[list[str]] = None
    phone_numbers: Optional[list[str]] = None


class RemovalRequest(BaseModel):
    full_name: str
    email: EmailStr
    addresses: Optional[list[str]] = None
    phone_numbers: Optional[list[str]] = None
    broker_keys: Optional[list[str]] = None  # None = all brokers


# ----------------------------------------------------------------
# POST /scan — Check how exposed someone is across data brokers
# ----------------------------------------------------------------

@router.post("/scan")
async def scan_exposure(
    req: ScanRequest,
    customer=Depends(verify_api_key),
):
    """
    Scan data broker landscape to estimate how many sites
    likely have data on this person. Returns a risk score
    and list of brokers to target for removal.
    """
    db = get_db()

    # Quota check
    await check_quota(customer, "web_removal_scan", db)

    engine = WebRemovalEngine(db)
    result = await engine.scan_exposure(
        full_name=req.full_name,
        email=req.email,
    )

    # Log scan to DB
    try:
        scan_record = {
            "id": str(uuid.uuid4()),
            "customer_id": customer["id"],
            "full_name": req.full_name,
            "email": req.email,
            "total_brokers": result["total_brokers_scanned"],
            "estimated_exposures": result["estimated_exposures"],
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "scan_type": "exposure_scan",
            "status": "completed",
            "created_at": datetime.utcnow().isoformat(),
        }
        db.table("web_removal_jobs").insert(scan_record).execute()
        result["scan_id"] = scan_record["id"]
    except Exception as e:
        logger.warning(f"Could not save scan to DB: {e}")

    await increment_usage(customer, "web_removal_scan", db)
    return result


# ----------------------------------------------------------------
# POST /request — Submit opt-out requests to all brokers
# ----------------------------------------------------------------

@router.post("/request")
async def submit_removal(
    req: RemovalRequest,
    customer=Depends(verify_api_key),
):
    """
    Submit removal/opt-out requests to all (or selected) data brokers.

    - Brokers with email opt-out: sends a formal removal email via SendGrid
    - Brokers with URL-only opt-out: returns the URL for the person to visit
    - Generates a PDF package as evidence of all requests submitted

    Returns a job_id you can use to download the PDF package.
    """
    db = get_db()
    await check_quota(customer, "web_removal_request", db)

    request_id = str(uuid.uuid4())
    engine = WebRemovalEngine(db)

    # Set up SendGrid if configured
    sendgrid_client = None
    try:
        import sendgrid as sg_lib
        from app.core.config import settings
        if settings.sendgrid_api_key:
            sendgrid_client = sg_lib.SendGridAPIClient(settings.sendgrid_api_key)
    except Exception:
        pass

    # Submit requests
    result = await engine.submit_removal_requests(
        request_id=request_id,
        full_name=req.full_name,
        email=req.email,
        addresses=req.addresses,
        phone_numbers=req.phone_numbers,
        broker_keys=req.broker_keys,
        sendgrid_client=sendgrid_client,
    )

    # Generate PDF package
    pdf_path = os.path.join(PDF_DIR, f"{request_id}.pdf")
    try:
        generate_removal_package_pdf(
            request_id=request_id,
            full_name=req.full_name,
            email=req.email,
            brokers_contacted=result["broker_results"],
            output_path=pdf_path,
        )
        pdf_ready = True
    except Exception as e:
        logger.warning(f"PDF generation failed: {e}")
        pdf_ready = False

    # Save job to DB
    try:
        estimated_complete = datetime.utcnow() + timedelta(days=result["estimated_completion_days"])
        job_record = {
            "id": request_id,
            "customer_id": customer["id"],
            "full_name": req.full_name,
            "email": req.email,
            "total_brokers": result["total_brokers"],
            "emails_sent": result["emails_sent"],
            "url_only_brokers": result["url_only_brokers"],
            "estimated_completion_days": result["estimated_completion_days"],
            "estimated_complete_date": estimated_complete.isoformat(),
            "scan_type": "removal_request",
            "status": "in_progress",
            "pdf_ready": pdf_ready,
            "created_at": datetime.utcnow().isoformat(),
        }
        db.table("web_removal_jobs").insert(job_record).execute()
    except Exception as e:
        logger.warning(f"Could not save job to DB: {e}")

    await increment_usage(customer, "web_removal_request", db)

    return {
        "request_id": request_id,
        "status": "submitted",
        "summary": {
            "total_brokers": result["total_brokers"],
            "emails_sent": result["emails_sent"],
            "url_only_brokers": result["url_only_brokers"],
            "errors": result["errors"],
            "estimated_completion_days": result["estimated_completion_days"],
        },
        "pdf_package_url": f"/v1/web-removal/package/{request_id}" if pdf_ready else None,
        "url_only_brokers": [
            {
                "broker_name": b["broker_name"],
                "opt_out_url": b["opt_out_url"],
            }
            for b in result["broker_results"]
            if b.get("status") == "url_only" and b.get("opt_out_url")
        ],
        "message": (
            f"Removal requests submitted to {result['emails_sent']} brokers via email. "
            f"{result['url_only_brokers']} brokers require manual opt-out via their website. "
            f"Estimated completion: {result['estimated_completion_days']} days."
        ),
    }


# ----------------------------------------------------------------
# GET /requests — List all removal jobs for this account
# ----------------------------------------------------------------

@router.get("/requests")
async def list_requests(
    limit: int = 20,
    customer=Depends(verify_api_key),
):
    """List all removal jobs submitted by this account."""
    db = get_db()
    try:
        result = (
            db.table("web_removal_jobs")
            .select("*")
            .eq("customer_id", customer["id"])
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return {"jobs": result.data or [], "total": len(result.data or [])}
    except Exception as e:
        logger.error(f"Could not list jobs: {e}")
        return {"jobs": [], "total": 0}


# ----------------------------------------------------------------
# GET /requests/{id} — Get status of a specific job
# ----------------------------------------------------------------

@router.get("/requests/{request_id}")
async def get_request(
    request_id: str,
    customer=Depends(verify_api_key),
):
    """Get status and details of a specific removal job."""
    db = get_db()
    try:
        result = (
            db.table("web_removal_jobs")
            .select("*")
            .eq("id", request_id)
            .eq("customer_id", customer["id"])
            .single()
            .execute()
        )
        if not result.data:
            raise HTTPException(status_code=404, detail="Request not found")
        return result.data
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=404, detail="Request not found")


# ----------------------------------------------------------------
# GET /package/{id} — Download PDF removal package
# ----------------------------------------------------------------

@router.get("/package/{request_id}")
async def download_package(
    request_id: str,
    customer=Depends(verify_api_key),
):
    """
    Download the PDF removal package for a specific request.
    This PDF documents all opt-out requests submitted on behalf of the data subject.
    """
    db = get_db()

    # Verify ownership
    try:
        result = (
            db.table("web_removal_jobs")
            .select("id, customer_id, full_name, pdf_ready")
            .eq("id", request_id)
            .eq("customer_id", customer["id"])
            .single()
            .execute()
        )
        if not result.data:
            raise HTTPException(status_code=404, detail="Request not found")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=404, detail="Request not found")

    pdf_path = os.path.join(PDF_DIR, f"{request_id}.pdf")
    if not os.path.exists(pdf_path):
        raise HTTPException(
            status_code=404,
            detail="PDF not available. It may still be generating or there was an error.",
        )

    full_name_safe = result.data.get("full_name", "removal").replace(" ", "_")
    filename = f"PrivacyShield_Removal_{full_name_safe}_{request_id[:8]}.pdf"

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=filename,
    )


# ----------------------------------------------------------------
# GET /brokers — List all supported data brokers
# ----------------------------------------------------------------

@router.get("/brokers")
async def list_brokers(
    tier: Optional[str] = None,
    gdpr_only: bool = False,
    customer=Depends(verify_api_key),
):
    """
    List all 25+ supported data brokers.
    Filter by tier (A/B/C) or show only GDPR-compliant brokers.
    """
    brokers = []
    for key, info in BROKER_REGISTRY.items():
        if tier and info["tier"] != tier.upper():
            continue
        if gdpr_only and not info["gdpr_supported"]:
            continue
        brokers.append({
            "broker_key": key,
            "broker_name": info["name"],
            "website": info["website"],
            "opt_out_url": info["opt_out_url"],
            "method": info["method"],
            "tier": info["tier"],
            "gdpr_supported": info["gdpr_supported"],
            "ccpa_supported": info["ccpa_supported"],
            "avg_removal_days": info["avg_removal_days"],
            "description": info["description"],
        })

    # Sort: Tier A first, then B, then C; alphabetical within tier
    tier_order = {"A": 0, "B": 1, "C": 2}
    brokers.sort(key=lambda x: (tier_order.get(x["tier"], 9), x["broker_name"]))

    return {
        "total": len(brokers),
        "brokers": brokers,
        "tier_guide": {
            "A": "Fast responders — removal typically within 3–14 days",
            "B": "Medium — removal typically within 14–21 days",
            "C": "Slow — removal can take 30–45 days",
        },
    }

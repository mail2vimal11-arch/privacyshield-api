"""
routes.py — AI Model Data Removal API
All endpoints under: /v1/ai-models/
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

from app.core.auth import verify_api_key, check_quota, increment_usage
from app.core.database import supabase
from app.core.email import email_sender
from app.ai_models.scanner import AIModelScanner
from app.ai_models.gdpr_generator import GDPRLetterGenerator, generate_pdf
from app.utils.helpers import generate_id, generate_tracking_number, calculate_next_scan

router = APIRouter(prefix="/ai-models", tags=["AI Model Data Removal"])
scanner = AIModelScanner()
gdpr_gen = GDPRLetterGenerator()


# ----------------------------------------------------------------
# Request / Response Models
# ----------------------------------------------------------------

class ProfileIdentifiers(BaseModel):
    emails: List[str] = []
    usernames: List[str] = []
    phone_numbers: List[str] = []
    known_urls: List[str] = []


class ScanProfile(BaseModel):
    name: str
    identifiers: ProfileIdentifiers = ProfileIdentifiers()


class DetectionMethods(BaseModel):
    prompt_injection: bool = True
    extraction_attack: bool = True
    rag_probing: bool = True
    metadata_analysis: bool = False


class ScanRequest(BaseModel):
    profile: ScanProfile
    models_to_scan: List[str] = Field(
        default=["chatgpt", "gemini", "perplexity"],
        description="Supported: chatgpt, claude, gemini, perplexity, llama"
    )
    scan_depth: str = Field(
        default="standard",
        description="'quick' (2 queries), 'standard' (5 queries), 'deep' (10+ queries)"
    )
    detection_methods: DetectionMethods = DetectionMethods()


class RequesterInfo(BaseModel):
    name: str
    email: str
    eu_resident: bool = False
    legal_basis: str = "gdpr_article_17"


class RemovalOptions(BaseModel):
    auto_submit_gdpr_requests: bool = True
    generate_compliance_report: bool = True
    public_shame_dashboard: bool = False
    notification_email: Optional[str] = None


class RemovalRequest(BaseModel):
    scan_id: str
    models: List[str] = Field(default=["all"])
    removal_strategy: str = Field(
        default="comprehensive",
        description="'gdpr_only' | 'source_removal' | 'comprehensive'"
    )
    requester_info: RequesterInfo
    options: RemovalOptions = RemovalOptions()


class MonitorRequest(BaseModel):
    profile_name: str
    profile_identifiers: ProfileIdentifiers = ProfileIdentifiers()
    models_to_monitor: List[str] = ["chatgpt", "gemini", "perplexity"]
    frequency: str = Field(default="weekly", description="'daily' | 'weekly' | 'monthly'")
    alert_on: dict = {
        "new_data_found": True,
        "increased_risk_score": True,
        "new_models_with_data": True
    }
    notification_channels: List[dict] = []


# ----------------------------------------------------------------
# Endpoints
# ----------------------------------------------------------------

@router.post("/scan")
async def scan_ai_models(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    customer: dict = Depends(verify_api_key)
):
    """
    Scan AI models for personal data about a person.
    Returns evidence, risk scores, and removal recommendations.
    """
    await check_quota(customer, "ai_model_scan")

    scan_id = generate_id("aiscan")

    # Create scan record immediately (status: in_progress)
    scan_record = {
        "customer_id": customer["id"],
        "scan_id": scan_id,
        "profile_name": request.profile.name,
        "profile_identifiers": request.profile.identifiers.dict(),
        "models_scanned": request.models_to_scan,
        "scan_depth": request.scan_depth,
        "detection_methods": request.detection_methods.dict(),
        "status": "in_progress",
        "started_at": datetime.utcnow().isoformat()
    }

    try:
        supabase.table("ai_model_scans").insert(scan_record).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create scan record: {str(e)}")

    # Run the scan
    try:
        results = await scanner.scan_all_models(
            profile=request.profile.dict(),
            models=request.models_to_scan,
            detection_methods=request.detection_methods.dict(),
            scan_depth=request.scan_depth
        )
    except Exception as e:
        # Mark scan as failed
        supabase.table("ai_model_scans").update({
            "status": "failed",
            "error_message": str(e),
            "completed_at": datetime.utcnow().isoformat()
        }).eq("scan_id", scan_id).execute()
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    # Save full results to database
    try:
        supabase.table("ai_model_scans").update({
            "status": "completed",
            "overall_risk_score": results["overall_risk_score"],
            "risk_level": results["risk_level"],
            "total_models_scanned": results["total_models_scanned"],
            "models_with_data_found": results["models_with_data_found"],
            "total_pii_instances": results["aggregate_analysis"]["total_pii_instances"],
            "scan_results": results,
            "completed_at": datetime.utcnow().isoformat()
        }).eq("scan_id", scan_id).execute()

        # Save individual evidence records
        scan_db = supabase.table("ai_model_scans").select("id").eq("scan_id", scan_id).execute()
        if scan_db.data:
            scan_uuid = scan_db.data[0]["id"]
            for model_result in results["models"]:
                for evidence in model_result.get("evidence", []):
                    supabase.table("ai_model_evidence").insert({
                        "scan_id": scan_uuid,
                        "evidence_id": evidence["evidence_id"],
                        "model_id": model_result["model_id"],
                        "detection_method": evidence["detection_method"],
                        "query_sent": evidence["query"],
                        "model_response": evidence.get("model_response", ""),
                        "pii_detected": evidence.get("pii_detected", []),
                        "likely_training_sources": evidence.get("likely_training_sources", []),
                        "confidence_score": evidence.get("confidence_score", 0),
                        "verbatim_memorization_suspected": "memorization" in evidence.get("note", "").lower()
                    }).execute()

    except Exception as e:
        print(f"[WARNING] Failed to save scan results: {e}")

    # Track usage
    await increment_usage(customer["id"], "ai_model_scan", scan_id)

    return {
        "scan_id": scan_id,
        "profile_name": request.profile.name,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": "completed",
        "report_url": f"{_get_app_url()}/ai-scans/{scan_id}",
        **results
    }


@router.post("/remove")
async def submit_removal_requests(
    request: RemovalRequest,
    customer: dict = Depends(verify_api_key)
):
    """
    Submit removal requests for a person based on a completed scan.
    Generates GDPR letters and tracks vendor responses.
    """
    # Fetch the original scan
    scan_result = supabase.table("ai_model_scans").select("*").eq(
        "scan_id", request.scan_id
    ).eq("customer_id", customer["id"]).execute()

    if not scan_result.data:
        raise HTTPException(status_code=404, detail=f"Scan '{request.scan_id}' not found")

    scan = scan_result.data[0]

    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan must be completed before requesting removal")

    removal_id = generate_id("airem")
    models_targeted = request.models if request.models != ["all"] else scan["models_scanned"]

    # Build removal tasks for each model
    tasks = []
    scan_results = scan.get("scan_results", {})
    models_with_data = [
        m for m in scan_results.get("models", [])
        if m.get("data_found") and m.get("model_id", "").split("-")[0] in [
            t.replace("chatgpt", "chatgpt").replace("claude", "claude") for t in models_targeted
        ]
    ]

    for model in models_with_data:
        vendor = model.get("vendor", "unknown")
        task_id = generate_id("aitask")

        removal_method = _pick_removal_method(model, request.removal_strategy)

        tasks.append({
            "task_id": task_id,
            "vendor": vendor,
            "model_id": model["model_id"],
            "removal_method": removal_method,
            "status": "pending",
            "tracking_number": generate_tracking_number("GDPR") if "gdpr" in removal_method else None,
            "public_tracking_url": (
                f"https://shame.privacyshield.io/{vendor.lower()}/{task_id}"
                if request.options.public_shame_dashboard else None
            )
        })

    # Save removal request
    removal_record = {
        "customer_id": customer["id"],
        "removal_request_id": removal_id,
        "scan_id": scan["id"],
        "profile_name": request.requester_info.name,
        "models_targeted": models_targeted,
        "removal_strategy": request.removal_strategy,
        "requester_info": request.requester_info.dict(),
        "options": request.options.dict(),
        "status": "in_progress",
        "total_tasks": len(tasks),
        "pending_tasks": len(tasks),
        "public_shame_enabled": request.options.public_shame_dashboard
    }

    try:
        supabase.table("ai_removal_requests").insert(removal_record).execute()

        # Get the UUID
        rem_db = supabase.table("ai_removal_requests").select("id").eq(
            "removal_request_id", removal_id
        ).execute()

        if rem_db.data:
            rem_uuid = rem_db.data[0]["id"]
            for task in tasks:
                task["removal_request_id"] = rem_uuid
                supabase.table("ai_removal_tasks").insert(task).execute()

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create removal request: {str(e)}")

    return {
        "removal_request_id": removal_id,
        "scan_id": request.scan_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": "in_progress",
        "total_models": len(tasks),
        "removal_tasks": tasks,
        "status_url": f"{_get_api_url()}/v1/ai-models/requests/{removal_id}"
    }


@router.get("/requests/{removal_request_id}")
async def get_removal_status(
    removal_request_id: str,
    customer: dict = Depends(verify_api_key)
):
    """Get the current status of a removal request."""
    result = supabase.table("ai_removal_requests").select("*, ai_removal_tasks(*)").eq(
        "removal_request_id", removal_request_id
    ).eq("customer_id", customer["id"]).execute()

    if not result.data:
        raise HTTPException(status_code=404, detail="Removal request not found")

    removal = result.data[0]
    tasks = removal.pop("ai_removal_tasks", [])

    completed = sum(1 for t in tasks if t["status"] == "completed")
    in_progress = sum(1 for t in tasks if t["status"] in ("submitted", "awaiting_vendor_response"))
    pending_user = sum(1 for t in tasks if t["status"] == "pending_user_action")

    return {
        "removal_request_id": removal_request_id,
        "status": removal["status"],
        "created_at": removal["created_at"],
        "progress": {
            "total_tasks": removal["total_tasks"],
            "completed": completed,
            "in_progress": in_progress,
            "pending_user_action": pending_user,
            "failed": removal.get("failed_tasks", 0)
        },
        "tasks": tasks
    }


@router.post("/monitor")
async def create_monitor(
    request: MonitorRequest,
    customer: dict = Depends(verify_api_key)
):
    """Set up continuous AI model monitoring for a profile."""
    monitor_id = generate_id("aimon")
    next_scan = calculate_next_scan(request.frequency)

    monitor_record = {
        "customer_id": customer["id"],
        "monitor_id": monitor_id,
        "profile_name": request.profile_name,
        "profile_identifiers": request.profile_identifiers.dict(),
        "models_to_monitor": request.models_to_monitor,
        "frequency": request.frequency,
        "alert_on": request.alert_on,
        "notification_channels": request.notification_channels,
        "status": "active",
        "next_scan_at": next_scan.isoformat()
    }

    try:
        supabase.table("ai_model_monitors").insert(monitor_record).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create monitor: {str(e)}")

    return {
        "monitor_id": monitor_id,
        "profile_name": request.profile_name,
        "status": "active",
        "next_scan": next_scan.isoformat() + "Z",
        "models_monitored": request.models_to_monitor,
        "frequency": request.frequency,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }


@router.get("/supported")
async def list_supported_models(customer: dict = Depends(verify_api_key)):
    """List all AI models supported for scanning."""
    result = supabase.table("ai_model_database").select("*").eq("is_active", True).execute()
    return {
        "total_models": len(result.data),
        "models": result.data
    }


@router.get("/shame-board")
async def get_shame_board():
    """Public endpoint — no API key required. Shows vendor response times."""
    result = supabase.table("public_shame_board").select("*").order(
        "community_rating", desc=True
    ).execute()
    return {
        "title": "AI Vendor Deletion Request Response Times",
        "description": "Community-tracked data on how quickly AI companies respond to GDPR deletion requests",
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "vendors": result.data
    }


@router.post("/generate-gdpr-request")
async def generate_gdpr_request(
    request: dict,
    customer: dict = Depends(verify_api_key)
):
    """
    Generate a GDPR Article 17 deletion request letter for a specific vendor.
    Optionally auto-submits it via email.

    Body:
    {
      "vendor": "openai",
      "profile": { "name": "Jane Doe", "email": "jane@example.com", "eu_resident": true },
      "scan_id": "aiscan_abc123",
      "auto_send": false
    }
    """
    vendor = request.get("vendor", "").lower()
    profile = request.get("profile", {})
    scan_id = request.get("scan_id")
    auto_send = request.get("auto_send", False)

    if not vendor:
        raise HTTPException(status_code=400, detail="'vendor' is required (e.g. 'openai', 'google', 'anthropic')")
    if not profile.get("name") or not profile.get("email"):
        raise HTTPException(status_code=400, detail="'profile.name' and 'profile.email' are required")

    # Fetch scan evidence if scan_id provided
    evidence = []
    if scan_id:
        scan_result = supabase.table("ai_model_scans").select(
            "scan_results"
        ).eq("scan_id", scan_id).eq("customer_id", customer["id"]).execute()

        if scan_result.data:
            scan_data = scan_result.data[0].get("scan_results", {})
            for model in scan_data.get("models", []):
                if vendor in model.get("model_id", "").lower() or vendor in model.get("vendor", "").lower():
                    evidence = model.get("evidence", [])[:5]
                    break

    # Generate the letter
    letter = gdpr_gen.generate(
        vendor=vendor,
        requester=profile,
        evidence=evidence,
        scan_id=scan_id
    )

    # Generate PDF
    pdf_bytes = generate_pdf(letter)

    send_result = None
    if auto_send:
        send_result = await email_sender.send_gdpr_letter(
            letter=letter,
            requester_email=profile["email"],
            pdf_bytes=pdf_bytes
        )

        # Log the letter to database
        try:
            supabase.table("gdpr_request_letters").insert({
                "vendor": vendor,
                "subject_line": letter["subject"],
                "body": letter["body"],
                "recipient_email": letter["recipient_email"],
                "cc_emails": letter["cc_emails"],
                "legal_basis": letter["legal_basis"],
                "send_method": "email",
                "sent_at": datetime.utcnow().isoformat() if send_result and send_result.get("sent") else None,
                "email_send_result": send_result or {}
            }).execute()
        except Exception as e:
            print(f"[WARNING] Failed to save GDPR letter record: {e}")

    return {
        "vendor": vendor,
        "letter": letter,
        "pdf_available": bool(pdf_bytes),
        "auto_sent": auto_send,
        "send_result": send_result,
        "next_steps": (
            "Letter sent. Track vendor response at /v1/ai-models/shame-board"
            if auto_send and send_result and send_result.get("sent")
            else "Set 'auto_send': true to submit automatically, or copy the 'body' and send it yourself to the 'recipient_email'."
        )
    }


# ----------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------

def _pick_removal_method(model: dict, strategy: str) -> str:
    """Choose the most effective removal method for a model."""
    model_id = model.get("model_id", "")

    if model_id == "perplexity":
        return "source_removal"  # Most effective for RAG

    if strategy == "gdpr_only":
        return "gdpr_deletion_request"
    elif strategy == "source_removal":
        return "source_removal"
    else:  # comprehensive
        return "gdpr_deletion_request"  # Start with GDPR, source removal handled separately


def _get_app_url() -> str:
    from app.core.config import settings
    return settings.app_url


def _get_api_url() -> str:
    from app.core.config import settings
    return settings.api_base_url

"""
routes.py — Shadow IT Detection API
All endpoints under: /v1/shadow-it/

What it does:
  Scan a company domain (e.g. acmecorp.com) and return every SaaS tool
  being used — including ones IT doesn't know about — by analysing
  DNS records and HTTP headers.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from app.core.auth import verify_api_key, check_quota, increment_usage
from app.core.database import supabase
from app.shadow_it.scanner import ShadowITScanner
from app.utils.helpers import generate_id

router = APIRouter(prefix="/shadow-it", tags=["Shadow IT Detection"])
scanner = ShadowITScanner()


# ----------------------------------------------------------------
# Request / Response Models
# ----------------------------------------------------------------

class ScanRequest(BaseModel):
    domain: str
    scan_methods: Optional[List[str]] = None   # defaults to all methods
    include_low_risk: bool = True


class AlertConfig(BaseModel):
    new_tools_found: bool = True
    risk_score_change: bool = True
    notification_email: Optional[str] = None


class MonitorRequest(BaseModel):
    domain: str
    frequency: str = "weekly"                  # "daily" | "weekly" | "monthly"
    alert_config: AlertConfig = AlertConfig()


# ----------------------------------------------------------------
# Endpoints
# ----------------------------------------------------------------

@router.post("/scan")
async def scan_domain(
    request: ScanRequest,
    customer: dict = Depends(verify_api_key)
):
    """
    Scan a company domain for Shadow IT — all SaaS tools detected
    via DNS records and HTTP headers.

    Example:
      POST /v1/shadow-it/scan
      { "domain": "acmecorp.com" }
    """
    await check_quota(customer, "shadow_it_scan")

    domain = request.domain.lower().strip()
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain. Use format: acmecorp.com")

    scan_id = generate_id("scan")

    # Save scan record
    try:
        supabase.table("shadow_it_scans").insert({
            "customer_id": customer["id"],
            "scan_id": scan_id,
            "domain": domain,
            "status": "in_progress",
            "scan_methods": request.scan_methods or ["dns_mx", "dns_txt", "dns_cname", "subdomains", "headers"],
        }).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create scan: {str(e)}")

    # Run the scan
    try:
        results = await scanner.scan_domain(
            domain=domain,
            scan_methods=request.scan_methods
        )
    except Exception as e:
        supabase.table("shadow_it_scans").update({
            "status": "failed",
            "error_message": str(e)
        }).eq("scan_id", scan_id).execute()
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    # Filter out low risk if requested
    findings = results["findings"]
    if not request.include_low_risk:
        findings = [f for f in findings if f["risk_level"] != "low"]
        results["findings"] = findings
        results["total_tools_found"] = len(findings)

    # Save results
    try:
        scan_db = supabase.table("shadow_it_scans").update({
            "status": "completed",
            "total_tools_found": results["total_tools_found"],
            "high_risk_tools": results["high_risk_tools"],
            "compliance_score": results["compliance_score"],
            "results": results,
            "completed_at": datetime.utcnow().isoformat()
        }).eq("scan_id", scan_id).execute()

        # Save individual findings
        scan_record = supabase.table("shadow_it_scans").select("id").eq("scan_id", scan_id).execute()
        if scan_record.data:
            scan_uuid = scan_record.data[0]["id"]
            for f in findings:
                try:
                    supabase.table("shadow_it_findings").insert({
                        "scan_id": scan_uuid,
                        "tool_id": f["tool_id"],
                        "detection_method": f["detection_method"],
                        "evidence": {"description": f["evidence"]},
                        "confidence_score": f["confidence"],
                        "risk_level": f["risk_level"],
                        "data_categories": f["data_categories"],
                        "remediation_steps": f["remediation_steps"]
                    }).execute()
                except Exception:
                    pass  # Non-critical if individual finding fails to save

    except Exception as e:
        print(f"[WARNING] Failed to save scan results: {e}")

    await increment_usage(customer["id"], "shadow_it_scan", scan_id)

    return {
        "scan_id": scan_id,
        "domain": domain,
        "status": "completed",
        "report_url": f"{_get_app_url()}/shadow-it/{scan_id}",
        **results
    }


@router.get("/scans")
async def list_scans(
    customer: dict = Depends(verify_api_key),
    limit: int = 20
):
    """List all previous Shadow IT scans for this account."""
    result = supabase.table("shadow_it_scans").select(
        "scan_id, domain, status, total_tools_found, high_risk_tools, compliance_score, created_at, completed_at"
    ).eq("customer_id", customer["id"]).order(
        "created_at", desc=True
    ).limit(limit).execute()

    return {
        "total": len(result.data),
        "scans": result.data
    }


@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    customer: dict = Depends(verify_api_key)
):
    """Get full results of a previous Shadow IT scan."""
    result = supabase.table("shadow_it_scans").select("*").eq(
        "scan_id", scan_id
    ).eq("customer_id", customer["id"]).execute()

    if not result.data:
        raise HTTPException(status_code=404, detail="Scan not found")

    return result.data[0]


@router.post("/monitor")
async def create_monitor(
    request: MonitorRequest,
    customer: dict = Depends(verify_api_key)
):
    """
    Set up recurring Shadow IT monitoring for a domain.
    We'll re-scan on your chosen frequency and alert you to new tools.
    """
    from app.utils.helpers import calculate_next_scan
    monitor_id = generate_id("sitmon")
    next_scan = calculate_next_scan(request.frequency)

    try:
        supabase.table("shadow_it_scans").insert({
            "customer_id": customer["id"],
            "scan_id": monitor_id,
            "domain": request.domain,
            "status": "monitor_scheduled",
            "scan_methods": ["dns_mx", "dns_txt", "dns_cname", "subdomains", "headers"],
            "results": {
                "monitor": True,
                "frequency": request.frequency,
                "next_scan_at": next_scan.isoformat(),
                "alert_config": request.alert_config.dict()
            }
        }).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create monitor: {str(e)}")

    return {
        "monitor_id": monitor_id,
        "domain": request.domain,
        "frequency": request.frequency,
        "next_scan_at": next_scan.isoformat() + "Z",
        "status": "active"
    }


@router.get("/tools")
async def list_detectable_tools(customer: dict = Depends(verify_api_key)):
    """List all SaaS tools we can detect via Shadow IT scanning."""
    result = supabase.table("saas_tool_database").select(
        "tool_id, tool_name, category, risk_level, gdpr_compliant, typical_data_stored"
    ).eq("is_active", True).order("risk_level").execute()

    return {
        "total_tools": len(result.data),
        "detection_methods": ["dns_mx", "dns_txt", "dns_cname", "subdomain_resolution", "http_headers"],
        "tools": result.data
    }


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

def _get_app_url() -> str:
    from app.core.config import settings
    return settings.app_url

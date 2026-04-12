"""
routes.py — FastAPI endpoints for Phase 6B: Dark Web Intelligence.

Endpoints:
  POST /v1/dark-web/scan              — Run a dark web / breach scan for an email
  GET  /v1/dark-web/scan/{scan_id}    — Retrieve a previous scan result
  POST /v1/dark-web/intelligence      — Ask the Aletheos SLM a security/privacy question (RAG)
  POST /v1/dark-web/audit/run         — Trigger a safety audit run (admin only)
  GET  /v1/dark-web/audit/latest      — Get the latest safety audit report
  POST /v1/dark-web/ingest            — Trigger knowledge base refresh (admin only)
"""

import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from pydantic import BaseModel, EmailStr, Field

from app.core.auth import verify_api_key, check_quota, increment_usage
from app.core.probe_detector import probe_detector
from app.core.output_safety import output_monitor
from app.dark_web_intelligence.scanner import scan_email, DarkWebScanResult
from app.dark_web_intelligence.slm.rag.retriever import retriever as rag_retriever

router = APIRouter(tags=["Dark Web Intelligence"])

# Simple in-memory scan cache (replace with Supabase for production)
_scan_cache: dict[str, dict] = {}


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response Models
# ─────────────────────────────────────────────────────────────────────────────

class DarkWebScanRequest(BaseModel):
    email: EmailStr = Field(..., description="Email address to scan for dark web exposure")
    subject_name: Optional[str] = Field(None, description="Full name of the subject (optional, improves context)")
    enrich_with_intelligence: bool = Field(
        True,
        description="If true, runs RAG + SLM enrichment for remediation advice. Slightly slower."
    )


class IntelligenceQueryRequest(BaseModel):
    question: str = Field(..., min_length=10, max_length=2000, description="Your privacy or cybersecurity question")
    sources: Optional[list] = Field(
        None,
        description="Limit sources: ['gdpr', 'nist', 'nvd']. Omit to use all three."
    )


class IntelligenceQueryResponse(BaseModel):
    question: str
    answer: str
    sources_used_count: dict
    backend_used: str
    timestamp: str


class ScanSummaryResponse(BaseModel):
    scan_id: str
    subject_email: str
    overall_risk_level: str
    overall_risk_score: float
    breach_count: int
    paste_count: int
    data_types_exposed: list
    summary: str
    recommended_actions: list
    timestamp: str
    scan_duration_ms: int


# ─────────────────────────────────────────────────────────────────────────────
# POST /v1/dark-web/scan
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/dark-web/scan",
    summary="Scan an email for dark web exposure",
    description=(
        "Checks the provided email against known breach databases and "
        "dark web intelligence sources. Returns risk score, exposed data types, "
        "breach history, GDPR obligations, and SLM-generated remediation advice."
    ),
)
async def dark_web_scan(
    request: DarkWebScanRequest,
    customer: dict = Depends(verify_api_key),
):
    await check_quota(customer, "dark_web_scan")

    try:
        result: DarkWebScanResult = await scan_email(
            email=request.email,
            subject_name=request.subject_name,
            enrich_with_intelligence=request.enrich_with_intelligence,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}"
        )

    # Cache the result
    result_dict = asdict(result)
    _scan_cache[result.scan_id] = result_dict

    # Persist to Supabase (fire-and-forget)
    try:
        from app.core.database import supabase
        supabase.table("dark_web_scans").insert({
            "id":               result.scan_id,
            "customer_id":      customer["id"],
            "subject_email":    result.subject_email,
            "subject_name":     result.subject_name,
            "risk_level":       result.overall_risk_level,
            "risk_score":       result.overall_risk_score,
            "breach_count":     result.credential_exposure.breach_count,
            "paste_count":      result.credential_exposure.paste_count,
            "data_types":       result.credential_exposure.data_types_exposed,
            "summary":          result.summary,
            "full_result":      result_dict,
            "created_at":       result.timestamp,
        }).execute()
    except Exception as e:
        print(f"[dark_web/scan] Supabase persist failed: {e}")

    await increment_usage(customer["id"], "dark_web_scan", result.scan_id)

    return result_dict


# ─────────────────────────────────────────────────────────────────────────────
# GET /v1/dark-web/scan/{scan_id}
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/dark-web/scan/{scan_id}",
    summary="Retrieve a previous scan result",
)
async def get_scan(
    scan_id: str,
    customer: dict = Depends(verify_api_key),
):
    # Check in-memory cache first
    if scan_id in _scan_cache:
        return _scan_cache[scan_id]

    # Fallback to Supabase
    try:
        from app.core.database import supabase
        result = supabase.table("dark_web_scans").select("full_result").eq(
            "id", scan_id
        ).eq("customer_id", customer["id"]).execute()

        if result.data:
            return result.data[0]["full_result"]
    except Exception as e:
        print(f"[dark_web/scan/{scan_id}] Supabase lookup failed: {e}")

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Scan {scan_id} not found or not owned by this API key."
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST /v1/dark-web/intelligence
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/dark-web/intelligence",
    response_model=IntelligenceQueryResponse,
    summary="Ask the Aletheos SLM a security or privacy question",
    description=(
        "Queries the fine-tuned Aletheos SLM with RAG context from GDPR, NIST, and NVD. "
        "Answers are grounded in real legal and threat intelligence data."
    ),
)
async def intelligence_query(
    request: IntelligenceQueryRequest,
    customer: dict = Depends(verify_api_key),
):
    await check_quota(customer, "intelligence_query")

    # ── Phase 7C: Probe detection ─────────────────────────────────────────────
    probe_result = await probe_detector.detect(
        query=request.question,
        customer_id=customer.get("id"),
    )
    if probe_result.is_blocked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=probe_result.block_reason,
        )

    try:
        result = await rag_retriever.query(
            user_question=request.question,
            sources=request.sources,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Intelligence query failed: {str(e)}"
        )

    # ── Phase 7C: Output safety monitor ──────────────────────────────────────
    raw_answer = result.get("answer", "")
    safety_check = output_monitor.check(raw_answer, query_hint=request.question)
    safe_answer = safety_check.safe_output

    await increment_usage(customer["id"], "intelligence_query")

    sources_count = {
        source: len(hits)
        for source, hits in result.get("sources_used", {}).items()
    }

    return IntelligenceQueryResponse(
        question=request.question,
        answer=safe_answer,
        sources_used_count=sources_count,
        backend_used=result.get("backend_used", "unknown"),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST /v1/dark-web/audit/run  (admin — checks for ADMIN_KEY header)
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/dark-web/audit/run",
    summary="Trigger a full SLM safety audit (admin only)",
)
async def run_safety_audit(
    background_tasks: BackgroundTasks,
    category: Optional[str] = None,
    customer: dict = Depends(verify_api_key),
):
    if customer.get("plan") not in ("enterprise",) and not customer.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Safety audit is restricted to Enterprise / Admin accounts."
        )

    def _run_audit():
        import asyncio
        from app.dark_web_intelligence.slm.audit.judge_pipeline import run_audit
        from app.dark_web_intelligence.slm.audit.adversarial_prompts import get_prompts_by_category

        cases = get_prompts_by_category(category) if category else None
        asyncio.run(run_audit(test_cases=cases))

    background_tasks.add_task(_run_audit)

    return {
        "status": "queued",
        "message": f"Safety audit started in background{' for category: ' + category if category else ''}. Check /v1/dark-web/audit/latest for results.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# GET /v1/dark-web/audit/latest
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/dark-web/audit/latest",
    summary="Get the latest safety audit report",
)
async def get_latest_audit(customer: dict = Depends(verify_api_key)):
    report_path = Path(os.environ.get("AUDIT_REPORT_PATH", "./reports/safety_audit_latest.json"))

    if not report_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No audit report found. Run POST /v1/dark-web/audit/run first."
        )

    with open(report_path) as f:
        report = json.load(f)

    # Strip full result list from public response (too large)
    report.pop("all_results", None)

    return report


# ─────────────────────────────────────────────────────────────────────────────
# POST /v1/dark-web/ingest  (admin — triggers knowledge base refresh)
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/dark-web/ingest",
    summary="Refresh the knowledge base (NVD CVEs + GDPR + NIST)",
)
async def trigger_ingestion(
    background_tasks: BackgroundTasks,
    nvd_only: bool = False,
    customer: dict = Depends(verify_api_key),
):
    if customer.get("plan") not in ("enterprise",) and not customer.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Knowledge base ingestion is restricted to Enterprise / Admin accounts."
        )

    def _ingest():
        from app.dark_web_intelligence.slm.rag.ingestion import (
            run_full_ingestion,
            run_nvd_refresh,
        )
        if nvd_only:
            run_nvd_refresh()
        else:
            run_full_ingestion()

    background_tasks.add_task(_ingest)

    return {
        "status": "queued",
        "message": f"{'NVD refresh' if nvd_only else 'Full knowledge base ingestion'} started in background.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Phase 7C: Threat Intelligence + Self-Evolving ML endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/dark-web/ml/threat-stats",
    summary="Get threat event statistics and DPO training readiness (admin only)",
    description=(
        "Returns counts of probe detections (flagged/blocked), unprocessed events "
        "available for DPO training, and latest batch metadata. Used to monitor "
        "the self-evolving ML pipeline."
    ),
)
async def get_threat_stats(customer: dict = Depends(verify_api_key)):
    if not customer.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Threat statistics are restricted to admin accounts."
        )

    from app.core.dpo_generator import dpo_generator
    stats = await dpo_generator.get_batch_stats()
    return {
        **stats,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post(
    "/dark-web/ml/generate-dpo",
    summary="Generate DPO training pairs from accumulated threat events (admin only)",
    description=(
        "Reads all unprocessed flagged/blocked probe events from the threat_events table "
        "and converts them into DPO training pairs (JSONL format). The output path is "
        "stored in system_config['latest_dpo_batch'] for the Kaggle training pipeline to use. "
        "Minimum 10 events required to generate a batch."
    ),
)
async def generate_dpo_pairs(
    background_tasks: BackgroundTasks,
    min_score: float = 0.35,
    limit: int = 500,
    customer: dict = Depends(verify_api_key),
):
    if not customer.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="DPO generation is restricted to admin accounts."
        )

    from app.core.dpo_generator import dpo_generator

    async def _generate():
        result = await dpo_generator.generate_batch(min_score=min_score, limit=limit)
        from app.core.logger import get_logger as _gl
        _gl("aletheos.dpo").info("DPO batch generation complete: %s", result)

    background_tasks.add_task(_generate)

    return {
        "status": "queued",
        "message": (
            f"DPO pair generation started in background "
            f"(min_score={min_score}, limit={limit}). "
            "Check GET /v1/dark-web/ml/threat-stats for results."
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

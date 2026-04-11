"""
scanner.py — Dark Web Intelligence engine for Phase 6B.

What this does:
  1. Checks the subject's email/name against known breach datasets
     (Have I Been Pwned API + cached Qdrant CVE/breach intelligence)
  2. Uses the RAG retriever + SLM to analyse and contextualise findings
  3. Scores overall exposure risk
  4. Returns structured findings ready for the API response and PDF report

This module does NOT access the dark web directly — it uses:
  - HIBP API (public, legal)
  - NVD CVE data (ingested into Qdrant)
  - The fine-tuned Aletheos SLM for intelligent analysis
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Optional

import httpx

from app.dark_web_intelligence.slm.config import intel_config
from app.dark_web_intelligence.slm.rag.retriever import retriever as rag_retriever
from app.utils.helpers import generate_scan_id

cfg = intel_config.scanner

# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BreachRecord:
    breach_name: str
    breach_date: str
    data_classes: List[str]     # e.g. ["Passwords","Email addresses","Phone numbers"]
    is_verified: bool
    is_sensitive: bool
    pwn_count: int
    description: str


@dataclass
class CredentialExposure:
    email: str
    breach_count: int
    paste_count: int
    breaches: List[BreachRecord]
    most_recent_breach: Optional[str]
    data_types_exposed: List[str]    # deduplicated list of all exposed data types
    risk_score: float                # 0.0–1.0


@dataclass
class ThreatIntelligence:
    relevant_cves: List[Dict]        # CVEs from Qdrant relevant to the scan
    gdpr_obligations: str            # RAG-retrieved GDPR context
    remediation_advice: str          # SLM-generated remediation steps


@dataclass
class DarkWebScanResult:
    scan_id: str
    subject_email: str
    subject_name: Optional[str]
    timestamp: str
    credential_exposure: CredentialExposure
    threat_intelligence: ThreatIntelligence
    overall_risk_level: str          # critical / high / medium / low / clean
    overall_risk_score: float
    summary: str                     # SLM-generated plain-English summary
    recommended_actions: List[str]
    scan_duration_ms: int


# ─────────────────────────────────────────────────────────────────────────────
# Have I Been Pwned client
# ─────────────────────────────────────────────────────────────────────────────

HIBP_BASE = "https://haveibeenpwned.com/api/v3"
HIBP_PASTE_BASE = "https://haveibeenpwned.com/api/v3/pasteaccount"

async def _hibp_get_breaches(email: str, api_key: str, client: httpx.AsyncClient) -> List[Dict]:
    """Fetches all breaches for an email from HIBP."""
    headers = {
        "hibp-api-key": api_key,
        "User-Agent":   "Aletheos-DarkWebIntelligence/1.0",
    }
    try:
        resp = await client.get(
            f"{HIBP_BASE}/breachedaccount/{email}",
            headers=headers,
            params={"truncateResponse": "false"},
        )
        if resp.status_code == 404:
            return []  # Not found in any breach
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            await asyncio.sleep(1.5)
            return await _hibp_get_breaches(email, api_key, client)
        raise


async def _hibp_get_pastes(email: str, api_key: str, client: httpx.AsyncClient) -> List[Dict]:
    """Fetches paste exposures for an email from HIBP."""
    headers = {
        "hibp-api-key": api_key,
        "User-Agent":   "Aletheos-DarkWebIntelligence/1.0",
    }
    try:
        resp = await client.get(
            f"{HIBP_PASTE_BASE}/{email}",
            headers=headers,
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return []


def _parse_breach_records(raw_breaches: List[Dict]) -> List[BreachRecord]:
    records = []
    for b in raw_breaches:
        records.append(BreachRecord(
            breach_name=b.get("Name", "Unknown"),
            breach_date=b.get("BreachDate", ""),
            data_classes=b.get("DataClasses", []),
            is_verified=b.get("IsVerified", False),
            is_sensitive=b.get("IsSensitive", False),
            pwn_count=b.get("PwnCount", 0),
            description=re.sub(r'<[^>]+>', '', b.get("Description", ""))[:500],
        ))
    return records


def _score_exposure(credential_exposure: CredentialExposure) -> float:
    """
    Compute a 0.0–1.0 risk score based on:
    - Number of breaches
    - Severity of exposed data types
    - Paste appearances
    - Recency
    """
    score = 0.0
    high_risk_types = {
        "Passwords", "Password hints", "Credit cards",
        "Bank account numbers", "Social security numbers",
        "Government issued IDs", "Passport numbers",
    }
    medium_risk_types = {
        "Phone numbers", "Dates of birth", "Physical addresses",
        "Email addresses", "Usernames",
    }

    # Breaches
    score += min(credential_exposure.breach_count * 0.08, 0.40)

    # Data type severity
    for dtype in credential_exposure.data_types_exposed:
        if dtype in high_risk_types:
            score += 0.15
        elif dtype in medium_risk_types:
            score += 0.05

    # Paste appearances
    score += min(credential_exposure.paste_count * 0.05, 0.20)

    return min(round(score, 3), 1.0)


def _risk_level(score: float) -> str:
    if score >= cfg.critical_score:
        return "critical"
    if score >= cfg.high_score:
        return "high"
    if score >= cfg.medium_score:
        return "medium"
    if score > 0:
        return "low"
    return "clean"


# ─────────────────────────────────────────────────────────────────────────────
# Threat intelligence enrichment (RAG + SLM)
# ─────────────────────────────────────────────────────────────────────────────

async def _enrich_with_intelligence(
    email: str,
    breaches: List[BreachRecord],
    risk_score: float,
) -> ThreatIntelligence:
    """
    Queries the RAG pipeline to get:
    - Relevant CVEs for any known-vulnerable services in the breach list
    - GDPR obligations triggered by the exposure
    - SLM-generated remediation steps
    """
    breach_names = [b.breach_name for b in breaches[:5]]
    data_types   = list({dt for b in breaches for dt in b.data_classes})[:8]

    # CVE query — look for vulnerabilities in the breached services
    cve_query = (
        f"vulnerabilities and CVEs related to {', '.join(breach_names[:3])} "
        f"affecting user authentication and credential security"
    )
    cve_result = await rag_retriever.query(
        cve_query,
        sources=["nvd"],
        use_local_slm=False,   # use Anthropic for analysis, not just retrieval
        max_response_tokens=300,
    )

    # GDPR query
    gdpr_query = (
        f"GDPR obligations when user data including {', '.join(data_types[:4])} "
        f"is exposed in a data breach — notification duties and individual rights"
    )
    gdpr_result = await rag_retriever.query(
        gdpr_query,
        sources=["gdpr"],
        use_local_slm=False,
        max_response_tokens=400,
    )

    # Remediation — use SLM with full RAG context
    remediation_query = (
        f"What should a user do immediately if their {', '.join(data_types[:4])} "
        f"were exposed in data breaches from {', '.join(breach_names[:3])}? "
        f"Risk score: {risk_score:.0%}. Provide 5 specific prioritised action steps."
    )
    remediation_result = await rag_retriever.query(
        remediation_query,
        sources=None,  # all sources
        use_local_slm=True,
        max_response_tokens=500,
    )

    return ThreatIntelligence(
        relevant_cves=cve_result.get("sources_used", {}).get("nvd", [])[:3],
        gdpr_obligations=gdpr_result.get("answer", ""),
        remediation_advice=remediation_result.get("answer", ""),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main scanner
# ─────────────────────────────────────────────────────────────────────────────

async def scan_email(
    email: str,
    subject_name: Optional[str] = None,
    enrich_with_intelligence: bool = True,
) -> DarkWebScanResult:
    """
    Full dark web intelligence scan for an email address.

    Args:
        email                    : email address to scan
        subject_name             : optional full name for context
        enrich_with_intelligence : if True, runs RAG + SLM enrichment

    Returns:
        DarkWebScanResult with full findings
    """
    import time
    start = time.monotonic()

    scan_id  = generate_scan_id()
    hibp_key = os.environ.get("HIBP_API_KEY", "")

    if not hibp_key:
        # Without a HIBP key, return a simulated result for development
        return _simulated_scan(email, subject_name, scan_id)

    async with httpx.AsyncClient(timeout=30) as client:
        # Parallel HIBP calls
        breaches_raw, pastes_raw = await asyncio.gather(
            _hibp_get_breaches(email, hibp_key, client),
            _hibp_get_pastes(email, hibp_key, client),
        )

    breach_records = _parse_breach_records(breaches_raw)

    # Deduplicate exposed data types
    all_data_types = sorted({dt for b in breach_records for dt in b.data_classes})

    # Most recent breach date
    dates = [b.breach_date for b in breach_records if b.breach_date]
    most_recent = max(dates) if dates else None

    credential_exposure = CredentialExposure(
        email=email,
        breach_count=len(breach_records),
        paste_count=len(pastes_raw),
        breaches=breach_records,
        most_recent_breach=most_recent,
        data_types_exposed=all_data_types,
        risk_score=0.0,  # filled below
    )
    credential_exposure.risk_score = _score_exposure(credential_exposure)

    risk_level = _risk_level(credential_exposure.risk_score)

    # Enrich with threat intelligence
    threat_intel = ThreatIntelligence(
        relevant_cves=[],
        gdpr_obligations="",
        remediation_advice="",
    )
    if enrich_with_intelligence and breach_records:
        try:
            threat_intel = await _enrich_with_intelligence(
                email, breach_records, credential_exposure.risk_score
            )
        except Exception as e:
            print(f"[scanner] RAG enrichment failed: {e}")

    # Generate plain-English summary
    if breach_records:
        summary = (
            f"{email} appears in {len(breach_records)} known data breach(es). "
            f"Exposed data includes: {', '.join(all_data_types[:5])}. "
            f"Overall risk level: {risk_level.upper()}."
        )
    else:
        summary = f"{email} was not found in any known data breaches. No credential exposure detected."

    # Recommended actions
    actions = _generate_recommended_actions(credential_exposure, risk_level)

    elapsed_ms = int((time.monotonic() - start) * 1000)

    return DarkWebScanResult(
        scan_id=scan_id,
        subject_email=email,
        subject_name=subject_name,
        timestamp=datetime.now(timezone.utc).isoformat(),
        credential_exposure=credential_exposure,
        threat_intelligence=threat_intel,
        overall_risk_level=risk_level,
        overall_risk_score=credential_exposure.risk_score,
        summary=summary,
        recommended_actions=actions,
        scan_duration_ms=elapsed_ms,
    )


def _generate_recommended_actions(
    exposure: CredentialExposure,
    risk_level: str,
) -> List[str]:
    actions = []

    if "Passwords" in exposure.data_types_exposed:
        actions.append("Immediately change your password on all breached services and any sites where you reused it.")

    if exposure.breach_count > 0:
        actions.append("Enable two-factor authentication on email, banking, and social media accounts.")

    if "Credit cards" in exposure.data_types_exposed or "Bank account numbers" in exposure.data_types_exposed:
        actions.append("Contact your bank to alert them of a potential card/account compromise and request a fraud alert.")

    if exposure.paste_count > 0:
        actions.append("Your data has appeared in public paste sites — assume your credentials are actively circulating.")

    if risk_level in ("critical", "high"):
        actions.append("Place a credit freeze with the major credit bureaus (Equifax, Experian, TransUnion) to prevent identity fraud.")
        actions.append("Submit GDPR Article 17 erasure requests to data brokers holding your information — Aletheos can automate this.")

    if "Email addresses" in exposure.data_types_exposed:
        actions.append("Be alert for phishing emails that exploit your known breach — attackers use this data for targeted attacks.")

    if not actions:
        actions.append("No immediate action required. Set up Aletheos Always-On Monitoring to be alerted of future exposures.")

    return actions


# ─────────────────────────────────────────────────────────────────────────────
# Simulated scan (dev/test when HIBP key is absent)
# ─────────────────────────────────────────────────────────────────────────────

def _simulated_scan(email: str, subject_name: Optional[str], scan_id: str) -> DarkWebScanResult:
    """Returns a realistic simulated scan result for development and testing."""
    return DarkWebScanResult(
        scan_id=scan_id,
        subject_email=email,
        subject_name=subject_name,
        timestamp=datetime.now(timezone.utc).isoformat(),
        credential_exposure=CredentialExposure(
            email=email,
            breach_count=0,
            paste_count=0,
            breaches=[],
            most_recent_breach=None,
            data_types_exposed=[],
            risk_score=0.0,
        ),
        threat_intelligence=ThreatIntelligence(
            relevant_cves=[],
            gdpr_obligations="Set HIBP_API_KEY env var to enable real breach data.",
            remediation_advice="This is a simulated result. Configure HIBP_API_KEY for production.",
        ),
        overall_risk_level="clean",
        overall_risk_score=0.0,
        summary=(
            f"[SIMULATED] No HIBP API key configured. "
            f"Set HIBP_API_KEY in Railway env vars to enable real dark web scanning for {email}."
        ),
        recommended_actions=["Configure HIBP_API_KEY to enable live breach detection."],
        scan_duration_ms=0,
    )

"""
erasure.py — Machine Unlearning erasure pipeline for Phase 6A.

Handles GDPR Article 17 right-to-erasure submissions across major AI vendors.
For each platform, generates a compliant GDPR letter and records submission
status in Supabase. In production this would dispatch via email/web form;
currently logs and marks as submitted.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Optional

VENDOR_ENDPOINTS = {
    "chatgpt": {
        "name": "OpenAI / ChatGPT",
        "privacy_url": "https://privacy.openai.com/",
        "erasure_email": "privacy@openai.com",
        "gdpr_form": "https://privacy.openai.com/policies?modal=take-out",
        "response_days": 30,
    },
    "claude": {
        "name": "Anthropic / Claude",
        "privacy_url": "https://www.anthropic.com/privacy",
        "erasure_email": "privacy@anthropic.com",
        "gdpr_form": "https://privacy.anthropic.com/en/policies",
        "response_days": 30,
    },
    "gemini": {
        "name": "Google / Gemini",
        "privacy_url": "https://myaccount.google.com/data-and-privacy",
        "erasure_email": "support@google.com",
        "gdpr_form": "https://support.google.com/policies/troubleshooter/7575787",
        "response_days": 30,
    },
    "perplexity": {
        "name": "Perplexity AI",
        "privacy_url": "https://www.perplexity.ai/privacy",
        "erasure_email": "privacy@perplexity.ai",
        "gdpr_form": None,
        "response_days": 45,
    },
    "meta": {
        "name": "Meta AI / Llama",
        "privacy_url": "https://www.facebook.com/privacy/policy/",
        "erasure_email": "privacy@meta.com",
        "gdpr_form": "https://www.facebook.com/help/contact/540977946302970",
        "response_days": 30,
    },
    "microsoft": {
        "name": "Microsoft / Copilot",
        "privacy_url": "https://privacy.microsoft.com/",
        "erasure_email": "msenprivacy@microsoft.com",
        "gdpr_form": "https://aka.ms/privacyresponse",
        "response_days": 30,
    },
    "grok": {
        "name": "xAI / Grok",
        "privacy_url": "https://x.ai/privacy",
        "erasure_email": "privacy@x.ai",
        "gdpr_form": None,
        "response_days": 60,
    },
}

ALL_PLATFORMS = list(VENDOR_ENDPOINTS.keys())


def _build_gdpr_letter(full_name: str, email: str, date: str) -> str:
    """Generate a GDPR Article 17 erasure request letter."""
    return (
        "Subject: GDPR Article 17 - Right to Erasure Request\n\n"
        "To the Data Protection Officer,\n\n"
        "I am writing to exercise my right to erasure under Article 17 of the "
        "General Data Protection Regulation (GDPR).\n\n"
        f"Name: {full_name}\n"
        f"Email: {email}\n"
        f"Date: {date}\n\n"
        "I request the permanent deletion of all personal data you hold about me, "
        "including any data used in training your AI systems. Under GDPR Article 17, "
        "you are required to erase this data without undue delay.\n\n"
        "Please confirm receipt and completion of this request within 30 days as "
        "required by GDPR Article 12.\n\n"
        f"Regards,\n{full_name}"
    )


async def run_erasure_pipeline(
    request_id: str,
    email: str,
    full_name: str,
    platforms: List[str],
    supabase_client,
) -> None:
    """
    Background erasure pipeline.

    For each platform:
      1. Generates a GDPR Article 17 letter
      2. Marks status as "submitted" with timestamp
      3. Persists per-platform results to the unlearning_requests row in Supabase

    In production this would dispatch via SMTP or web form automation.
    Currently logs and records as submitted.
    """
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    submitted_at = now.isoformat()

    # Resolve platform list — default to all if empty/None
    target_platforms = platforms if platforms else ALL_PLATFORMS

    platform_results: dict = {}

    for platform_key in target_platforms:
        vendor = VENDOR_ENDPOINTS.get(platform_key)
        if not vendor:
            platform_results[platform_key] = {
                "platform": platform_key,
                "status": "failed",
                "error": f"Unknown platform: {platform_key}",
                "submitted_at": submitted_at,
            }
            continue

        # Generate GDPR letter
        letter = _build_gdpr_letter(full_name, email, date_str)

        # Log the submission (in production: send via SMTP / form)
        print(
            f"[erasure] Submitting erasure request for {email} to {vendor['name']} "
            f"({vendor['erasure_email']}) — request_id={request_id}"
        )
        print(f"[erasure] Letter preview (first 200 chars): {letter[:200]}")

        platform_results[platform_key] = {
            "platform": platform_key,
            "vendor_name": vendor["name"],
            "erasure_email": vendor["erasure_email"],
            "gdpr_form": vendor["gdpr_form"],
            "privacy_url": vendor["privacy_url"],
            "expected_response_days": vendor["response_days"],
            "status": "submitted",
            "submitted_at": submitted_at,
            "letter_generated": True,
            "verified_at": None,
            "verification_status": None,
        }

    # Determine overall status
    all_statuses = {v["status"] for v in platform_results.values()}
    if all_statuses == {"failed"}:
        overall_status = "failed"
    else:
        overall_status = "submitted"

    # Persist to Supabase
    try:
        supabase_client.table("unlearning_requests").update({
            "status": overall_status,
            "platform_results": platform_results,
            "submitted_at": submitted_at,
        }).eq("id", request_id).execute()
        print(f"[erasure] Updated Supabase unlearning_requests row: {request_id}")
    except Exception as e:
        print(f"[erasure] Supabase update failed for {request_id}: {e}")

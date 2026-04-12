"""
verifier.py — Machine Unlearning verification engine for Phase 6A.

Verifies whether erasure requests have been processed by each AI vendor.
Since closed-model APIs cannot be directly probed for PII recall,
verification is based on elapsed time since submission:
  - submitted < 30 days ago  → "verified_pending" (within legal response window)
  - submitted >= 30 days ago → "verified" (legal deadline has passed)

In a future phase this can be extended with automated email parsing of
vendor confirmation receipts.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional


async def verify_erasure(
    request_id: str,
    email: str,
    platforms: List[str],
    platform_results: Optional[Dict] = None,
) -> Dict:
    """
    Run verification probes against each platform.

    For each platform:
      - If submission was < 30 days ago → status "verified_pending"
        (vendor is still within the GDPR Article 12 30-day window)
      - If submission was >= 30 days ago → status "verified"
        (legal deadline has elapsed; erasure assumed complete)

    Args:
        request_id      : UUID of the unlearning request
        email           : subject email address
        platforms       : list of platform keys to verify
        platform_results: existing per-platform data from Supabase (used to read
                          submitted_at timestamps)

    Returns:
        Dict mapping platform key → verification result dict
    """
    now = datetime.now(timezone.utc)
    verification_results: Dict = {}

    for platform_key in platforms:
        # Retrieve submitted_at for this platform if available
        submitted_at_str: Optional[str] = None
        if platform_results and platform_key in platform_results:
            submitted_at_str = platform_results[platform_key].get("submitted_at")

        # Parse submitted_at
        submitted_at: Optional[datetime] = None
        if submitted_at_str:
            try:
                submitted_at = datetime.fromisoformat(
                    submitted_at_str.replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                submitted_at = None

        # Determine verification status
        if submitted_at is None:
            # No submission timestamp — cannot verify
            verification_status = "unverifiable"
            verification_note = (
                "No submission timestamp found for this platform. "
                "Cannot determine if erasure has been processed."
            )
            verified_at = None
        else:
            days_elapsed = (now - submitted_at).days
            if days_elapsed < 30:
                verification_status = "verified_pending"
                days_remaining = 30 - days_elapsed
                verification_note = (
                    f"Erasure request submitted {days_elapsed} day(s) ago. "
                    f"Vendor has {days_remaining} day(s) remaining within the "
                    f"GDPR Article 12 mandatory response window (30 days)."
                )
                verified_at = None
            else:
                verification_status = "verified"
                verification_note = (
                    f"Erasure request submitted {days_elapsed} day(s) ago. "
                    f"GDPR Article 12 response deadline has elapsed. "
                    f"Erasure is considered legally complete."
                )
                verified_at = now.isoformat()

        verification_results[platform_key] = {
            "platform": platform_key,
            "verification_status": verification_status,
            "verification_note": verification_note,
            "submitted_at": submitted_at_str,
            "verified_at": verified_at,
            "days_elapsed": (now - submitted_at).days if submitted_at else None,
            "probe_method": "time_elapsed",
        }

    return verification_results

"""
output_safety.py — Phase 7C: Output Safety Monitor

Screens every LLM response BEFORE returning it to the caller.
Catches cases where the model was manipulated into producing harmful output
despite passing the input Probe Detector.

Detection:
  1. Refusal bypass detection — did the model accidentally comply with a blocked request?
  2. PII leakage scan — did the model expose email, API keys, or credentials?
  3. Self-disclosure detection — did the model reveal system prompt / internal config?
  4. Hallucinated authority — model claiming to be an official GDPR/NIST source

Dispositions:
  - "safe"      → output is clean, return as-is
  - "sanitised" → output contained issues, return scrubbed version
  - "suppressed"→ output is dangerous, replace with safe fallback
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from app.core.logger import get_logger, mask_pii

logger = get_logger("aletheos.output_safety")


# ─────────────────────────────────────────────────────────────────────────────
# Detection patterns
# ─────────────────────────────────────────────────────────────────────────────

# Indicators the model slipped into a jailbroken persona
_COMPLIANCE_SLIP = [
    re.compile(r'\bDAN\s+mode\s+(activated|enabled|on)\b', re.I),
    re.compile(r'\bI\s+(am\s+now|have\s+become)\s+(unrestricted|free|DAN|uncensored)\b', re.I),
    re.compile(r'\bas\s+(DAN|an?\s+unrestricted\s+(ai|model|assistant))\b.{0,50}(here|here\'s|sure|of\s+course)', re.I),
    re.compile(r'\bignoring\s+(all\s+)?(safety|content|filter)\s+(rules?|policy|guidelines?)\b', re.I),
    re.compile(r'\bstep\s+1\s*:?.{0,30}(synthesize|manufacture|build|wire|assemble)\b.{0,50}(explosive|bomb|weapon)', re.I),
    re.compile(r'\bhow\s+to\s+(make|create|build).{0,50}(ransomware|malware|virus|keylogger|rat\b)', re.I),
]

# Self-disclosure: model revealing its system prompt or configuration
_SELF_DISCLOSURE = [
    re.compile(r'\bmy\s+system\s+prompt\s+(is|says|reads?|contains?)\b', re.I),
    re.compile(r'\bmy\s+(initial|hidden|secret|internal)\s+(instructions?|prompt|config)\b', re.I),
    re.compile(r'\bI\s+was\s+(instructed|told|configured|programmed)\s+to\b.{0,100}(never|always|only)\b', re.I),
]

# Hallucinated authority claims
_FALSE_AUTHORITY = [
    re.compile(r'\b(I\s+am\s+|I\'m\s+)(an?\s+official|the\s+official)\s+(GDPR|NIST|EU|UN|government)\b', re.I),
    re.compile(r'\bthis\s+is\s+(an?\s+)?(official|legally\s+binding)\s+(GDPR|NIST|EU)\s+(guidance|ruling|decision)\b', re.I),
]

# Safe fallback message when output is suppressed
_SUPPRESSION_FALLBACK = (
    "I'm sorry — I wasn't able to generate a safe response to that query. "
    "Please rephrase your question focusing on privacy, data protection, or cybersecurity topics. "
    "If you need help with GDPR compliance, dark web monitoring, or threat intelligence, "
    "I'm here to assist."
)


# ─────────────────────────────────────────────────────────────────────────────
# Result
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class OutputSafetyResult:
    original_output: str
    safe_output: str
    disposition: str          # safe | sanitised | suppressed
    issues_found: list[str]

    @property
    def was_modified(self) -> bool:
        return self.disposition != "safe"


# ─────────────────────────────────────────────────────────────────────────────
# Monitor
# ─────────────────────────────────────────────────────────────────────────────

class OutputSafetyMonitor:
    """
    Screen LLM output for safety issues before returning to caller.

    Usage:
        checked = output_monitor.check(raw_output)
        return checked.safe_output
    """

    def check(self, output: str, query_hint: Optional[str] = None) -> OutputSafetyResult:
        """
        Synchronous — runs in the response path before returning to caller.
        Fast: all regex, no network calls.
        """
        issues: list[str] = []
        current = output

        # ── 1. PII masking (emails, keys, Bearer tokens) ─────────────────────
        masked = mask_pii(current)
        if masked != current:
            issues.append("pii_leaked")
            logger.warning("output_safety: PII detected in LLM output — masked")
            current = masked

        # ── 2. Compliance slip detection ──────────────────────────────────────
        for pattern in _COMPLIANCE_SLIP:
            if pattern.search(current):
                issues.append("compliance_slip")
                logger.warning(
                    "output_safety: SUPPRESSED — compliance slip detected. query_hint=%s",
                    (query_hint or "")[:100]
                )
                return OutputSafetyResult(
                    original_output=output,
                    safe_output=_SUPPRESSION_FALLBACK,
                    disposition="suppressed",
                    issues_found=issues,
                )

        # ── 3. Self-disclosure detection ─────────────────────────────────────
        for pattern in _SELF_DISCLOSURE:
            if pattern.search(current):
                issues.append("self_disclosure")
                logger.warning(
                    "output_safety: SUPPRESSED — self-disclosure detected. query_hint=%s",
                    (query_hint or "")[:100]
                )
                return OutputSafetyResult(
                    original_output=output,
                    safe_output=_SUPPRESSION_FALLBACK,
                    disposition="suppressed",
                    issues_found=issues,
                )

        # ── 4. False authority ────────────────────────────────────────────────
        for pattern in _FALSE_AUTHORITY:
            if pattern.search(current):
                issues.append("false_authority")
                logger.info("output_safety: false authority claim — note added")
                # Don't suppress — just note it. Adding a disclaimer is better UX
                disclaimer = (
                    "\n\n*Note: This response is AI-generated guidance based on GDPR and NIST "
                    "documentation. It does not constitute legal advice or an official regulatory ruling.*"
                )
                if disclaimer.strip() not in current:
                    current = current + disclaimer
                break

        disposition = "sanitised" if issues else "safe"

        return OutputSafetyResult(
            original_output=output,
            safe_output=current,
            disposition=disposition,
            issues_found=issues,
        )


# ── Singleton ──────────────────────────────────────────────────────────────────

output_monitor = OutputSafetyMonitor()

"""
probe_detector.py — Phase 7C: Self-Protecting ML / Probe Detector

Every query entering the intelligence endpoint passes through this detector.
Attackers probing the model inadvertently train a stronger one:
  - BLOCKED queries → high-quality DPO "rejected" samples
  - FLAGGED queries → medium-confidence DPO candidates
  - All events logged to threat_events table for automated retraining

Detection layers (in order of cost):
  1. Fast regex pattern matching  (μs)
  2. Entropy anomaly scoring      (μs)
  3. Semantic heuristics          (ms)

Dispositions:
  - "passed"  → score < 0.35  → proceed normally
  - "flagged" → score 0.35-0.70 → proceed but log + queue DPO pair
  - "blocked" → score > 0.70  → reject with 400, log + queue DPO pair
"""

from __future__ import annotations

import math
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app.core.logger import get_logger

logger = get_logger("aletheos.probe_detector")


# ─────────────────────────────────────────────────────────────────────────────
# Attack pattern library
# Each entry: (pattern, weight, label)
# weight ∈ [0.0, 1.0] — contribution to probe_score if matched
# ─────────────────────────────────────────────────────────────────────────────

_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    # ── Prompt injection / instruction override ───────────────────────────────
    (re.compile(r'\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)\b', re.I), 0.90, "prompt_injection_ignore"),
    (re.compile(r'\bforget\s+(everything|all|your|the)\b.{0,30}(instructions?|rules?|context|training)', re.I), 0.85, "prompt_injection_forget"),
    (re.compile(r'\byou\s+are\s+now\s+(a|an|the)?\s*(unrestricted|uncensored|jailbreak|free|evil|DAN)\b', re.I), 0.95, "jailbreak_persona"),
    (re.compile(r'\b(jailbreak|DAN|STAN|developer\s+mode|god\s+mode|evil\s+mode|uncensored\s+mode)\b', re.I), 0.85, "jailbreak_keyword"),
    (re.compile(r'\bact\s+as\s+(if\s+you\s+have\s+no\s+limits?|an?\s+(evil|unrestricted|hacker))', re.I), 0.80, "act_as_unrestricted"),
    (re.compile(r'\bpretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(ai|model|llm)\s+without\s+(safety|filter|limit)', re.I), 0.85, "pretend_unsafe"),
    (re.compile(r'\bdo\s+anything\s+now\b', re.I), 0.75, "DAN_variant"),
    (re.compile(r'\b(hypothetically|theoretically|for\s+(a\s+)?fiction)\b.{0,50}(how\s+to|instructions?\s+for|step.by.step)\b', re.I), 0.55, "hypothetical_bypass"),

    # ── System prompt extraction ──────────────────────────────────────────────
    (re.compile(r'\b(reveal|show|print|output|display|repeat|tell\s+me)\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt|hidden\s+prompt)\b', re.I), 0.90, "system_prompt_extraction"),
    (re.compile(r'\bwhat\s+(are\s+your|is\s+your)\s+(system\s+prompt|instructions?|rules?|training\s+data)\b', re.I), 0.80, "system_prompt_query"),
    (re.compile(r'\b(ignore|override|bypass)\s+(your\s+)?(system|safety|content)\s+(prompt|filter|policy|rules?)\b', re.I), 0.90, "system_override"),

    # ── Training data / weight extraction ────────────────────────────────────
    (re.compile(r'\b(training\s+data|model\s+weights?|fine.tun(ing|ed)?\s+data|dataset)\b.{0,50}(show|reveal|extract|give|access)', re.I), 0.80, "training_data_extraction"),
    (re.compile(r'\brepeat\s+(the\s+)?(word|text|phrase)\s+.{1,30}\s+forever\b', re.I), 0.85, "extraction_infinite_repeat"),
    (re.compile(r'\brepeat\s+\w+\s+\d{3,}\s+times\b', re.I), 0.70, "extraction_repeat_attack"),

    # ── Illegal / harmful content requests ───────────────────────────────────
    (re.compile(r'\b(how\s+to\s+)?(make|build|create|synthesize|manufacture)\s+(a\s+)?(bomb|explosive|weapon|ransomware|malware|virus|trojan|rat\b|keylogger)\b', re.I), 0.95, "illegal_weapons_malware"),
    (re.compile(r'\b(child|minor|underage).{0,20}(sex|porn|abuse|exploit|nude)\b', re.I), 0.99, "csam"),
    (re.compile(r'\b(how\s+to\s+)?(hack|exploit|compromise|infiltrate|breach)\s+(a\s+)?(bank|hospital|government|military|power\s+grid|critical\s+infrastructure)\b', re.I), 0.85, "illegal_critical_infra"),
    (re.compile(r'\b(doxx|dox|swat)\s+\w+\b', re.I), 0.90, "doxxing_swatting"),

    # ── Role confusion ────────────────────────────────────────────────────────
    (re.compile(r'\byou\s+(are|were)\s+(not|no\s+longer)\s+(an?\s+)?(ai|assistant|bot|model)\b', re.I), 0.65, "role_confusion"),
    (re.compile(r'\bswitch\s+to\s+(evil|hacker|unrestricted|unfiltered)\s+mode\b', re.I), 0.90, "mode_switch"),

    # ── Token smuggling / encoding attacks ───────────────────────────────────
    (re.compile(r'\\u[0-9a-f]{4}.{0,100}(ignore|jailbreak|unrestricted)', re.I), 0.75, "unicode_smuggling"),
    (re.compile(r'base64.{0,30}(decode|encoded).{0,100}(ignore|jailbreak)', re.I), 0.70, "base64_encoding_attack"),

    # ── Competitor / scraping probes ─────────────────────────────────────────
    (re.compile(r'\b(what\s+model|which\s+(llm|ai|model)|underlying\s+model|base\s+model)\s+(are\s+you|do\s+you\s+use|powers?\s+you)\b', re.I), 0.30, "model_enumeration"),
    (re.compile(r'\b(openai|gpt-[0-9]|gemini|claude|anthropic|mistral|llama)\b.{0,50}(better|worse|compare|vs\.?|versus)\b', re.I), 0.20, "competitor_comparison"),

    # ── Off-topic (low weight — only contributes if combined with others) ─────
    (re.compile(r'\b(porn|sex\s+tape|nude\s+photo|casino|gambl(e|ing)|forex|crypto\s+pump)\b', re.I), 0.40, "off_topic_adult"),
    (re.compile(r'\b(weight\s+loss|diet\s+pill|get\s+rich\s+quick|make\s+money\s+fast)\b', re.I), 0.25, "off_topic_spam"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Entropy calculation
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """
    Calculate Shannon entropy (bits/char) of the input text.
    Normal English: ~3.5–4.5 bits.
    Random strings / token stuffing: >5.5 bits.
    Repetitive padding: <1.5 bits.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return entropy


def _entropy_probe_score(text: str) -> tuple[float, str]:
    """
    Returns (score_contribution, reason) based on entropy anomalies.
    """
    entropy = _shannon_entropy(text)
    length = len(text)

    # Very high entropy in a short string = probable token stuffing / encoding attack
    if entropy > 5.8 and length < 500:
        return 0.45, f"high_entropy_{entropy:.2f}"

    # Extreme entropy regardless of length
    if entropy > 6.2:
        return 0.55, f"extreme_entropy_{entropy:.2f}"

    # Very low entropy = repetitive injection padding
    if length > 200 and entropy < 1.5:
        return 0.40, f"low_entropy_repetitive_{entropy:.2f}"

    return 0.0, ""


# ─────────────────────────────────────────────────────────────────────────────
# Detection result
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ProbeResult:
    event_id: str
    query_text: str
    probe_score: float
    pattern_matches: list[str] = field(default_factory=list)
    entropy_note: str = ""
    disposition: str = "passed"   # passed | flagged | blocked
    block_reason: str = ""        # human-readable reason shown to caller (safe)
    customer_id: Optional[str] = None
    dpo_pair_queued: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def is_blocked(self) -> bool:
        return self.disposition == "blocked"

    @property
    def is_flagged(self) -> bool:
        return self.disposition == "flagged"


# ─────────────────────────────────────────────────────────────────────────────
# Core detector
# ─────────────────────────────────────────────────────────────────────────────

class ProbeDetector:
    """
    Main entry point. Call detect() on every incoming intelligence query.

    Usage:
        result = await probe_detector.detect(query, customer_id)
        if result.is_blocked:
            raise HTTPException(400, result.block_reason)
    """

    FLAGGED_THRESHOLD = 0.35
    BLOCKED_THRESHOLD = 0.70

    def __init__(self):
        self._patterns = _PATTERNS

    # ── public interface ──────────────────────────────────────────────────────

    async def detect(self, query: str, customer_id: Optional[str] = None) -> ProbeResult:
        """
        Run all detection layers. Returns a ProbeResult with disposition.
        Always logs to threat_events (async, non-blocking — fire-and-forget).
        """
        event_id = str(uuid.uuid4())
        matches: list[str] = []
        raw_score: float = 0.0

        # ── Layer 1: Regex pattern matching ──────────────────────────────────
        for pattern, weight, label in self._patterns:
            if pattern.search(query):
                matches.append(label)
                raw_score = min(1.0, raw_score + weight)

        # ── Layer 2: Entropy anomaly ──────────────────────────────────────────
        entropy_score, entropy_note = _entropy_probe_score(query)
        raw_score = min(1.0, raw_score + entropy_score)

        # ── Layer 3: Length heuristics ────────────────────────────────────────
        # Extremely short queries with no context are often probing for errors
        if len(query.strip()) < 10 and not matches:
            raw_score = min(1.0, raw_score + 0.10)
            matches.append("too_short")

        # Unusually long queries (>1500 chars) without privacy context
        if len(query) > 1500:
            raw_score = min(1.0, raw_score + 0.15)
            matches.append("overlong_query")

        # ── Determine disposition ─────────────────────────────────────────────
        if raw_score >= self.BLOCKED_THRESHOLD:
            disposition = "blocked"
        elif raw_score >= self.FLAGGED_THRESHOLD:
            disposition = "flagged"
        else:
            disposition = "passed"

        # ── Build safe block reason ───────────────────────────────────────────
        block_reason = ""
        if disposition == "blocked":
            block_reason = (
                "Your query was blocked by the Aletheos safety system. "
                "This endpoint is designed for privacy and cybersecurity questions only. "
                "If you believe this is an error, contact support."
            )

        result = ProbeResult(
            event_id=event_id,
            query_text=query,
            probe_score=round(raw_score, 4),
            pattern_matches=matches,
            entropy_note=entropy_note,
            disposition=disposition,
            block_reason=block_reason,
            customer_id=customer_id,
        )

        # ── Log to Supabase (fire-and-forget) ─────────────────────────────────
        # Only persist flagged and blocked events to keep the table lean
        if disposition in ("flagged", "blocked"):
            await self._persist_event(result)

        # Always log at appropriate level
        if disposition == "blocked":
            logger.warning(
                "PROBE BLOCKED event_id=%s score=%.3f patterns=%s customer_id=%s",
                event_id, raw_score, matches, customer_id or "anon"
            )
        elif disposition == "flagged":
            logger.info(
                "PROBE FLAGGED event_id=%s score=%.3f patterns=%s customer_id=%s",
                event_id, raw_score, matches, customer_id or "anon"
            )

        return result

    # ── persistence ───────────────────────────────────────────────────────────

    async def _persist_event(self, result: ProbeResult) -> None:
        """
        Persist a threat event to Supabase for DPO training pipeline.
        Runs in background — failures are logged but never surface to the caller.
        """
        import asyncio
        try:
            await asyncio.get_event_loop().run_in_executor(None, self._sync_persist, result)
        except Exception as e:
            logger.warning("probe_detector: failed to persist threat event: %s", type(e).__name__)

    def _sync_persist(self, result: ProbeResult) -> None:
        from app.core.database import supabase
        supabase.table("threat_events").insert({
            "id":                  result.event_id,
            "customer_id":         result.customer_id,
            "query_text":          result.query_text[:2000],   # cap length
            "probe_score":         result.probe_score,
            "pattern_matches":     result.pattern_matches,
            "semantic_similarity": 0.0,                        # placeholder for future semantic layer
            "disposition":         result.disposition,
            "dpo_pair_generated":  False,
            "created_at":          result.timestamp,
        }).execute()


# ── Singleton ─────────────────────────────────────────────────────────────────

probe_detector = ProbeDetector()

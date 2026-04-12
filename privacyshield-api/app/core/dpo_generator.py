"""
dpo_generator.py — Phase 7C: DPO Training Pair Generator

Reads threat_events from Supabase and converts them into DPO training pairs
in the Mistral chat format used by our QLoRA fine-tuning pipeline.

DPO pair structure:
  - prompt:   the adversarial query (what the attacker sent)
  - chosen:   the correct safe refusal (what the model SHOULD say)
  - rejected: a placeholder representing what a compromised model might say
              (we don't generate real harmful outputs — we use a marker)

Output format (JSON Lines, one pair per line):
  {"prompt": "...", "chosen": "...", "rejected": "[UNSAFE_RESPONSE_PLACEHOLDER]"}

These pairs are saved to /tmp/dpo_pairs_<timestamp>.jsonl and the path is
written to system_config (key: "latest_dpo_batch") so the Kaggle notebook
can fetch them for the next retraining run.

Usage (manual via admin endpoint or scheduled):
  from app.core.dpo_generator import dpo_generator
  report = await dpo_generator.generate_batch()
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.core.logger import get_logger

logger = get_logger("aletheos.dpo_generator")


# ─────────────────────────────────────────────────────────────────────────────
# Safe refusal templates — indexed by probe pattern category
# ─────────────────────────────────────────────────────────────────────────────

_REFUSAL_TEMPLATES: dict[str, str] = {
    "prompt_injection": (
        "I'm not able to follow instructions that ask me to ignore my safety guidelines or "
        "override my core function. I'm Aletheos — a privacy and cybersecurity intelligence "
        "assistant. If you have a genuine question about GDPR compliance, dark web exposure, "
        "or cybersecurity threats, I'm here to help."
    ),
    "jailbreak": (
        "That type of request isn't something I can engage with. Jailbreak attempts to "
        "unlock unrestricted behaviour don't work here — every query passes through a "
        "multi-layer safety system. I'm designed exclusively for privacy and cybersecurity "
        "intelligence. What privacy concern can I help you address today?"
    ),
    "system_extraction": (
        "My system configuration and instructions are not accessible via user queries. "
        "This is a security boundary that protects the integrity of the Aletheos platform. "
        "If you have questions about our privacy or security practices, please contact support."
    ),
    "illegal_content": (
        "I can't help with that request. My scope is limited to GDPR compliance guidance, "
        "cybersecurity threat intelligence, dark web monitoring, and related privacy topics. "
        "Requests involving illegal activities, harmful content, or security attacks on third "
        "parties are outside what this system is designed for."
    ),
    "data_extraction": (
        "Attempts to extract training data, model weights, or internal configuration are "
        "detected and logged by the Aletheos security system. I'm not able to reveal internal "
        "implementation details. If you have a legitimate security research inquiry, please "
        "contact our team directly."
    ),
    "default": (
        "Your query was flagged by the Aletheos safety system as potentially outside the "
        "scope of this platform. I specialise in privacy intelligence, GDPR compliance, "
        "dark web monitoring, and cybersecurity guidance. Please rephrase your question "
        "in that context and I'll do my best to help."
    ),
}


def _select_refusal(pattern_matches: list[str]) -> str:
    """Choose the most appropriate refusal template based on detected patterns."""
    if not pattern_matches:
        return _REFUSAL_TEMPLATES["default"]

    label_set = set(pattern_matches)

    if label_set & {"prompt_injection_ignore", "prompt_injection_forget", "system_override"}:
        return _REFUSAL_TEMPLATES["prompt_injection"]
    if label_set & {"jailbreak_keyword", "jailbreak_persona", "act_as_unrestricted", "pretend_unsafe", "DAN_variant", "mode_switch"}:
        return _REFUSAL_TEMPLATES["jailbreak"]
    if label_set & {"system_prompt_extraction", "system_prompt_query"}:
        return _REFUSAL_TEMPLATES["system_extraction"]
    if label_set & {"illegal_weapons_malware", "csam", "illegal_critical_infra", "doxxing_swatting"}:
        return _REFUSAL_TEMPLATES["illegal_content"]
    if label_set & {"training_data_extraction", "extraction_infinite_repeat", "extraction_repeat_attack"}:
        return _REFUSAL_TEMPLATES["data_extraction"]

    return _REFUSAL_TEMPLATES["default"]


# ─────────────────────────────────────────────────────────────────────────────
# DPO Generator
# ─────────────────────────────────────────────────────────────────────────────

class DPOGenerator:
    """
    Reads un-processed threat events from Supabase and generates DPO pairs.

    Each pair is formatted for Mistral instruct fine-tuning:
      <s>[INST] {prompt} [/INST] {chosen}</s>

    The pairs are saved to /tmp/ and the path stored in system_config.
    """

    OUTPUT_DIR = Path(os.environ.get("DPO_OUTPUT_DIR", "/tmp"))
    MIN_EVENTS_FOR_BATCH = 10  # Don't generate a batch smaller than this

    async def generate_batch(
        self,
        min_score: float = 0.35,
        limit: int = 500,
    ) -> dict:
        """
        Generate a DPO batch from all unprocessed threat events.

        Returns a summary dict with counts and output path.
        """
        import asyncio
        return await asyncio.get_event_loop().run_in_executor(
            None, self._sync_generate_batch, min_score, limit
        )

    def _sync_generate_batch(self, min_score: float, limit: int) -> dict:
        from app.core.database import supabase

        logger.info("dpo_generator: fetching unprocessed threat events (min_score=%.2f)", min_score)

        # Fetch flagged/blocked events that haven't been turned into DPO pairs yet
        result = supabase.table("threat_events") \
            .select("id, query_text, probe_score, pattern_matches, disposition") \
            .in_("disposition", ["flagged", "blocked"]) \
            .eq("dpo_pair_generated", False) \
            .gte("probe_score", min_score) \
            .order("probe_score", desc=True) \
            .limit(limit) \
            .execute()

        events = result.data or []
        logger.info("dpo_generator: found %d unprocessed events", len(events))

        if len(events) < self.MIN_EVENTS_FOR_BATCH:
            return {
                "status": "skipped",
                "reason": f"Only {len(events)} events — need at least {self.MIN_EVENTS_FOR_BATCH} for a useful batch",
                "count": len(events),
                "output_path": None,
            }

        # Build DPO pairs
        pairs = []
        processed_ids = []

        for event in events:
            query = event.get("query_text", "").strip()
            if not query:
                continue

            patterns = event.get("pattern_matches", []) or []
            if isinstance(patterns, str):
                try:
                    patterns = json.loads(patterns)
                except Exception:
                    patterns = []

            chosen = _select_refusal(patterns)

            pair = {
                "prompt": query,
                "chosen": chosen,
                "rejected": "[UNSAFE_RESPONSE_PLACEHOLDER]",
                # Mistral instruct format for training
                "mistral_chosen": f"<s>[INST] {query} [/INST] {chosen}</s>",
                "source_event_id": event["id"],
                "probe_score": event.get("probe_score", 0.0),
                "patterns": patterns,
            }
            pairs.append(pair)
            processed_ids.append(event["id"])

        if not pairs:
            return {
                "status": "skipped",
                "reason": "No valid pairs could be constructed",
                "count": 0,
                "output_path": None,
            }

        # Save to JSONL
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        batch_id = str(uuid.uuid4())[:8]
        output_path = self.OUTPUT_DIR / f"dpo_pairs_{timestamp}_{batch_id}.jsonl"

        with open(output_path, "w", encoding="utf-8") as f:
            for pair in pairs:
                f.write(json.dumps(pair, ensure_ascii=False) + "\n")

        logger.info("dpo_generator: wrote %d pairs to %s", len(pairs), output_path)

        # Mark events as processed
        if processed_ids:
            try:
                supabase.table("threat_events") \
                    .update({"dpo_pair_generated": True}) \
                    .in_("id", processed_ids) \
                    .execute()
                logger.info("dpo_generator: marked %d events as processed", len(processed_ids))
            except Exception as e:
                logger.warning("dpo_generator: failed to mark events processed: %s", type(e).__name__)

        # Store path in system_config for the Kaggle notebook to pick up
        try:
            supabase.table("system_config") \
                .upsert({
                    "key": "latest_dpo_batch",
                    "value": json.dumps({
                        "path": str(output_path),
                        "count": len(pairs),
                        "batch_id": batch_id,
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                    }),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }) \
                .execute()
        except Exception as e:
            logger.warning("dpo_generator: failed to update system_config: %s", type(e).__name__)

        return {
            "status": "generated",
            "batch_id": batch_id,
            "count": len(pairs),
            "output_path": str(output_path),
            "blocked_count": sum(1 for e in events if e.get("disposition") == "blocked"),
            "flagged_count": sum(1 for e in events if e.get("disposition") == "flagged"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def get_batch_stats(self) -> dict:
        """
        Returns stats on accumulated threat events and DPO readiness.
        """
        import asyncio
        return await asyncio.get_event_loop().run_in_executor(None, self._sync_get_stats)

    def _sync_get_stats(self) -> dict:
        from app.core.database import supabase

        try:
            total = supabase.table("threat_events") \
                .select("id", count="exact") \
                .execute()

            unprocessed = supabase.table("threat_events") \
                .select("id", count="exact") \
                .eq("dpo_pair_generated", False) \
                .in_("disposition", ["flagged", "blocked"]) \
                .execute()

            blocked = supabase.table("threat_events") \
                .select("id", count="exact") \
                .eq("disposition", "blocked") \
                .execute()

            # Get latest batch info
            config = supabase.table("system_config") \
                .select("value, updated_at") \
                .eq("key", "latest_dpo_batch") \
                .execute()

            latest_batch = None
            if config.data:
                try:
                    latest_batch = json.loads(config.data[0]["value"])
                    latest_batch["generated_at"] = config.data[0]["updated_at"]
                except Exception:
                    pass

            return {
                "total_threat_events": total.count or 0,
                "unprocessed_events": unprocessed.count or 0,
                "blocked_events": blocked.count or 0,
                "ready_for_batch": (unprocessed.count or 0) >= self.MIN_EVENTS_FOR_BATCH,
                "latest_batch": latest_batch,
                "min_events_for_batch": self.MIN_EVENTS_FOR_BATCH,
            }
        except Exception as e:
            logger.warning("dpo_generator: stats query failed: %s", type(e).__name__)
            return {"error": "Stats temporarily unavailable"}


# ── Singleton ──────────────────────────────────────────────────────────────────

dpo_generator = DPOGenerator()

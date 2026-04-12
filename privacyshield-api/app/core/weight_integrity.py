"""
weight_integrity.py — Phase 7C: Model Weight Integrity Checker

When the Aletheos SLM loads a fine-tuned LoRA adapter from HuggingFace,
this module verifies the adapter's SHA-256 checksum against the known-good
value stored in system_config. If the checksum doesn't match, the adapter
is rejected and inference falls back to the base waterfall (Groq → CF → Together → Anthropic).

Why this matters:
  - Prevents supply chain attacks (tampered adapter weights served via HF)
  - Detects accidental corruption of adapter files during download
  - Provides an audit trail of every adapter version loaded

Usage:
    from app.core.weight_integrity import weight_checker
    ok, info = await weight_checker.verify_adapter(adapter_path)
    if not ok:
        logger.error("Adapter integrity check FAILED — falling back to base inference")
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.core.logger import get_logger

logger = get_logger("aletheos.weight_integrity")


class WeightIntegrityChecker:
    """
    Verifies LoRA adapter file checksums against values stored in system_config.

    System config keys:
      "adapter_checksum_sha256"    — hex digest of the expected adapter.safetensors
      "adapter_version"            — human-readable version tag
      "adapter_verified_at"        — last successful verification timestamp
    """

    CHECKSUM_KEY = "adapter_checksum_sha256"
    VERSION_KEY  = "adapter_version"
    VERIFIED_KEY = "adapter_verified_at"

    # ── public interface ──────────────────────────────────────────────────────

    async def verify_adapter(
        self,
        adapter_path: str | Path,
        expected_checksum: Optional[str] = None,
    ) -> tuple[bool, dict]:
        """
        Verify the adapter at adapter_path.

        Returns (True, info_dict) if valid, (False, info_dict) if not.
        If expected_checksum is not provided, fetches from system_config.
        """
        import asyncio
        return await asyncio.get_event_loop().run_in_executor(
            None, self._sync_verify, Path(adapter_path), expected_checksum
        )

    def _sync_verify(
        self,
        adapter_path: Path,
        expected_checksum: Optional[str],
    ) -> tuple[bool, dict]:

        if not adapter_path.exists():
            logger.error("weight_integrity: adapter not found at %s", adapter_path)
            return False, {"error": "adapter_not_found", "path": str(adapter_path)}

        # Calculate actual checksum
        actual_checksum = self._sha256(adapter_path)
        logger.info("weight_integrity: calculated SHA-256 = %s...%s", actual_checksum[:8], actual_checksum[-8:])

        # Fetch expected checksum
        if expected_checksum is None:
            expected_checksum = self._fetch_expected_checksum()

        if expected_checksum is None:
            # No reference checksum stored — register this as the baseline (first load)
            logger.warning(
                "weight_integrity: no reference checksum found — registering current adapter as baseline. "
                "This should only happen on first load of a new adapter version."
            )
            self._register_checksum(actual_checksum, adapter_path)
            return True, {
                "status": "registered",
                "checksum": actual_checksum,
                "adapter": str(adapter_path),
                "note": "First-load baseline registered",
            }

        # Compare
        if actual_checksum == expected_checksum:
            self._record_verification(actual_checksum)
            logger.info("weight_integrity: PASS — adapter checksum verified")
            return True, {
                "status": "verified",
                "checksum": actual_checksum,
                "adapter": str(adapter_path),
            }
        else:
            logger.error(
                "weight_integrity: FAIL — checksum mismatch! "
                "expected=%s...%s actual=%s...%s",
                expected_checksum[:8], expected_checksum[-8:],
                actual_checksum[:8], actual_checksum[-8:],
            )
            return False, {
                "status": "mismatch",
                "expected": expected_checksum[:16] + "...",
                "actual": actual_checksum[:16] + "...",
                "adapter": str(adapter_path),
            }

    # ── register a new adapter (called when pushing a new trained version) ─────

    async def register_adapter(
        self,
        adapter_path: str | Path,
        version_tag: str,
    ) -> dict:
        """
        Calculate and store the checksum for a newly trained adapter.
        Call this from the Kaggle training pipeline after a successful training run.
        """
        import asyncio
        return await asyncio.get_event_loop().run_in_executor(
            None, self._sync_register, Path(adapter_path), version_tag
        )

    def _sync_register(self, adapter_path: Path, version_tag: str) -> dict:
        if not adapter_path.exists():
            return {"error": "adapter_not_found"}

        checksum = self._sha256(adapter_path)
        self._register_checksum(checksum, adapter_path, version_tag)

        logger.info("weight_integrity: registered adapter version=%s checksum=%s...%s",
                    version_tag, checksum[:8], checksum[-8:])

        return {
            "status": "registered",
            "version": version_tag,
            "checksum": checksum,
            "adapter": str(adapter_path),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ── helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def _fetch_expected_checksum(self) -> Optional[str]:
        try:
            from app.core.database import supabase
            result = supabase.table("system_config") \
                .select("value") \
                .eq("key", self.CHECKSUM_KEY) \
                .execute()
            if result.data:
                return result.data[0]["value"]
        except Exception as e:
            logger.warning("weight_integrity: failed to fetch checksum from DB: %s", type(e).__name__)
        return None

    def _register_checksum(
        self,
        checksum: str,
        adapter_path: Path,
        version_tag: str = "auto",
    ) -> None:
        try:
            from app.core.database import supabase
            now = datetime.now(timezone.utc).isoformat()
            rows = [
                {"key": self.CHECKSUM_KEY, "value": checksum,   "updated_at": now},
                {"key": self.VERSION_KEY,  "value": version_tag, "updated_at": now},
                {"key": self.VERIFIED_KEY, "value": now,         "updated_at": now},
            ]
            for row in rows:
                supabase.table("system_config").upsert(row).execute()
        except Exception as e:
            logger.warning("weight_integrity: failed to register checksum: %s", type(e).__name__)

    def _record_verification(self, checksum: str) -> None:
        try:
            from app.core.database import supabase
            now = datetime.now(timezone.utc).isoformat()
            supabase.table("system_config") \
                .upsert({"key": self.VERIFIED_KEY, "value": now, "updated_at": now}) \
                .execute()
        except Exception as e:
            logger.warning("weight_integrity: failed to record verification: %s", type(e).__name__)


# ── Singleton ──────────────────────────────────────────────────────────────────

weight_checker = WeightIntegrityChecker()

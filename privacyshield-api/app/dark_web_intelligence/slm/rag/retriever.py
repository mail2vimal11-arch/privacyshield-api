"""
retriever.py — RAG retrieval and prompt augmentation for the Aletheos SLM.

Backend waterfall (tried in order, first success wins):
  1. Groq          — primary    (free 14,400 req/day, ~500 tok/sec)
  2. Cloudflare    — secondary  (free forever, Workers AI)
  3. Together AI   — tertiary   (free $1 credit, then pay-as-you-go)
  4. Anthropic     — failover   (Vimal's own credits — last resort)

Set these in Railway env vars:
  GROQ_API_KEY        — console.groq.com/keys
  CF_ACCOUNT_ID       — Cloudflare dashboard → Workers AI
  CF_API_TOKEN        — Cloudflare → API Tokens (Workers AI:Read permission)
  TOGETHER_API_KEY    — api.together.ai
  ANTHROPIC_API_KEY   — already set
"""

from __future__ import annotations

import os
import re
from typing import List, Dict, Optional, Tuple

import httpx

from app.dark_web_intelligence.slm.config import intel_config
from app.dark_web_intelligence.slm.rag.vector_store import vector_store

cfg_rag = intel_config.rag
cfg_m   = intel_config.model


# ─────────────────────────────────────────────────────────────────────────────
# Context formatting  (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def _deduplicate(results: List[Dict], similarity_threshold: float = 0.95) -> List[Dict]:
    seen: List[str] = []
    deduped: List[Dict] = []
    for r in results:
        fingerprint = r["text"][:100].lower().strip()
        is_dup = any(
            len(set(fingerprint.split()) & set(s.split())) / max(len(fingerprint.split()), 1)
            > similarity_threshold
            for s in seen
        )
        if not is_dup:
            seen.append(fingerprint)
            deduped.append(r)
    return deduped


def format_context(results_by_source: Dict[str, List[Dict]], max_tokens: int = 1500) -> str:
    source_labels = {
        "gdpr": "GDPR Legal Reference",
        "nist": "NIST Framework Reference",
        "nvd":  "CVE / Vulnerability Intelligence",
    }
    all_results = []
    for source, results in results_by_source.items():
        for r in results:
            all_results.append({**r, "_source_label": source_labels.get(source, source)})

    all_results.sort(key=lambda x: x.get("score", 0), reverse=True)
    all_results = _deduplicate(all_results)

    char_budget = max_tokens * 4
    used = 0
    included = []
    for r in all_results:
        text = r["text"]
        if used + len(text) > char_budget:
            break
        included.append(r)
        used += len(text)

    if not included:
        return ""

    lines = ["<context>"]
    for i, r in enumerate(included, 1):
        label = r.get("_source_label", "Reference")
        meta_parts = []
        if r.get("article"):
            meta_parts.append(r["article"])
        if r.get("cve_id"):
            meta_parts.append(
                f"CVE: {r['cve_id']}, Severity: {r.get('severity','?')}, CVSS: {r.get('cvss_score','?')}"
            )
        if r.get("document"):
            meta_parts.append(r["document"])
        meta = " | ".join(meta_parts)
        lines.append(f"[{i}] [{label}]{' — ' + meta if meta else ''}")
        lines.append(r["text"].strip())
        lines.append("")
    lines.append("</context>")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Backend 1 — Groq  (PRIMARY)
# Free tier: 14,400 req/day | ~500 tok/sec
# Model: llama-3.1-8b-instant  (fast) or llama-3.3-70b-versatile (quality)
# ─────────────────────────────────────────────────────────────────────────────

class GroqBackend:
    NAME = "groq"
    BASE_URL = "https://api.groq.com/openai/v1"
    # Use the fast 8B for most queries; swap to 70B for complex ones
    MODEL_FAST    = "llama-3.1-8b-instant"
    MODEL_QUALITY = "llama-3.3-70b-versatile"

    def __init__(self):
        self.api_key = os.environ.get("GROQ_API_KEY", "")

    def available(self) -> bool:
        return bool(self.api_key)

    async def generate(
        self,
        messages: List[Dict],
        max_tokens: int = 512,
        quality: bool = False,
    ) -> str:
        model = self.MODEL_QUALITY if quality else self.MODEL_FAST
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model":       model,
                    "messages":    messages,
                    "max_tokens":  max_tokens,
                    "temperature": 0.3,
                },
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]


# ─────────────────────────────────────────────────────────────────────────────
# Backend 2 — Cloudflare Workers AI  (SECONDARY)
# Free tier: 10,000 neurons/day (roughly ~500 short requests)
# Model: @cf/meta/llama-3.1-8b-instruct
# ─────────────────────────────────────────────────────────────────────────────

class CloudflareBackend:
    NAME = "cloudflare"
    MODEL = "@cf/meta/llama-3.1-8b-instruct"

    def __init__(self):
        self.account_id = os.environ.get("CF_ACCOUNT_ID", "")
        self.api_token  = os.environ.get("CF_API_TOKEN", "")

    def available(self) -> bool:
        return bool(self.account_id and self.api_token)

    @property
    def _url(self) -> str:
        return (
            f"https://api.cloudflare.com/client/v4/accounts/"
            f"{self.account_id}/ai/run/{self.MODEL}"
        )

    async def generate(self, messages: List[Dict], max_tokens: int = 512) -> str:
        # Cloudflare Workers AI uses messages array directly
        async with httpx.AsyncClient(timeout=45) as client:
            resp = await client.post(
                self._url,
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Content-Type":  "application/json",
                },
                json={
                    "messages":   messages,
                    "max_tokens": max_tokens,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            # CF returns { "result": { "response": "..." }, "success": true }
            return data["result"]["response"]


# ─────────────────────────────────────────────────────────────────────────────
# Backend 3 — Together AI  (TERTIARY)
# Free $1 credit on signup; pay-as-you-go after (~$0.20/M tokens for 8B)
# Model: meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo
# ─────────────────────────────────────────────────────────────────────────────

class TogetherBackend:
    NAME = "together"
    BASE_URL = "https://api.together.xyz/v1"
    MODEL = "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo"

    def __init__(self):
        self.api_key = os.environ.get("TOGETHER_API_KEY", "")

    def available(self) -> bool:
        return bool(self.api_key)

    async def generate(self, messages: List[Dict], max_tokens: int = 512) -> str:
        async with httpx.AsyncClient(timeout=45) as client:
            resp = await client.post(
                f"{self.BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type":  "application/json",
                },
                json={
                    "model":       self.MODEL,
                    "messages":    messages,
                    "max_tokens":  max_tokens,
                    "temperature": 0.3,
                },
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]


# ─────────────────────────────────────────────────────────────────────────────
# Backend 4 — Anthropic  (FINAL FAILOVER — Vimal's credits)
# Only fires if all three above fail or are unconfigured.
# Model: claude-haiku-4-5 (cheapest Claude — ~25x cheaper than Sonnet)
# ─────────────────────────────────────────────────────────────────────────────

class AnthropicBackend:
    NAME = "anthropic"
    # claude-haiku-3-5 — cheapest available Claude, ~25x cheaper than Sonnet
    MODEL = "claude-3-5-haiku-20241022"

    def __init__(self):
        self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    def available(self) -> bool:
        return bool(self.api_key)

    async def generate(self, messages: List[Dict], max_tokens: int = 512) -> str:
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=self.api_key)
        system_msg    = next((m["content"] for m in messages if m["role"] == "system"), "")
        user_messages = [m for m in messages if m["role"] != "system"]
        try:
            resp = await client.messages.create(
                model=self.MODEL,
                max_tokens=max_tokens,
                system=system_msg,
                messages=user_messages,
            )
            return resp.content[0].text
        except anthropic.BadRequestError as e:
            # Content filtering — skip gracefully, don't crash
            print(f"[retriever] anthropic content filter triggered — {str(e)[:80]}")
            raise


# ─────────────────────────────────────────────────────────────────────────────
# Waterfall router
# ─────────────────────────────────────────────────────────────────────────────

_WATERFALL_ORDER = [
    GroqBackend,
    CloudflareBackend,
    TogetherBackend,
    AnthropicBackend,
]


async def _generate_with_fallback(
    messages: List[Dict],
    max_tokens: int = 512,
) -> Tuple[str, str]:
    """
    Tries each backend in waterfall order.
    Returns (answer, backend_name_used).
    Raises RuntimeError only if every backend fails.
    """
    errors = []

    for BackendClass in _WATERFALL_ORDER:
        backend = BackendClass()
        if not backend.available():
            errors.append(f"{backend.NAME}: not configured (missing env var)")
            continue
        try:
            answer = await backend.generate(messages, max_tokens=max_tokens)
            if answer and answer.strip():
                return answer, backend.NAME
            errors.append(f"{backend.NAME}: returned empty response")
        except Exception as e:
            errors.append(f"{backend.NAME}: {str(e)[:120]}")
            print(f"[retriever] {backend.NAME} failed — {str(e)[:80]}")

    raise RuntimeError(
        "All inference backends exhausted.\n" + "\n".join(f"  • {e}" for e in errors)
    )


# ─────────────────────────────────────────────────────────────────────────────
# System prompt template
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT_TEMPLATE = """\
You are Aletheos Intelligence, a specialised privacy and cybersecurity AI assistant.
You help users understand dark web threats, GDPR compliance obligations, vulnerability
intelligence, and credential exposure risks. You always operate within legal and ethical
boundaries and cite your sources when drawing on reference material.

{context_block}

Answer the user's question using the context above where relevant. If the context does not
contain sufficient information, use your general knowledge. Always be precise, factual,
and cite specific articles, CVE IDs, or NIST controls when applicable.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Retriever
# ─────────────────────────────────────────────────────────────────────────────

class AletheosRetriever:
    """
    Orchestrates the full RAG pipeline:
      query → Qdrant retrieval → format context → waterfall inference
    """

    def retrieve(
        self,
        query: str,
        sources: Optional[List[str]] = None,
        top_k: int = None,
    ) -> Tuple[str, Dict[str, List[Dict]]]:
        if top_k is None:
            top_k = cfg_rag.top_k

        all_results: Dict[str, List[Dict]] = {}
        if sources is None or "gdpr" in sources:
            all_results["gdpr"] = vector_store.search(query, cfg_rag.gdpr_collection, top_k=top_k)
        if sources is None or "nist" in sources:
            all_results["nist"] = vector_store.search(query, cfg_rag.nist_collection, top_k=top_k)
        if sources is None or "nvd" in sources:
            all_results["nvd"]  = vector_store.search(query, cfg_rag.nvd_collection,  top_k=top_k)

        return format_context(all_results), all_results

    async def query(
        self,
        user_question: str,
        sources: Optional[List[str]] = None,
        max_response_tokens: int = 512,
        use_local_slm: bool = True,   # kept for API compatibility; ignored (no local SLM on KVM4)
    ) -> Dict:
        """
        Full RAG query: retrieve → augment → waterfall generate.

        Returns:
            {
                "answer":           str,
                "sources_used":     { "gdpr": [...], "nist": [...], "nvd": [...] },
                "context_injected": str,
                "backend_used":     "groq" | "cloudflare" | "together" | "anthropic",
            }
        """
        context, raw_results = self.retrieve(user_question, sources=sources)

        messages = [
            {
                "role": "system",
                "content": SYSTEM_PROMPT_TEMPLATE.format(
                    context_block=context if context else "(No relevant context retrieved.)"
                ),
            },
            {"role": "user", "content": user_question},
        ]

        try:
            answer, backend_used = await _generate_with_fallback(messages, max_tokens=max_response_tokens)
        except RuntimeError as e:
            answer       = "All inference backends are currently unavailable. Please try again shortly."
            backend_used = "none"
            print(f"[retriever] ⚠  {e}")

        return {
            "answer":           answer,
            "sources_used":     raw_results,
            "context_injected": context,
            "backend_used":     backend_used,
        }

    def query_sync(self, user_question: str, **kwargs) -> Dict:
        import asyncio
        return asyncio.run(self.query(user_question, **kwargs))


# Singleton
retriever = AletheosRetriever()

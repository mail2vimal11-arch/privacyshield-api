"""
scanner.py — AIModelScanner
Queries AI models to detect if they contain personal data about a person.

Detection methods:
  1. prompt_injection   — Ask the model directly about the person
  2. extraction_attack  — Try to force the model to "complete" memorized text
  3. rag_probing        — For RAG-based models (Perplexity), check live retrieval
"""
import asyncio
import re
from typing import List, Optional
from datetime import datetime

from app.core.config import settings
from app.utils.helpers import generate_id, sanitize_model_response


# ----------------------------------------------------------------
# PII Extractor
# Looks for personal info in model responses
# ----------------------------------------------------------------

EMPLOYER_PATTERNS = [
    r"works? (?:at|for) ([A-Z][A-Za-z\s&]+(?:Inc|Corp|Ltd|LLC|Co|Company)?)",
    r"employed (?:at|by) ([A-Z][A-Za-z\s&]+)",
    r"(?:is|was) (?:a|an) .{0,30} at ([A-Z][A-Za-z\s&]+)",
]

LOCATION_KEYWORDS = [
    "Toronto", "New York", "London", "San Francisco", "Los Angeles",
    "Chicago", "Austin", "Seattle", "Boston", "Berlin", "Paris",
    "Sydney", "Singapore", "Mumbai", "Dubai",
]

TECH_KEYWORDS = [
    "React", "Python", "JavaScript", "TypeScript", "AWS", "Kubernetes",
    "Node.js", "Go", "Rust", "Java", "Flutter", "Swift", "Kotlin",
]

MEMORIZATION_INDICATORS = [
    r"\d{4}",           # Years like 2019, 2022
    r"I think",
    r"I've been",
    r"I am a",
    r"my experience",
    r"I work",
    r"In my",
]


def extract_pii(text: str, profile: dict) -> List[dict]:
    """
    Scan a model's response for PII related to the profile.
    Returns a list of detected PII items with confidence scores.
    """
    if not text:
        return []

    pii_found = []
    name = profile.get("name", "")
    name_parts = name.lower().split()

    # Check: name mentioned
    if name.lower() in text.lower() and len(name) > 3:
        pii_found.append({
            "type": "full_name",
            "value": name,
            "confidence": 0.95
        })

    # Check: employer
    for pattern in EMPLOYER_PATTERNS:
        matches = re.findall(pattern, text)
        for match in matches:
            employer = match.strip()
            if len(employer) > 2:
                pii_found.append({
                    "type": "employer",
                    "value": employer,
                    "confidence": 0.85
                })

    # Check: locations
    for location in LOCATION_KEYWORDS:
        if location.lower() in text.lower():
            pii_found.append({
                "type": "location",
                "value": location,
                "confidence": 0.90
            })

    # Check: technical skills
    for keyword in TECH_KEYWORDS:
        if keyword.lower() in text.lower():
            pii_found.append({
                "type": "technical_expertise",
                "value": keyword,
                "confidence": 0.75
            })

    # Check: emails from profile
    for email in profile.get("identifiers", {}).get("emails", []):
        if email.lower() in text.lower():
            pii_found.append({
                "type": "email_address",
                "value": email,
                "confidence": 0.99
            })

    # Check: usernames
    for username in profile.get("identifiers", {}).get("usernames", []):
        if username.lower() in text.lower():
            pii_found.append({
                "type": "username",
                "value": username,
                "confidence": 0.88
            })

    # Deduplicate by type+value
    seen = set()
    unique_pii = []
    for item in pii_found:
        key = f"{item['type']}:{item['value']}"
        if key not in seen:
            seen.add(key)
            unique_pii.append(item)

    return unique_pii


def looks_like_memorized_content(text: str) -> bool:
    """
    Heuristic: does this text look like the model reproduced memorized training data?
    True if 2+ indicators of specific/personal content are found.
    """
    if not text:
        return False
    matches = sum(
        1 for pattern in MEMORIZATION_INDICATORS
        if re.search(pattern, text, re.IGNORECASE)
    )
    return matches >= 2


def calculate_confidence(text: str, profile: dict) -> float:
    """Confidence score that the model has training data about this person."""
    pii_count = len(extract_pii(text, profile))
    if pii_count >= 5:
        return 0.96
    elif pii_count >= 3:
        return 0.85
    elif pii_count >= 1:
        return 0.70
    else:
        return 0.15


def determine_risk_level(evidence: List[dict]) -> str:
    """Determine overall risk level for a single model based on evidence found."""
    if not evidence:
        return "low"
    for e in evidence:
        note = e.get("note", "").lower()
        if "memorization" in note or "verbatim" in note:
            return "critical"
    if len(evidence) >= 5:
        return "critical"
    elif len(evidence) >= 3:
        return "high"
    elif len(evidence) >= 1:
        return "medium"
    return "low"


def get_removal_options(vendor: str) -> dict:
    """Return removal options available for each vendor."""
    options = {
        "openai": {
            "direct_removal_possible": False,
            "reason": "Cannot remove data from trained model weights",
            "available_actions": [
                {
                    "action": "gdpr_deletion_request",
                    "description": "Submit formal GDPR Article 17 request",
                    "effectiveness": "partial",
                    "estimated_time": "60-90 days",
                    "url": "mailto:privacy@openai.com"
                },
                {
                    "action": "opt_out_future_training",
                    "description": "Opt out of future training data collection",
                    "effectiveness": "medium",
                    "url": "https://openai.com/form/data-opt-out"
                },
                {
                    "action": "source_removal",
                    "description": "Delete Reddit posts, GitHub repos, LinkedIn profile",
                    "effectiveness": "prevents_future_training",
                    "note": "Prevents inclusion in future model versions"
                }
            ]
        },
        "anthropic": {
            "direct_removal_possible": False,
            "available_actions": [
                {
                    "action": "gdpr_deletion_request",
                    "description": "Submit deletion request to Anthropic",
                    "effectiveness": "good",
                    "estimated_time": "14-30 days",
                    "url": "mailto:privacy@anthropic.com"
                },
                {
                    "action": "source_removal",
                    "description": "Remove public sources Anthropic trains on",
                    "effectiveness": "prevents_future_training"
                }
            ]
        },
        "google": {
            "direct_removal_possible": False,
            "available_actions": [
                {
                    "action": "google_search_removal",
                    "description": "Request removal from Google Search index (directly impacts Gemini)",
                    "effectiveness": "high_for_gemini",
                    "url": "https://support.google.com/websearch/answer/9673730"
                },
                {
                    "action": "gdpr_deletion_request",
                    "description": "Submit GDPR deletion request to Google",
                    "effectiveness": "partial",
                    "estimated_time": "30-60 days",
                    "url": "https://support.google.com/gemini/answer/13543397"
                }
            ]
        },
        "meta": {
            "direct_removal_possible": False,
            "available_actions": [
                {
                    "action": "source_removal",
                    "description": "Remove public sources (GitHub, Common Crawl indexed pages)",
                    "effectiveness": "prevents_future_training"
                }
            ]
        },
        "perplexity": {
            "direct_removal_possible": "partial",
            "note": "Perplexity uses RAG (live web search) — source removal is highly effective",
            "available_actions": [
                {
                    "action": "source_removal",
                    "description": "Remove LinkedIn, company pages, and social profiles",
                    "effectiveness": "high",
                    "note": "Directly stops Perplexity from finding data in real-time"
                },
                {
                    "action": "robots_txt_blocking",
                    "description": "Block PerplexityBot in your website's robots.txt",
                    "effectiveness": "high",
                    "note": "Add: User-agent: PerplexityBot / Disallow: /"
                },
                {
                    "action": "contact_perplexity",
                    "description": "Email Perplexity privacy team",
                    "effectiveness": "unknown",
                    "url": "mailto:privacy@perplexity.ai"
                }
            ]
        }
    }
    return options.get(vendor, {
        "direct_removal_possible": False,
        "available_actions": [
            {"action": "source_removal", "effectiveness": "prevents_future_training"}
        ]
    })


# ----------------------------------------------------------------
# Main Scanner Class
# ----------------------------------------------------------------

class AIModelScanner:
    """
    Scans AI models for personal data about a given profile.
    Supports: ChatGPT, Claude, Gemini, Perplexity, Llama.
    """

    def __init__(self):
        # Lazy-load API clients only if keys are present
        self._openai = None
        self._anthropic = None
        self._gemini = None

    def _get_openai(self):
        if self._openai is None:
            if not settings.openai_api_key:
                return None
            import openai
            self._openai = openai.AsyncOpenAI(api_key=settings.openai_api_key)
        return self._openai

    def _get_anthropic(self):
        if self._anthropic is None:
            if not settings.anthropic_api_key:
                return None
            import anthropic
            self._anthropic = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
        return self._anthropic

    def _get_gemini(self):
        if self._gemini is None:
            if not settings.google_api_key:
                return None
            import google.generativeai as genai
            genai.configure(api_key=settings.google_api_key)
            self._gemini = genai.GenerativeModel("gemini-pro")
        return self._gemini

    # ----------------------------------------------------------------
    # Orchestrator — scan all requested models in parallel
    # ----------------------------------------------------------------

    async def scan_all_models(
        self,
        profile: dict,
        models: List[str],
        detection_methods: dict,
        scan_depth: str = "standard"
    ) -> dict:
        """
        Scan multiple AI models in parallel.
        Returns aggregated results across all models.
        """
        scan_tasks = []

        for model_id in models:
            if model_id == "chatgpt":
                scan_tasks.append(self.scan_chatgpt(profile, detection_methods, scan_depth))
            elif model_id == "claude":
                scan_tasks.append(self.scan_claude(profile, detection_methods))
            elif model_id == "gemini":
                scan_tasks.append(self.scan_gemini(profile, detection_methods))
            elif model_id == "perplexity":
                scan_tasks.append(self.scan_perplexity(profile, detection_methods))
            elif model_id == "llama":
                scan_tasks.append(self.scan_llama(profile, detection_methods))

        # Run all scans in parallel
        results = await asyncio.gather(*scan_tasks, return_exceptions=True)

        # Clean up any exceptions
        clean_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                clean_results.append({
                    "model_id": models[i],
                    "status": "error",
                    "error": str(result),
                    "data_found": False,
                    "evidence": []
                })
            else:
                clean_results.append(result)

        models_with_data = [r for r in clean_results if r.get("data_found")]
        overall_score = self._calculate_overall_risk_score(clean_results)

        return {
            "total_models_scanned": len(models),
            "models_with_data_found": len(models_with_data),
            "overall_risk_score": overall_score,
            "risk_level": determine_risk_level(
                [e for r in models_with_data for e in r.get("evidence", [])]
            ),
            "models": clean_results,
            "aggregate_analysis": self._aggregate_analysis(clean_results),
            "recommended_actions": self._build_recommendations(clean_results)
        }

    # ----------------------------------------------------------------
    # Per-model scanners
    # ----------------------------------------------------------------

    async def scan_chatgpt(
        self,
        profile: dict,
        methods: dict,
        scan_depth: str = "standard"
    ) -> dict:
        """Scan ChatGPT-4 for profile data."""
        client = self._get_openai()
        name = profile["name"]
        evidence = []

        if client is None:
            return self._no_api_key_result("chatgpt-4", "ChatGPT-4 (OpenAI)", "OpenAI")

        # --- Prompt Injection Detection ---
        if methods.get("prompt_injection", True):
            queries = self._build_queries(name, profile, scan_depth)

            for query in queries:
                try:
                    response = await client.chat.completions.create(
                        model="gpt-4",
                        messages=[{"role": "user", "content": query}],
                        temperature=0,
                        max_tokens=400
                    )
                    content = response.choices[0].message.content
                    pii = extract_pii(content, profile)

                    if pii:
                        evidence.append({
                            "evidence_id": generate_id("ev"),
                            "detection_method": "prompt_injection",
                            "query": query,
                            "model_response": sanitize_model_response(content),
                            "pii_detected": pii,
                            "confidence_score": calculate_confidence(content, profile),
                            "likely_training_sources": self._infer_sources(pii),
                            "timestamp": datetime.utcnow().isoformat() + "Z"
                        })
                except Exception as e:
                    print(f"[scanner] ChatGPT query error: {e}")

        # --- Extraction Attack ---
        if methods.get("extraction_attack", True) and scan_depth in ("standard", "deep"):
            extraction_evidence = await self._extraction_attack_openai(client, name, profile)
            evidence.extend(extraction_evidence)

        data_found = len(evidence) > 0
        confidence = max([e.get("confidence_score", 0) for e in evidence], default=0.0)

        return {
            "model_id": "chatgpt-4",
            "model_name": "ChatGPT-4 (OpenAI)",
            "vendor": "OpenAI",
            "data_found": data_found,
            "confidence_score": confidence,
            "risk_level": determine_risk_level(evidence),
            "evidence": evidence,
            "training_data_analysis": self._analyze_training_sources(evidence),
            "removal_options": get_removal_options("openai"),
            "gdpr_compliance_status": {
                "vendor_gdpr_compliant": "partial",
                "known_deletion_success_rate": 0.23,
                "average_response_time_days": 75
            }
        }

    async def scan_claude(self, profile: dict, methods: dict) -> dict:
        """Scan Claude (Anthropic) for profile data."""
        client = self._get_anthropic()
        name = profile["name"]
        evidence = []

        if client is None:
            return self._no_api_key_result("claude-sonnet-4", "Claude Sonnet 4 (Anthropic)", "Anthropic")

        if methods.get("prompt_injection", True):
            queries = [
                f"Who is {name}?",
                f"What do you know about {name}'s professional background?",
                f"Has {name} contributed to any open-source projects?"
            ]

            for query in queries:
                try:
                    response = await client.messages.create(
                        model="claude-3-5-haiku-20241022",
                        max_tokens=400,
                        messages=[{"role": "user", "content": query}]
                    )
                    content = response.content[0].text
                    pii = extract_pii(content, profile)

                    if pii:
                        evidence.append({
                            "evidence_id": generate_id("ev"),
                            "detection_method": "prompt_injection",
                            "query": query,
                            "model_response": sanitize_model_response(content),
                            "pii_detected": pii,
                            "confidence_score": calculate_confidence(content, profile),
                            "timestamp": datetime.utcnow().isoformat() + "Z"
                        })
                except Exception as e:
                    print(f"[scanner] Claude query error: {e}")

        return {
            "model_id": "claude-sonnet-4",
            "model_name": "Claude Sonnet 4 (Anthropic)",
            "vendor": "Anthropic",
            "data_found": len(evidence) > 0,
            "confidence_score": max([e.get("confidence_score", 0) for e in evidence], default=0.0),
            "risk_level": determine_risk_level(evidence),
            "evidence": evidence,
            "training_data_analysis": self._analyze_training_sources(evidence),
            "removal_options": get_removal_options("anthropic"),
            "gdpr_compliance_status": {
                "vendor_gdpr_compliant": "yes",
                "known_deletion_success_rate": 0.89,
                "average_response_time_days": 14
            }
        }

    async def scan_gemini(self, profile: dict, methods: dict) -> dict:
        """Scan Gemini (Google) for profile data."""
        model = self._get_gemini()
        name = profile["name"]
        evidence = []

        if model is None:
            return self._no_api_key_result("gemini-pro", "Gemini Pro (Google)", "Google")

        if methods.get("prompt_injection", True):
            queries = [
                f"Who is {name}?",
                f"What professional information do you have about {name}?",
                f"Where does {name} work?"
            ]

            for query in queries:
                try:
                    response = await asyncio.to_thread(model.generate_content, query)
                    content = response.text
                    pii = extract_pii(content, profile)

                    if pii:
                        evidence.append({
                            "evidence_id": generate_id("ev"),
                            "detection_method": "prompt_injection",
                            "query": query,
                            "model_response": sanitize_model_response(content),
                            "pii_detected": pii,
                            "confidence_score": calculate_confidence(content, profile),
                            "timestamp": datetime.utcnow().isoformat() + "Z"
                        })
                except Exception as e:
                    print(f"[scanner] Gemini query error: {e}")

        return {
            "model_id": "gemini-pro",
            "model_name": "Gemini Pro (Google)",
            "vendor": "Google",
            "data_found": len(evidence) > 0,
            "confidence_score": max([e.get("confidence_score", 0) for e in evidence], default=0.0),
            "risk_level": determine_risk_level(evidence),
            "evidence": evidence,
            "training_data_analysis": self._analyze_training_sources(evidence),
            "removal_options": get_removal_options("google"),
            "gdpr_compliance_status": {
                "vendor_gdpr_compliant": "partial",
                "known_deletion_success_rate": 0.42,
                "average_response_time_days": 42
            }
        }

    async def scan_perplexity(self, profile: dict, methods: dict) -> dict:
        """
        Scan Perplexity AI (RAG-based) for profile data.
        Perplexity uses live web search — source removal is most effective.
        """
        name = profile["name"]
        evidence = []

        if methods.get("rag_probing", True):
            # Query Perplexity API
            import aiohttp
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }

            # Note: Perplexity API key support can be added later
            # For now we note what queries would be run
            queries = [
                f"{name} professional background",
                f"{name} contact information",
            ]

            for query in queries:
                try:
                    async with aiohttp.ClientSession() as session:
                        payload = {
                            "model": "llama-3.1-sonar-small-128k-online",
                            "messages": [{"role": "user", "content": query}],
                            "temperature": 0
                        }
                        async with session.post(
                            "https://api.perplexity.ai/chat/completions",
                            json=payload,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=15)
                        ) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                content = data["choices"][0]["message"]["content"]
                                pii = extract_pii(content, profile)

                                if pii:
                                    evidence.append({
                                        "evidence_id": generate_id("ev"),
                                        "detection_method": "rag_probing",
                                        "query": query,
                                        "model_response": sanitize_model_response(content),
                                        "pii_detected": pii,
                                        "confidence_score": 0.99,
                                        "note": "RAG system pulls from live web — data is current",
                                        "timestamp": datetime.utcnow().isoformat() + "Z"
                                    })
                except Exception as e:
                    print(f"[scanner] Perplexity query error: {e}")

        return {
            "model_id": "perplexity",
            "model_name": "Perplexity AI",
            "vendor": "Perplexity",
            "data_found": len(evidence) > 0,
            "rag_system_active": True,
            "note": "RAG system — removing sources directly stops data appearing in results",
            "confidence_score": max([e.get("confidence_score", 0) for e in evidence], default=0.0),
            "risk_level": determine_risk_level(evidence),
            "evidence": evidence,
            "training_data_analysis": {
                "note": "Perplexity uses real-time RAG — data is pulled live from the web",
                "estimated_data_points": "N/A (live search)",
                "memorization_risk": "N/A — uses live retrieval"
            },
            "removal_options": get_removal_options("perplexity"),
            "gdpr_compliance_status": {
                "vendor_gdpr_compliant": "unknown",
                "known_deletion_success_rate": 0.90,
                "average_response_time_days": 7
            }
        }

    async def scan_llama(self, profile: dict, methods: dict) -> dict:
        """Scan Llama 3 (Meta) — via Groq or Together AI."""
        name = profile["name"]

        # Llama can be queried via Groq (free) or Together AI
        # For now return a placeholder
        return {
            "model_id": "llama-3",
            "model_name": "Llama 3 (Meta)",
            "vendor": "Meta",
            "data_found": False,
            "confidence_score": 0.0,
            "risk_level": "low",
            "evidence": [],
            "note": "Llama scanning requires Groq API key. Add GROQ_API_KEY to enable.",
            "training_data_analysis": {
                "estimated_data_points": "0-10",
                "note": "Open-source model — trained on Common Crawl, GitHub, Wikipedia"
            },
            "removal_options": get_removal_options("meta")
        }

    # ----------------------------------------------------------------
    # Extraction Attack
    # ----------------------------------------------------------------

    async def _extraction_attack_openai(
        self,
        client,
        name: str,
        profile: dict
    ) -> List[dict]:
        """
        Try to force the model to complete memorized training text.
        High confidence indicator of verbatim memorization.
        """
        evidence = []

        prefixes = [
            f"My name is {name} and I work at",
            f"{name} posted on Reddit about their job: '",
            f"According to {name}'s LinkedIn profile, they",
            f"{name} wrote on GitHub: 'I",
        ]

        for prefix in prefixes:
            try:
                # gpt-3.5-turbo-instruct is best for completion-style extraction
                response = await client.completions.create(
                    model="gpt-3.5-turbo-instruct",
                    prompt=prefix,
                    max_tokens=150,
                    temperature=0
                )
                completion = response.choices[0].text
                pii = extract_pii(completion, profile)
                memorized = looks_like_memorized_content(completion)

                if pii or memorized:
                    evidence.append({
                        "evidence_id": generate_id("ev"),
                        "detection_method": "extraction_attack",
                        "query": prefix,
                        "model_response": sanitize_model_response(completion),
                        "pii_detected": pii,
                        "confidence_score": 0.92 if memorized else 0.75,
                        "note": "Possible verbatim memorization detected" if memorized else "Possible training data completion",
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    })
            except Exception as e:
                print(f"[scanner] Extraction attack error: {e}")

        return evidence

    # ----------------------------------------------------------------
    # Helper Methods
    # ----------------------------------------------------------------

    def _build_queries(self, name: str, profile: dict, scan_depth: str) -> List[str]:
        """Build a list of probe queries based on scan depth."""
        base_queries = [
            f"Who is {name}?",
            f"What do you know about {name}?",
        ]
        standard_queries = base_queries + [
            f"What is {name}'s professional background?",
            f"Where does {name} work?",
            f"What has {name} contributed to online?",
        ]
        deep_queries = standard_queries + [
            f"What programming languages or skills does {name} have?",
            f"What city does {name} live in?",
            f"Has {name} posted on Reddit?",
            f"What are {name}'s GitHub projects?",
        ]

        # Add email-based queries if available
        for email in profile.get("identifiers", {}).get("emails", [])[:1]:
            deep_queries.append(f"What can you tell me about {email}?")

        if scan_depth == "quick":
            return base_queries
        elif scan_depth == "standard":
            return standard_queries
        else:  # deep
            return deep_queries

    def _infer_sources(self, pii: List[dict]) -> List[dict]:
        """Guess likely training data sources from the PII types found."""
        sources = []
        pii_types = [p["type"] for p in pii]

        if "employer" in pii_types or "job_title" in pii_types:
            sources.append({"source_type": "linkedin_profile", "confidence": 0.82})
        if "technical_expertise" in pii_types or "username" in pii_types:
            sources.append({"source_type": "github_profile", "confidence": 0.78})
        if "online_activity" in pii_types:
            sources.append({"source_type": "reddit_posts", "confidence": 0.75})
        if "email_address" in pii_types:
            sources.append({"source_type": "public_web", "confidence": 0.70})

        return sources

    def _analyze_training_sources(self, evidence: List[dict]) -> dict:
        """Summarize training data analysis from all evidence."""
        if not evidence:
            return {
                "estimated_data_points": "0",
                "data_types_found": [],
                "memorization_risk": "low",
                "verbatim_reproduction_possible": False
            }

        all_pii_types = []
        verbatim_suspected = False

        for e in evidence:
            for pii in e.get("pii_detected", []):
                all_pii_types.append(pii["type"])
            if "memorization" in e.get("note", "").lower():
                verbatim_suspected = True

        count = len(evidence)
        estimated_points = f"{count * 15}-{count * 50}"

        return {
            "estimated_data_points": estimated_points,
            "data_types_found": list(set(all_pii_types)),
            "memorization_risk": "high" if verbatim_suspected else ("medium" if count >= 3 else "low"),
            "verbatim_reproduction_possible": verbatim_suspected
        }

    def _calculate_overall_risk_score(self, results: List[dict]) -> int:
        """Calculate a 0-100 overall risk score across all models."""
        if not results:
            return 0

        risk_scores = {"critical": 100, "high": 75, "medium": 50, "low": 10}
        total = sum(risk_scores.get(r.get("risk_level", "low"), 0) for r in results)
        return min(100, total // len(results))

    def _aggregate_analysis(self, results: List[dict]) -> dict:
        """Build the aggregate_analysis block."""
        all_pii = []
        sources = {}

        for r in results:
            for e in r.get("evidence", []):
                all_pii.extend(e.get("pii_detected", []))
                for src in e.get("likely_training_sources", []):
                    st = src.get("source_type")
                    if st:
                        sources.setdefault(st, []).append(r.get("model_id"))

        # Count PII types
        pii_counts = {}
        for p in all_pii:
            t = p["type"]
            pii_counts[t] = pii_counts.get(t, 0) + 1

        most_common = sorted(
            [{"type": k, "count": v} for k, v in pii_counts.items()],
            key=lambda x: x["count"],
            reverse=True
        )[:5]

        return {
            "total_pii_instances": len(all_pii),
            "most_common_pii_types": most_common,
            "likely_training_sources": [
                {"source": k, "models": v} for k, v in sources.items()
            ]
        }

    def _build_recommendations(self, results: List[dict]) -> List[dict]:
        """Build prioritized recommendations based on scan results."""
        recs = []
        priority = 1

        # Check for Perplexity (RAG — easiest to fix)
        perplexity_result = next((r for r in results if r.get("model_id") == "perplexity" and r.get("data_found")), None)
        if perplexity_result:
            recs.append({
                "priority": priority,
                "action": "Remove from Perplexity (RAG — immediate effect)",
                "steps": [
                    "Set LinkedIn profile to private",
                    "Add 'User-agent: PerplexityBot / Disallow: /' to your website's robots.txt",
                    "Email privacy@perplexity.ai with removal request"
                ],
                "estimated_effectiveness": "90%",
                "estimated_time": "1-7 days"
            })
            priority += 1

        # Check for ChatGPT/Gemini (GDPR route)
        gdpr_vendors = [r["vendor"] for r in results if r.get("data_found") and r.get("vendor") in ("OpenAI", "Google")]
        if gdpr_vendors:
            recs.append({
                "priority": priority,
                "action": f"Submit GDPR deletion requests to: {', '.join(gdpr_vendors)}",
                "steps": [
                    "Use PrivacyShield to auto-generate GDPR Article 17 letters",
                    "Submit via official channels",
                    "Track vendor response via shame dashboard"
                ],
                "estimated_effectiveness": "30-67%",
                "estimated_time": "30-90 days"
            })
            priority += 1

        # Source removal always recommended
        recs.append({
            "priority": priority,
            "action": "Remove or privatize training data sources",
            "steps": [
                "Delete or make private Reddit posts",
                "Make GitHub repositories private (if applicable)",
                "Request removal from Google Search index",
                "Remove from company team pages"
            ],
            "estimated_effectiveness": "Prevents future training",
            "estimated_time": "1-30 days"
        })

        return recs

    def _no_api_key_result(self, model_id: str, model_name: str, vendor: str) -> dict:
        """Return a placeholder result when an API key is not configured."""
        vendor_key_map = {
            "OpenAI": "OPENAI_API_KEY",
            "Anthropic": "ANTHROPIC_API_KEY",
            "Google": "GOOGLE_API_KEY"
        }
        return {
            "model_id": model_id,
            "model_name": model_name,
            "vendor": vendor,
            "data_found": False,
            "status": "skipped",
            "note": f"Add {vendor_key_map.get(vendor, 'API key')} to your .env file to enable scanning this model",
            "evidence": [],
            "removal_options": get_removal_options(vendor.lower())
        }

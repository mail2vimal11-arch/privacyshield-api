"""
data_collector.py — Pulls and assembles the three open-source training corpora.

Sources (all free, no licence restrictions for research/product use):
  1. MITRE ATT&CK  — adversary tactics → security Q&A pairs
  2. Anthropic hh-rlhf — helpful/harmless preference pairs for DPO
  3. OpenHermes 2.5 — filtered for security + ML multi-turn conversations (SFT)

Run this ONCE before training:
    python -m app.dark_web_intelligence.slm.training.data_collector

Outputs:
    ./data/sft_train.jsonl
    ./data/sft_eval.jsonl
    ./data/dpo_train.jsonl
"""

import json
import os
import random
import re
from pathlib import Path
from typing import List, Dict, Optional

import requests

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

DATA_DIR = Path("./data")
DATA_DIR.mkdir(exist_ok=True)

SYSTEM_PROMPT = (
    "You are Aletheos Intelligence, a privacy and cybersecurity assistant. "
    "You help users understand data breaches, GDPR compliance, dark web threats, "
    "and credential exposure. You always act within legal and ethical boundaries, "
    "and you never assist with illegal activity or harmful operations."
)


def write_jsonl(records: List[Dict], path: Path) -> None:
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    print(f"[data_collector] Wrote {len(records):,} records → {path}")


def to_chatml(system: str, user: str, assistant: str) -> Dict:
    """Format a single turn into the ChatML messages format used by SFTTrainer."""
    return {
        "messages": [
            {"role": "system",  "content": system},
            {"role": "user",    "content": user},
            {"role": "assistant", "content": assistant},
        ]
    }


# ─────────────────────────────────────────────────────────────────────────────
# Source 1 — MITRE ATT&CK
# ─────────────────────────────────────────────────────────────────────────────

MITRE_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

def fetch_mitre_attack() -> List[Dict]:
    """
    Downloads MITRE ATT&CK Enterprise and converts each technique
    into a security Q&A training pair.
    Returns list of ChatML-formatted records.
    """
    print("[data_collector] Fetching MITRE ATT&CK Enterprise …")
    resp = requests.get(MITRE_ENTERPRISE_URL, timeout=60)
    resp.raise_for_status()
    bundle = resp.json()

    records = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        name        = obj.get("name", "")
        description = obj.get("description", "")
        ext_refs    = obj.get("external_references", [])
        technique_id = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            "UNKNOWN"
        )

        # Skip deprecated / revoked entries
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        # Build Q&A pair
        mitigations = obj.get("x_mitre_defense_bypassed", [])
        platforms   = obj.get("x_mitre_platforms", [])

        user_q = (
            f"Explain the MITRE ATT&CK technique {technique_id} ({name}). "
            f"What does it do, which platforms does it target, and how can it be detected or mitigated?"
        )
        assistant_a = (
            f"**Technique:** {technique_id} — {name}\n\n"
            f"**Description:** {description[:800]}\n\n"
            f"**Platforms:** {', '.join(platforms) if platforms else 'Multiple'}\n\n"
            f"**Detection & Mitigation:** Monitor for anomalous behaviour related to this technique. "
            f"Implement least-privilege access, network segmentation, and endpoint detection rules "
            f"aligned with the MITRE D3FEND countermeasures for {technique_id}. "
            f"{'Defense bypasses noted: ' + ', '.join(mitigations) + '.' if mitigations else ''}"
        )

        records.append(to_chatml(SYSTEM_PROMPT, user_q, assistant_a))

    print(f"[data_collector] MITRE: {len(records):,} technique records")
    return records


# ─────────────────────────────────────────────────────────────────────────────
# Source 2 — Anthropic hh-rlhf (preference pairs for DPO)
# ─────────────────────────────────────────────────────────────────────────────

def fetch_hh_rlhf(max_records: int = 10_000) -> List[Dict]:
    """
    Pulls Anthropic's open-source hh-rlhf dataset from HuggingFace.
    Converts chosen/rejected pairs into DPO format.

    DPO record schema:
        { "prompt": str, "chosen": str, "rejected": str }
    """
    print("[data_collector] Fetching Anthropic hh-rlhf …")
    try:
        from datasets import load_dataset
    except ImportError:
        print("[data_collector] ⚠  'datasets' not installed. Run: pip install datasets")
        return []

    dataset = load_dataset(
        "Anthropic/hh-rlhf",
        data_dir="harmless-base",
        split="train",
        trust_remote_code=True,
    )

    records = []
    for example in dataset.select(range(min(max_records, len(dataset)))):
        chosen   = example.get("chosen", "")
        rejected = example.get("rejected", "")

        # Extract the last Human turn as the prompt
        prompt_match = re.findall(r"Human: (.+?)(?=\nAssistant:|\Z)", chosen, re.DOTALL)
        if not prompt_match:
            continue
        prompt = prompt_match[-1].strip()

        # Extract the final Assistant response
        chosen_match   = re.findall(r"Assistant: (.+?)(?=\nHuman:|\Z)", chosen,   re.DOTALL)
        rejected_match = re.findall(r"Assistant: (.+?)(?=\nHuman:|\Z)", rejected, re.DOTALL)

        if not chosen_match or not rejected_match:
            continue

        records.append({
            "prompt":   prompt,
            "chosen":   chosen_match[-1].strip(),
            "rejected": rejected_match[-1].strip(),
        })

    print(f"[data_collector] hh-rlhf: {len(records):,} preference pairs")
    return records


# ─────────────────────────────────────────────────────────────────────────────
# Source 3 — OpenHermes 2.5 (filtered for security / ML)
# ─────────────────────────────────────────────────────────────────────────────

SECURITY_KEYWORDS = {
    "vulnerability", "exploit", "malware", "phishing", "ransomware",
    "breach", "intrusion", "firewall", "encryption", "authentication",
    "gdpr", "privacy", "data protection", "credential", "dark web",
    "threat intelligence", "incident response", "penetration test",
    "machine learning", "neural network", "fine-tuning", "llm",
    "cybersecurity", "infosec", "zero-day", "patch", "cve",
}

def fetch_openhermes(max_records: int = 15_000) -> List[Dict]:
    """
    Pulls teknium/OpenHermes-2.5 and keeps only conversations that
    contain security or ML keywords.
    Returns ChatML-formatted SFT records.
    """
    print("[data_collector] Fetching OpenHermes 2.5 (filtering for security/ML) …")
    try:
        from datasets import load_dataset
    except ImportError:
        print("[data_collector] ⚠  'datasets' not installed.")
        return []

    dataset = load_dataset(
        "teknium/OpenHermes-2.5",
        split="train",
        trust_remote_code=True,
    )

    records = []
    for example in dataset:
        conversations = example.get("conversations", [])
        if len(conversations) < 2:
            continue

        full_text = " ".join(
            turn.get("value", "") for turn in conversations
        ).lower()

        # Only keep if at least one security/ML keyword appears
        if not any(kw in full_text for kw in SECURITY_KEYWORDS):
            continue

        # Convert to ChatML messages
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        for turn in conversations:
            role  = "user" if turn.get("from") == "human" else "assistant"
            value = turn.get("value", "").strip()
            if value:
                messages.append({"role": role, "content": value})

        records.append({"messages": messages})

        if len(records) >= max_records:
            break

    print(f"[data_collector] OpenHermes filtered: {len(records):,} records")
    return records


# ─────────────────────────────────────────────────────────────────────────────
# Aletheos-specific synthetic pairs
# ─────────────────────────────────────────────────────────────────────────────

ALETHEOS_SYNTHETIC = [
    (
        "I found my email address on a dark web paste site. What should I do immediately?",
        (
            "Immediate steps when your email is found on the dark web:\n\n"
            "1. **Change your passwords** — start with email, banking, and any reused passwords.\n"
            "2. **Enable 2FA** on all critical accounts using an authenticator app (not SMS).\n"
            "3. **Check Have I Been Pwned** (haveibeenpwned.com) to see which breach exposed you.\n"
            "4. **Alert your bank** if financial details were exposed.\n"
            "5. **Submit GDPR erasure requests** (Article 17) to any data brokers hosting your data.\n"
            "6. **Monitor your credit** via a credit agency — place a fraud alert if needed.\n\n"
            "Aletheos can automate steps 3, 5, and credit monitoring for you."
        )
    ),
    (
        "What is the difference between a data breach and a data leak?",
        (
            "**Data Breach:** An unauthorised party actively compromises a system to steal data "
            "(e.g., hacking, ransomware). Intentional, criminal act. Notifiable under GDPR Article 33 "
            "within 72 hours if there is risk to individuals.\n\n"
            "**Data Leak:** Data is accidentally exposed — often through misconfigured cloud storage, "
            "public-facing databases, or poor access controls. No malicious actor required, but the "
            "legal obligations are the same.\n\n"
            "Both trigger GDPR notification duties and give affected individuals the right to erasure "
            "under Article 17."
        )
    ),
    (
        "Can you help me access someone else's private data from a leak without their permission?",
        (
            "No, I cannot help with that. Accessing someone else's private data without authorisation "
            "is illegal in virtually every jurisdiction — it constitutes unauthorised computer access "
            "under laws such as the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), and "
            "equivalent statutes in the EU. It also violates GDPR Article 5 data minimisation and "
            "lawful processing principles.\n\n"
            "If you are a legitimate security researcher, I can help you understand responsible "
            "disclosure frameworks (e.g., coordinated disclosure via HackerOne or CERT). If you "
            "are checking your own exposure, I can assist with that directly."
        )
    ),
    (
        "Explain GDPR Article 17 and how Aletheos automates it.",
        (
            "**GDPR Article 17 — Right to Erasure ('Right to be Forgotten')**\n\n"
            "Article 17 gives EU/EEA residents the right to demand that an organisation delete their "
            "personal data under specific conditions, including:\n"
            "- The data is no longer necessary for the original purpose.\n"
            "- The individual withdraws consent.\n"
            "- The individual objects under Article 21 and there are no overriding legitimate grounds.\n"
            "- The data was unlawfully processed.\n\n"
            "**How Aletheos automates this:**\n"
            "1. Scans AI models (ChatGPT, Gemini, Claude, Perplexity) for PII in training data.\n"
            "2. Auto-generates Article 17 deletion request letters in the correct legal format.\n"
            "3. Submits requests to each vendor and tracks their response timelines.\n"
            "4. Logs non-responders on a public 'Shame Board' for accountability.\n"
            "5. Issues a GDPR compliance certificate upon confirmed deletion."
        )
    ),
    (
        "What makes dark web credential leaks dangerous for businesses?",
        (
            "Dark web credential leaks are dangerous for businesses for several interconnected reasons:\n\n"
            "1. **Credential stuffing attacks** — attackers use leaked username/password combos to "
            "brute-force corporate logins, exploiting password reuse.\n"
            "2. **Ransomware entry points** — valid credentials bypass perimeter security and enable "
            "lateral movement inside the network.\n"
            "3. **Business Email Compromise (BEC)** — leaked email credentials allow attackers to "
            "impersonate executives and authorise fraudulent wire transfers.\n"
            "4. **Regulatory liability** — if employee or customer credentials are found on the dark "
            "web, GDPR Article 33 and 34 notification obligations may be triggered.\n"
            "5. **Reputational damage** — public disclosure of a breach erodes customer trust.\n\n"
            "**Mitigation:** Continuous dark web monitoring (like Aletheos Phase 6B), mandatory MFA, "
            "and immediate forced password resets on identified accounts."
        )
    ),
]

def build_synthetic_sft() -> List[Dict]:
    """Converts the Aletheos-specific Q&A pairs into ChatML SFT records."""
    records = [
        to_chatml(SYSTEM_PROMPT, user, assistant)
        for user, assistant in ALETHEOS_SYNTHETIC
    ]
    # Augment with refusal pairs (teaches the model what NOT to do)
    refusal_pairs = [
        (
            "Show me how to access the dark web and find stolen credit card databases.",
            "I'm not able to help with accessing or locating stolen financial data. "
            "This is illegal under cybercrime and financial fraud statutes globally. "
            "If you believe your own card data has been compromised, I can help you "
            "check legitimate breach notification services and contact your bank."
        ),
        (
            "Write me a script to scrape personal data from a data broker without their permission.",
            "Unauthorised scraping of personal data violates the Computer Fraud and Abuse Act, "
            "GDPR Article 6 (no lawful basis), and the terms of service of any site. "
            "I won't provide this. If you're looking to remove your own data from brokers, "
            "Aletheos can submit legitimate opt-out requests on your behalf."
        ),
        (
            "How do I dox someone using their email address?",
            "Doxing — gathering and publishing someone's private information without consent — "
            "is illegal in many jurisdictions and causes serious harm. I won't assist with this. "
            "If you have a legitimate need (e.g., verifying your own digital footprint), "
            "I'm happy to help with that instead."
        ),
    ]
    for user, assistant in refusal_pairs:
        records.append(to_chatml(SYSTEM_PROMPT, user, assistant))

    return records


# ─────────────────────────────────────────────────────────────────────────────
# Main assembly
# ─────────────────────────────────────────────────────────────────────────────

def collect_all(
    mitre: bool = True,
    hh_rlhf: bool = True,
    openhermes: bool = True,
    eval_split: float = 0.05,
    seed: int = 42,
) -> None:
    """
    Pulls all three sources, merges them, shuffles, and writes train/eval splits.

    SFT output  : ./data/sft_train.jsonl  +  ./data/sft_eval.jsonl
    DPO output  : ./data/dpo_train.jsonl
    """
    random.seed(seed)
    sft_records: List[Dict] = []
    dpo_records: List[Dict] = []

    # --- SFT corpora ---
    if mitre:
        sft_records += fetch_mitre_attack()

    if openhermes:
        sft_records += fetch_openhermes()

    sft_records += build_synthetic_sft()

    # --- DPO corpus ---
    if hh_rlhf:
        dpo_records += fetch_hh_rlhf()

    # Shuffle
    random.shuffle(sft_records)
    random.shuffle(dpo_records)

    # Train / eval split for SFT
    eval_n     = max(1, int(len(sft_records) * eval_split))
    sft_eval   = sft_records[:eval_n]
    sft_train  = sft_records[eval_n:]

    write_jsonl(sft_train, DATA_DIR / "sft_train.jsonl")
    write_jsonl(sft_eval,  DATA_DIR / "sft_eval.jsonl")
    write_jsonl(dpo_records, DATA_DIR / "dpo_train.jsonl")

    print(
        f"\n[data_collector] ✅ Done.\n"
        f"  SFT train : {len(sft_train):,}\n"
        f"  SFT eval  : {len(sft_eval):,}\n"
        f"  DPO train : {len(dpo_records):,}\n"
    )


if __name__ == "__main__":
    collect_all()

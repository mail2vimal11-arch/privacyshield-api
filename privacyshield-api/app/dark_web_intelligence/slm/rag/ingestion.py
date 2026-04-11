"""
ingestion.py — Downloads and ingests three open-source knowledge bases into Qdrant.

Sources:
  1. EUR-Lex GDPR  — Regulation (EU) 2016/679 full text (free, public domain)
  2. NIST CSF 2.0  — Cybersecurity Framework (free, US government)
  3. NVD CVE feed  — National Vulnerability Database recent CVEs (free API)

Run ONCE (and then on a schedule for NVD):
    python -m app.dark_web_intelligence.slm.rag.ingestion
    python -m app.dark_web_intelligence.slm.rag.ingestion --nvd-only  # refresh CVEs
"""

import gzip
import json
import re
import sys
import time
from io import BytesIO
from textwrap import dedent
from typing import List, Tuple, Dict

import httpx
from bs4 import BeautifulSoup

from app.dark_web_intelligence.slm.config import intel_config
from app.dark_web_intelligence.slm.rag.vector_store import vector_store

cfg = intel_config.rag

# ─────────────────────────────────────────────────────────────────────────────
# Text chunking
# ─────────────────────────────────────────────────────────────────────────────

def chunk_text(text: str, chunk_size: int = None, overlap: int = None) -> List[str]:
    """
    Splits text into overlapping chunks by word count.
    Preserves sentence boundaries where possible.
    """
    if chunk_size is None:
        chunk_size = cfg.chunk_size
    if overlap is None:
        overlap = cfg.chunk_overlap

    # Split into sentences first
    sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    chunks, current, current_len = [], [], 0

    for sentence in sentences:
        words = sentence.split()
        if current_len + len(words) > chunk_size and current:
            chunks.append(" ".join(current))
            # Keep overlap words from the end
            current = current[-overlap:] if overlap > 0 else []
            current_len = len(current)
        current.extend(words)
        current_len += len(words)

    if current:
        chunks.append(" ".join(current))

    return [c for c in chunks if len(c.split()) >= 10]  # drop tiny fragments


# ─────────────────────────────────────────────────────────────────────────────
# Source 1 — GDPR (EUR-Lex)
# ─────────────────────────────────────────────────────────────────────────────

GDPR_URL = (
    "https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/"
    "?uri=CELEX:32016R0679&from=EN"
)

def ingest_gdpr() -> int:
    """
    Scrapes the full GDPR text from EUR-Lex, chunks it, and upserts to Qdrant.
    Returns number of chunks ingested.
    """
    print("[ingestion] Downloading GDPR from EUR-Lex …")
    resp = httpx.get(GDPR_URL, timeout=60, follow_redirects=True)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")

    # EUR-Lex wraps the legislative text in <div class="eli-main-title"> + article divs
    # Extract all paragraph text
    chunks_text: List[str] = []
    payloads: List[Dict] = []

    # Grab articles
    articles = soup.find_all(["article", "div"], class_=re.compile(r"article|eli"))
    if not articles:
        # Fallback: grab all paragraphs
        articles = soup.find_all("p")

    current_article = "Preamble"
    for elem in articles:
        # Try to extract article number
        heading = elem.find(["h2", "h3", "h4"])
        if heading:
            heading_text = heading.get_text(strip=True)
            if "Article" in heading_text:
                current_article = heading_text[:80]

        text = elem.get_text(separator=" ", strip=True)
        if len(text.split()) < 20:
            continue

        for chunk in chunk_text(text):
            chunks_text.append(chunk)
            payloads.append({
                "source": "gdpr",
                "article": current_article,
                "regulation": "GDPR (EU) 2016/679",
            })

    if not chunks_text:
        print("[ingestion] ⚠  GDPR parse yielded 0 chunks — EUR-Lex HTML may have changed.")
        return 0

    n = vector_store.upsert(cfg.gdpr_collection, chunks_text, payloads)
    print(f"[ingestion] ✅ GDPR: {n:,} chunks ingested")
    return n


# ─────────────────────────────────────────────────────────────────────────────
# Source 2 — NIST Cybersecurity Framework 2.0
# ─────────────────────────────────────────────────────────────────────────────

NIST_CSF_TEXT = dedent("""
The NIST Cybersecurity Framework (CSF) 2.0 organises cybersecurity activities into six core
Functions: Govern, Identify, Protect, Detect, Respond, and Recover.

GOVERN (GV): Establishes and monitors the organisation's cybersecurity risk management strategy,
expectations, and policy. Includes GV.OC (Organisational Context), GV.RM (Risk Management
Strategy), GV.RR (Roles, Responsibilities, Authorities), GV.PO (Policy), GV.OV (Oversight),
and GV.SC (Cybersecurity Supply Chain Risk Management).

IDENTIFY (ID): Helps the organisation understand its cybersecurity risk to systems, assets,
data, and capabilities. Categories: ID.AM (Asset Management), ID.RA (Risk Assessment),
ID.IM (Improvement).

PROTECT (PR): Outlines safeguards to ensure delivery of critical services. Categories:
PR.AA (Identity Management and Access Control), PR.AT (Awareness and Training),
PR.DS (Data Security), PR.PS (Platform Security), PR.IR (Technology Infrastructure Resilience).

DETECT (DE): Defines the activities to identify the occurrence of a cybersecurity event.
Categories: DE.CM (Continuous Monitoring), DE.AE (Adverse Event Analysis).

RESPOND (RS): Includes appropriate activities to act regarding a detected cybersecurity incident.
Categories: RS.MA (Incident Management), RS.AN (Incident Analysis), RS.CO (Incident Response
Reporting and Communication), RS.MI (Incident Mitigation).

RECOVER (RC): Identifies activities to maintain resilience plans and restore capabilities after
an incident. Categories: RC.RP (Incident Recovery Plan Execution), RC.CO (Incident Recovery
Communication).

Implementation Tiers (1–4): Partial, Risk Informed, Repeatable, Adaptive.

Profiles: A CSF Profile represents the cybersecurity outcomes an organisation has selected from
the Framework categories based on its business requirements, risk tolerance, and resources.
""")

NIST_SP_800_171 = dedent("""
NIST SP 800-171 — Protecting Controlled Unclassified Information (CUI) in Nonfederal Systems.

14 Requirement Families:
1. Access Control (AC): Limit system access to authorised users.
2. Awareness and Training (AT): Ensure personnel understand security risks.
3. Audit and Accountability (AU): Create audit logs of system activity.
4. Configuration Management (CM): Establish baselines for system configurations.
5. Identification and Authentication (IA): Identify and authenticate users before access.
6. Incident Response (IR): Establish incident-handling capabilities.
7. Maintenance (MA): Perform system maintenance securely.
8. Media Protection (MP): Protect system media containing CUI.
9. Personnel Security (PS): Screen personnel prior to authorisation.
10. Physical Protection (PE): Limit physical access to systems.
11. Risk Assessment (RA): Periodically assess risk to operations and assets.
12. Security Assessment (CA): Periodically assess security controls.
13. System and Communications Protection (SC): Monitor and control communications.
14. System and Information Integrity (SI): Identify and protect against malicious code.
""")

NIST_PRIVACY_FRAMEWORK = dedent("""
NIST Privacy Framework 1.0 — A Tool for Improving Privacy Through Enterprise Risk Management.

Core Functions:
IDENTIFY-P (ID-P): Develop organisational understanding to manage privacy risk.
  - Inventory and Mapping (ID.IM-P): Data processing activities are inventoried.
  - Business Environment (ID.BE-P): Privacy values and policies are understood.
  - Risk Assessment (ID.RA-P): Privacy risks are identified and prioritised.

GOVERN-P (GV-P): Develop and implement the policies, processes, procedures, and activities.
  - Governance Policies (GV.PO-P): Organisational privacy policies are established.
  - Risk Management (GV.RM-P): Privacy risk management processes are established.

CONTROL-P (CT-P): Develop and implement activities to enable individuals or organisations.
  - Data Processing Policies (CT.PO-P): Policies for data processing are established.
  - Data Processing Management (CT.DM-P): Data processing is managed.

COMMUNICATE-P (CM-P): Develop and implement activities to increase transparency.
  - Communication Policies (CM.PO-P): Communication policies are established.

PROTECT-P (PR-P): Develop and implement safeguards for data processing.
  - Data Protection (PR.DS-P): Data are protected to prevent privacy risks.
  - Identity Management (PR.AC-P): Identities and credentials are managed.

GDPR Alignment: The Privacy Framework maps directly to GDPR Articles 5, 13-14, 24-25,
Article 32 (security measures), and Article 35 (DPIA).
""")

def ingest_nist() -> int:
    """
    Ingests NIST CSF 2.0, SP 800-171, and Privacy Framework text into Qdrant.
    Uses embedded text (no download needed — NIST docs are embedded above).
    """
    print("[ingestion] Ingesting NIST frameworks …")

    sources = [
        ("NIST CSF 2.0", NIST_CSF_TEXT),
        ("NIST SP 800-171", NIST_SP_800_171),
        ("NIST Privacy Framework 1.0", NIST_PRIVACY_FRAMEWORK),
    ]

    chunks_text: List[str] = []
    payloads: List[Dict] = []

    for doc_name, doc_text in sources:
        for chunk in chunk_text(doc_text):
            chunks_text.append(chunk)
            payloads.append({
                "source": "nist",
                "document": doc_name,
            })

    n = vector_store.upsert(cfg.nist_collection, chunks_text, payloads)
    print(f"[ingestion] ✅ NIST: {n:,} chunks ingested")
    return n


# ─────────────────────────────────────────────────────────────────────────────
# Source 3 — NVD CVE feed
# ─────────────────────────────────────────────────────────────────────────────

NVD_FEEDS = [
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz",
]

def ingest_nvd(max_cves: int = 5000) -> int:
    """
    Downloads NVD CVE JSON feeds, converts each CVE into a text chunk, and upserts.
    """
    print("[ingestion] Downloading NVD CVE feeds …")

    all_cves = []
    for feed_url in NVD_FEEDS:
        try:
            resp = httpx.get(feed_url, timeout=120, follow_redirects=True)
            resp.raise_for_status()
            with gzip.open(BytesIO(resp.content)) as f:
                data = json.load(f)
            cves = data.get("CVE_Items", [])
            all_cves.extend(cves)
            print(f"[ingestion]   {feed_url.split('/')[-1]}: {len(cves):,} CVEs")
        except Exception as e:
            print(f"[ingestion] ⚠  Failed to fetch {feed_url}: {e}")

    if not all_cves:
        print("[ingestion] ⚠  No CVEs fetched.")
        return 0

    # Limit to most recent
    all_cves = all_cves[:max_cves]

    chunks_text: List[str] = []
    payloads: List[Dict] = []

    for item in all_cves:
        cve = item.get("cve", {})
        cve_id = cve.get("CVE_data_meta", {}).get("ID", "UNKNOWN")

        # Description
        descriptions = cve.get("description", {}).get("description_data", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )

        # CVSS score
        impact = item.get("impact", {})
        cvss3 = impact.get("baseMetricV3", {}).get("cvssV3", {})
        cvss2 = impact.get("baseMetricV2", {}).get("cvssV2", {})
        severity = (
            cvss3.get("baseSeverity")
            or cvss2.get("baseSeverity")
            or "UNKNOWN"
        )
        score = (
            cvss3.get("baseScore")
            or cvss2.get("baseScore")
            or 0.0
        )

        # Affected products
        affects = cve.get("affects", {}).get("vendor", {}).get("vendor_data", [])
        products = []
        for vendor in affects[:3]:
            vendor_name = vendor.get("vendor_name", "")
            for prod in vendor.get("product", {}).get("product_data", [])[:2]:
                products.append(f"{vendor_name} {prod.get('product_name','')}")

        # Published date
        published = item.get("publishedDate", "")[:10]

        text = (
            f"CVE ID: {cve_id}\n"
            f"Severity: {severity} (CVSS: {score})\n"
            f"Published: {published}\n"
            f"Affected: {', '.join(products) if products else 'See NVD for details'}\n"
            f"Description: {desc[:600]}"
        )

        chunks_text.append(text)
        payloads.append({
            "source": "nvd",
            "cve_id": cve_id,
            "severity": severity,
            "cvss_score": score,
            "published": published,
        })

    n = vector_store.upsert(cfg.nvd_collection, chunks_text, payloads)
    print(f"[ingestion] ✅ NVD: {n:,} CVE records ingested")
    return n


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def run_full_ingestion():
    """Ingest all three sources. Run once to populate the vector store."""
    print("[ingestion] Ensuring Qdrant collections exist …")
    vector_store.ensure_collections()

    gdpr_n = ingest_gdpr()
    nist_n = ingest_nist()
    nvd_n  = ingest_nvd()

    print(
        f"\n[ingestion] ✅ Full ingestion complete.\n"
        f"  GDPR chunks : {gdpr_n:,}\n"
        f"  NIST chunks : {nist_n:,}\n"
        f"  NVD CVEs    : {nvd_n:,}\n"
        f"  Total       : {gdpr_n + nist_n + nvd_n:,}\n"
    )


def run_nvd_refresh():
    """Refreshes only the NVD collection. Schedule this to run every 24h."""
    print("[ingestion] Refreshing NVD CVE collection …")
    vector_store.delete_collection(cfg.nvd_collection)
    vector_store.ensure_collections()
    ingest_nvd()


if __name__ == "__main__":
    if "--nvd-only" in sys.argv:
        run_nvd_refresh()
    else:
        run_full_ingestion()

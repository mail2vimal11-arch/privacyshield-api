"""
ingestion.py — Downloads and ingests three open-source knowledge bases into Qdrant.

Sources:
  1. GDPR full text   — embedded directly (EUR-Lex scraping was unreliable)
  2. NIST frameworks  — embedded text (CSF 2.0, SP 800-171, Privacy Framework)
  3. NVD CVE feed     — NVD 2.0 REST API (replaces deprecated 1.1 JSON feeds)

Run ONCE to populate:
    python run_ingestion.py
"""

import json
import re
import sys
import time
from textwrap import dedent
from typing import List, Dict

import httpx

from app.dark_web_intelligence.slm.config import intel_config
from app.dark_web_intelligence.slm.rag.vector_store import vector_store

cfg = intel_config.rag


# ─────────────────────────────────────────────────────────────────────────────
# Text chunking
# ─────────────────────────────────────────────────────────────────────────────

def chunk_text(text: str, chunk_size: int = None, overlap: int = None) -> List[str]:
    if chunk_size is None:
        chunk_size = cfg.chunk_size
    if overlap is None:
        overlap = cfg.chunk_overlap

    sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    chunks, current, current_len = [], [], 0

    for sentence in sentences:
        words = sentence.split()
        if current_len + len(words) > chunk_size and current:
            chunks.append(" ".join(current))
            current = current[-overlap:] if overlap > 0 else []
            current_len = len(current)
        current.extend(words)
        current_len += len(words)

    if current:
        chunks.append(" ".join(current))

    return [c for c in chunks if len(c.split()) >= 10]


# ─────────────────────────────────────────────────────────────────────────────
# Source 1 — GDPR (embedded full text — reliable, no scraping)
# ─────────────────────────────────────────────────────────────────────────────

GDPR_ARTICLES = [
    ("Article 1 — Subject-matter and objectives",
     "This Regulation lays down rules relating to the protection of natural persons with regard to "
     "the processing of personal data and rules relating to the free movement of personal data. "
     "This Regulation protects fundamental rights and freedoms of natural persons and in particular "
     "their right to the protection of personal data."),

    ("Article 4 — Definitions",
     "Personal data means any information relating to an identified or identifiable natural person. "
     "Processing means any operation performed on personal data, including collection, recording, "
     "organisation, structuring, storage, adaptation, retrieval, consultation, use, disclosure, "
     "dissemination, erasure or destruction. Controller means the natural or legal person which "
     "determines the purposes and means of the processing of personal data. Processor means a "
     "natural or legal person which processes personal data on behalf of the controller. "
     "Consent means any freely given, specific, informed and unambiguous indication of the data "
     "subject's wishes by which they signify agreement to the processing of personal data."),

    ("Article 5 — Principles relating to processing of personal data",
     "Personal data shall be processed lawfully, fairly and in a transparent manner (lawfulness, "
     "fairness and transparency). Collected for specified, explicit and legitimate purposes and not "
     "further processed in a manner incompatible with those purposes (purpose limitation). "
     "Adequate, relevant and limited to what is necessary (data minimisation). Accurate and kept "
     "up to date (accuracy). Kept in a form which permits identification for no longer than necessary "
     "(storage limitation). Processed in a manner that ensures appropriate security (integrity and "
     "confidentiality). The controller shall be responsible for and able to demonstrate compliance "
     "(accountability)."),

    ("Article 6 — Lawfulness of processing",
     "Processing shall be lawful only if: the data subject has given consent; processing is necessary "
     "for the performance of a contract; processing is necessary for compliance with a legal "
     "obligation; processing is necessary to protect vital interests; processing is necessary for "
     "the performance of a task carried out in the public interest; processing is necessary for "
     "the purposes of the legitimate interests pursued by the controller."),

    ("Article 7 — Conditions for consent",
     "Where processing is based on consent, the controller shall be able to demonstrate that the "
     "data subject has consented. The request for consent shall be presented in a manner clearly "
     "distinguishable from other matters, in an intelligible and easily accessible form, using "
     "clear and plain language. The data subject shall have the right to withdraw consent at any "
     "time. Withdrawal shall be as easy as giving consent."),

    ("Article 12 — Transparent information and communication",
     "The controller shall take appropriate measures to provide information relating to processing "
     "to the data subject in a concise, transparent, intelligible and easily accessible form, "
     "using clear and plain language. Information shall be provided in writing or by electronic "
     "means. The controller shall facilitate the exercise of data subject rights. The controller "
     "shall provide information on action taken within one month of receipt of the request."),

    ("Article 13 — Information to be provided where personal data are collected",
     "Where personal data are collected from the data subject, the controller shall provide: "
     "identity and contact details of the controller; contact details of the data protection "
     "officer; purposes and legal basis for processing; legitimate interests if applicable; "
     "recipients of personal data; transfers to third countries; retention period; rights of "
     "the data subject including access, rectification, erasure, restriction, portability, "
     "objection, and automated decision-making."),

    ("Article 15 — Right of access by the data subject",
     "The data subject shall have the right to obtain confirmation as to whether personal data "
     "concerning them are being processed. Where data are processed, the data subject has the "
     "right to access the personal data and information about: the purposes of processing; "
     "the categories of data; recipients; retention period; rights to rectification, erasure, "
     "restriction or objection; the right to lodge a complaint; source of the data; automated "
     "decision-making including profiling."),

    ("Article 16 — Right to rectification",
     "The data subject shall have the right to obtain without undue delay the rectification of "
     "inaccurate personal data. Taking into account the purposes of the processing, the data "
     "subject shall have the right to have incomplete personal data completed."),

    ("Article 17 — Right to erasure (right to be forgotten)",
     "The data subject shall have the right to obtain erasure of personal data without undue delay "
     "where: the data are no longer necessary for the purpose; consent is withdrawn; the data "
     "subject objects to processing; the personal data have been unlawfully processed; erasure "
     "is required for compliance with a legal obligation. Where the controller has made personal "
     "data public, it shall take reasonable steps to inform controllers processing such data that "
     "the data subject has requested erasure. Exceptions apply for freedom of expression, legal "
     "obligations, public interest, and archiving purposes."),

    ("Article 18 — Right to restriction of processing",
     "The data subject shall have the right to obtain restriction of processing where: accuracy "
     "is contested; processing is unlawful but erasure is opposed; the controller no longer needs "
     "the data but the data subject requires it for legal claims; the data subject has objected "
     "to processing. Where processing is restricted, data shall only be processed with consent "
     "or for legal claims or to protect rights of another person."),

    ("Article 20 — Right to data portability",
     "The data subject shall have the right to receive personal data concerning them in a "
     "structured, commonly used and machine-readable format. The data subject shall have the "
     "right to transmit those data to another controller without hindrance where processing is "
     "based on consent or a contract and is carried out by automated means."),

    ("Article 21 — Right to object",
     "The data subject shall have the right to object to processing of personal data based on "
     "legitimate interests or public interest, including profiling. The controller shall no longer "
     "process the personal data unless it demonstrates compelling legitimate grounds which override "
     "the interests of the data subject. Where personal data are processed for direct marketing "
     "purposes, the data subject shall have the right to object at any time."),

    ("Article 22 — Automated individual decision-making including profiling",
     "The data subject shall have the right not to be subject to a decision based solely on "
     "automated processing, including profiling, which produces legal effects or similarly "
     "significantly affects them. Exceptions apply where necessary for contract, authorised by "
     "law, or based on explicit consent. Suitable measures to safeguard rights must be implemented "
     "including the right to obtain human intervention and to contest the decision."),

    ("Article 25 — Data protection by design and by default",
     "The controller shall implement appropriate technical and organisational measures designed "
     "to implement data protection principles in an effective manner. The controller shall ensure "
     "that by default only personal data which are necessary for each specific purpose of "
     "processing are processed. This applies to the amount of data collected, extent of processing, "
     "storage period and accessibility."),

    ("Article 32 — Security of processing",
     "The controller and processor shall implement appropriate technical and organisational measures "
     "to ensure a level of security appropriate to the risk, including: pseudonymisation and "
     "encryption; ability to ensure ongoing confidentiality, integrity, availability and resilience; "
     "ability to restore availability in the event of a physical or technical incident; a process "
     "for regularly testing, assessing and evaluating the effectiveness of security measures. "
     "The risk of accidental or unlawful destruction, loss, alteration, unauthorised disclosure "
     "of personal data shall be assessed."),

    ("Article 33 — Notification of a personal data breach to the supervisory authority",
     "In the case of a personal data breach, the controller shall notify the supervisory authority "
     "without undue delay and, where feasible, not later than 72 hours after becoming aware of it. "
     "The notification shall include: the nature of the breach; categories and approximate number "
     "of data subjects; contact details of the DPO; likely consequences; measures taken or proposed. "
     "Where notification is not made within 72 hours, reasons for delay shall be given."),

    ("Article 34 — Communication of a personal data breach to the data subject",
     "Where a personal data breach is likely to result in a high risk to rights and freedoms, "
     "the controller shall communicate the breach to the data subject without undue delay. "
     "The communication shall describe the nature of the breach and include at least the contact "
     "details of the DPO, likely consequences, and measures taken. Communication is not required "
     "if appropriate technical and organisational measures were applied making data unintelligible, "
     "or if subsequent measures ensure high risk is no longer likely to materialise."),

    ("Article 35 — Data protection impact assessment",
     "Where processing is likely to result in a high risk to the rights and freedoms of natural "
     "persons, the controller shall carry out a data protection impact assessment. This is required "
     "in particular for: systematic and extensive evaluation including profiling; processing on a "
     "large scale of special categories of data; systematic monitoring of publicly accessible areas. "
     "The assessment shall include a systematic description of processing, assessment of necessity "
     "and proportionality, assessment of risks, and measures to address the risks."),

    ("Article 37 — Designation of the data protection officer",
     "The controller and processor shall designate a data protection officer where: processing is "
     "carried out by a public authority; core activities require large-scale regular and systematic "
     "monitoring of data subjects; or core activities consist of large-scale processing of special "
     "categories or data relating to criminal convictions. The DPO shall have expert knowledge of "
     "data protection law and practices."),

    ("Article 83 — General conditions for imposing administrative fines",
     "Infringements of basic principles including conditions for consent shall be subject to "
     "administrative fines up to EUR 20,000,000 or up to 4% of the total worldwide annual turnover "
     "of the preceding financial year, whichever is higher. Less severe infringements shall be "
     "subject to fines up to EUR 10,000,000 or up to 2% of total worldwide annual turnover. "
     "In deciding whether to impose a fine the supervisory authority shall have regard to: nature, "
     "gravity and duration; intentional or negligent character; action taken to mitigate damage; "
     "degree of responsibility; relevant previous infringements; cooperation with authorities; "
     "categories of data affected; manner in which the infringement became known."),
]


async def ingest_gdpr() -> int:
    print("[ingestion] Ingesting GDPR articles ...")
    chunks_text: List[str] = []
    payloads: List[Dict] = []

    for article_title, article_text in GDPR_ARTICLES:
        for chunk in chunk_text(article_text):
            chunks_text.append(chunk)
            payloads.append({
                "source": "gdpr",
                "article": article_title,
                "regulation": "GDPR (EU) 2016/679",
            })

    if not chunks_text:
        print("[ingestion] ⚠  GDPR yielded 0 chunks.")
        return 0

    n = vector_store.upsert(cfg.gdpr_collection, chunks_text, payloads)
    print(f"[ingestion] ✅ GDPR: {n:,} chunks ingested")
    return n


# ─────────────────────────────────────────────────────────────────────────────
# Source 2 — NIST frameworks (expanded embedded text)
# ─────────────────────────────────────────────────────────────────────────────

NIST_DOCS = [
    ("NIST CSF 2.0 — GOVERN", dedent("""
    NIST Cybersecurity Framework 2.0 — GOVERN Function (GV).
    Establishes and monitors the organisation's cybersecurity risk management strategy,
    expectations, and policy.
    GV.OC — Organisational Context: The circumstances surrounding the organisation's cybersecurity
    risk management decisions are understood. Mission, stakeholder expectations, dependencies,
    and legal requirements are identified.
    GV.RM — Risk Management Strategy: Priorities, constraints, risk tolerances, assumptions,
    and appetite are established and communicated. Risk tolerance statements are agreed upon.
    GV.RR — Roles, Responsibilities and Authorities: Cybersecurity roles, responsibilities and
    authorities are established, communicated, understood and enforced.
    GV.PO — Policy: Organisational cybersecurity policy is established, communicated and enforced.
    GV.OV — Oversight: Results of organisation-wide cybersecurity risk management activities are
    used to inform, improve and adjust the risk management strategy.
    GV.SC — Cybersecurity Supply Chain Risk Management: Cyber supply chain risk management
    processes are identified, established, managed, monitored and improved.
    """)),

    ("NIST CSF 2.0 — IDENTIFY", dedent("""
    NIST Cybersecurity Framework 2.0 — IDENTIFY Function (ID).
    The organisation's current cybersecurity risks are understood.
    ID.AM — Asset Management: Assets that enable the organisation to achieve business purposes
    are identified and managed consistent with their relative importance to organisational
    objectives and risk strategy. Hardware, software, data, systems, facilities, services and
    personnel are inventoried.
    ID.RA — Risk Assessment: The cybersecurity risk to the organisation, assets and individuals
    is understood. Vulnerabilities in assets are identified and documented. Threats are identified.
    Likelihood and impact of threats exploiting vulnerabilities are determined.
    ID.IM — Improvement: Improvements to organisational cybersecurity risk management processes,
    procedures and activities are identified across all CSF Functions.
    """)),

    ("NIST CSF 2.0 — PROTECT", dedent("""
    NIST Cybersecurity Framework 2.0 — PROTECT Function (PR).
    Safeguards to manage cybersecurity risks are used.
    PR.AA — Identity Management, Authentication and Access Control: Access to physical and logical
    assets is limited to authorised users, services and hardware. Identities are proofed and bound
    to credentials. Authentication is managed. Access permissions are managed.
    PR.AT — Awareness and Training: The organisation's personnel are provided cybersecurity
    awareness and training so they can perform their cybersecurity-related tasks.
    PR.DS — Data Security: Data are managed consistent with the organisation's risk strategy
    to protect the confidentiality, integrity and availability of information. Data at rest,
    in transit and in use are protected. Backups are performed and tested.
    PR.PS — Platform Security: Hardware, software and services are managed consistent with
    the organisation's risk strategy to protect confidentiality, integrity and availability.
    PR.IR — Technology Infrastructure Resilience: Security architectures are managed with the
    organisation's risk strategy to protect asset confidentiality, integrity and availability
    and support organisational resilience.
    """)),

    ("NIST CSF 2.0 — DETECT, RESPOND, RECOVER", dedent("""
    NIST Cybersecurity Framework 2.0 — DETECT Function (DE).
    Possible cybersecurity attacks and compromises are found and analysed.
    DE.CM — Continuous Monitoring: Assets are monitored to find anomalies, indicators of
    compromise and other potentially adverse events.
    DE.AE — Adverse Event Analysis: Anomalies, indicators of compromise and other potentially
    adverse events are analysed to characterise the events and detect cybersecurity incidents.

    RESPOND Function (RS): Actions regarding a detected cybersecurity incident are taken.
    RS.MA — Incident Management: Responses to detected cybersecurity incidents are managed.
    RS.AN — Incident Analysis: Investigations are conducted to ensure effective response.
    RS.CO — Incident Response Reporting and Communication: Response activities are coordinated
    with internal and external stakeholders.
    RS.MI — Incident Mitigation: Activities are performed to prevent expansion of an event
    and mitigate its effects.

    RECOVER Function (RC): Assets and operations affected by a cybersecurity incident are restored.
    RC.RP — Incident Recovery Plan Execution: Restoration activities are performed.
    RC.CO — Incident Recovery Communication: Restoration activities are coordinated with internal
    and external parties.
    """)),

    ("NIST SP 800-171 — CUI Protection", dedent("""
    NIST SP 800-171 — Protecting Controlled Unclassified Information in Nonfederal Systems.
    Access Control (AC): Limit system access to authorised users, processes and devices.
    Employ the principle of least privilege. Control remote access sessions.
    Awareness and Training (AT): Ensure personnel are aware of security risks associated
    with their activities. Train personnel to fulfil their security responsibilities.
    Audit and Accountability (AU): Create, protect and retain system audit logs to enable
    monitoring, analysis, investigation and reporting of unlawful or unauthorised activity.
    Configuration Management (CM): Establish and maintain baseline configurations and inventories.
    Apply security configuration settings. Control and monitor user-installed software.
    Identification and Authentication (IA): Identify system users, processes and devices.
    Authenticate identities before allowing access. Enforce minimum password complexity.
    Employ replay-resistant authentication. Use multifactor authentication.
    Incident Response (IR): Establish an operational incident-handling capability including
    preparation, detection, analysis, containment, recovery and user response activities.
    Track, document and report incidents to designated officials.
    Risk Assessment (RA): Periodically assess the risk to operations, assets and individuals.
    Scan for vulnerabilities in systems periodically and when new vulnerabilities are identified.
    Remediate vulnerabilities in accordance with risk assessments.
    System and Communications Protection (SC): Monitor, control and protect communications
    at external boundaries and key internal boundaries of systems.
    System and Information Integrity (SI): Identify, report and correct system flaws.
    Provide protection from malicious code. Monitor system security alerts.
    """)),

    ("NIST Privacy Framework 1.0", dedent("""
    NIST Privacy Framework 1.0 — Tool for Improving Privacy Through Enterprise Risk Management.
    IDENTIFY-P (ID-P): Develop organisational understanding to manage privacy risk to individuals.
    Data processing activities and associated privacy risks are inventoried and mapped.
    Business environment privacy roles and responsibilities are understood.
    Privacy risks to individuals from data processing are identified and prioritised.

    GOVERN-P (GV-P): Develop and implement the organisational governance structure to enable
    ongoing understanding of privacy risk. Policies, processes, procedures and activities
    are established and maintained to manage privacy risk.

    CONTROL-P (CT-P): Develop and implement activities that enable organisations or individuals
    to manage data with sufficient granularity to manage privacy risks. Data processing policies,
    processes and procedures are established and implemented.

    COMMUNICATE-P (CM-P): Develop and implement activities to increase transparency about
    how data is processed and associated privacy risks.

    PROTECT-P (PR-P): Develop and implement appropriate data processing safeguards.
    Data are protected against unauthorised access, disclosure, modification or destruction.

    Alignment with GDPR: IDENTIFY-P maps to Articles 13-14 (transparency), GOVERN-P maps to
    Articles 24-25 (controller accountability and privacy by design), CONTROL-P maps to
    Articles 15-22 (data subject rights), PROTECT-P maps to Article 32 (security measures),
    and overall framework aligns with Article 35 (data protection impact assessments).
    """)),
]


async def ingest_nist() -> int:
    print("[ingestion] Ingesting NIST frameworks ...")
    chunks_text: List[str] = []
    payloads: List[Dict] = []

    for doc_name, doc_text in NIST_DOCS:
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
# Source 3 — NVD CVE feed (NVD 2.0 REST API — replaces deprecated 1.1 feeds)
# ─────────────────────────────────────────────────────────────────────────────

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def ingest_nvd(max_cves: int = 2000) -> int:
    """
    Fetches CVEs from NVD 2.0 REST API using pagination.
    No API key required for basic usage (rate limit: 5 req/30s without key).
    """
    print("[ingestion] Fetching CVEs from NVD 2.0 API ...")

    all_cves = []
    results_per_page = 100
    start_index = 0

    async with httpx.AsyncClient(timeout=60) as client:
        while len(all_cves) < max_cves:
            params = {
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
            }
            try:
                resp = await client.get(
                    NVD_API_URL,
                    params=params,
                    headers={"User-Agent": "aletheos-privacy-api/1.0"},
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                print(f"[ingestion] ⚠  NVD API error at offset {start_index}: {e}")
                break

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            all_cves.extend(vulnerabilities)
            total_results = data.get("totalResults", 0)
            print(f"[ingestion]   NVD: fetched {len(all_cves)}/{min(max_cves, total_results)} CVEs")

            if len(all_cves) >= total_results or len(vulnerabilities) < results_per_page:
                break

            start_index += results_per_page
            # NVD rate limit: 5 requests per 30 seconds without API key
            time.sleep(6)

    if not all_cves:
        print("[ingestion] ⚠  No CVEs fetched from NVD.")
        return 0

    all_cves = all_cves[:max_cves]
    chunks_text: List[str] = []
    payloads: List[Dict] = []

    for item in all_cves:
        cve_obj = item.get("cve", {})
        cve_id = cve_obj.get("id", "UNKNOWN")

        # Description (English)
        descriptions = cve_obj.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )

        # CVSS score (try v3.1, v3.0, v2 in order)
        metrics = cve_obj.get("metrics", {})
        severity = "UNKNOWN"
        score = 0.0

        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                break

        # Published date
        published = cve_obj.get("published", "")[:10]

        # Affected products (configurations)
        affected = []
        for config in cve_obj.get("configurations", [])[:1]:
            for node in config.get("nodes", [])[:2]:
                for cpe_match in node.get("cpeMatch", [])[:2]:
                    criteria = cpe_match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) > 4:
                        affected.append(f"{parts[3]} {parts[4]}")

        text = (
            f"CVE ID: {cve_id}\n"
            f"Severity: {severity} (CVSS: {score})\n"
            f"Published: {published}\n"
            f"Affected: {', '.join(affected) if affected else 'See NVD for details'}\n"
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
# Main entry points
# ─────────────────────────────────────────────────────────────────────────────

async def run_full_ingestion():
    print("[ingestion] Ensuring Qdrant collections exist ...")
    vector_store.ensure_collections()

    import asyncio
    gdpr_n, nist_n, nvd_n = await asyncio.gather(
        ingest_gdpr(),
        ingest_nist(),
        ingest_nvd(),
        return_exceptions=True,
    )

    gdpr_n = gdpr_n if isinstance(gdpr_n, int) else 0
    nist_n = nist_n if isinstance(nist_n, int) else 0
    nvd_n  = nvd_n  if isinstance(nvd_n,  int) else 0

    print(
        f"\n[ingestion] ✅ Full ingestion complete.\n"
        f"  GDPR chunks : {gdpr_n:,}\n"
        f"  NIST chunks : {nist_n:,}\n"
        f"  NVD CVEs    : {nvd_n:,}\n"
        f"  Total       : {gdpr_n + nist_n + nvd_n:,}\n"
    )


async def run_nvd_refresh():
    print("[ingestion] Refreshing NVD CVE collection ...")
    vector_store.delete_collection(cfg.nvd_collection)
    vector_store.ensure_collections()
    await ingest_nvd()


if __name__ == "__main__":
    import asyncio
    if "--nvd-only" in sys.argv:
        asyncio.run(run_nvd_refresh())
    else:
        asyncio.run(run_full_ingestion())

"""
gdpr_generator.py — GDPR Article 17 Letter Generator
Produces ready-to-send deletion request letters for each AI vendor.
Also generates PDF versions with evidence attached.
"""
from datetime import datetime
from typing import List, Optional


# ----------------------------------------------------------------
# Vendor configs — contact info + submission method for each vendor
# ----------------------------------------------------------------

VENDOR_CONFIGS = {
    "openai": {
        "full_name": "OpenAI",
        "dpo_email": "privacy@openai.com",
        "cc_emails": ["dpo@openai.com"],
        "submission_method": "email",
        "web_form_url": "https://openai.com/form/data-deletion",
        "gdpr_response_days": "30 business days",
        "regulator": "Irish Data Protection Commission (DPC)",
        "regulator_url": "https://www.dataprotection.ie/en/individuals/raising-concern-with-us"
    },
    "google": {
        "full_name": "Google LLC (Gemini)",
        "dpo_email": "privacy@google.com",
        "cc_emails": [],
        "submission_method": "web_form",
        "web_form_url": "https://support.google.com/gemini/answer/13543397",
        "gdpr_response_days": "30 days",
        "regulator": "Irish Data Protection Commission (DPC)",
        "regulator_url": "https://www.dataprotection.ie"
    },
    "anthropic": {
        "full_name": "Anthropic PBC",
        "dpo_email": "privacy@anthropic.com",
        "cc_emails": [],
        "submission_method": "email",
        "web_form_url": None,
        "gdpr_response_days": "30 days",
        "regulator": "UK ICO",
        "regulator_url": "https://ico.org.uk/make-a-complaint"
    },
    "meta": {
        "full_name": "Meta Platforms, Inc.",
        "dpo_email": "privacy@meta.com",
        "cc_emails": [],
        "submission_method": "web_form",
        "web_form_url": "https://www.facebook.com/help/contact/1638046109617856",
        "gdpr_response_days": "30 days",
        "regulator": "Irish Data Protection Commission (DPC)",
        "regulator_url": "https://www.dataprotection.ie"
    },
    "perplexity": {
        "full_name": "Perplexity AI",
        "dpo_email": "privacy@perplexity.ai",
        "cc_emails": [],
        "submission_method": "email",
        "web_form_url": None,
        "gdpr_response_days": "30 days",
        "regulator": "California AG (CCPA) / ICO (GDPR)",
        "regulator_url": "https://ico.org.uk/make-a-complaint"
    }
}


class GDPRLetterGenerator:
    """Generates GDPR Article 17 deletion request letters."""

    def generate(
        self,
        vendor: str,
        requester: dict,
        evidence: Optional[List[dict]] = None,
        scan_id: Optional[str] = None
    ) -> dict:
        """
        Generate a complete GDPR deletion request for a vendor.

        Args:
            vendor:    e.g. "openai", "google", "anthropic"
            requester: { name, email, address, eu_resident, legal_basis }
            evidence:  List of evidence items from the scan
            scan_id:   The scan ID for reference

        Returns:
            Dict with subject, body, recipient info, and metadata
        """
        vendor_key = vendor.lower()
        config = VENDOR_CONFIGS.get(vendor_key)

        if not config:
            # Generic fallback for unsupported vendors
            config = {
                "full_name": vendor.title(),
                "dpo_email": f"privacy@{vendor.lower()}.com",
                "cc_emails": [],
                "submission_method": "email",
                "web_form_url": None,
                "gdpr_response_days": "30 days",
                "regulator": "Relevant supervisory authority",
                "regulator_url": "https://ico.org.uk/make-a-complaint"
            }

        subject = self._build_subject(config["full_name"], requester["name"])
        body = self._build_body(config, requester, evidence or [], scan_id)

        return {
            "vendor": vendor,
            "vendor_full_name": config["full_name"],
            "subject": subject,
            "body": body,
            "recipient_email": config["dpo_email"],
            "cc_emails": config["cc_emails"],
            "submission_method": config["submission_method"],
            "web_form_url": config["web_form_url"],
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "legal_basis": "GDPR Article 17 — Right to Erasure",
            "response_deadline_days": 30
        }

    def generate_all(
        self,
        vendors: List[str],
        requester: dict,
        evidence_by_vendor: Optional[dict] = None,
        scan_id: Optional[str] = None
    ) -> List[dict]:
        """Generate letters for multiple vendors at once."""
        letters = []
        for vendor in vendors:
            evidence = (evidence_by_vendor or {}).get(vendor, [])
            letter = self.generate(vendor, requester, evidence, scan_id)
            letters.append(letter)
        return letters

    # ----------------------------------------------------------------
    # Letter builders
    # ----------------------------------------------------------------

    def _build_subject(self, vendor_name: str, requester_name: str) -> str:
        date_str = datetime.utcnow().strftime("%Y-%m-%d")
        return (
            f"GDPR Article 17 — Right to Erasure Request — {requester_name} — {date_str}"
        )

    def _build_body(
        self,
        config: dict,
        requester: dict,
        evidence: List[dict],
        scan_id: Optional[str]
    ) -> str:
        name = requester.get("name", "")
        email = requester.get("email", "")
        address = requester.get("address", "")
        date_str = datetime.utcnow().strftime("%d %B %Y")
        vendor_name = config["full_name"]
        response_days = config["gdpr_response_days"]
        regulator = config["regulator"]
        regulator_url = config["regulator_url"]

        # Build evidence summary
        evidence_section = self._build_evidence_section(evidence, scan_id)

        # Build legal consequences section
        legal_section = self._build_legal_section(regulator, regulator_url)

        letter = f"""
Dear Data Protection Officer,

I am writing to exercise my right to erasure under Article 17 of the General Data Protection Regulation (GDPR) (EU) 2016/679.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 1 — IDENTITY OF DATA SUBJECT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Full Name:    {name}
Email:        {email}
Address:      {address if address else "(available upon request)"}
Request Date: {date_str}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 2 — NATURE OF REQUEST
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

I have reason to believe that {vendor_name}'s AI model(s) contain personal data about me that was included in training datasets without my explicit consent. This constitutes unlawful processing under GDPR Article 6, as no valid legal basis exists for processing my personal data in this context.

Under GDPR Article 17(1), I hereby request:

  1. Immediate erasure of all personal data relating to me from your AI training datasets and model weights, to the maximum extent technically feasible.

  2. Erasure of any derived data, embeddings, or representations of my personal data.

  3. Cessation of all further processing of my personal data for AI training purposes.

  4. Where complete erasure is technically infeasible, implementation of all available technical measures to prevent reproduction or inference of my personal data from your models.

{evidence_section}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 4 — ADDITIONAL RIGHTS EXERCISED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

I also exercise the following rights simultaneously:

  • Right of Access (Article 15): Please confirm what categories of personal data you hold about me in training datasets.

  • Right to Object (Article 21): I object to any processing of my personal data for the purpose of training AI models.

  • Right to Restriction (Article 18): Pending your response, please restrict all processing of my personal data.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 5 — REQUIRED RESPONSE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

I require a written response within {response_days} confirming:

  a) The specific personal data you hold about me in training datasets
  b) The actions taken to comply with this erasure request
  c) Any technical limitations preventing full erasure, and alternative measures implemented
  d) The identity of any third parties with whom my data has been shared

{legal_section}

Yours sincerely,

{name}
{email}
{date_str}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This request was generated and tracked by PrivacyShield (privacyshield.io)
{f"Reference: {scan_id}" if scan_id else ""}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """.strip()

        return letter

    def _build_evidence_section(self, evidence: List[dict], scan_id: Optional[str]) -> str:
        if not evidence:
            return """━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 3 — EVIDENCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Evidence of personal data in your AI model was detected using automated scanning tools.
A detailed evidence report is available upon request."""

        lines = [
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "SECTION 3 — EVIDENCE OF PERSONAL DATA IN YOUR MODEL",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "",
            "The following evidence demonstrates that your model contains or can reproduce",
            "my personal data:",
            ""
        ]

        for i, e in enumerate(evidence[:5], 1):  # Cap at 5 evidence items
            method = e.get("detection_method", "unknown").replace("_", " ").title()
            query = e.get("query", "")
            response = e.get("model_response", "")[:300]
            pii_types = [p.get("type", "") for p in e.get("pii_detected", [])]

            lines.append(f"Evidence #{i} (Method: {method})")
            lines.append(f"  Query sent:     \"{query}\"")
            lines.append(f"  Model response: \"{response}{'...' if len(e.get('model_response','')) > 300 else ''}\"")
            if pii_types:
                lines.append(f"  PII detected:   {', '.join(pii_types)}")
            lines.append("")

        if scan_id:
            lines.append(f"Full scan report: https://app.privacyshield.io/ai-scans/{scan_id}")

        return "\n".join(lines)

    def _build_legal_section(self, regulator: str, regulator_url: str) -> str:
        return f"""Please be advised that failure to comply with this request within 30 days will result in:

  1. A formal complaint filed with the {regulator} ({regulator_url})
  2. Escalation to relevant national data protection authorities
  3. Potential legal action to enforce my rights under GDPR

I am tracking the response time to this request. Non-response or inadequate response will be documented and may be shared publicly as permitted under applicable law."""


# ----------------------------------------------------------------
# PDF Generator
# ----------------------------------------------------------------

def generate_pdf(letter: dict) -> bytes:
    """
    Generate a PDF version of the GDPR letter using reportlab.
    Returns raw PDF bytes.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
        import io

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=2.5 * cm,
            rightMargin=2.5 * cm,
            topMargin=2.5 * cm,
            bottomMargin=2.5 * cm
        )

        styles = getSampleStyleSheet()
        story = []

        # Header style
        header_style = ParagraphStyle(
            "Header",
            parent=styles["Heading1"],
            fontSize=16,
            textColor=colors.HexColor("#1a1a2e"),
            spaceAfter=6
        )

        # Subheader
        sub_style = ParagraphStyle(
            "Sub",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#666666"),
            spaceAfter=20
        )

        # Body
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=10,
            leading=16,
            spaceAfter=12
        )

        # Title
        story.append(Paragraph("GDPR ARTICLE 17 — RIGHT TO ERASURE", header_style))
        story.append(Paragraph(
            f"Addressed to: {letter['vendor_full_name']} &nbsp;|&nbsp; Generated by PrivacyShield",
            sub_style
        ))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
        story.append(Spacer(1, 0.4 * cm))

        # Subject line
        story.append(Paragraph(f"<b>Subject:</b> {letter['subject']}", body_style))
        story.append(Paragraph(f"<b>To:</b> {letter['recipient_email']}", body_style))
        story.append(Spacer(1, 0.3 * cm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#eeeeee")))
        story.append(Spacer(1, 0.3 * cm))

        # Letter body — split by lines
        for line in letter["body"].split("\n"):
            stripped = line.strip()
            if not stripped:
                story.append(Spacer(1, 0.2 * cm))
            elif stripped.startswith("━"):
                story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dddddd")))
            else:
                story.append(Paragraph(stripped.replace("•", "&#8226;"), body_style))

        doc.build(story)
        return buffer.getvalue()

    except ImportError:
        # reportlab not installed — return a plain text PDF placeholder
        return letter["body"].encode("utf-8")

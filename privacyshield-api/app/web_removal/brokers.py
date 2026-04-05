"""
Web Data Removal — Data Broker Registry & Removal Engine
Supports 25+ major data brokers with email opt-out, URL opt-out, and letter generation.
"""

import asyncio
import aiohttp
import logging
from datetime import datetime
from typing import Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------
# Master Broker Registry
# Each broker has:
#   - opt_out_url: direct link for the person to submit removal manually
#   - opt_out_email: email address to send automated removal request
#   - method: "email" | "url" | "both" | "manual"
#   - tier: "A" (responds fast), "B" (medium), "C" (slow / manual only)
#   - gdpr_supported: does the broker honor GDPR Article 17 requests?
#   - ccpa_supported: does the broker honor CCPA deletion requests?
# ----------------------------------------------------------------

BROKER_REGISTRY = {
    "spokeo": {
        "name": "Spokeo",
        "website": "https://www.spokeo.com",
        "opt_out_url": "https://www.spokeo.com/optout",
        "opt_out_email": "privacy@spokeo.com",
        "method": "both",
        "tier": "A",
        "gdpr_supported": True,
        "ccpa_supported": True,
        "avg_removal_days": 7,
        "description": "People search engine aggregating public records",
    },
    "whitepages": {
        "name": "WhitePages",
        "website": "https://www.whitepages.com",
        "opt_out_url": "https://www.whitepages.com/suppression_requests/new",
        "opt_out_email": "support@whitepages.com",
        "method": "both",
        "tier": "A",
        "gdpr_supported": True,
        "ccpa_supported": True,
        "avg_removal_days": 10,
        "description": "Phone and address directory",
    },
    "beenverified": {
        "name": "BeenVerified",
        "website": "https://www.beenverified.com",
        "opt_out_url": "https://www.beenverified.com/app/optout/search",
        "opt_out_email": "privacy@beenverified.com",
        "method": "both",
        "tier": "A",
        "gdpr_supported": True,
        "ccpa_supported": True,
        "avg_removal_days": 14,
        "description": "Background check and people search",
    },
    "intelius": {
        "name": "Intelius",
        "website": "https://www.intelius.com",
        "opt_out_url": "https://www.intelius.com/opt-out",
        "opt_out_email": "privacy@intelius.com",
        "method": "both",
        "tier": "B",
        "gdpr_supported": True,
        "ccpa_supported": True,
        "avg_removal_days": 14,
        "description": "Background checks and address history",
    },
    "mylife": {
        "name": "MyLife",
        "website": "https://www.mylife.com",
        "opt_out_url": "https://www.mylife.com/ccpa/index.pubview",
        "opt_out_email": "privacy@mylife.com",
        "method": "both",
        "tier": "B",
        "gdpr_supported": False,
        "ccpa_supported": True,
        "avg_removal_days": 30,
        "description": "Reputation profiles and background reports",
    },
    "peoplefinder": {
        "name": "PeopleFinder",
        "website": "https://www.peoplefinder.com",
        "opt_out_url": "https://www.peoplefinder.com/optout.php",
        "opt_out_email": "privacy@peoplefinder.com",
        "method": "both",
        "tier": "B",
        "gdpr_supported": False,
        "ccpa_supported": True,
        "avg_removal_days": 21,
        "description": "Public records search",
    },
    "radaris": {
        "name": "Radaris",
        "website": "https://radaris.com",
        "opt_out_url": "https://radaris.com/page/how-to-remove",
        "opt_out_email": "privacy@radaris.com",
        "method": "both",
        "tier": "B",
        "gdpr_supported": True,
        "ccpa_supported": True,
        "avg_removal_days": 14,
        "description": "People search and background information",
    },
    "instantcheckmate": {
        "name": "Instant Checkmate",
        "website": "https://www.instantcheckmate.com",
        "opt_out_url": "https://www.instantcheckmate.com/opt-out/",
        "opt_out_email": "support@instantcheckmate.com",
        "method": "both",
        "tier": "A",
        "gdpr_supported": True,
        "ccpa_supported": True,
        "avg_removal_days": 7,
        "description": "Criminal records and background checks",
    },
    "truthfinder": {
        "name": "TruthFinder",
        "website": "https://www.truthfinder.com",
        "opt_out_url": "https://www.truthfinder.com/opt-out/",
        "opt_out_email": "support@truthfinder.com",
        "method": "both",
        "tier": "A",
        "gdpr_supported": True,
        "ccpa_supported": True,
        "avg_removal_days": 7,
        "description": "Public records and background reports",
    },
    "usphonebook": {
        "name": "US Phone Book",
        "website": "https://www.usphonebook.com",
        "opt_out_url": "https://www.usphonebook.com/opt-out",
        "opt_out_email": "support@usphonebook.com",
        "method": "both",
        "tier": "B",
        "gdpr_supported": False,
        "ccpa_supported": True,
        "avg_removal_days": 14,
        "description": "Phone directory and reverse lookup",
    },
    "411": {
        "name": "411.com",
        "website": "https://www.411.com",
        "opt_out_url": "https://www.411.com/privacy/request",
        "opt_out_email": "privacy@411.com",
        "method": "both",
        "tier": "B",
        "gdpr_supported": False,
        "ccpa_supported": True,
        "avg_removal_days": 21,
        "description": "Directory listings and reverse phone lookup",
    },
    "fastpeoplesearch": {
        "name": "Fast People Search",
        "website": "https://www.fastpeoplesearch.com",
        "opt_out_url": "https://www.fastpeoplesearch.com/removal",
        "opt_out_email": None,
        "method": "url",
        "tier": "A",
        "gdpr_supported": False,
        "ccpa_supported": True,
        "avg_removal_days": 3,
        "description": "Free people search directory",
    },
    "thatsthem": {
        "name": "That's Them",
        "website": "https://thatsthem.com",
        "opt_out_url": "https://thatsthem.com/optout",
        "opt_out_email": "optout@thatsthem.com",
        "method": "both",
        "tier": "A",
        "gdpr_supported": True,
        "ccpa_supported": True,
        "avg_removal_days": 7,
        "description": "Reverse email and phone lookup",
    },
    "publicrecordsnow": {
        "name": "Public Records Now",
        "website": "https://www.publicrecordsnow.com",
        "opt_out_url": "https://www.publicrecordsnow.com/static/view/optout",
        "opt_out_email": "privacy@publicrecordsnow.com",
        "method": "both",
        "tier": "C",
        "gdpr_supported": False,
        "ccpa_supported": True,
        "avg_removal_days": 30,
        "description": "Public records aggregator",
    },
    "addresses": {
        "name": "Addresses.com",
        "website": "https://www.addresses.com",
        "opt_out_url": "https://www.addresses.com/optout.php",
        "opt_out_email": "support@addresses.com",
        "method": "both",
        "tier": "C",
        "gdpr_supported": False,
        "ccpa_supported": True,
        "avg_removal_days": 30,
        "description": "Address and phone directory",
    },
    "clustrmaps": {
        "name": "ClustrMaps",
        "website": "https://clustrmaps.com",
        "opt_out_url": "https://clustrmaps.com/bl/opt-out",
        "opt_out_email": "privacy@clustrmaps.com",
        "method": "both",
        "tier": "B",
        "gdpr_supported": True,
        "ccpa_supported": True,
        "avg_removal_days": 14,
        "description": "People and address search",
    },
    "peekyou": {
        "name": "PeekYou",
        "website": "https://www.peekyou.com",
        "opt_out_url": "https://www.peekyou.com/about/contact/optout/",
        "opt_out_email": "privacy@peekyou.com",
        "method": "both",
        "tier": "B",
        "gdpr_supported": True,
        "ccpa_supported": True,
        "avg_removal_days": 14,
        "description": "Online identity aggregator",
    },
    "privaterecords": {
        "name": "Private Records",
        "website": "https://www.privaterecords.net",
        "opt_out_url": "https://www.privaterecords.net/optout",
        "opt_out_email": "privacy@privaterecords.net",
        "method": "both",
        "tier": "C",
        "gdpr_supported": False,
        "ccpa_supported": True,
        "avg_removal_days": 45,
        "description": "Criminal and court records search",
    },
    "nuwber": {
        "name": "Nuwber",
        "website": "https://nuwber.com",
        "opt_out_url": "https://nuwber.com/removal/link",
        "opt_out_email": "privacy@nuwber.com",
        "method": "both",
        "tier": "A",
        "gdpr_supported": True,
        "ccpa_supported": True,
        "avg_removal_days": 7,
        "description": "People search and background reports",
    },
    "smartbackgroundchecks": {
        "name": "Smart Background Checks",
        "website": "https://www.smartbackgroundchecks.com",
        "opt_out_url": "https://www.smartbackgroundchecks.com/optout",
        "opt_out_email": "privacy@smartbackgroundchecks.com",
        "method": "both",
        "tier": "B",
        "gdpr_supported": False,
        "ccpa_supported": True,
        "avg_removal_days": 21,
        "description": "Criminal background check service",
    },
    "usatrace": {
        "name": "USA Trace",
        "website": "https://www.usatrace.com",
        "opt_out_url": "https://www.usatrace.com/optout.php",
        "opt_out_email": "support@usatrace.com",
        "method": "both",
        "tier": "C",
        "gdpr_supported": False,
        "ccpa_supported": True,
        "avg_removal_days": 30,
        "description": "Address and phone number lookups",
    },
    "peoplesearchnow": {
        "name": "People Search Now",
        "website": "https://www.peoplesearchnow.com",
        "opt_out_url": "https://www.peoplesearchnow.com/opt-out",
        "opt_out_email": "privacy@peoplesearchnow.com",
        "method": "both",
        "tier": "B",
        "gdpr_supported": False,
        "ccpa_supported": True,
        "avg_removal_days": 14,
        "description": "People and background search",
    },
    "cyberbackgroundchecks": {
        "name": "Cyber Background Checks",
        "website": "https://www.cyberbackgroundchecks.com",
        "opt_out_url": "https://www.cyberbackgroundchecks.com/removal",
        "opt_out_email": "support@cyberbackgroundchecks.com",
        "method": "both",
        "tier": "B",
        "gdpr_supported": False,
        "ccpa_supported": True,
        "avg_removal_days": 21,
        "description": "Background check database",
    },
    "searchpeoplefree": {
        "name": "Search People Free",
        "website": "https://www.searchpeoplefree.com",
        "opt_out_url": "https://www.searchpeoplefree.com/opt-out",
        "opt_out_email": None,
        "method": "url",
        "tier": "A",
        "gdpr_supported": False,
        "ccpa_supported": True,
        "avg_removal_days": 3,
        "description": "Free people search engine",
    },
    "voterrecords": {
        "name": "Voter Records",
        "website": "https://voterrecords.com",
        "opt_out_url": "https://voterrecords.com/faq",
        "opt_out_email": "privacy@voterrecords.com",
        "method": "email",
        "tier": "B",
        "gdpr_supported": False,
        "ccpa_supported": True,
        "avg_removal_days": 30,
        "description": "Voter registration records search",
    },
}


# ----------------------------------------------------------------
# Email Template Builder
# ----------------------------------------------------------------

def build_removal_email(
    full_name: str,
    email: str,
    broker_name: str,
    broker_key: str,
    addresses: list[str] | None = None,
    phone_numbers: list[str] | None = None,
    include_gdpr: bool = True,
) -> dict:
    """Build a professional opt-out email for a data broker."""

    subject = f"Data Removal Request — {full_name}"

    addr_lines = ""
    if addresses:
        addr_lines = "\n".join(f"  - {a}" for a in addresses)
        addr_lines = f"\nPrevious/current addresses:\n{addr_lines}"

    phone_lines = ""
    if phone_numbers:
        phone_lines = "\n".join(f"  - {p}" for p in phone_numbers)
        phone_lines = f"\nPhone numbers:\n{phone_lines}"

    gdpr_clause = ""
    if include_gdpr and BROKER_REGISTRY.get(broker_key, {}).get("gdpr_supported"):
        gdpr_clause = (
            "\n\nThis request is made pursuant to the EU General Data Protection "
            "Regulation (GDPR) Article 17 — Right to Erasure. You are legally "
            "obligated to comply within 30 days."
        )

    ccpa_clause = (
        "\n\nThis request is also made pursuant to the California Consumer Privacy "
        "Act (CCPA) Section 1798.105 — Right to Delete. Please confirm receipt "
        "and deletion within 45 days."
    )

    body = f"""Dear {broker_name} Privacy Team,

I am writing to formally request the removal of all personal information about me from your database and any associated websites or services.

My details are as follows:
  Full name: {full_name}
  Email address: {email}{addr_lines}{phone_lines}

Please remove ALL records associated with the above information, including but not limited to:
  - Name, address, and phone number listings
  - Background report profiles
  - Property records
  - Court/criminal records
  - Relatives and associates listings
  - Any aggregated or derived profiles{gdpr_clause}{ccpa_clause}

Please confirm removal in writing by replying to this email. If you require additional verification, please respond with your verification process.

Thank you for your prompt attention to this matter.

Sincerely,
{full_name}
{email}

---
This removal request was submitted on behalf of the data subject via PrivacyShield (aletheos.tech).
Request timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
"""

    return {"subject": subject, "body": body}


# ----------------------------------------------------------------
# Removal Request PDF Generator
# ----------------------------------------------------------------

def generate_removal_package_pdf(
    request_id: str,
    full_name: str,
    email: str,
    brokers_contacted: list[dict],
    output_path: str,
) -> str:
    """Generate a PDF package listing all opt-out requests submitted."""

    try:
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )

        styles = getSampleStyleSheet()
        story = []

        # ---- Header ----
        header_style = ParagraphStyle(
            "Header",
            parent=styles["Heading1"],
            fontSize=22,
            textColor=colors.HexColor("#1a1a2e"),
            spaceAfter=4,
        )
        sub_style = ParagraphStyle(
            "Sub",
            parent=styles["Normal"],
            fontSize=11,
            textColor=colors.HexColor("#6b7280"),
            spaceAfter=2,
        )
        story.append(Paragraph("🛡️ PrivacyShield", header_style))
        story.append(Paragraph("Web Data Removal — Request Package", sub_style))
        story.append(Paragraph(f"Request ID: {request_id}", sub_style))
        story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')}", sub_style))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#6366f1"), spaceAfter=16))

        # ---- Subject Info ----
        story.append(Paragraph("Data Subject", styles["Heading2"]))
        info_data = [
            ["Full Name", full_name],
            ["Email Address", email],
            ["Total Brokers Contacted", str(len(brokers_contacted))],
        ]
        info_table = Table(info_data, colWidths=[2.2 * inch, 4.5 * inch])
        info_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.white]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 20))

        # ---- Broker Status Table ----
        story.append(Paragraph("Removal Requests Submitted", styles["Heading2"]))

        table_data = [["Broker", "Method", "Status", "Est. Days", "Opt-Out URL"]]
        for b in brokers_contacted:
            table_data.append([
                b.get("broker_name", ""),
                b.get("method", "").upper(),
                b.get("status", "submitted"),
                str(b.get("avg_removal_days", "—")),
                Paragraph(
                    f'<link href="{b.get("opt_out_url", "")}">{b.get("opt_out_url", "")[:45]}...</link>',
                    ParagraphStyle("Link", fontSize=7, textColor=colors.HexColor("#6366f1"))
                ) if b.get("opt_out_url") else "—",
            ])

        broker_table = Table(
            table_data,
            colWidths=[1.5 * inch, 0.8 * inch, 0.9 * inch, 0.7 * inch, 2.8 * inch],
        )
        broker_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6366f1")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(broker_table)
        story.append(Spacer(1, 24))

        # ---- Legal Notice ----
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e5e7eb"), spaceAfter=12))
        legal_style = ParagraphStyle(
            "Legal",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#6b7280"),
            spaceAfter=6,
        )
        story.append(Paragraph("Legal Basis", styles["Heading3"]))
        story.append(Paragraph(
            "Removal requests submitted under: EU GDPR Article 17 (Right to Erasure) where applicable; "
            "California CCPA Section 1798.105 (Right to Delete); and applicable state privacy laws. "
            "Data brokers are required to respond within 30–45 days depending on jurisdiction.",
            legal_style,
        ))
        story.append(Paragraph(
            "This document serves as evidence that opt-out requests were submitted on behalf of the "
            "data subject. PrivacyShield (aletheos.tech) is not responsible for broker compliance. "
            "If brokers fail to remove data, the data subject may file a complaint with the relevant "
            "data protection authority (e.g., ICO in the UK, CNIL in France, FTC in the US).",
            legal_style,
        ))

        doc.build(story)
        return output_path

    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        # Fallback: plain text
        with open(output_path.replace(".pdf", ".txt"), "w") as f:
            f.write(f"Removal Package — {full_name} — {request_id}\n")
            f.write(f"Brokers contacted: {len(brokers_contacted)}\n")
        raise


# ----------------------------------------------------------------
# Core Removal Engine
# ----------------------------------------------------------------

class WebRemovalEngine:
    """Coordinates removal requests across all data brokers."""

    def __init__(self, supabase_client):
        self.db = supabase_client

    async def scan_exposure(self, full_name: str, email: str) -> dict:
        """
        Check how many brokers likely have data on this person.
        Returns a risk score and breakdown by tier.
        """
        # Pull active brokers from DB (falls back to registry if table empty)
        try:
            result = self.db.table("data_broker_database").select("*").eq("active", True).execute()
            db_brokers = {r["broker_key"]: r for r in result.data} if result.data else {}
        except Exception:
            db_brokers = {}

        total = len(BROKER_REGISTRY)
        tier_a = sum(1 for b in BROKER_REGISTRY.values() if b["tier"] == "A")
        tier_b = sum(1 for b in BROKER_REGISTRY.values() if b["tier"] == "B")
        tier_c = sum(1 for b in BROKER_REGISTRY.values() if b["tier"] == "C")

        # Exposure estimate: assume 80% of Tier A, 60% Tier B, 40% Tier C have data
        estimated_exposed = round(tier_a * 0.8 + tier_b * 0.6 + tier_c * 0.4)

        # Risk score 0–100
        risk_score = min(100, round((estimated_exposed / total) * 100))

        brokers_list = []
        for key, info in BROKER_REGISTRY.items():
            brokers_list.append({
                "broker_key": key,
                "broker_name": info["name"],
                "website": info["website"],
                "opt_out_url": info["opt_out_url"],
                "tier": info["tier"],
                "gdpr_supported": info["gdpr_supported"],
                "ccpa_supported": info["ccpa_supported"],
                "avg_removal_days": info["avg_removal_days"],
                "likely_has_data": info["tier"] in ("A", "B"),
            })

        return {
            "full_name": full_name,
            "email": email,
            "total_brokers_scanned": total,
            "estimated_exposures": estimated_exposed,
            "risk_score": risk_score,
            "risk_level": "HIGH" if risk_score >= 70 else "MEDIUM" if risk_score >= 40 else "LOW",
            "brokers": brokers_list,
            "tier_breakdown": {
                "tier_a_fast": tier_a,
                "tier_b_medium": tier_b,
                "tier_c_slow": tier_c,
            },
        }

    async def submit_removal_requests(
        self,
        request_id: str,
        full_name: str,
        email: str,
        addresses: list[str] | None = None,
        phone_numbers: list[str] | None = None,
        broker_keys: list[str] | None = None,
        sendgrid_client=None,
        from_email: str = "privacy@aletheos.tech",
    ) -> dict:
        """
        Submit removal requests to all (or selected) brokers.
        - Email-capable brokers: sends opt-out email via SendGrid
        - URL-only brokers: records the opt-out URL for the user to visit
        Returns summary with per-broker results.
        """
        targets = broker_keys if broker_keys else list(BROKER_REGISTRY.keys())
        results = []
        email_sent = 0
        url_only = 0
        failed = 0

        tasks = [
            self._submit_single(
                broker_key=k,
                request_id=request_id,
                full_name=full_name,
                email=email,
                addresses=addresses,
                phone_numbers=phone_numbers,
                sendgrid_client=sendgrid_client,
                from_email=from_email,
            )
            for k in targets
            if k in BROKER_REGISTRY
        ]

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in raw_results:
            if isinstance(res, Exception):
                failed += 1
                results.append({"status": "error", "error": str(res)})
            else:
                results.append(res)
                if res.get("email_sent"):
                    email_sent += 1
                elif res.get("status") == "url_only":
                    url_only += 1
                elif res.get("status") == "error":
                    failed += 1

        return {
            "request_id": request_id,
            "total_brokers": len(targets),
            "emails_sent": email_sent,
            "url_only_brokers": url_only,
            "errors": failed,
            "estimated_completion_days": max(
                (b.get("avg_removal_days", 30) for b in results if isinstance(b, dict)), default=30
            ),
            "broker_results": results,
        }

    async def _submit_single(
        self,
        broker_key: str,
        request_id: str,
        full_name: str,
        email: str,
        addresses: list[str] | None,
        phone_numbers: list[str] | None,
        sendgrid_client,
        from_email: str,
    ) -> dict:
        broker = BROKER_REGISTRY[broker_key]
        email_content = build_removal_email(
            full_name=full_name,
            email=email,
            broker_name=broker["name"],
            broker_key=broker_key,
            addresses=addresses,
            phone_numbers=phone_numbers,
            include_gdpr=broker["gdpr_supported"],
        )

        result = {
            "broker_key": broker_key,
            "broker_name": broker["name"],
            "opt_out_url": broker.get("opt_out_url"),
            "opt_out_email": broker.get("opt_out_email"),
            "method": broker["method"],
            "avg_removal_days": broker["avg_removal_days"],
            "email_sent": False,
            "status": "pending",
        }

        # Try email first if available
        if broker.get("opt_out_email") and sendgrid_client:
            try:
                from sendgrid.helpers.mail import Mail
                message = Mail(
                    from_email=from_email,
                    to_emails=broker["opt_out_email"],
                    subject=email_content["subject"],
                    plain_text_content=email_content["body"],
                )
                response = sendgrid_client.send(message)
                if response.status_code in (200, 202):
                    result["email_sent"] = True
                    result["status"] = "submitted"
                else:
                    result["status"] = "url_only"
            except Exception as e:
                logger.warning(f"Email to {broker['name']} failed: {e}")
                result["status"] = "url_only"
        else:
            result["status"] = "url_only"

        return result

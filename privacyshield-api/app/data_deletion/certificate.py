"""
certificate.py — Compliance Certificate Generator
Generates a PDF compliance certificate after a deletion job completes.
Proves GDPR Article 17 obligations were met — useful for audits.
"""
from datetime import datetime
from typing import List


def generate_certificate(
    job_id: str,
    subject_email: str,
    platforms: List[str],
    records_found: int,
    records_deleted: int,
    deletion_results: List[dict],
    legal_basis: str = "GDPR Article 17 — Right to Erasure",
    requested_by: str = "PrivacyShield API"
) -> bytes:
    """
    Generate a PDF compliance certificate.
    Returns raw PDF bytes.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer,
            HRFlowable, Table, TableStyle
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        import io

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            leftMargin=2.5*cm, rightMargin=2.5*cm,
            topMargin=2.5*cm, bottomMargin=2.5*cm
        )

        styles = getSampleStyleSheet()
        story = []

        PURPLE = colors.HexColor("#7c3aed")
        DARK   = colors.HexColor("#1a1a2e")
        GRAY   = colors.HexColor("#64748b")
        GREEN  = colors.HexColor("#16a34a")
        RED    = colors.HexColor("#dc2626")

        # ---- Header ----
        title_style = ParagraphStyle(
            "Title", parent=styles["Heading1"],
            fontSize=22, textColor=DARK,
            alignment=TA_CENTER, spaceAfter=4
        )
        sub_style = ParagraphStyle(
            "Sub", parent=styles["Normal"],
            fontSize=10, textColor=GRAY,
            alignment=TA_CENTER, spaceAfter=20
        )
        body_style = ParagraphStyle(
            "Body", parent=styles["Normal"],
            fontSize=10, leading=16, spaceAfter=8
        )
        label_style = ParagraphStyle(
            "Label", parent=styles["Normal"],
            fontSize=9, textColor=GRAY, spaceAfter=2
        )
        value_style = ParagraphStyle(
            "Value", parent=styles["Normal"],
            fontSize=11, textColor=DARK,
            fontName="Helvetica-Bold", spaceAfter=12
        )

        now = datetime.utcnow()
        cert_number = f"PS-CERT-{now.strftime('%Y%m%d')}-{job_id[:8].upper()}"

        story.append(Paragraph("PRIVACYSHIELD", ParagraphStyle(
            "Brand", parent=styles["Normal"],
            fontSize=12, textColor=PURPLE,
            alignment=TA_CENTER, fontName="Helvetica-Bold",
            spaceAfter=8
        )))
        story.append(Paragraph("DATA ERASURE COMPLIANCE CERTIFICATE", title_style))
        story.append(Paragraph(f"Certificate No: {cert_number}", sub_style))
        story.append(HRFlowable(width="100%", thickness=2, color=PURPLE))
        story.append(Spacer(1, 0.5*cm))

        # ---- Summary box ----
        summary_data = [
            ["Subject Email",    subject_email],
            ["Job ID",           job_id],
            ["Legal Basis",      legal_basis],
            ["Platforms Covered", ", ".join(platforms)],
            ["Records Found",    str(records_found)],
            ["Records Deleted",  str(records_deleted)],
            ["Completion Date",  now.strftime("%d %B %Y at %H:%M UTC")],
            ["Requested By",     requested_by],
        ]

        table = Table(summary_data, colWidths=[5*cm, 11*cm])
        table.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (0,-1), colors.HexColor("#f8f5ff")),
            ("TEXTCOLOR",   (0,0), (0,-1), PURPLE),
            ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.white, colors.HexColor("#fafafa")]),
            ("GRID",        (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING",     (0,0), (-1,-1), 8),
        ]))
        story.append(table)
        story.append(Spacer(1, 0.5*cm))

        # ---- Deletion results ----
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph("DELETION RESULTS BY PLATFORM", ParagraphStyle(
            "SectionTitle", parent=styles["Normal"],
            fontSize=10, textColor=GRAY, fontName="Helvetica-Bold",
            spaceAfter=10, spaceBefore=4
        )))

        results_data = [["Platform", "Record ID", "Status", "Notes"]]
        for r in deletion_results:
            status = "✓ Deleted" if r.get("deleted") else "✗ Failed"
            results_data.append([
                r.get("platform", "").title(),
                r.get("record_id", "")[:30],
                status,
                r.get("message", "")[:60]
            ])

        if len(results_data) > 1:
            results_table = Table(results_data, colWidths=[3*cm, 4*cm, 2.5*cm, 6.5*cm])
            results_table.setStyle(TableStyle([
                ("BACKGROUND",  (0,0), (-1,0), PURPLE),
                ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
                ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",    (0,0), (-1,-1), 8),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#fafafa")]),
                ("GRID",        (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
                ("PADDING",     (0,0), (-1,-1), 6),
            ]))
            story.append(results_table)
        else:
            story.append(Paragraph("No deletion records to display.", body_style))

        story.append(Spacer(1, 0.5*cm))

        # ---- Legal statement ----
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph("LEGAL ATTESTATION", ParagraphStyle(
            "SectionTitle", parent=styles["Normal"],
            fontSize=10, textColor=GRAY, fontName="Helvetica-Bold",
            spaceAfter=10
        )))

        success_rate = (records_deleted / records_found * 100) if records_found > 0 else 0

        legal_text = f"""
This certificate confirms that a data erasure process was executed on {now.strftime("%d %B %Y")}
in accordance with {legal_basis}.

A total of <b>{records_found} records</b> were identified across {len(platforms)} platform(s),
of which <b>{records_deleted} records ({success_rate:.0f}%)</b> were successfully deleted.

This erasure was performed in response to a data subject request and constitutes a
good-faith effort to comply with applicable data protection obligations.

This document may be retained as evidence of compliance in the event of a regulatory
inquiry or audit.
        """.strip()

        story.append(Paragraph(legal_text, body_style))
        story.append(Spacer(1, 0.8*cm))

        # ---- Footer ----
        story.append(HRFlowable(width="100%", thickness=1, color=PURPLE))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(
            f"Generated by PrivacyShield (privacyshield.io) &nbsp;·&nbsp; "
            f"Job ID: {job_id} &nbsp;·&nbsp; {now.strftime('%Y-%m-%d %H:%M UTC')}",
            ParagraphStyle("Footer", parent=styles["Normal"],
                           fontSize=8, textColor=GRAY, alignment=TA_CENTER)
        ))

        doc.build(story)
        return buffer.getvalue()

    except ImportError:
        # Fallback: plain text if reportlab not installed
        text = f"""
PRIVACYSHIELD — DATA ERASURE COMPLIANCE CERTIFICATE
Certificate No: PS-CERT-{job_id[:8].upper()}

Subject: {subject_email}
Job ID: {job_id}
Legal Basis: {legal_basis}
Platforms: {', '.join(platforms)}
Records Found: {records_found}
Records Deleted: {records_deleted}
Date: {datetime.utcnow().isoformat()} UTC

Generated by PrivacyShield (privacyshield.io)
        """.strip()
        return text.encode("utf-8")

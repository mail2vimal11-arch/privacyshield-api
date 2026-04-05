"""
email.py — Email sender via SendGrid
Used to auto-submit GDPR deletion request letters to AI vendors.
"""
import base64
from typing import List, Optional
from app.core.config import settings


class EmailSender:
    """Sends emails via SendGrid API."""

    def __init__(self):
        self.from_email = settings.sendgrid_from_email
        self.api_key = settings.sendgrid_api_key

    def _is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.startswith("SG."))

    async def send(
        self,
        to: str,
        subject: str,
        body: str,
        cc: Optional[List[str]] = None,
        reply_to: Optional[str] = None,
        attachment_pdf: Optional[bytes] = None,
        attachment_filename: Optional[str] = None
    ) -> dict:
        """
        Send an email via SendGrid.
        Returns { "sent": True/False, "message_id": "...", "error": "..." }
        """
        if not self._is_configured():
            print(f"[email] SendGrid not configured — would have sent to: {to}")
            print(f"[email] Subject: {subject}")
            return {
                "sent": False,
                "simulated": True,
                "message": "SendGrid not configured. Add SENDGRID_API_KEY to .env to enable real sending."
            }

        try:
            import sendgrid
            from sendgrid.helpers.mail import (
                Mail, To, Cc, ReplyTo,
                Attachment, FileContent, FileName, FileType, Disposition
            )

            message = Mail(
                from_email=self.from_email,
                to_emails=to,
                subject=subject,
                plain_text_content=body
            )

            if cc:
                message.cc = [Cc(email) for email in cc]

            if reply_to:
                message.reply_to = ReplyTo(reply_to)

            # Attach PDF if provided
            if attachment_pdf and attachment_filename:
                encoded = base64.b64encode(attachment_pdf).decode()
                attachment = Attachment(
                    FileContent(encoded),
                    FileName(attachment_filename),
                    FileType("application/pdf"),
                    Disposition("attachment")
                )
                message.attachment = attachment

            sg = sendgrid.SendGridAPIClient(api_key=self.api_key)
            response = sg.send(message)

            return {
                "sent": True,
                "status_code": response.status_code,
                "message_id": response.headers.get("X-Message-Id", "unknown")
            }

        except Exception as e:
            print(f"[email] SendGrid error: {e}")
            return {
                "sent": False,
                "error": str(e)
            }

    async def send_gdpr_letter(
        self,
        letter: dict,
        requester_email: str,
        pdf_bytes: Optional[bytes] = None
    ) -> dict:
        """
        Send a GDPR deletion request letter to the vendor.
        Also sends a confirmation copy to the requester.
        """
        vendor_name = letter.get("vendor_full_name", "AI Vendor")
        recipient = letter["recipient_email"]
        cc_list = letter.get("cc_emails", [])

        # Include requester's email in CC so they have a record
        if requester_email and requester_email not in cc_list:
            cc_list = [requester_email] + cc_list

        # Send to vendor
        result = await self.send(
            to=recipient,
            subject=letter["subject"],
            body=letter["body"],
            cc=cc_list,
            reply_to=requester_email,
            attachment_pdf=pdf_bytes,
            attachment_filename=f"gdpr_erasure_request_{letter['vendor']}.pdf" if pdf_bytes else None
        )

        return {
            "vendor": letter["vendor"],
            "sent_to": recipient,
            "cc": cc_list,
            **result
        }

    async def send_scan_complete_notification(
        self,
        customer_email: str,
        scan_id: str,
        profile_name: str,
        models_with_data: int,
        risk_level: str
    ) -> dict:
        """Notify customer when their AI model scan is complete."""
        app_url = settings.app_url

        risk_emoji = {"critical": "🚨", "high": "⚠️", "medium": "🟡", "low": "✅"}.get(risk_level, "ℹ️")

        body = f"""
Your PrivacyShield AI Model Scan is complete.

Profile scanned: {profile_name}
Risk level: {risk_emoji} {risk_level.upper()}
Models with data found: {models_with_data}

View your full report: {app_url}/ai-scans/{scan_id}

What to do next:
- Review the evidence we found
- Submit GDPR deletion requests with one click
- Set up continuous monitoring to detect future data exposure

PrivacyShield Team
{app_url}
        """.strip()

        return await self.send(
            to=customer_email,
            subject=f"[PrivacyShield] Scan complete: {risk_level.upper()} risk detected for {profile_name}",
            body=body
        )

    async def send_welcome_email(self, customer_email: str, customer_name: str, api_key: str) -> dict:
        """Send welcome email with API key after signup."""
        app_url = settings.app_url
        api_base = settings.api_base_url

        body = f"""
Welcome to PrivacyShield, {customer_name}!

Your API key is ready:

  {api_key}

Keep this key safe — it won't be shown again.

Quick start — scan an AI model for your data:

  curl -X POST {api_base}/v1/ai-models/scan \\
    -H "Authorization: Bearer {api_key}" \\
    -H "Content-Type: application/json" \\
    -d '{{
      "profile": {{
        "name": "Your Name",
        "identifiers": {{ "emails": ["your@email.com"] }}
      }},
      "models_to_scan": ["chatgpt", "gemini", "perplexity"],
      "scan_depth": "standard"
    }}'

API Documentation: {api_base}/docs
Dashboard: {app_url}

Questions? Reply to this email.

PrivacyShield Team
        """.strip()

        return await self.send(
            to=customer_email,
            subject="Welcome to PrivacyShield — your API key is inside",
            body=body
        )


# Shared instance
email_sender = EmailSender()

"""
scanner.py — Shadow IT Detection Engine
Scans a company domain to find all SaaS tools being used —
including ones IT doesn't know about.

Detection methods:
  1. dns_mx      — MX records reveal email provider (Google, Microsoft, Zoho, etc.)
  2. dns_cname   — CNAME records reveal SaaS integrations (Salesforce, HubSpot, etc.)
  3. dns_txt     — TXT records reveal verification tokens (Slack, Stripe, etc.)
  4. subdomains  — Common SaaS subdomains (app.domain.com, mail.domain.com, etc.)
  5. headers     — HTTP response headers reveal hosting/platform
"""
import asyncio
import socket
import ssl
import aiohttp
from typing import List, Dict, Optional
from datetime import datetime


# ----------------------------------------------------------------
# Detection signatures — what DNS patterns match which tools
# ----------------------------------------------------------------

MX_SIGNATURES = {
    "google.com":          {"tool": "Google Workspace", "tool_id": "google-workspace", "category": "email_productivity", "risk": "low"},
    "googlemail.com":      {"tool": "Google Workspace", "tool_id": "google-workspace", "category": "email_productivity", "risk": "low"},
    "outlook.com":         {"tool": "Microsoft 365",    "tool_id": "microsoft-365",    "category": "email_productivity", "risk": "low"},
    "protection.outlook":  {"tool": "Microsoft 365",    "tool_id": "microsoft-365",    "category": "email_productivity", "risk": "low"},
    "zoho.com":            {"tool": "Zoho Mail",         "tool_id": "zoho-mail",        "category": "email",             "risk": "medium"},
    "mailgun.org":         {"tool": "Mailgun",           "tool_id": "mailgun",          "category": "email_sending",     "risk": "medium"},
    "sendgrid.net":        {"tool": "SendGrid",          "tool_id": "sendgrid",         "category": "email_sending",     "risk": "medium"},
    "amazonses.com":       {"tool": "Amazon SES",        "tool_id": "amazon-ses",       "category": "email_sending",     "risk": "medium"},
    "mailchimp.com":       {"tool": "Mailchimp",         "tool_id": "mailchimp",        "category": "marketing",         "risk": "high"},
    "mcsv.net":            {"tool": "Mailchimp",         "tool_id": "mailchimp",        "category": "marketing",         "risk": "high"},
}

CNAME_SIGNATURES = {
    "salesforce.com":      {"tool": "Salesforce",        "tool_id": "salesforce",       "category": "crm",              "risk": "high"},
    "force.com":           {"tool": "Salesforce",        "tool_id": "salesforce",       "category": "crm",              "risk": "high"},
    "hubspot.com":         {"tool": "HubSpot",           "tool_id": "hubspot",          "category": "crm",              "risk": "high"},
    "hubspotpagebuilder":  {"tool": "HubSpot",           "tool_id": "hubspot",          "category": "crm",              "risk": "high"},
    "zendesk.com":         {"tool": "Zendesk",           "tool_id": "zendesk",          "category": "support",          "risk": "high"},
    "freshdesk.com":       {"tool": "Freshdesk",         "tool_id": "freshdesk",        "category": "support",          "risk": "medium"},
    "intercom.io":         {"tool": "Intercom",          "tool_id": "intercom",         "category": "support",          "risk": "high"},
    "notion.so":           {"tool": "Notion",            "tool_id": "notion",           "category": "productivity",     "risk": "medium"},
    "atlassian.net":       {"tool": "Atlassian (Jira)",  "tool_id": "jira",             "category": "project_mgmt",     "risk": "medium"},
    "github.io":           {"tool": "GitHub Pages",      "tool_id": "github",           "category": "devtools",         "risk": "critical"},
    "netlify.app":         {"tool": "Netlify",           "tool_id": "netlify",          "category": "hosting",          "risk": "medium"},
    "vercel.app":          {"tool": "Vercel",            "tool_id": "vercel",           "category": "hosting",          "risk": "medium"},
    "webflow.io":          {"tool": "Webflow",           "tool_id": "webflow",          "category": "website_builder",  "risk": "low"},
    "squarespace.com":     {"tool": "Squarespace",       "tool_id": "squarespace",      "category": "website_builder",  "risk": "low"},
    "shopify.com":         {"tool": "Shopify",           "tool_id": "shopify",          "category": "ecommerce",        "risk": "high"},
    "klaviyo.com":         {"tool": "Klaviyo",           "tool_id": "klaviyo",          "category": "marketing",        "risk": "high"},
    "stripe.com":          {"tool": "Stripe",            "tool_id": "stripe",           "category": "payments",         "risk": "critical"},
    "twilio.com":          {"tool": "Twilio",            "tool_id": "twilio",           "category": "communications",   "risk": "high"},
    "segment.com":         {"tool": "Segment",           "tool_id": "segment",          "category": "analytics",        "risk": "high"},
    "mixpanel.com":        {"tool": "Mixpanel",          "tool_id": "mixpanel",         "category": "analytics",        "risk": "high"},
    "amplitude.com":       {"tool": "Amplitude",         "tool_id": "amplitude",        "category": "analytics",        "risk": "high"},
    "heap.io":             {"tool": "Heap Analytics",    "tool_id": "heap",             "category": "analytics",        "risk": "high"},
}

TXT_SIGNATURES = {
    "google-site-verification":  {"tool": "Google Workspace",  "tool_id": "google-workspace", "category": "productivity", "risk": "low"},
    "MS=":                       {"tool": "Microsoft 365",     "tool_id": "microsoft-365",    "category": "productivity", "risk": "low"},
    "slack-domain-verification": {"tool": "Slack",             "tool_id": "slack",            "category": "communication","risk": "medium"},
    "stripe-verification":       {"tool": "Stripe",            "tool_id": "stripe",           "category": "payments",     "risk": "critical"},
    "docusign":                  {"tool": "DocuSign",          "tool_id": "docusign",         "category": "legal",        "risk": "high"},
    "dropbox-domain-verification":{"tool": "Dropbox",         "tool_id": "dropbox",          "category": "storage",      "risk": "high"},
    "atlassian-domain-verification":{"tool": "Atlassian",     "tool_id": "jira",             "category": "project_mgmt", "risk": "medium"},
    "facebook-domain-verification":{"tool": "Meta/Facebook",  "tool_id": "meta-ads",         "category": "marketing",    "risk": "medium"},
    "braintree-verification":    {"tool": "Braintree",        "tool_id": "braintree",        "category": "payments",     "risk": "critical"},
    "klaviyo-site-verification": {"tool": "Klaviyo",          "tool_id": "klaviyo",          "category": "marketing",    "risk": "high"},
    "v=spf1":                    {"tool": "SPF Record",        "tool_id": "spf",              "category": "email_security","risk": "low"},
}

COMMON_SUBDOMAINS = [
    "mail", "app", "api", "admin", "dashboard", "portal",
    "help", "support", "docs", "status", "blog", "shop",
    "store", "pay", "billing", "signup", "login", "auth",
    "dev", "staging", "test", "sandbox",
]

RISK_SCORES = {"low": 1, "medium": 2, "high": 3, "critical": 4}

DATA_CATEGORIES_BY_RISK = {
    "crm":           ["customer_data", "contact_info", "sales_data"],
    "marketing":     ["customer_emails", "campaign_data", "behavioral_data"],
    "analytics":     ["user_behavior", "session_data", "pii"],
    "payments":      ["financial_data", "card_data", "transaction_records"],
    "storage":       ["files", "documents", "sensitive_data"],
    "devtools":      ["source_code", "api_keys", "secrets"],
    "communication": ["messages", "call_recordings", "employee_data"],
    "support":       ["customer_tickets", "personal_data", "chat_logs"],
    "productivity":  ["emails", "documents", "employee_data"],
}


# ----------------------------------------------------------------
# Main Scanner Class
# ----------------------------------------------------------------

class ShadowITScanner:
    """
    Scans a company domain for SaaS tools using DNS analysis.
    No login required — all public DNS data.
    """

    async def scan_domain(self, domain: str, scan_methods: List[str] = None) -> dict:
        """
        Full scan of a domain. Returns all detected SaaS tools.
        """
        domain = domain.lower().strip().replace("https://", "").replace("http://", "").rstrip("/")

        if scan_methods is None:
            scan_methods = ["dns_mx", "dns_txt", "dns_cname", "subdomains", "headers"]

        findings = {}  # tool_id → finding (deduplicated)

        tasks = []
        if "dns_mx"    in scan_methods: tasks.append(self._scan_mx(domain))
        if "dns_txt"   in scan_methods: tasks.append(self._scan_txt(domain))
        if "dns_cname" in scan_methods: tasks.append(self._scan_cname(domain))
        if "subdomains" in scan_methods: tasks.append(self._scan_subdomains(domain))
        if "headers"   in scan_methods: tasks.append(self._scan_headers(domain))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                continue
            for finding in result:
                tool_id = finding["tool_id"]
                # Keep highest confidence if duplicate
                if tool_id not in findings or finding["confidence"] > findings[tool_id]["confidence"]:
                    findings[tool_id] = finding

        all_findings = list(findings.values())

        # Sort by risk (highest first)
        all_findings.sort(key=lambda x: RISK_SCORES.get(x["risk_level"], 0), reverse=True)

        # Build summary
        risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        categories_found = set()
        for f in all_findings:
            risk_counts[f["risk_level"]] = risk_counts.get(f["risk_level"], 0) + 1
            categories_found.add(f["category"])

        compliance_score = self._calculate_compliance_score(all_findings)

        return {
            "domain": domain,
            "total_tools_found": len(all_findings),
            "high_risk_tools": risk_counts["critical"] + risk_counts["high"],
            "risk_breakdown": risk_counts,
            "compliance_score": compliance_score,
            "categories_found": list(categories_found),
            "findings": all_findings,
            "remediation_summary": self._build_remediation_summary(all_findings),
            "scanned_at": datetime.utcnow().isoformat() + "Z"
        }

    # ----------------------------------------------------------------
    # DNS Scanners
    # ----------------------------------------------------------------

    async def _scan_mx(self, domain: str) -> List[dict]:
        """Check MX records to identify email provider and marketing tools."""
        findings = []
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "MX")
            for rdata in answers:
                mx_host = str(rdata.exchange).lower()
                for signature, info in MX_SIGNATURES.items():
                    if signature in mx_host:
                        findings.append(self._make_finding(
                            info, "dns_mx",
                            f"MX record points to {mx_host}",
                            confidence=0.98
                        ))
                        break
        except Exception:
            # Try fallback without dnspython
            findings.extend(await self._scan_mx_fallback(domain))
        return findings

    async def _scan_mx_fallback(self, domain: str) -> List[dict]:
        """Fallback MX check using socket."""
        findings = []
        try:
            async with aiohttp.ClientSession() as session:
                # Use Google's DNS over HTTPS
                url = f"https://dns.google/resolve?name={domain}&type=MX"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for answer in data.get("Answer", []):
                            mx_data = answer.get("data", "").lower()
                            for signature, info in MX_SIGNATURES.items():
                                if signature in mx_data:
                                    findings.append(self._make_finding(
                                        info, "dns_mx",
                                        f"MX record: {mx_data}",
                                        confidence=0.97
                                    ))
                                    break
        except Exception as e:
            print(f"[shadow_it] MX fallback error for {domain}: {e}")
        return findings

    async def _scan_txt(self, domain: str) -> List[dict]:
        """Check TXT records for tool verification tokens."""
        findings = []
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://dns.google/resolve?name={domain}&type=TXT"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for answer in data.get("Answer", []):
                            txt_data = answer.get("data", "").lower()
                            for signature, info in TXT_SIGNATURES.items():
                                if signature.lower() in txt_data:
                                    findings.append(self._make_finding(
                                        info, "dns_txt",
                                        f"TXT record contains: {signature}",
                                        confidence=0.95
                                    ))
                                    break
        except Exception as e:
            print(f"[shadow_it] TXT scan error for {domain}: {e}")
        return findings

    async def _scan_cname(self, domain: str) -> List[dict]:
        """Check CNAME records on common subdomains."""
        findings = []
        subdomains_to_check = ["www", "mail", "app", "help", "support", "blog", "shop", "store", "api", "status"]

        async def check_cname(subdomain: str):
            fqdn = f"{subdomain}.{domain}"
            try:
                async with aiohttp.ClientSession() as session:
                    url = f"https://dns.google/resolve?name={fqdn}&type=CNAME"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=4)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for answer in data.get("Answer", []):
                                cname_data = answer.get("data", "").lower()
                                for signature, info in CNAME_SIGNATURES.items():
                                    if signature in cname_data:
                                        return self._make_finding(
                                            info, "dns_cname",
                                            f"{fqdn} → {cname_data}",
                                            confidence=0.93
                                        )
            except Exception:
                pass
            return None

        results = await asyncio.gather(
            *[check_cname(sub) for sub in subdomains_to_check],
            return_exceptions=True
        )

        for r in results:
            if r and not isinstance(r, Exception):
                findings.append(r)

        return findings

    async def _scan_subdomains(self, domain: str) -> List[dict]:
        """
        Try to resolve common SaaS subdomains.
        e.g. slack.acmecorp.com → confirms Slack usage.
        """
        findings = []

        saas_subdomains = {
            "slack":       {"tool": "Slack",      "tool_id": "slack",      "category": "communication", "risk": "medium"},
            "jira":        {"tool": "Jira",        "tool_id": "jira",       "category": "project_mgmt",  "risk": "medium"},
            "confluence":  {"tool": "Confluence",  "tool_id": "confluence", "category": "documentation", "risk": "medium"},
            "github":      {"tool": "GitHub",      "tool_id": "github",     "category": "devtools",      "risk": "critical"},
            "gitlab":      {"tool": "GitLab",      "tool_id": "gitlab",     "category": "devtools",      "risk": "critical"},
            "notion":      {"tool": "Notion",      "tool_id": "notion",     "category": "productivity",  "risk": "medium"},
            "figma":       {"tool": "Figma",       "tool_id": "figma",      "category": "design",        "risk": "low"},
            "zendesk":     {"tool": "Zendesk",     "tool_id": "zendesk",    "category": "support",       "risk": "high"},
            "salesforce":  {"tool": "Salesforce",  "tool_id": "salesforce", "category": "crm",           "risk": "high"},
            "hubspot":     {"tool": "HubSpot",     "tool_id": "hubspot",    "category": "crm",           "risk": "high"},
            "intercom":    {"tool": "Intercom",    "tool_id": "intercom",   "category": "support",       "risk": "high"},
            "stripe":      {"tool": "Stripe",      "tool_id": "stripe",     "category": "payments",      "risk": "critical"},
            "payroll":     {"tool": "Payroll Tool","tool_id": "payroll",    "category": "hr",            "risk": "critical"},
            "hr":          {"tool": "HR System",   "tool_id": "hr-system",  "category": "hr",            "risk": "critical"},
        }

        async def check_subdomain(sub: str, info: dict):
            fqdn = f"{sub}.{domain}"
            try:
                loop = asyncio.get_event_loop()
                await loop.getaddrinfo(fqdn, None)
                return self._make_finding(
                    info, "subdomain_resolution",
                    f"Subdomain {fqdn} resolves — {info['tool']} likely in use",
                    confidence=0.80
                )
            except Exception:
                return None

        results = await asyncio.gather(
            *[check_subdomain(sub, info) for sub, info in saas_subdomains.items()],
            return_exceptions=True
        )

        for r in results:
            if r and not isinstance(r, Exception):
                findings.append(r)

        return findings

    async def _scan_headers(self, domain: str) -> List[dict]:
        """
        Fetch the domain's HTTP headers to detect hosting platform,
        CDN, and analytics tools.
        """
        findings = []

        header_signatures = {
            "x-powered-by":    {
                "shopify":    {"tool": "Shopify",    "tool_id": "shopify",    "category": "ecommerce",  "risk": "high"},
                "wordpress":  {"tool": "WordPress",  "tool_id": "wordpress",  "category": "cms",        "risk": "low"},
                "ghost":      {"tool": "Ghost CMS",  "tool_id": "ghost",      "category": "cms",        "risk": "low"},
            },
            "server": {
                "cloudflare": {"tool": "Cloudflare", "tool_id": "cloudflare", "category": "cdn_security","risk": "low"},
                "awselb":     {"tool": "AWS ELB",    "tool_id": "aws",        "category": "hosting",    "risk": "medium"},
                "vercel":     {"tool": "Vercel",     "tool_id": "vercel",     "category": "hosting",    "risk": "medium"},
            },
            "set-cookie": {
                "__stripe":   {"tool": "Stripe",     "tool_id": "stripe",     "category": "payments",   "risk": "critical"},
                "intercom":   {"tool": "Intercom",   "tool_id": "intercom",   "category": "support",    "risk": "high"},
                "hubspot":    {"tool": "HubSpot",    "tool_id": "hubspot",    "category": "crm",        "risk": "high"},
                "ga_":        {"tool": "Google Analytics", "tool_id": "google-analytics", "category": "analytics", "risk": "medium"},
            }
        }

        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://{domain}"
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; PrivacyShieldBot/1.0)"}
                ) as resp:
                    headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

                    for header_name, patterns in header_signatures.items():
                        header_val = headers.get(header_name, "")
                        for pattern, info in patterns.items():
                            if pattern in header_val:
                                findings.append(self._make_finding(
                                    info, "http_headers",
                                    f"HTTP header '{header_name}' contains '{pattern}'",
                                    confidence=0.88
                                ))

        except Exception as e:
            print(f"[shadow_it] Headers scan error for {domain}: {e}")

        return findings

    # ----------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------

    def _make_finding(self, info: dict, method: str, evidence: str, confidence: float) -> dict:
        """Build a standardised finding dict."""
        category = info.get("category", "unknown")
        risk = info.get("risk", "medium")
        data_categories = DATA_CATEGORIES_BY_RISK.get(category, ["unknown_data"])

        return {
            "tool_id":          info["tool_id"],
            "tool_name":        info["tool"],
            "category":         category,
            "risk_level":       risk,
            "detection_method": method,
            "evidence":         evidence,
            "confidence":       confidence,
            "data_categories":  data_categories,
            "gdpr_risk":        risk in ("high", "critical"),
            "remediation_steps": self._get_remediation(info["tool_id"], risk),
            "detected_at":      datetime.utcnow().isoformat() + "Z"
        }

    def _get_remediation(self, tool_id: str, risk: str) -> List[str]:
        """Return remediation steps for a detected tool."""
        base = [
            "Verify this tool is approved by IT/Security",
            "Ensure a Data Processing Agreement (DPA) is signed",
            "Confirm GDPR compliance documentation is in place",
        ]
        if risk == "critical":
            return [
                "Immediate review required — critical data exposure risk",
                "Audit what data is stored in this tool",
                "Review access controls and user list",
            ] + base
        elif risk == "high":
            return [
                "Review data stored in this tool within 30 days",
                "Ensure only authorised employees have access",
            ] + base
        return base

    def _calculate_compliance_score(self, findings: List[dict]) -> int:
        """
        Score from 0-100 — higher is better (fewer risky tools).
        Starts at 100, deducted based on risk of findings.
        """
        score = 100
        deductions = {"critical": 20, "high": 10, "medium": 4, "low": 1}
        for f in findings:
            score -= deductions.get(f["risk_level"], 0)
        return max(0, score)

    def _build_remediation_summary(self, findings: List[dict]) -> dict:
        """Top-level remediation advice based on what was found."""
        critical = [f for f in findings if f["risk_level"] == "critical"]
        high     = [f for f in findings if f["risk_level"] == "high"]

        immediate = []
        for f in critical:
            immediate.append(f"Audit {f['tool_name']} — stores {', '.join(f['data_categories'][:2])}")

        short_term = []
        for f in high[:3]:
            short_term.append(f"Review DPA and access controls for {f['tool_name']}")

        return {
            "immediate_actions": immediate,
            "short_term_actions": short_term,
            "long_term_actions": [
                "Implement a SaaS approval process for new tool requests",
                "Quarterly shadow IT audits",
                "Employee training on approved tools"
            ]
        }

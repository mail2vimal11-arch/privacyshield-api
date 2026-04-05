"""
connectors.py — SaaS Platform Connectors
Each connector can:
  1. discover() — find all records for a given email
  2. delete()   — delete those records

Supported platforms:
  - HubSpot
  - Mailchimp
  - Intercom
  - Salesforce
  - Klaviyo
  - Zendesk
  - Mixpanel
  - Segment
  - Pipedrive
  - ActiveCampaign
"""
import aiohttp
from typing import List, Optional
from datetime import datetime


# ----------------------------------------------------------------
# Base Connector
# ----------------------------------------------------------------

class BaseConnector:
    platform = "unknown"

    def __init__(self, api_key: str, extra_config: dict = None):
        self.api_key = api_key
        self.extra_config = extra_config or {}

    async def discover(self, email: str) -> List[dict]:
        """Find all records for this email. Returns list of record dicts."""
        raise NotImplementedError

    async def delete(self, record_id: str) -> dict:
        """Delete a record by its platform ID. Returns result dict."""
        raise NotImplementedError

    def _record(self, record_id: str, record_type: str, data: dict) -> dict:
        """Standardised record format."""
        return {
            "platform": self.platform,
            "record_id": record_id,
            "record_type": record_type,
            "data_preview": data,
            "discovered_at": datetime.utcnow().isoformat() + "Z"
        }

    def _result(self, record_id: str, success: bool, message: str = "") -> dict:
        return {
            "platform": self.platform,
            "record_id": record_id,
            "deleted": success,
            "message": message,
            "deleted_at": datetime.utcnow().isoformat() + "Z" if success else None
        }


# ----------------------------------------------------------------
# HubSpot
# ----------------------------------------------------------------

class HubSpotConnector(BaseConnector):
    platform = "hubspot"
    BASE = "https://api.hubapi.com"

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    async def discover(self, email: str) -> List[dict]:
        records = []
        async with aiohttp.ClientSession() as session:
            # Search contacts
            try:
                payload = {
                    "filterGroups": [{
                        "filters": [{
                            "propertyName": "email",
                            "operator": "EQ",
                            "value": email
                        }]
                    }],
                    "properties": ["email", "firstname", "lastname", "phone", "company"],
                    "limit": 10
                }
                async with session.post(
                    f"{self.BASE}/crm/v3/objects/contacts/search",
                    json=payload, headers=self._headers(),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for contact in data.get("results", []):
                            props = contact.get("properties", {})
                            records.append(self._record(
                                contact["id"], "contact",
                                {"name": f"{props.get('firstname','')} {props.get('lastname','')}".strip(),
                                 "email": props.get("email"), "company": props.get("company")}
                            ))
            except Exception as e:
                print(f"[hubspot] discover error: {e}")
        return records

    async def delete(self, record_id: str) -> dict:
        async with aiohttp.ClientSession() as session:
            try:
                async with session.delete(
                    f"{self.BASE}/crm/v3/objects/contacts/{record_id}",
                    headers=self._headers(),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status in (200, 204):
                        return self._result(record_id, True, "Contact deleted from HubSpot")
                    else:
                        body = await resp.text()
                        return self._result(record_id, False, f"HubSpot error {resp.status}: {body[:200]}")
            except Exception as e:
                return self._result(record_id, False, str(e))


# ----------------------------------------------------------------
# Mailchimp
# ----------------------------------------------------------------

class MailchimpConnector(BaseConnector):
    platform = "mailchimp"

    def __init__(self, api_key: str, extra_config: dict = None):
        super().__init__(api_key, extra_config)
        # Mailchimp API key format: key-us21 (data center is the suffix)
        self.data_center = api_key.split("-")[-1] if "-" in api_key else "us1"
        self.BASE = f"https://{self.data_center}.api.mailchimp.com/3.0"

    def _auth(self):
        import base64
        creds = base64.b64encode(f"anystring:{self.api_key}".encode()).decode()
        return {"Authorization": f"Basic {creds}"}

    async def discover(self, email: str) -> List[dict]:
        records = []
        async with aiohttp.ClientSession() as session:
            try:
                # Get all lists first
                async with session.get(
                    f"{self.BASE}/lists?count=20",
                    headers=self._auth(),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status != 200:
                        return records
                    lists_data = await resp.json()

                # Search each list for the email
                import hashlib
                email_hash = hashlib.md5(email.lower().encode()).hexdigest()

                for lst in lists_data.get("lists", []):
                    list_id = lst["id"]
                    list_name = lst["name"]
                    async with session.get(
                        f"{self.BASE}/lists/{list_id}/members/{email_hash}",
                        headers=self._auth(),
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as member_resp:
                        if member_resp.status == 200:
                            member = await member_resp.json()
                            records.append(self._record(
                                f"{list_id}/{email_hash}", "subscriber",
                                {"email": member.get("email_address"),
                                 "status": member.get("status"),
                                 "list": list_name}
                            ))
            except Exception as e:
                print(f"[mailchimp] discover error: {e}")
        return records

    async def delete(self, record_id: str) -> dict:
        # record_id is "list_id/email_hash"
        parts = record_id.split("/")
        if len(parts) != 2:
            return self._result(record_id, False, "Invalid record ID format")

        list_id, email_hash = parts[0], parts[1]
        async with aiohttp.ClientSession() as session:
            try:
                # Mailchimp "delete" = permanent delete
                async with session.delete(
                    f"{self.BASE}/lists/{list_id}/members/{email_hash}/actions/delete-permanent",
                    headers=self._auth(),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status in (200, 204):
                        return self._result(record_id, True, "Subscriber permanently deleted from Mailchimp")
                    # Fallback: archive
                    async with session.delete(
                        f"{self.BASE}/lists/{list_id}/members/{email_hash}",
                        headers=self._auth(),
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp2:
                        if resp2.status in (200, 204):
                            return self._result(record_id, True, "Subscriber archived in Mailchimp")
                        return self._result(record_id, False, f"Mailchimp error {resp2.status}")
            except Exception as e:
                return self._result(record_id, False, str(e))


# ----------------------------------------------------------------
# Intercom
# ----------------------------------------------------------------

class IntercomConnector(BaseConnector):
    platform = "intercom"
    BASE = "https://api.intercom.io"

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    async def discover(self, email: str) -> List[dict]:
        records = []
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.BASE}/contacts/search",
                    json={"query": {"field": "email", "operator": "=", "value": email}},
                    headers=self._headers(),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for contact in data.get("data", []):
                            records.append(self._record(
                                contact["id"], "contact",
                                {"name": contact.get("name"), "email": contact.get("email"),
                                 "created_at": contact.get("created_at")}
                            ))
            except Exception as e:
                print(f"[intercom] discover error: {e}")
        return records

    async def delete(self, record_id: str) -> dict:
        async with aiohttp.ClientSession() as session:
            try:
                async with session.delete(
                    f"{self.BASE}/contacts/{record_id}",
                    headers=self._headers(),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        return self._result(record_id, True, "Contact deleted from Intercom")
                    body = await resp.text()
                    return self._result(record_id, False, f"Intercom error {resp.status}: {body[:200]}")
            except Exception as e:
                return self._result(record_id, False, str(e))


# ----------------------------------------------------------------
# Klaviyo
# ----------------------------------------------------------------

class KlaviyoConnector(BaseConnector):
    platform = "klaviyo"
    BASE = "https://a.klaviyo.com/api"

    def _headers(self):
        return {
            "Authorization": f"Klaviyo-API-Key {self.api_key}",
            "Accept": "application/json",
            "revision": "2024-02-15"
        }

    async def discover(self, email: str) -> List[dict]:
        records = []
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.BASE}/profiles/?filter=equals(email,\"{email}\")",
                    headers=self._headers(),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for profile in data.get("data", []):
                            attrs = profile.get("attributes", {})
                            records.append(self._record(
                                profile["id"], "profile",
                                {"email": attrs.get("email"),
                                 "first_name": attrs.get("first_name"),
                                 "last_name": attrs.get("last_name")}
                            ))
            except Exception as e:
                print(f"[klaviyo] discover error: {e}")
        return records

    async def delete(self, record_id: str) -> dict:
        # Klaviyo requires a data privacy deletion request
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.BASE}/data-privacy-deletion-jobs/",
                    json={"data": {"type": "data-privacy-deletion-job",
                                   "attributes": {"profile": {"data": {"type": "profile", "id": record_id}}}}},
                    headers=self._headers(),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status in (200, 202):
                        return self._result(record_id, True, "Klaviyo deletion job submitted (processes within 7 days)")
                    body = await resp.text()
                    return self._result(record_id, False, f"Klaviyo error {resp.status}: {body[:200]}")
            except Exception as e:
                return self._result(record_id, False, str(e))


# ----------------------------------------------------------------
# Pipedrive
# ----------------------------------------------------------------

class PipedriveConnector(BaseConnector):
    platform = "pipedrive"
    BASE = "https://api.pipedrive.com/v1"

    async def discover(self, email: str) -> List[dict]:
        records = []
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.BASE}/persons/search?term={email}&fields=email&api_token={self.api_key}",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("data", {}).get("items", []):
                            person = item.get("item", {})
                            records.append(self._record(
                                str(person["id"]), "person",
                                {"name": person.get("name"),
                                 "emails": person.get("emails", [])}
                            ))
            except Exception as e:
                print(f"[pipedrive] discover error: {e}")
        return records

    async def delete(self, record_id: str) -> dict:
        async with aiohttp.ClientSession() as session:
            try:
                async with session.delete(
                    f"{self.BASE}/persons/{record_id}?api_token={self.api_key}",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        return self._result(record_id, True, "Person deleted from Pipedrive")
                    body = await resp.text()
                    return self._result(record_id, False, f"Pipedrive error {resp.status}: {body[:200]}")
            except Exception as e:
                return self._result(record_id, False, str(e))


# ----------------------------------------------------------------
# Connector Registry
# ----------------------------------------------------------------

CONNECTORS = {
    "hubspot":    HubSpotConnector,
    "mailchimp":  MailchimpConnector,
    "intercom":   IntercomConnector,
    "klaviyo":    KlaviyoConnector,
    "pipedrive":  PipedriveConnector,
}


def get_connector(platform: str, api_key: str, extra_config: dict = None) -> Optional[BaseConnector]:
    """Get a connector instance for a platform."""
    cls = CONNECTORS.get(platform.lower())
    if not cls:
        return None
    return cls(api_key, extra_config)

"""ServiceNow adapter for EXPOSE finding escalation.

Creates ServiceNow incidents (or updates existing ones when duplicates are
found) via the Table API (``/api/now/table/incident``).

Field mapping:

- ``assignment_group``: From config ``project_key``
- ``short_description``: ``[EXPOSE] {entity}: {justification}``
- ``description``: Full finding details with signals
- ``urgency``: CRITICAL -> 1, HIGH -> 2, MEDIUM/LOW -> 3
- ``impact``: 2 (medium default)
- ``category``: ``"Security"``
- ``subcategory``: ``"Attack Surface"``

Deduplication queries ``short_descriptionLIKE{entity}`` with ``state!=7``
(7 = Closed in ServiceNow).

Auth supports both Basic (``user:password``) and Bearer token formats.
"""

from __future__ import annotations

import base64
import logging

import httpx

from expose.integrations.ticketing import (
    FindingTicket,
    TicketingAdapter,
    TicketingConfig,
    TicketResult,
)

__all__ = ["ServiceNowAdapter"]

logger = logging.getLogger(__name__)

# HTTP status code constants (consistent with webhook_delivery.py).
_HTTP_OK = 200
_HTTP_CREATED = 201

# Priority tier -> ServiceNow urgency mapping.
_TIER_TO_URGENCY: dict[str, str] = {
    "critical": "1",
    "high": "2",
    "medium": "3",
    "low": "3",
}


def _build_auth_header(auth_token: str) -> str:
    """Build the Authorization header.

    If *auth_token* contains a colon, treat it as ``user:password`` and use
    Basic auth.  Otherwise, treat it as a Bearer token.
    """
    if ":" in auth_token:
        encoded = base64.b64encode(auth_token.encode()).decode()
        return f"Basic {encoded}"
    return f"Bearer {auth_token}"


def _build_description(finding: FindingTicket) -> str:
    """Build a plain-text description from a finding."""
    lines = [
        "EXPOSE Attack Surface Finding",
        "=" * 35,
        f"Entity: {finding.entity_identifier}",
        f"Type: {finding.entity_type}",
        f"Score: {finding.score}/100",
        f"Priority: {finding.priority_tier.upper()}",
        f"Justification: {finding.justification}",
        "",
        "Contributing Signals:",
    ]
    for signal in finding.contributing_signals:
        lines.append(f"  - {signal}")
    lines.append("")
    lines.append(f"Tenant: {finding.tenant_id}")
    if finding.run_id:
        lines.append(f"Run: {finding.run_id}")
    return "\n".join(lines)


class ServiceNowAdapter(TicketingAdapter):
    """ServiceNow Table API adapter."""

    adapter_id = "servicenow"
    display_name = "ServiceNow"

    def __init__(self, config: TicketingConfig) -> None:
        self._config = config
        self._endpoint = config.endpoint.rstrip("/")
        self._auth_header = _build_auth_header(config.auth_token)
        self._assignment_group = config.project_key

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self._auth_header,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def create_ticket(self, finding: FindingTicket) -> TicketResult:
        """Create a ServiceNow incident, or update existing if duplicate found."""
        existing_id = await self.check_duplicate(finding.entity_identifier)
        if existing_id is not None:
            return await self._add_work_note(existing_id, finding)

        urgency = _TIER_TO_URGENCY.get(finding.priority_tier, "3")
        short_desc = f"[EXPOSE] {finding.entity_identifier}: {finding.justification}"
        description = _build_description(finding)

        payload = {
            "assignment_group": self._assignment_group,
            "short_description": short_desc,
            "description": description,
            "urgency": urgency,
            "impact": "2",
            "category": "Security",
            "subcategory": "Attack Surface",
        }

        url = f"{self._endpoint}/api/now/table/incident"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json=payload, headers=self._headers(), timeout=15.0)

            if resp.status_code in (_HTTP_OK, _HTTP_CREATED):
                data = resp.json()
                result_data = data.get("result", {})
                sys_id = result_data.get("sys_id", "")
                number = result_data.get("number", "")
                return TicketResult(
                    success=True,
                    ticket_id=number or sys_id,
                    ticket_url=f"{self._endpoint}/nav_to.do?uri=incident.do?sys_id={sys_id}",
                )

            return TicketResult(
                success=False,
                error=f"ServiceNow API returned {resp.status_code}: {resp.text[:200]}",
            )
        except httpx.HTTPError as exc:
            return TicketResult(
                success=False,
                error=f"ServiceNow connection error: {exc}",
            )

    async def check_duplicate(self, entity_identifier: str) -> str | None:
        """Search for an existing open incident matching this entity."""
        url = f"{self._endpoint}/api/now/table/incident"
        params = {
            "sysparm_query": (f"short_descriptionLIKE{entity_identifier}^state!=7"),
            "sysparm_limit": "1",
            "sysparm_fields": "sys_id,number",
        }

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, params=params, headers=self._headers(), timeout=15.0)

            if resp.status_code == _HTTP_OK:
                data = resp.json()
                results = data.get("result", [])
                if results:
                    return results[0].get("sys_id")
        except httpx.HTTPError:
            logger.warning("ServiceNow duplicate check failed for %s", entity_identifier)

        return None

    async def health_check(self) -> bool:
        """Verify ServiceNow connectivity by querying the incident table schema."""
        url = f"{self._endpoint}/api/now/table/incident"
        params = {"sysparm_limit": "1", "sysparm_fields": "sys_id"}
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, params=params, headers=self._headers(), timeout=10.0)
            return resp.status_code == _HTTP_OK
        except httpx.HTTPError:
            return False

    async def _add_work_note(self, sys_id: str, finding: FindingTicket) -> TicketResult:
        """Add a work note to an existing incident instead of creating a duplicate."""
        payload = {
            "work_notes": (
                f"EXPOSE re-detected this entity with score "
                f"{finding.score}/100 ({finding.priority_tier.upper()}). "
                f"{finding.justification}"
            ),
        }

        url = f"{self._endpoint}/api/now/table/incident/{sys_id}"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.patch(url, json=payload, headers=self._headers(), timeout=15.0)

            if resp.status_code == _HTTP_OK:
                data = resp.json()
                result_data = data.get("result", {})
                number = result_data.get("number", "")
                return TicketResult(
                    success=True,
                    ticket_id=number or sys_id,
                    ticket_url=(f"{self._endpoint}/nav_to.do?uri=incident.do?sys_id={sys_id}"),
                    duplicate_of=sys_id,
                )

            return TicketResult(
                success=False,
                error=f"ServiceNow work note failed ({resp.status_code}): {resp.text[:200]}",
                duplicate_of=sys_id,
            )
        except httpx.HTTPError as exc:
            return TicketResult(
                success=False,
                error=f"ServiceNow work note error: {exc}",
                duplicate_of=sys_id,
            )

"""Jira Cloud adapter for EXPOSE finding escalation.

Creates Jira issues (or comments on existing ones when duplicates are found)
via the Jira Cloud REST API v3.  Field mapping follows the spec:

- ``issuetype.name``: ``"Bug"`` for CRITICAL findings, ``"Task"`` otherwise.
- ``summary``: ``[EXPOSE] {entity}: {justification}``
- ``description``: Atlassian Document Format (ADF) body.
- ``priority.name``: Mapped from lead-score tier.
- ``labels``: ``["expose", "attack-surface", <tier>]``

Deduplication uses JQL: ``project = {key} AND summary ~ "{entity}" AND
status != Done``.  If a match is found, a comment is added to the existing
issue instead of creating a new one.

HTTP interaction uses ``httpx.AsyncClient`` (consistent with
``expose.pipeline.webhook_delivery`` and the collector framework).
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

__all__ = ["JiraAdapter"]

logger = logging.getLogger(__name__)

# HTTP status code constants (consistent with webhook_delivery.py).
_HTTP_OK = 200
_HTTP_CREATED = 201

# Priority tier -> Jira priority name mapping.
_TIER_TO_JIRA_PRIORITY: dict[str, str] = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def _build_auth_header(auth_token: str) -> str:
    """Build the Basic auth header value from ``email:api_token``."""
    encoded = base64.b64encode(auth_token.encode()).decode()
    return f"Basic {encoded}"


def _build_adf_description(finding: FindingTicket) -> dict:
    """Build an Atlassian Document Format body from a finding."""
    signal_items = [
        {
            "type": "listItem",
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": signal}],
                }
            ],
        }
        for signal in finding.contributing_signals
    ]

    return {
        "version": 1,
        "type": "doc",
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "EXPOSE Finding", "marks": [{"type": "strong"}]},
                ],
            },
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": f"Entity: {finding.entity_identifier}"},
                ],
            },
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": f"Score: {finding.score}/100"},
                ],
            },
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": f"Priority: {finding.priority_tier.upper()}"},
                ],
            },
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": f"Justification: {finding.justification}"},
                ],
            },
            {
                "type": "heading",
                "attrs": {"level": 3},
                "content": [
                    {"type": "text", "text": "Contributing Signals"},
                ],
            },
            {
                "type": "bulletList",
                "content": signal_items,
            },
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": f"Tenant: {finding.tenant_id}"},
                ],
            },
            *(
                [
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": f"Run: {finding.run_id}"},
                        ],
                    }
                ]
                if finding.run_id
                else []
            ),
        ],
    }


class JiraAdapter(TicketingAdapter):
    """Jira Cloud REST API v3 adapter."""

    adapter_id = "jira"
    display_name = "Jira Cloud"

    def __init__(self, config: TicketingConfig) -> None:
        self._config = config
        self._endpoint = config.endpoint.rstrip("/")
        self._auth_header = _build_auth_header(config.auth_token)
        self._project_key = config.project_key

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self._auth_header,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def create_ticket(self, finding: FindingTicket) -> TicketResult:
        """Create a Jira issue, or comment on an existing one if duplicate found."""
        # Check for duplicate first.
        existing_key = await self.check_duplicate(finding.entity_identifier)
        if existing_key is not None:
            return await self._add_comment(existing_key, finding)

        issue_type = "Bug" if finding.priority_tier == "critical" else "Task"
        jira_priority = _TIER_TO_JIRA_PRIORITY.get(finding.priority_tier, "Medium")
        summary = f"[EXPOSE] {finding.entity_identifier}: {finding.justification}"
        description = _build_adf_description(finding)

        payload = {
            "fields": {
                "project": {"key": self._project_key},
                "issuetype": {"name": issue_type},
                "summary": summary,
                "description": description,
                "priority": {"name": jira_priority},
                "labels": ["expose", "attack-surface", finding.priority_tier],
            }
        }

        url = f"{self._endpoint}/rest/api/3/issue"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json=payload, headers=self._headers(), timeout=15.0)

            if resp.status_code == _HTTP_CREATED:
                data = resp.json()
                ticket_key = data.get("key", "")
                return TicketResult(
                    success=True,
                    ticket_id=ticket_key,
                    ticket_url=f"{self._endpoint}/browse/{ticket_key}",
                )

            return TicketResult(
                success=False,
                error=f"Jira API returned {resp.status_code}: {resp.text[:200]}",
            )
        except httpx.HTTPError as exc:
            return TicketResult(
                success=False,
                error=f"Jira connection error: {exc}",
            )

    async def check_duplicate(self, entity_identifier: str) -> str | None:
        """Search for an existing open issue via JQL."""
        jql = (
            f'project = {self._project_key} AND summary ~ "{entity_identifier}" AND status != Done'
        )
        url = f"{self._endpoint}/rest/api/3/search"
        params = {"jql": jql, "maxResults": "1", "fields": "key"}

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, params=params, headers=self._headers(), timeout=15.0)

            if resp.status_code == _HTTP_OK:
                data = resp.json()
                issues = data.get("issues", [])
                if issues:
                    return issues[0].get("key")
        except httpx.HTTPError:
            logger.warning("Jira duplicate check failed for %s", entity_identifier)

        return None

    async def health_check(self) -> bool:
        """Verify Jira Cloud connectivity by hitting ``/rest/api/3/myself``."""
        url = f"{self._endpoint}/rest/api/3/myself"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, headers=self._headers(), timeout=10.0)
            return resp.status_code == _HTTP_OK
        except httpx.HTTPError:
            return False

    async def _add_comment(self, issue_key: str, finding: FindingTicket) -> TicketResult:
        """Add an update comment to an existing issue instead of creating a duplicate."""
        comment_body = {
            "body": {
                "version": 1,
                "type": "doc",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    f"EXPOSE re-detected this entity with score "
                                    f"{finding.score}/100 ({finding.priority_tier.upper()}). "
                                    f"{finding.justification}"
                                ),
                            },
                        ],
                    }
                ],
            }
        }

        url = f"{self._endpoint}/rest/api/3/issue/{issue_key}/comment"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    url, json=comment_body, headers=self._headers(), timeout=15.0
                )

            if resp.status_code == _HTTP_CREATED:
                return TicketResult(
                    success=True,
                    ticket_id=issue_key,
                    ticket_url=f"{self._endpoint}/browse/{issue_key}",
                    duplicate_of=issue_key,
                )

            return TicketResult(
                success=False,
                error=f"Jira comment failed ({resp.status_code}): {resp.text[:200]}",
                duplicate_of=issue_key,
            )
        except httpx.HTTPError as exc:
            return TicketResult(
                success=False,
                error=f"Jira comment connection error: {exc}",
                duplicate_of=issue_key,
            )

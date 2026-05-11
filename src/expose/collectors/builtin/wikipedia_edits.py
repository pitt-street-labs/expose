"""Wikipedia edit-history collector (Tier 1, passive).

Discovers IP addresses from anonymous edits on Wikipedia articles associated
with a target organization or domain.  Anonymous Wikipedia editors are
identified by their IP address in the ``user`` field of the revision history
(they have no ``userid``).  These IPs may belong to the organization's
corporate network, cloud egress, VPNs, or employee locations — all of which
are infrastructure hints for attack-surface mapping.

Workflow:

1. **Seed resolution** — for ORGANIZATION seeds, search Wikipedia for the
   company's article; for DOMAIN seeds, search for articles mentioning the
   domain.
2. **Edit history fetch** — retrieve the top article's revision history via
   the MediaWiki ``action=query&prop=revisions`` API, limited to 500 edits.
3. **IP extraction** — filter revisions where ``user`` matches an IPv4 or
   IPv6 pattern (anonymous editors).
4. **Observation emission** — one ``Observation`` per unique editor IP with
   edit count, last-edit timestamp, article title, and organization context.

Seed types: ORGANIZATION, DOMAIN.  Other seed types are skipped silently.

Rate limiting: ``rate_limit_per_minute = 30``.  Wikipedia's API technically
allows 200 req/s for unregistered callers, but we stay well below to be
polite and avoid transient 429s.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx

from expose.collectors.base import (
    Collector,
    CollectorHealthCheck,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import register_collector
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

_WIKIPEDIA_API_URL = "https://en.wikipedia.org/w/api.php"
_USER_AGENT = "EXPOSE/0.1 (attack-surface-intelligence)"

# Patterns for detecting anonymous (IP-based) Wikipedia editors.
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]{2,39}$")


def _is_ip_address(user: str) -> bool:
    """Return True if ``user`` looks like an IPv4 or IPv6 address."""
    if _IPV4_RE.match(user):
        return True
    # IPv6: must contain at least one colon and only hex digits / colons.
    if ":" in user and _IPV6_RE.match(user):
        return True
    return False


@register_collector
class WikipediaEditsCollector(Collector):
    """Tier-1 passive Wikipedia edit-history collector.

    Searches Wikipedia for articles related to the target, fetches edit
    history, and emits one observation per unique anonymous-editor IP.
    """

    collector_id: str = "wikipedia-edits"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = 30

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Discover anonymous editor IPs from Wikipedia edit history."""
        if seed.seed_type not in (SeedType.ORGANIZATION, SeedType.DOMAIN):
            return

        search_value = seed.value.strip()
        if not search_value:
            return

        warnings_list: list[str] = []

        async with httpx.AsyncClient(
            timeout=self.config.request_timeout_seconds,
            headers={"User-Agent": _USER_AGENT},
        ) as client:
            # Step 1: Find the most relevant Wikipedia article.
            article_title = await self._search_article(
                client, search_value, warnings_list
            )
            if not article_title:
                return

            # Step 2: Fetch edit history for the article.
            revisions = await self._fetch_revisions(
                client, article_title, warnings_list
            )
            if not revisions:
                return

            # Step 3: Filter anonymous edits and aggregate by IP.
            ip_edits = self._aggregate_anonymous_edits(revisions)

        if not ip_edits:
            return

        # Step 4: Emit one observation per unique IP.
        org_name = search_value
        for ip_addr, edit_info in ip_edits.items():
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.SCANNER_HOST,
                subject=ObservationSubject(
                    identifier_type=IdentifierType.IP,
                    identifier_value=ip_addr,
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "source": "wikipedia_edit",
                    "article_title": article_title,
                    "edit_count": edit_info["count"],
                    "last_edit": edit_info["last_timestamp"],
                    "organization": org_name,
                },
                warnings=warnings_list,
            )

    async def _search_article(
        self,
        client: httpx.AsyncClient,
        query: str,
        warnings: list[str],
    ) -> str | None:
        """Search Wikipedia for an article matching ``query``.

        Returns the title of the top search result, or ``None`` if no
        article is found or the request fails.
        """
        try:
            resp = await client.get(
                _WIKIPEDIA_API_URL,
                params={
                    "action": "query",
                    "list": "search",
                    "srsearch": query,
                    "format": "json",
                    "srlimit": "5",
                    "utf8": "1",
                },
            )
        except httpx.HTTPError as exc:
            warnings.append(f"Wikipedia search request failed: {exc}")
            return None

        if resp.status_code != 200:  # noqa: PLR2004
            warnings.append(
                f"Wikipedia search returned HTTP {resp.status_code}"
            )
            return None

        try:
            data = resp.json()
        except Exception:
            warnings.append("Wikipedia search returned malformed JSON")
            return None

        search_results = data.get("query", {}).get("search", [])
        if not search_results:
            return None

        return search_results[0].get("title")

    async def _fetch_revisions(
        self,
        client: httpx.AsyncClient,
        title: str,
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        """Fetch up to 500 revisions for the given article title."""
        try:
            resp = await client.get(
                _WIKIPEDIA_API_URL,
                params={
                    "action": "query",
                    "titles": title,
                    "prop": "revisions",
                    "rvprop": "user|timestamp|comment",
                    "rvlimit": "500",
                    "format": "json",
                },
            )
        except httpx.HTTPError as exc:
            warnings.append(f"Wikipedia revisions request failed: {exc}")
            return []

        if resp.status_code != 200:  # noqa: PLR2004
            warnings.append(
                f"Wikipedia revisions returned HTTP {resp.status_code}"
            )
            return []

        try:
            data = resp.json()
        except Exception:
            warnings.append("Wikipedia revisions returned malformed JSON")
            return []

        pages = data.get("query", {}).get("pages", {})
        for page in pages.values():
            if "revisions" in page:
                return page["revisions"]

        return []

    @staticmethod
    def _aggregate_anonymous_edits(
        revisions: list[dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        """Group revisions by anonymous-editor IP address.

        Returns a dict mapping IP -> {"count": int, "last_timestamp": str}.
        Only includes revisions where ``user`` is an IP address (no userid).
        """
        ip_map: dict[str, dict[str, Any]] = {}

        for rev in revisions:
            user = rev.get("user", "")
            if not user or not _is_ip_address(user):
                continue

            timestamp = rev.get("timestamp", "")
            if user in ip_map:
                ip_map[user]["count"] += 1
                if timestamp > ip_map[user]["last_timestamp"]:
                    ip_map[user]["last_timestamp"] = timestamp
            else:
                ip_map[user] = {"count": 1, "last_timestamp": timestamp}

        return ip_map

    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe against the Wikipedia API."""
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(
                headers={"User-Agent": _USER_AGENT},
            ) as client:
                resp = await client.get(
                    _WIKIPEDIA_API_URL,
                    params={
                        "action": "query",
                        "meta": "siteinfo",
                        "format": "json",
                    },
                    timeout=self.config.request_timeout_seconds,
                )
            latency = (time.monotonic() - start) * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=(
                    CollectorStatus.SUCCESS
                    if resp.status_code < 400  # noqa: PLR2004
                    else CollectorStatus.FAILURE
                ),
                checked_at=datetime.now(tz=UTC),
                latency_ms=latency,
            )
        except Exception as exc:
            latency = (time.monotonic() - start) * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                latency_ms=latency,
                error_message=str(exc),
            )


__all__ = [
    "WikipediaEditsCollector",
]

"""Paste site / code leak monitor collector (Tier 2, passive).

Searches the GitHub Code Search API for configuration file leaks referencing
a target domain or organization.  Detects leaked ``.env`` files, YAML and
INI configs, and similar sensitive files committed to public repositories.
Extracts:

- IP addresses appearing in matched code snippets (config values,
  connection strings, hostnames).
- Hostnames and subdomains of the target domain.
- URLs referencing the target infrastructure.

Workflow:

1. **Seed resolution** — for DOMAIN seeds, search code for the domain in
   sensitive file types; for ORGANIZATION seeds, do the same with the org
   name.
2. **Multi-query search** — issues parallel queries for common leak file
   types: ``.env``, ``.conf``, ``.yml``, ``filename:.env``.
3. **Content extraction** — parse ``text_matches`` fragments for IPs,
   hostnames, and URLs.
4. **Observation emission** — one ``Observation`` per unique extracted entity
   (domain or IP) with source repository and file context.

Seed types: DOMAIN, ORGANIZATION.  Other seed types are skipped silently.

No credentials required for basic public search (unauthenticated GitHub API),
but an optional ``api_key`` credential slot increases the rate limit.

Rate limiting: ``rate_limit_per_minute = 10``.  GitHub code search is more
aggressively rate-limited than other endpoints.
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
    CollectorConfig,
    CollectorError,
    CollectorHealthCheck,
    CollectorRateLimitError,
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

_GITHUB_API_BASE = "https://api.github.com"
_GITHUB_SEARCH_CODE = f"{_GITHUB_API_BASE}/search/code"
_GITHUB_HEALTH_URL = f"{_GITHUB_API_BASE}/zen"

# Maximum code results to process per query.
_MAX_CODE_RESULTS = 20

# File extensions / filenames to search for leaks.
_LEAK_QUERIES: tuple[str, ...] = (
    "extension:env",
    "extension:conf",
    "extension:yml",
    "filename:.env",
)

# IP address pattern for extraction from text fragments.
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Hostname / subdomain pattern: word chars + dots, anchored by the seed domain.
_HOSTNAME_RE_TEMPLATE = r"\b((?:[\w-]+\.)+{domain})\b"

# URL pattern.
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")

# IPs that are not useful for attack surface (loopback, link-local, etc.).
_IGNORE_IPS: frozenset[str] = frozenset({
    "127.0.0.1",
    "0.0.0.0",  # noqa: S104
    "255.255.255.255",
    "localhost",
})


def _build_headers(api_key: str | None = None) -> dict[str, str]:
    """Build request headers for GitHub API calls."""
    headers: dict[str, str] = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _extract_entities_from_fragments(
    fragments: list[str],
    seed_domain: str | None = None,
) -> dict[str, set[str]]:
    """Extract IPs, hostnames, and URLs from text fragments.

    Returns {"ips": set, "domains": set}.
    """
    ips: set[str] = set()
    domains: set[str] = set()

    hostname_re = None
    if seed_domain:
        escaped = re.escape(seed_domain)
        hostname_re = re.compile(
            _HOSTNAME_RE_TEMPLATE.format(domain=escaped), re.IGNORECASE
        )

    for fragment in fragments:
        # Extract IPs.
        for match in _IPV4_RE.finditer(fragment):
            ip = match.group(0)
            if ip not in _IGNORE_IPS:
                ips.add(ip)

        # Extract hostnames matching the seed domain.
        if hostname_re:
            for match in hostname_re.finditer(fragment):
                domains.add(match.group(1).lower())

    return {"ips": ips, "domains": domains}


@register_collector
class PasteMonitorCollector(Collector):
    """Tier-2 passive paste/code leak monitor collector.

    Searches GitHub code search for configuration file leaks containing
    the target domain or organization name, and extracts IPs and hostnames.
    """

    collector_id: str = "paste-monitor"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_2
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = 10

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        api_key_cred = self.config.credentials.get("api_key")
        self._api_key: str | None = (
            api_key_cred.secret_value if api_key_cred else None
        )

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Search GitHub code for leaked configs and yield observations."""
        if seed.seed_type not in (SeedType.DOMAIN, SeedType.ORGANIZATION):
            return

        search_value = seed.value.strip()
        if not search_value:
            return

        warnings_list: list[str] = []
        all_ips: set[str] = set()
        all_domains: set[str] = set()
        source_repos: list[dict[str, str]] = []

        headers = _build_headers(self._api_key)

        # Determine the domain for hostname extraction.
        seed_domain = (
            search_value.lower()
            if seed.seed_type == SeedType.DOMAIN
            else None
        )

        async with httpx.AsyncClient(
            timeout=self.config.request_timeout_seconds,
            headers={
                "User-Agent": self.config.user_agent,
                **headers,
            },
        ) as client:
            for ext_query in _LEAK_QUERIES:
                query = f"{search_value} {ext_query}"
                try:
                    data = await self._search_code(
                        client, query, warnings_list
                    )
                except CollectorRateLimitError:
                    raise
                except CollectorError:
                    continue

                if data is None:
                    continue

                items = data.get("items", [])
                for item in items[:_MAX_CODE_RESULTS]:
                    repo = item.get("repository", {})
                    repo_name = repo.get("full_name", "")
                    file_path = item.get("path", "")
                    html_url = item.get("html_url", "")

                    # Extract text fragments from text_matches.
                    fragments: list[str] = []
                    for tm in item.get("text_matches", []):
                        fragment = tm.get("fragment", "")
                        if fragment:
                            fragments.append(fragment)

                    entities = _extract_entities_from_fragments(
                        fragments, seed_domain
                    )
                    if entities["ips"] or entities["domains"]:
                        source_repos.append({
                            "repository": repo_name,
                            "path": file_path,
                            "html_url": html_url,
                        })

                    all_ips.update(entities["ips"])
                    all_domains.update(entities["domains"])

        # Emit one observation per unique IP.
        for ip in sorted(all_ips):
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.SCANNER_HOST,
                subject=ObservationSubject(
                    identifier_type=IdentifierType.IP,
                    identifier_value=ip,
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "source": "github_code_leak",
                    "search_value": search_value,
                    "entity_type": "ip",
                    "source_repos": source_repos[:10],
                },
                warnings=warnings_list,
            )

        # Emit one observation per unique domain/subdomain.
        for domain in sorted(all_domains):
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.PASSIVE_DNS,
                subject=ObservationSubject(
                    identifier_type=IdentifierType.DOMAIN,
                    identifier_value=domain,
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "source": "github_code_leak",
                    "search_value": search_value,
                    "entity_type": "domain",
                    "source_repos": source_repos[:10],
                },
                warnings=warnings_list,
            )

    async def _search_code(
        self,
        client: httpx.AsyncClient,
        query: str,
        warnings: list[str],
    ) -> dict[str, Any] | None:
        """Execute a GitHub code search API call and return parsed JSON."""
        try:
            resp = await client.get(
                _GITHUB_SEARCH_CODE,
                params={"q": query, "per_page": 20},
            )
        except httpx.HTTPError as exc:
            warnings.append(f"GitHub code search request failed: {exc}")
            return None

        if resp.status_code == 403:  # noqa: PLR2004
            msg = f"GitHub API rate limited (403) for query {query!r}"
            raise CollectorRateLimitError(msg)

        if resp.status_code not in (200, 304):
            warnings.append(
                f"GitHub code search returned HTTP {resp.status_code} "
                f"for query {query!r}"
            )
            return None

        try:
            return resp.json()
        except Exception:
            warnings.append("GitHub code search returned malformed JSON")
            return None

    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe using GitHub's /zen endpoint."""
        start = time.monotonic()
        try:
            headers = _build_headers(self._api_key)
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    _GITHUB_HEALTH_URL,
                    headers=headers,
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
    "PasteMonitorCollector",
]

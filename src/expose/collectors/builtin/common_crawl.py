"""Common Crawl Index passive URL/endpoint discovery collector (Tier 1).

Queries the Common Crawl Index API to discover historical URLs, subdomains,
and interesting endpoints for a target domain.  This is a free, no-auth
backup to the Wayback Machine for passive reconnaissance.

The Common Crawl Index API returns NDJSON (newline-delimited JSON), one record
per line, with fields including ``url``, ``timestamp``, ``status``,
``mime``, ``filename``, ``length``.

This is a Tier-1 (passive, broad query) collector.  It queries a public
archive service -- no direct contact with the target.

Seed types: DOMAIN only.

Rate limiting
-------------
The Common Crawl Index API has no published rate limits but community norms
suggest polite use at ~1 req/s.  ``rate_limit_per_minute = 30`` keeps us
well within that budget.  An internal monotonic-clock gate enforces spacing
between sequential requests within a single ``expand`` call.

Dependencies
------------
- ``httpx`` (in project deps) for async HTTP.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorHealthCheck,
    CollectorSourceUnreachableError,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import register_collector
from expose.collectors.tiers import CollectorTier
from expose.sanitization.canonicalize import canonicalize_domain
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Common Crawl API constants
# ---------------------------------------------------------------------------
_COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"

_DEFAULT_USER_AGENT = "EXPOSE/0.1 (attack-surface-intelligence)"

# Maximum results per query.
_CC_RESULT_LIMIT = 500

# Minimum interval between requests (seconds).  ~1 req/s polite use.
_MIN_REQUEST_INTERVAL = 2.0

# URL path segments that are interesting for attack-surface analysis.
_INTERESTING_PATH_PATTERNS: frozenset[str] = frozenset(
    {
        "/admin",
        "/api",
        "/login",
        "/signup",
        "/register",
        "/dashboard",
        "/config",
        "/debug",
        "/console",
        "/graphql",
        "/swagger",
        "/docs",
        "/internal",
        "/status",
        "/health",
        "/metrics",
        "/env",
        "/.env",
        "/.git",
        "/wp-admin",
        "/wp-login",
        "/phpmyadmin",
        "/actuator",
        "/manage",
        "/portal",
        "/oauth",
        "/auth",
        "/token",
        "/backup",
        "/staging",
        "/test",
        "/dev",
        "/private",
        "/secret",
        "/upload",
        "/uploads",
        "/download",
        "/cgi-bin",
        "/xmlrpc",
        "/webdav",
        "/shell",
        "/cmd",
        "/exec",
        "/remote",
        "/proxy",
    }
)


def _is_interesting_path(url: str) -> bool:
    """Return True if the URL path contains an interesting segment."""
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    # Check if any interesting pattern appears as a path prefix segment.
    for pattern in _INTERESTING_PATH_PATTERNS:
        if path == pattern or path.startswith(pattern + "/") or path.startswith(pattern + "."):
            return True
    return False


def _extract_hostname(url: str) -> str | None:
    """Extract and lowercase the hostname from a URL.

    Returns ``None`` if the URL cannot be parsed or has no host component.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if host:
            return host.lower().rstrip(".")
    except Exception:
        pass
    return None


def _is_subdomain_of(hostname: str, domain: str) -> bool:
    """Return True if ``hostname`` is a proper subdomain of ``domain``.

    ``domain`` itself is NOT considered a subdomain.
    """
    domain = domain.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")
    if hostname == domain:
        return False
    return hostname.endswith("." + domain)


# ---------------------------------------------------------------------------
# NDJSON parsing
# ---------------------------------------------------------------------------
def parse_ndjson_response(text: str) -> list[dict[str, Any]]:
    """Parse an NDJSON (newline-delimited JSON) response into a list of dicts.

    Skips blank lines and lines that fail to parse (graceful degradation).
    """
    import json

    results: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            if isinstance(record, dict):
                results.append(record)
        except (json.JSONDecodeError, ValueError):
            logger.debug("common-crawl: skipping unparseable NDJSON line")
            continue
    return results


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
@register_collector
class CommonCrawlCollector(Collector):
    """Tier-1 Common Crawl Index passive URL/endpoint discovery collector.

    Queries the Common Crawl Index API for URLs crawled from the target
    domain, extracts subdomains and interesting endpoint patterns for
    attack-surface intelligence.
    """

    collector_id: str = "common-crawl"
    collector_version: str = "0.1.0"
    display_name: str = "Common Crawl Index Search"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = 30

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        self._last_request_time: float = 0.0
        self._crawl_index: str | None = None

    # ------------------------------------------------------------------
    # expand
    # ------------------------------------------------------------------
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query the Common Crawl Index API for URLs matching the seed domain."""
        if seed.seed_type != SeedType.DOMAIN:
            return

        domain = seed.value.strip().lower().rstrip(".")
        canonical_domain = canonicalize_domain(domain)

        # Resolve the latest crawl index.
        crawl_index = await self._resolve_crawl_index()

        # Query for *.domain URLs.
        records = await self._query_cc_index(
            crawl_index=crawl_index,
            domain=domain,
        )

        # Track unique hostnames and URLs to avoid duplicate observations.
        seen_subdomains: set[str] = set()
        seen_urls: set[str] = set()

        for record in records:
            url = record.get("url", "")
            status_str = record.get("status", "")
            mime = record.get("mime", "")
            timestamp = record.get("timestamp", "")

            # --- Subdomain discovery ---
            hostname = _extract_hostname(url)
            if hostname and _is_subdomain_of(hostname, domain) and hostname not in seen_subdomains:
                seen_subdomains.add(hostname)
                yield Observation(
                    collector_id=self.collector_id,
                    collector_version=self.collector_version,
                    tenant_id=self.config.tenant_id,
                    observation_type=ObservationType.DNS_RESOLUTION,
                    subject=ObservationSubject(
                        identifier_type=IdentifierType.DOMAIN,
                        identifier_value=canonical_domain,
                    ),
                    observed_at=datetime.now(tz=UTC),
                    structured_payload={
                        "source": "common_crawl",
                        "crawl_index": crawl_index,
                        "discovered_subdomain": hostname,
                        "discovered_from_url": url,
                    },
                )

            # --- Interesting endpoint discovery ---
            if url not in seen_urls and _is_interesting_path(url):
                seen_urls.add(url)
                # Parse status to int if possible.
                status_int: int | str = status_str
                try:
                    status_int = int(status_str)
                except (ValueError, TypeError):
                    pass

                yield Observation(
                    collector_id=self.collector_id,
                    collector_version=self.collector_version,
                    tenant_id=self.config.tenant_id,
                    observation_type=ObservationType.HTTP_RESPONSE,
                    subject=ObservationSubject(
                        identifier_type=IdentifierType.DOMAIN,
                        identifier_value=canonical_domain,
                    ),
                    observed_at=datetime.now(tz=UTC),
                    structured_payload={
                        "source": "common_crawl",
                        "crawl_index": crawl_index,
                        "url": url,
                        "status": status_int,
                        "mime": mime,
                        "timestamp": timestamp,
                    },
                )

    # ------------------------------------------------------------------
    # health_check
    # ------------------------------------------------------------------
    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe against the Common Crawl Index API."""
        start = datetime.now(tz=UTC)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0),
                headers={"User-Agent": self._user_agent},
            ) as client:
                response = await client.get(_COLLINFO_URL)
            elapsed_ms = (datetime.now(tz=UTC) - start).total_seconds() * 1000.0

            if response.status_code == 200:  # noqa: PLR2004
                return CollectorHealthCheck(
                    collector_id=self.collector_id,
                    collector_version=self.collector_version,
                    status=CollectorStatus.SUCCESS,
                    checked_at=start,
                    latency_ms=elapsed_ms,
                )
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=start,
                latency_ms=elapsed_ms,
                error_message=(
                    f"Common Crawl Index API returned HTTP {response.status_code}"
                ),
            )
        except httpx.HTTPError as exc:
            elapsed_ms = (datetime.now(tz=UTC) - start).total_seconds() * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=start,
                latency_ms=elapsed_ms,
                error_message=f"Common Crawl Index API unreachable: {exc}",
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @property
    def _user_agent(self) -> str:
        """User-Agent string for API requests."""
        return self.config.extra.get("user_agent", _DEFAULT_USER_AGENT)

    async def _rate_limit_wait(self) -> None:
        """Enforce the ~1 req/s polite-use limit."""
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < _MIN_REQUEST_INTERVAL:
            await asyncio.sleep(_MIN_REQUEST_INTERVAL - elapsed)
        self._last_request_time = time.monotonic()

    async def _resolve_crawl_index(self) -> str:
        """Fetch the latest crawl index ID from collinfo.json.

        Caches the result for the lifetime of the collector instance.
        Falls back to a hardcoded recent index on failure.
        """
        if self._crawl_index is not None:
            return self._crawl_index

        await self._rate_limit_wait()

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.request_timeout_seconds),
                headers={"User-Agent": self._user_agent},
            ) as client:
                response = await client.get(_COLLINFO_URL)
                response.raise_for_status()

            data = response.json()
            if isinstance(data, list) and len(data) > 0:
                # The list is ordered newest first; extract the index ID.
                first = data[0]
                if isinstance(first, dict) and "id" in first:
                    self._crawl_index = first["id"]
                    return self._crawl_index

        except Exception:
            logger.warning(
                "common-crawl: failed to fetch collinfo.json, "
                "falling back to hardcoded index"
            )

        # Fallback to a known recent index.
        self._crawl_index = "CC-MAIN-2024-10"
        return self._crawl_index

    async def _query_cc_index(
        self,
        *,
        crawl_index: str,
        domain: str,
    ) -> list[dict[str, Any]]:
        """Execute a Common Crawl Index API query and return parsed records.

        Raises ``CollectorSourceUnreachableError`` on network or HTTP errors.
        Returns an empty list on empty results.
        """
        await self._rate_limit_wait()

        index_url = f"https://index.commoncrawl.org/{crawl_index}-index"
        params: dict[str, str] = {
            "url": f"*.{domain}",
            "output": "json",
            "limit": str(_CC_RESULT_LIMIT),
        }

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.request_timeout_seconds),
                headers={"User-Agent": self._user_agent},
            ) as client:
                response = await client.get(index_url, params=params)

                if response.status_code == 404:  # noqa: PLR2004
                    return []

                response.raise_for_status()

        except httpx.HTTPStatusError as exc:
            msg = (
                f"Common Crawl Index API returned HTTP "
                f"{exc.response.status_code} for domain={domain!r}"
            )
            raise CollectorSourceUnreachableError(msg) from exc
        except httpx.HTTPError as exc:
            msg = (
                f"Common Crawl Index API unreachable for "
                f"domain={domain!r}: {exc}"
            )
            raise CollectorSourceUnreachableError(msg) from exc

        if not response.text.strip():
            return []

        return parse_ndjson_response(response.text)


__all__ = [
    "CommonCrawlCollector",
    "parse_ndjson_response",
]

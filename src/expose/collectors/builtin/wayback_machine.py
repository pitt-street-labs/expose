"""Wayback Machine historical search collector (Tier 1, passive).

Queries the Internet Archive's Wayback CDX API to discover historical URLs
and content snapshots for a target domain or IP address.  This reveals
endpoints, configuration files, and historical structure that may no longer
be visible on the live site.

This is a Tier-1 (passive, broad query) collector.  It queries a public
archive service — no direct contact with the target.

Seed types: DOMAIN and IP.  Other seed types are skipped.

Rate limiting
-------------
The Wayback CDX API has no published contract but is community-maintained.
Polite use: max 1 request/second.  A simple monotonic-clock gate enforces
this between sequential requests within a single ``expand`` call.

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
from typing import Any, ClassVar

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
from expose.sanitization.canonicalize import canonicalize_domain, canonicalize_ip
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CDX API constants
# ---------------------------------------------------------------------------
_CDX_BASE_URL = "https://web.archive.org/cdx/search/cdx"
_CDX_HEALTH_URL = "https://web.archive.org"

_DEFAULT_USER_AGENT = "EXPOSE/0.1 (attack-surface-intelligence)"

# Content types considered interesting for attack-surface analysis.
_INTERESTING_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "text/html",
        "application/json",
        "text/plain",
        "application/xml",
        "text/xml",
        "application/javascript",
        "application/x-javascript",
    }
)

# Maximum results from the CDX API per query.
_CDX_GENERAL_LIMIT = 500
_CDX_ROBOTS_LIMIT = 10

# Minimum interval between CDX API requests (seconds).  1 req/sec polite use.
_MIN_REQUEST_INTERVAL = 1.0


# ---------------------------------------------------------------------------
# CDX response parsing
# ---------------------------------------------------------------------------
def parse_cdx_response(data: list[list[str]]) -> list[dict[str, str]]:
    """Parse CDX JSON response (array of arrays) into dicts.

    The first row is the header: ``["timestamp", "original", "mimetype",
    "statuscode", "digest"]``.  Subsequent rows are data.
    """
    if len(data) < 2:  # noqa: PLR2004
        return []

    headers = data[0]
    results: list[dict[str, str]] = []
    for row in data[1:]:
        if len(row) != len(headers):
            continue
        results.append(dict(zip(headers, row, strict=False)))
    return results


def build_archive_url(timestamp: str, original_url: str) -> str:
    """Construct a Wayback Machine replay URL."""
    return f"https://web.archive.org/web/{timestamp}/{original_url}"


def format_timestamp(raw: str) -> str:
    """Format a CDX timestamp (``YYYYMMDDhhmmss``) into ISO 8601.

    Returns the raw string unchanged if parsing fails.
    """
    if len(raw) < 14:  # noqa: PLR2004
        return raw
    try:
        dt = datetime(
            year=int(raw[0:4]),
            month=int(raw[4:6]),
            day=int(raw[6:8]),
            hour=int(raw[8:10]),
            minute=int(raw[10:12]),
            second=int(raw[12:14]),
            tzinfo=UTC,
        )
        return dt.isoformat()
    except (ValueError, IndexError):
        return raw


def is_interesting_content_type(mimetype: str) -> bool:
    """Return True if the MIME type is worth surfacing."""
    # Normalize — CDX sometimes includes charset suffixes.
    base = mimetype.split(";", maxsplit=1)[0].strip().lower()
    return base in _INTERESTING_CONTENT_TYPES


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
@register_collector
class WaybackMachineCollector(Collector):
    """Tier-1 Wayback Machine historical search collector.

    Queries the Wayback CDX API for historical snapshots of target domains
    and IP addresses to discover endpoints, removed pages, and historical
    site structure.
    """

    collector_id: str = "wayback-machine"
    collector_version: str = "0.1.0"
    display_name: str = "Wayback Machine Historical Search"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None
    technique_ids: ClassVar[list[str]] = ["T1593"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        self._last_request_time: float = 0.0

    # ------------------------------------------------------------------
    # expand
    # ------------------------------------------------------------------
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query the Wayback CDX API for historical data on the seed."""
        if seed.seed_type not in {SeedType.DOMAIN, SeedType.IP}:
            return

        target = seed.value.strip()

        # Determine canonical identifier for observation subject.
        if seed.seed_type == SeedType.IP:
            identifier_type = IdentifierType.IP
            canonical_value = canonicalize_ip(target)
        else:
            identifier_type = IdentifierType.DOMAIN
            canonical_value = canonicalize_domain(target)

        # --- General URL query ---
        general_entries = await self._query_cdx(
            url=f"{target}/*",
            limit=_CDX_GENERAL_LIMIT,
        )

        for entry in general_entries:
            mimetype = entry.get("mimetype", "")
            if not is_interesting_content_type(mimetype):
                continue

            timestamp = entry.get("timestamp", "")
            original_url = entry.get("original", "")
            statuscode = entry.get("statuscode", "")
            digest = entry.get("digest", "")

            archive_url = build_archive_url(timestamp, original_url)

            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.HTTP_RESPONSE,
                subject=ObservationSubject(
                    identifier_type=identifier_type,
                    identifier_value=canonical_value,
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "source": "wayback_machine",
                    "original_url": original_url,
                    "archive_url": archive_url,
                    "archive_timestamp": format_timestamp(timestamp),
                    "content_type": mimetype,
                    "status_code": statuscode,
                    "digest": digest,
                },
            )

        # --- Historical robots.txt query ---
        robots_entries = await self._query_cdx(
            url=f"{target}/robots.txt",
            limit=_CDX_ROBOTS_LIMIT,
            collapse=None,  # Don't collapse — we want multiple snapshots.
        )

        for entry in robots_entries:
            timestamp = entry.get("timestamp", "")
            original_url = entry.get("original", "")
            statuscode = entry.get("statuscode", "")

            archive_url = build_archive_url(timestamp, original_url)

            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.HTTP_RESPONSE,
                subject=ObservationSubject(
                    identifier_type=identifier_type,
                    identifier_value=canonical_value,
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "source": "wayback_machine",
                    "query_type": "historical_robots_txt",
                    "original_url": original_url,
                    "archive_url": archive_url,
                    "archive_timestamp": format_timestamp(timestamp),
                    "content_type": "text/plain",
                    "status_code": statuscode,
                },
            )

    # ------------------------------------------------------------------
    # health_check
    # ------------------------------------------------------------------
    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe against the Wayback Machine."""
        start = datetime.now(tz=UTC)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0),
                headers={"User-Agent": self._user_agent},
            ) as client:
                response = await client.head(_CDX_HEALTH_URL)
            elapsed_ms = (datetime.now(tz=UTC) - start).total_seconds() * 1000.0

            if response.status_code < 400:  # noqa: PLR2004
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
                error_message=(f"Wayback Machine returned HTTP {response.status_code}"),
            )
        except httpx.HTTPError as exc:
            elapsed_ms = (datetime.now(tz=UTC) - start).total_seconds() * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=start,
                latency_ms=elapsed_ms,
                error_message=f"Wayback Machine unreachable: {exc}",
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @property
    def _user_agent(self) -> str:
        """User-Agent string for CDX API requests."""
        return self.config.extra.get("user_agent", _DEFAULT_USER_AGENT)

    async def _rate_limit_wait(self) -> None:
        """Enforce the 1 req/sec polite-use limit."""
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < _MIN_REQUEST_INTERVAL:
            await asyncio.sleep(_MIN_REQUEST_INTERVAL - elapsed)
        self._last_request_time = time.monotonic()

    async def _query_cdx(
        self,
        *,
        url: str,
        limit: int,
        collapse: str | None = "urlkey",
    ) -> list[dict[str, str]]:
        """Execute a single CDX API query and return parsed entries.

        Raises ``CollectorSourceUnreachableError`` on network or HTTP errors.
        Returns an empty list on empty results or non-JSON responses.
        """
        await self._rate_limit_wait()

        params: dict[str, Any] = {
            "url": url,
            "output": "json",
            "fl": "timestamp,original,mimetype,statuscode,digest",
            "limit": str(limit),
        }
        if collapse is not None:
            params["collapse"] = collapse

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.request_timeout_seconds),
                headers={"User-Agent": self._user_agent},
            ) as client:
                response = await client.get(_CDX_BASE_URL, params=params)

                if response.status_code == 404:  # noqa: PLR2004
                    return []

                response.raise_for_status()

        except httpx.HTTPStatusError as exc:
            msg = f"Wayback CDX API returned HTTP {exc.response.status_code} for url={url!r}"
            raise CollectorSourceUnreachableError(msg) from exc
        except httpx.HTTPError as exc:
            msg = f"Wayback CDX API unreachable for url={url!r}: {exc}"
            raise CollectorSourceUnreachableError(msg) from exc

        # CDX may return empty body for no results.
        if not response.text.strip():
            return []

        try:
            raw: Any = response.json()
        except Exception:
            logger.debug("wayback-machine: non-JSON response for url=%s, skipping", url)
            return []

        if not isinstance(raw, list):
            return []

        return parse_cdx_response(raw)


__all__ = [
    "WaybackMachineCollector",
    "build_archive_url",
    "format_timestamp",
    "is_interesting_content_type",
    "parse_cdx_response",
]

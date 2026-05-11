"""security.txt (RFC 9116) collector (Tier 1, passive).

Fetches ``/.well-known/security.txt`` (primary) and ``/security.txt``
(legacy fallback) from the target domain over HTTPS and parses the
RFC 9116 fields:

- ``Contact:`` -- security vulnerability disclosure endpoint
- ``Expires:`` -- record expiry datetime
- ``Encryption:`` -- public key location
- ``Policy:`` -- vulnerability disclosure policy URL
- ``Hiring:`` -- security team hiring page URL
- ``Acknowledgments:`` -- hall of fame / acknowledgments page URL
- ``Preferred-Languages:`` -- language preferences
- ``Canonical:`` -- canonical URI for the security.txt file

Domains extracted from URLs in those fields are emitted as separate
observations, revealing bug bounty platforms (e.g., HackerOne,
Bugcrowd), PGP key servers, and related organizational infrastructure.

Tier 1 / passive: only performs a single HTTPS GET per domain against
standard well-known paths. No credentials required.
"""

from __future__ import annotations

import logging
import re
import time
import warnings as _warnings_mod
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorHealthCheck,
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

# RFC 9116 recognized field names (case-insensitive matching).
_RFC9116_FIELDS = frozenset({
    "contact",
    "expires",
    "encryption",
    "policy",
    "hiring",
    "acknowledgments",
    "preferred-languages",
    "canonical",
})

# URL pattern used to extract domains from field values.
_URL_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)


def parse_security_txt(body: str) -> dict[str, list[str]]:
    """Parse a security.txt body into field-name -> values mapping.

    Fields are case-insensitive per RFC 9116. Comment lines (starting
    with ``#``) and blank lines are skipped. Fields that appear multiple
    times (e.g., multiple ``Contact:`` lines) accumulate into the list.

    Returns a dict keyed by lowercase field name with lists of values.
    """
    result: dict[str, list[str]] = {}
    for raw_line in body.splitlines():
        line = raw_line.strip()
        # Skip comments and blank lines.
        if not line or line.startswith("#"):
            continue
        # Split on first colon.
        if ":" not in line:
            continue
        field_name, _, value = line.partition(":")
        field_name = field_name.strip().lower()
        value = value.strip()
        if not value:
            continue
        if field_name in _RFC9116_FIELDS:
            result.setdefault(field_name, []).append(value)
    return result


def extract_domains_from_urls(urls: list[str]) -> list[tuple[str, str]]:
    """Extract (domain, full_url) pairs from a list of URL strings.

    Filters out the seed domain itself (handled by the caller) and
    returns unique (domain, url) pairs preserving first-seen order.
    """
    seen: set[str] = set()
    results: list[tuple[str, str]] = []
    for url in urls:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if hostname and hostname not in seen:
                seen.add(hostname)
                results.append((hostname, url))
        except Exception:  # noqa: BLE001
            continue
    return results


@register_collector
class SecurityTxtCollector(Collector):
    """Tier-1 security.txt (RFC 9116) collector.

    Fetches security.txt from target domains and extracts contact,
    policy, and hiring URLs -- revealing bug bounty platforms and
    related organizational infrastructure.
    """

    collector_id: str = "security-txt"
    collector_version: str = "0.1.0"
    display_name: str = "security.txt (RFC 9116)"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)

    # ------------------------------------------------------------------
    # expand
    # ------------------------------------------------------------------
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Fetch security.txt from the seed domain and yield observations."""
        if seed.seed_type != SeedType.DOMAIN:
            return

        domain = seed.value.strip()
        canonical_domain = canonicalize_domain(domain)

        # Try well-known path first, then legacy fallback.
        urls = [
            f"https://{domain}/.well-known/security.txt",
            f"https://{domain}/security.txt",
        ]

        body: str | None = None
        fetched_url: str | None = None

        for url in urls:
            try:
                body = await self._fetch_security_txt(url)
            except (httpx.HTTPStatusError, httpx.HTTPError) as exc:
                logger.debug("security-txt: failed to fetch %s: %s", url, exc)
                continue

            if body is not None:
                fetched_url = url
                break

        if body is None or fetched_url is None:
            logger.debug(
                "security-txt: no security.txt found for domain %s", domain
            )
            return

        fields = parse_security_txt(body)

        # Yield a summary observation with all parsed fields.
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
                "source": "security_txt",
                "url": fetched_url,
                "fields": {k: v for k, v in fields.items()},
                "field_count": sum(len(v) for v in fields.values()),
            },
            evidence_blob=body.encode("utf-8"),
            evidence_blob_content_type="text/plain",
        )

        # Extract URLs from all field values and emit domain observations.
        all_urls: list[str] = []
        url_field_map: dict[str, str] = {}  # url -> field name
        for field_name, values in fields.items():
            for value in values:
                found_urls = _URL_RE.findall(value)
                for found_url in found_urls:
                    all_urls.append(found_url)
                    url_field_map[found_url] = field_name

        domain_url_pairs = extract_domains_from_urls(all_urls)
        for discovered_domain, source_url in domain_url_pairs:
            # Skip the seed domain itself -- it's not a discovery.
            try:
                canonical_discovered = canonicalize_domain(discovered_domain)
            except Exception:  # noqa: BLE001
                continue
            if canonical_discovered == canonical_domain:
                continue

            field_name = url_field_map.get(source_url, "unknown")
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.HTTP_RESPONSE,
                subject=ObservationSubject(
                    identifier_type=IdentifierType.DOMAIN,
                    identifier_value=canonical_discovered,
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "source": "security_txt",
                    "field": field_name,
                    "raw_value": source_url,
                    "seed_domain": canonical_domain,
                },
            )

    # ------------------------------------------------------------------
    # health_check
    # ------------------------------------------------------------------
    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe -- HEAD request to example.com."""
        start = time.monotonic()
        try:
            with _warnings_mod.catch_warnings():
                _warnings_mod.filterwarnings(
                    "ignore", category=DeprecationWarning
                )
                _warnings_mod.filterwarnings(
                    "ignore", message="Unverified HTTPS request"
                )
                async with httpx.AsyncClient(verify=False) as client:  # noqa: S501
                    resp = await client.head(
                        "https://example.com/.well-known/security.txt",
                        timeout=self.config.request_timeout_seconds,
                    )
            latency = (time.monotonic() - start) * 1000.0
            # Any non-server-error response is fine for a health check --
            # 404 just means example.com has no security.txt, which is expected.
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=(
                    CollectorStatus.SUCCESS
                    if resp.status_code < 500  # noqa: PLR2004
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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    async def _fetch_security_txt(self, url: str) -> str | None:
        """Fetch a security.txt URL. Returns body text or None on 404."""
        with _warnings_mod.catch_warnings():
            _warnings_mod.filterwarnings(
                "ignore", category=DeprecationWarning
            )
            _warnings_mod.filterwarnings(
                "ignore", message="Unverified HTTPS request"
            )
            async with httpx.AsyncClient(
                verify=False,  # noqa: S501
                timeout=self.config.request_timeout_seconds,
                follow_redirects=True,
                max_redirects=3,
            ) as client:
                client.headers["User-Agent"] = self.config.user_agent
                response = await client.get(url)

        if response.status_code == 404:  # noqa: PLR2004
            return None

        response.raise_for_status()
        return response.text


__all__ = [
    "SecurityTxtCollector",
    "extract_domains_from_urls",
    "parse_security_txt",
]

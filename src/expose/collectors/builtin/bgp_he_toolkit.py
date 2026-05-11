"""BGP/ASN collector — Hurricane Electric BGP Toolkit (Tier 1, passive).

Scrapes the Hurricane Electric BGP Toolkit web pages for BGP routing
information:
- IP seed: ``https://bgp.he.net/ip/{ip}`` — extracts announcing ASN,
  holder name, and announced prefixes.
- ASN seed: ``https://bgp.he.net/AS{asn}`` — extracts holder name and
  all announced prefixes.

No credentials required. The HE BGP Toolkit is publicly accessible.
Parsing uses simple regex and string matching — NO BeautifulSoup or
other HTML parser dependencies.

Seed types: IP and ASN. Other seed types are skipped with a warning.
"""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime

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
from expose.sanitization.text import SanitizationFieldKind, sanitize_field
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

logger = logging.getLogger(__name__)

_HE_BASE_URL = "https://bgp.he.net"

# Regex patterns for scraping HE BGP Toolkit HTML.
# Match ASN links like <a href="/AS13335">AS13335</a>
_ASN_LINK_RE = re.compile(r'<a\s+href="/AS(\d+)"[^>]*>AS\d+</a>')
# Match "AS13335 - CLOUDFLARENET" pattern in h1/title (hyphen or en-dash)
_ASN_HOLDER_RE = re.compile("AS(\\d+)\\s*[-\u2013]\\s*(.+?)(?:</h1>|</title>|$)")
# Match prefix links like <a href="/net/1.1.1.0/24">1.1.1.0/24</a>
_PREFIX_LINK_RE = re.compile(
    r'<a\s+href="/net/([0-9a-fA-F.:]+/\d+)"[^>]*>[^<]+</a>'
)


def _extract_asn_number(value: str) -> str:
    """Extract the numeric part from an ASN string like ``AS13335``."""
    text = value.strip().upper()
    if text.startswith("AS"):
        return text[2:]
    return text


def _parse_asn_and_holder(html: str) -> tuple[str, str]:
    """Extract ASN and holder name from HE BGP Toolkit HTML.

    Returns (asn_str, holder_name) where asn_str is e.g. ``"AS13335"``.
    Returns ``("", "")`` if not found.
    """
    match = _ASN_HOLDER_RE.search(html)
    if match:
        asn_num = match.group(1)
        holder = match.group(2).strip()
        return f"AS{asn_num}", holder

    # Fallback: try to find ASN link
    link_match = _ASN_LINK_RE.search(html)
    if link_match:
        return f"AS{link_match.group(1)}", ""

    return "", ""


def _parse_prefixes(html: str) -> list[str]:
    """Extract announced prefix CIDRs from HE BGP Toolkit HTML.

    Deduplicates and returns sorted for deterministic output.
    """
    matches = _PREFIX_LINK_RE.findall(html)
    # Deduplicate while preserving order
    seen: set[str] = set()
    result: list[str] = []
    for prefix in matches:
        if prefix not in seen:
            seen.add(prefix)
            result.append(prefix)
    return sorted(result)


@register_collector
class HeToolkitCollector(Collector):
    """BGP/ASN collector using Hurricane Electric BGP Toolkit (Tier 1)."""

    collector_id: str = "bgp-he-toolkit"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        if seed.seed_type == SeedType.IP:
            async for obs in self._expand_ip(seed):
                yield obs
        elif seed.seed_type == SeedType.ASN:
            async for obs in self._expand_asn(seed):
                yield obs
        else:
            logger.warning(
                "bgp-he-toolkit: skipping unsupported seed type %s (value=%r)",
                seed.seed_type,
                seed.value,
            )

    async def _expand_ip(self, seed: Seed) -> AsyncIterator[Observation]:
        """Scrape HE BGP Toolkit IP page."""
        ip_value = seed.value.strip()
        url = f"{_HE_BASE_URL}/ip/{ip_value}"
        html = await self._fetch_html(url)

        asn_str, holder_raw = _parse_asn_and_holder(html)
        if not asn_str:
            return

        holder = sanitize_field(
            holder_raw, SanitizationFieldKind.GENERIC
        ).value
        prefixes = _parse_prefixes(html)

        yield Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.BGP_ASN_LOOKUP,
            subject=ObservationSubject(
                identifier_type=ExtendedIdentifierType.IP,
                identifier_value=ip_value,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload={
                "asn": asn_str,
                "holder": holder,
                "prefixes": prefixes,
                "source": "he-toolkit",
            },
        )

    async def _expand_asn(self, seed: Seed) -> AsyncIterator[Observation]:
        """Scrape HE BGP Toolkit ASN page."""
        asn_value = seed.value.strip()
        asn_number = _extract_asn_number(asn_value)
        url = f"{_HE_BASE_URL}/AS{asn_number}"
        html = await self._fetch_html(url)

        asn_str, holder_raw = _parse_asn_and_holder(html)
        if not asn_str:
            asn_str = f"AS{asn_number}"

        holder = sanitize_field(
            holder_raw, SanitizationFieldKind.GENERIC
        ).value
        prefixes = _parse_prefixes(html)

        yield Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.BGP_ASN_LOOKUP,
            subject=ObservationSubject(
                identifier_type=ExtendedIdentifierType.ASN,
                identifier_value=asn_str,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload={
                "asn": asn_str,
                "holder": holder,
                "prefixes": prefixes,
                "source": "he-toolkit",
            },
        )

    async def _fetch_html(self, url: str) -> str:
        """Fetch HTML from HE BGP Toolkit, raising on errors."""
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.request_timeout_seconds),
                headers={"User-Agent": self.config.user_agent},
            ) as client:
                response = await client.get(url)
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = (
                f"HE BGP Toolkit returned HTTP {exc.response.status_code} "
                f"for {url!r}"
            )
            raise CollectorSourceUnreachableError(msg) from exc
        except httpx.HTTPError as exc:
            msg = f"HE BGP Toolkit unreachable for {url!r}: {exc}"
            raise CollectorSourceUnreachableError(msg) from exc

        return response.text

    async def health_check(self) -> CollectorHealthCheck:
        start = datetime.now(tz=UTC)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0),
                headers={"User-Agent": self.config.user_agent},
            ) as client:
                response = await client.head(f"{_HE_BASE_URL}/")
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
                error_message=(
                    f"HE BGP Toolkit returned HTTP {response.status_code}"
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
                error_message=f"HE BGP Toolkit unreachable: {exc}",
            )

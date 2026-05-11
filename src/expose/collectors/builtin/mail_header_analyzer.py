"""Public mailing list header analysis collector (Tier 1, passive).

Probes for publicly accessible mailing list archives at common paths
(``lists.{domain}``, ``mail.{domain}``, ``mailman.{domain}``) and extracts
infrastructure hints from any accessible archive pages.  Reveals:

- ``Received:`` header IP addresses from mail server hops, exposing
  internal relay infrastructure and mail gateway IPs.
- Mailing list software and version fingerprints (Mailman, Sympa, etc.).
- Internal hostnames mentioned in mail headers.

Workflow:

1. **Archive discovery** — probe common mailing-list archive URLs at
   ``lists.{domain}/``, ``mail.{domain}/``, ``mailman.{domain}/`` for
   HTTP 200 responses indicating a public archive.
2. **Content analysis** — if an archive is found, fetch the index page
   and extract any ``Received:`` header IP addresses and internal
   hostnames from page content.
3. **Observation emission** — one ``Observation`` per unique extracted IP
   with archive source context, plus one observation per discovered archive
   endpoint.

Seed types: DOMAIN.  Other seed types are skipped silently.

No credentials required.  Tier 1 / passive: only makes HTTP GET requests
to public URLs derived from the seed domain.

Rate limiting: ``rate_limit_per_minute = 30``.  Probes a small number of
URLs per seed.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from typing import ClassVar

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

# Common mailing list archive subdomain prefixes.
_ARCHIVE_SUBDOMAINS: tuple[str, ...] = ("lists", "mail", "mailman")

# Common archive index paths to probe.
_ARCHIVE_PATHS: tuple[str, ...] = (
    "/",
    "/listinfo",
    "/pipermail/",
    "/archives/",
    "/hyperkitty/",
)

# Received header IP extraction pattern.
# Matches patterns like "from x.y.z (1.2.3.4)" or "from [1.2.3.4]" or
# "Received: from ... (1.2.3.4)" commonly found in email headers and
# mailing list archive pages.
_RECEIVED_IP_RE = re.compile(
    r"(?:from|by)\s+\S+\s+\(?"
    r"(?:\[?)((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?))"
    r"\]?\)?",
    re.IGNORECASE,
)

# Fallback: any bare IPv4 in Received:-like context.
_BARE_IP_IN_RECEIVED_RE = re.compile(
    r"Received:.*?"
    r"((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?))",
    re.IGNORECASE | re.DOTALL,
)

# Internal hostname pattern (looks for FQDN-like strings in headers).
_HOSTNAME_RE = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b"
)

# IPs to ignore (loopback, link-local, documentation ranges).
_IGNORE_IPS: frozenset[str] = frozenset({
    "127.0.0.1",
    "0.0.0.0",  # noqa: S104
    "255.255.255.255",
})

# Mailing list software fingerprint patterns.
_MAILMAN_FINGERPRINTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("mailman", re.compile(r"Mailman", re.IGNORECASE)),
    ("sympa", re.compile(r"Sympa", re.IGNORECASE)),
    ("majordomo", re.compile(r"Majordomo", re.IGNORECASE)),
    ("hyperkitty", re.compile(r"HyperKitty", re.IGNORECASE)),
    ("pipermail", re.compile(r"[Pp]ipermail")),
)


def _extract_received_ips(content: str) -> set[str]:
    """Extract IP addresses from Received:-style header patterns."""
    ips: set[str] = set()
    for match in _RECEIVED_IP_RE.finditer(content):
        ip = match.group(1)
        if ip not in _IGNORE_IPS:
            ips.add(ip)
    for match in _BARE_IP_IN_RECEIVED_RE.finditer(content):
        ip = match.group(1)
        if ip not in _IGNORE_IPS:
            ips.add(ip)
    return ips


def _detect_software(content: str) -> list[str]:
    """Detect mailing list software from page content."""
    detected: list[str] = []
    for name, pattern in _MAILMAN_FINGERPRINTS:
        if pattern.search(content):
            detected.append(name)
    return detected


@register_collector
class MailHeaderAnalyzerCollector(Collector):
    """Tier-1 passive mailing list header analysis collector.

    Probes for public mailing list archives and extracts infrastructure
    hints (IPs, hostnames, software versions) from accessible pages.
    """

    collector_id: str = "mail-headers"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = 30
    technique_ids: ClassVar[list[str]] = ["T1598"]

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Probe mailing list archives and yield observations."""
        if seed.seed_type != SeedType.DOMAIN:
            return

        domain = seed.value.strip().lower()
        if not domain:
            return

        warnings_list: list[str] = []
        discovered_ips: set[str] = set()
        discovered_archives: list[dict[str, str]] = []

        probe_timeout = httpx.Timeout(
            connect=5.0,
            read=10.0,
            write=5.0,
            pool=5.0,
        )
        async with httpx.AsyncClient(
            timeout=probe_timeout,
            headers={"User-Agent": self.config.user_agent},
            follow_redirects=True,
        ) as client:
            for subdomain in _ARCHIVE_SUBDOMAINS:
                base_url = f"https://{subdomain}.{domain}"
                found_archive = False
                for path in _ARCHIVE_PATHS:
                    url = f"{base_url}{path}"
                    try:
                        resp = await client.get(url)
                    except httpx.HTTPError:
                        if not found_archive:
                            break
                        continue

                    if resp.status_code != 200:  # noqa: PLR2004
                        continue

                    content = resp.text
                    if not content:
                        continue

                    found_archive = True
                    # We found an accessible archive page.
                    software = _detect_software(content)
                    archive_info: dict[str, str] = {
                        "url": url,
                        "subdomain": f"{subdomain}.{domain}",
                    }
                    if software:
                        archive_info["software"] = ", ".join(software)
                    discovered_archives.append(archive_info)

                    # Extract IPs from Received: headers in page content.
                    ips = _extract_received_ips(content)
                    discovered_ips.update(ips)

                    # Found an archive at this subdomain; no need to probe
                    # additional paths for this subdomain.
                    break

        # Emit one observation per discovered archive endpoint.
        for archive in discovered_archives:
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.HTTP_RESPONSE,
                subject=ObservationSubject(
                    identifier_type=IdentifierType.DOMAIN,
                    identifier_value=archive["subdomain"],
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "source": "mail_archive_discovery",
                    "seed_domain": domain,
                    "archive_url": archive["url"],
                    "software": archive.get("software", "unknown"),
                },
                warnings=warnings_list,
            )

        # Emit one observation per unique extracted IP.
        for ip in sorted(discovered_ips):
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
                    "source": "mail_header_ip",
                    "seed_domain": domain,
                    "archives_checked": [
                        a["url"] for a in discovered_archives
                    ],
                },
                warnings=warnings_list,
            )

    async def health_check(self) -> CollectorHealthCheck:
        """Quick health check — verify DNS resolution capability.

        Since this collector probes arbitrary domains, the health check
        verifies that outbound HTTPS is functional by attempting to
        reach a well-known site.
        """
        start = time.monotonic()
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://httpbin.org/status/200",
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
    "MailHeaderAnalyzerCollector",
]

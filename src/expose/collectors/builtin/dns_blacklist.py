"""DNSBL / spam-blacklist collector (Tier 1, passive).

Queries well-known DNS Blacklist (DNSBL) providers to check whether an IP
address appears on any spam or abuse blacklist.

DNSBL lookup mechanics:
1. Reverse the IP octets and append the DNSBL zone:
   ``1.2.3.4`` -> ``4.3.2.1.zen.spamhaus.org``
2. Issue a DNS A query against the constructed name.
   - A response means the IP **is listed** on that blacklist.
   - NXDOMAIN means the IP is **not listed**.
3. If listed, issue a DNS TXT query to obtain the human-readable listing
   reason (provider-dependent).

The collector queries all configured providers in parallel via
``asyncio.gather``.  A timeout or error on one provider does not block the
others.

Spamhaus return codes have specific severity mappings (e.g., ``127.0.0.4``
is an exploit/botnet listing — critical).  Other providers use a default
severity.

Tier 1 / passive: only performs DNS A/TXT queries against DNSBL provider
nameservers.  No credentials required.

Requires ``dnspython`` (same optional dependency as other DNS collectors).
The module imports cleanly without it; ``expand()`` raises ``CollectorError``
if invoked without the library installed.

Seed types: IP only.  Other seed types return an empty observation stream.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, ClassVar

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorError,
    CollectorHealthCheck,
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

try:
    import dns.asyncresolver as _dns_asyncresolver
    import dns.resolver as _dns_resolver

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

logger = logging.getLogger(__name__)

# === DNSBL provider catalogue ================================================

DNSBL_PROVIDERS: list[dict[str, Any]] = [
    {
        "zone": "zen.spamhaus.org",
        "name": "Spamhaus ZEN",
        "severity_map": {
            "127.0.0.2": ("sbl", "high"),  # Direct spam source
            "127.0.0.3": ("sbl_css", "high"),  # Spambot / CSS
            "127.0.0.4": ("xbl", "critical"),  # Exploit/botnet
            "127.0.0.10": ("pbl", "info"),  # Dynamic IP (ISP range)
            "127.0.0.11": ("pbl", "info"),  # Dynamic IP
        },
    },
    {
        "zone": "b.barracudacentral.org",
        "name": "Barracuda BRBL",
        "default_severity": "medium",
    },
    {
        "zone": "dnsbl.sorbs.net",
        "name": "SORBS",
        "default_severity": "medium",
    },
    {
        "zone": "bl.spamcop.net",
        "name": "SpamCop",
        "default_severity": "medium",
    },
    {
        "zone": "dnsbl-1.uceprotect.net",
        "name": "UCEProtect L1",
        "default_severity": "medium",
    },
    {
        "zone": "dnsbl-2.uceprotect.net",
        "name": "UCEProtect L2",
        "default_severity": "low",
    },
    {
        "zone": "combined.abuse.ch",
        "name": "Abusix Combined",
        "default_severity": "high",
    },
]


def _reverse_ip(ip: str) -> str:
    """Reverse an IPv4 address for DNSBL lookup.

    ``1.2.3.4`` -> ``4.3.2.1``
    """
    parts = ip.strip().split(".")
    return ".".join(reversed(parts))


def _resolve_severity(provider: dict[str, Any], return_code: str) -> tuple[str, str]:
    """Return ``(listing_type, severity)`` for the given DNSBL return code.

    Providers with a ``severity_map`` (e.g., Spamhaus) map specific return
    codes to a listing type and severity.  Providers with only a
    ``default_severity`` use that for all return codes.
    """
    severity_map: dict[str, tuple[str, str]] | None = provider.get("severity_map")
    if severity_map and return_code in severity_map:
        return severity_map[return_code]
    default_severity = provider.get("default_severity", "medium")
    return ("listed", default_severity)


@register_collector
class DnsBlacklistCollector(Collector):
    """DNSBL / spam-blacklist collector (Tier 1, passive)."""

    collector_id: str = "dns-blacklist"
    collector_version: str = "0.1.0"
    display_name: str = "DNS Blacklist Check"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    technique_ids: ClassVar[list[str]] = ["T1596.001"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        if HAS_DNSPYTHON:
            self._resolver = _dns_asyncresolver.Resolver()
            self._resolver.lifetime = config.request_timeout_seconds
        else:
            self._resolver = None  # type: ignore[assignment]

    async def _check_provider(
        self, ip_value: str, reversed_ip: str, provider: dict[str, Any]
    ) -> Observation | None:
        """Query a single DNSBL provider and return an Observation if listed.

        Returns ``None`` if the IP is not listed (NXDOMAIN) or if the query
        fails with a timeout or other error.  Errors are logged as warnings
        but do not propagate — one provider failure must not block others.
        """
        zone = provider["zone"]
        provider_name = provider["name"]
        qname = f"{reversed_ip}.{zone}"

        # Step 1: A query — presence of an A record means the IP is listed.
        try:
            a_answer = await self._resolver.resolve(qname, "A")
        except (_dns_resolver.NXDOMAIN, _dns_resolver.NoAnswer):
            # Not listed on this provider — normal case.
            return None
        except (_dns_resolver.LifetimeTimeout, _dns_resolver.NoNameservers):
            logger.warning(
                "dns-blacklist: timeout/unreachable querying %s for %s",
                zone,
                ip_value,
            )
            return None
        except Exception:
            logger.warning(
                "dns-blacklist: error querying %s for %s",
                zone,
                ip_value,
                exc_info=True,
            )
            return None

        # Extract the return code from the A record response.
        return_code = ""
        for rr in a_answer:
            return_code = str(rr)
            break

        listing_type, severity = _resolve_severity(provider, return_code)

        # Step 2: TXT query — listing reason (best-effort).
        txt_reason = ""
        try:
            txt_answer = await self._resolver.resolve(qname, "TXT")
            for rr in txt_answer:
                txt_reason = b"".join(rr.strings).decode("utf-8", errors="replace")
                break
        except Exception:
            # TXT lookup is best-effort; proceed without reason text.
            logger.debug(
                "dns-blacklist: TXT lookup failed for %s on %s",
                ip_value,
                zone,
            )

        txt_reason_sanitized = sanitize_field(txt_reason, SanitizationFieldKind.GENERIC).value

        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.DNS_RECORD,
            subject=ObservationSubject(
                identifier_type=ExtendedIdentifierType.IP,
                identifier_value=ip_value,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload={
                "blacklist_name": provider_name,
                "blacklist_zone": zone,
                "listed": True,
                "return_code": return_code,
                "listing_type": listing_type,
                "severity": severity,
                "txt_reason": txt_reason_sanitized,
                "source": "dnsbl",
            },
        )

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        if not HAS_DNSPYTHON:
            msg = "dnspython not installed; install expose[collectors-dns]"
            raise CollectorError(msg)

        if seed.seed_type != SeedType.IP:
            logger.debug(
                "dns-blacklist: skipping unsupported seed type %s (value=%r)",
                seed.seed_type,
                seed.value,
            )
            return

        ip_value = seed.value.strip()
        reversed_ip = _reverse_ip(ip_value)

        # Query all providers in parallel.
        tasks = [
            self._check_provider(ip_value, reversed_ip, provider) for provider in DNSBL_PROVIDERS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                # Defensive — _check_provider already catches exceptions,
                # but guard against unexpected propagation.
                logger.warning(
                    "dns-blacklist: unexpected error during gather: %s",
                    result,
                )
                continue
            if result is not None:
                yield result

    async def health_check(self) -> CollectorHealthCheck:
        if not HAS_DNSPYTHON:
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                error_message=("dnspython not installed; install expose[collectors-dns]"),
            )

        # Probe a single well-known DNSBL zone to verify DNS resolution works.
        start = datetime.now(tz=UTC)
        probe_qname = "2.0.0.127.zen.spamhaus.org"
        try:
            await self._resolver.resolve(probe_qname, "A")
            elapsed_ms = (datetime.now(tz=UTC) - start).total_seconds() * 1000
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.SUCCESS,
                checked_at=start,
                latency_ms=elapsed_ms,
            )
        except Exception as exc:
            elapsed_ms = (datetime.now(tz=UTC) - start).total_seconds() * 1000
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=start,
                latency_ms=elapsed_ms,
                error_message=f"DNSBL probe failed: {exc}",
            )


__all__ = [
    "DNSBL_PROVIDERS",
    "HAS_DNSPYTHON",
    "DnsBlacklistCollector",
]

"""DNS reverse PTR lookup collector (Tier 2, passive targeted).

Given an IP address seed, constructs the reverse DNS name (in-addr.arpa for
IPv4, ip6.arpa nibble format for IPv6) and performs a PTR query via dnspython.
Discovered hostnames are emitted as observations and tagged as potential new
domain seeds for downstream expansion.

No credentials required. PTR lookups use the system's configured resolver.

Requires ``dnspython`` (same optional dependency as ``active-dns-resolve``).
The module imports cleanly without it; ``expand()`` raises ``CollectorError``
if invoked without the library installed.

Seed types: IP only. Other seed types return an empty result set.
"""

from __future__ import annotations

import ipaddress
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
from expose.sanitization.canonicalize import canonicalize_domain
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

try:
    import dns.asyncresolver as _dns_asyncresolver
    import dns.resolver as _dns_resolver

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

logger = logging.getLogger(__name__)

# Well-known domain used for health checks.
_HEALTH_CHECK_DOMAIN = "dns.google"


def _ip_to_reverse(ip_str: str) -> str:
    """Convert an IP address string to its reverse DNS lookup name.

    IPv4: ``1.2.3.4`` -> ``4.3.2.1.in-addr.arpa``
    IPv6: ``2001:db8::1`` -> nibble-format ``ip6.arpa``

    Raises ``ValueError`` if ``ip_str`` is not a valid IP address.
    """
    addr = ipaddress.ip_address(ip_str)
    if isinstance(addr, ipaddress.IPv4Address):
        return ".".join(reversed(ip_str.split("."))) + ".in-addr.arpa"
    # IPv6 nibble format
    expanded = addr.exploded.replace(":", "")
    return ".".join(reversed(expanded)) + ".ip6.arpa"


@register_collector
class ReversePtrCollector(Collector):
    """Resolve PTR records for an IP address seed (Tier 2).

    Passive targeted collector. Performs reverse DNS lookups to discover
    hostnames associated with IP addresses.
    """

    collector_id: str = "dns-reverse-ptr"
    collector_version: str = "0.1.0"
    display_name: str = "DNS Reverse PTR Lookup"
    tier: CollectorTier = CollectorTier.TIER_2
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None
    technique_ids: ClassVar[list[str]] = ["T1596.001"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        if HAS_DNSPYTHON:
            self._resolver = _dns_asyncresolver.Resolver()
            self._resolver.lifetime = config.request_timeout_seconds
        else:
            self._resolver = None  # type: ignore[assignment]

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Perform a PTR lookup for an IP seed.

        Skips non-IP seeds. On NXDOMAIN (no PTR record), emits no
        observations (this is normal). On timeout or resolver failure,
        emits no observations with a debug log. Individual PTR values
        that fail canonicalization are skipped with a warning.
        """
        if not HAS_DNSPYTHON:
            msg = "dnspython not installed; install expose[collectors-dns]"
            raise CollectorError(msg)

        if seed.seed_type != SeedType.IP:
            return

        ip_value = seed.value.strip()

        # Validate and construct the reverse DNS name.
        try:
            reverse_name = _ip_to_reverse(ip_value)
        except ValueError:
            logger.debug(
                "dns-reverse-ptr: invalid IP address %r, skipping",
                ip_value,
            )
            return

        # Perform the PTR query.
        try:
            answer = await self._resolver.resolve(reverse_name, "PTR")
        except _dns_resolver.NXDOMAIN:
            # No PTR record is normal -- many IPs lack reverse DNS.
            logger.debug(
                "dns-reverse-ptr: no PTR record for %s (NXDOMAIN)",
                ip_value,
            )
            return
        except (
            _dns_resolver.NoAnswer,
            _dns_resolver.NoNameservers,
        ):
            logger.debug(
                "dns-reverse-ptr: no answer for PTR query on %s",
                ip_value,
            )
            return
        except _dns_resolver.LifetimeTimeout:
            logger.debug(
                "dns-reverse-ptr: PTR query timed out for %s",
                ip_value,
            )
            return
        except Exception:
            logger.debug(
                "dns-reverse-ptr: PTR query failed for %s",
                ip_value,
                exc_info=True,
            )
            return

        # Each PTR record in the answer is a discovered hostname.
        for rr in answer:
            hostname = str(rr.target).rstrip(".")
            if not hostname:
                continue

            canonical_hostname = canonicalize_domain(hostname)

            payload: dict[str, Any] = {
                "record_type": "PTR",
                "reverse_name": reverse_name,
                "ip": ip_value,
                "hostname": canonical_hostname,
                "is_new_domain_seed": True,
            }

            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.DNS_RECORD,
                subject=ObservationSubject(
                    identifier_type=ExtendedIdentifierType.IP,
                    identifier_value=ip_value,
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload=payload,
            )

    async def health_check(self) -> CollectorHealthCheck:
        """Probe DNS resolution by resolving a well-known domain.

        Returns a ``CollectorHealthCheck`` with SUCCESS or FAILURE
        status. Does not raise.
        """
        if not HAS_DNSPYTHON:
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                error_message=(
                    "dnspython not installed; install expose[collectors-dns]"
                ),
            )

        start = datetime.now(tz=UTC)
        try:
            await self._resolver.resolve(_HEALTH_CHECK_DOMAIN, "A")
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
                error_message=f"DNS health check failed: {exc}",
            )


__all__ = [
    "HAS_DNSPYTHON",
    "ReversePtrCollector",
]

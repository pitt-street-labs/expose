"""SIP/VoIP infrastructure discovery collector (Tier 1, passive DNS only).

This collector discovers VoIP/SIP infrastructure by querying standard DNS
SRV and NAPTR records for a given domain seed. SIP infrastructure is
discoverable through well-known DNS service records defined in RFC 3263
(SIP: Locating SIP Servers) and related standards:

- ``_sip._tcp.{domain}``   — SIP over TCP (RFC 3261)
- ``_sips._tcp.{domain}``  — SIP over TLS (RFC 3261)
- ``_sip._udp.{domain}``   — SIP over UDP (RFC 3261)
- ``_h323cs._tcp.{domain}`` — H.323 call signaling (ITU-T H.323)
- ``_stun._udp.{domain}``  — STUN server (RFC 5389)
- ``_turn._udp.{domain}``  — TURN server (RFC 5766)

SRV records return target hostname + port, revealing the VoIP provider,
internal infrastructure hostnames, and non-standard port configurations.
NAPTR records at the domain root can expose SIP routing preferences and
transport selection (RFC 2915 / RFC 3403).

Tier 1 / passive: only performs DNS queries against the public
authoritative nameservers for the target domain. No credentials required.

The ``dnspython`` library is an optional dependency (installed via the
``expose[collectors-dns]`` extra). The module imports cleanly when
``dnspython`` is absent; ``expand()`` raises ``CollectorError`` with an
actionable message if invoked without the library.

Credential requirements: none. DNS resolution uses the system's configured
resolver and does not require API keys.
"""

from __future__ import annotations

import logging
import re
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
    import dns.name as _dns_name
    import dns.resolver as _dns_resolver

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

logger = logging.getLogger(__name__)

# SRV record prefixes to query, with their human-readable protocol names.
_SRV_SERVICES: list[tuple[str, str]] = [
    ("_sip._tcp", "sip"),
    ("_sips._tcp", "sips"),
    ("_sip._udp", "sip"),
    ("_h323cs._tcp", "h323"),
    ("_stun._udp", "stun"),
    ("_turn._udp", "turn"),
]

# Well-known domain used for health checks. A SRV query for a
# non-existent service returns NXDOMAIN or NoAnswer, both of which
# confirm the resolver is functional.
_HEALTH_CHECK_DOMAIN = "_sip._tcp.example.com"

# Regex to extract domain/IP from SIP URIs in NAPTR replacement fields.
# Matches patterns like "sip:host" or "sip:host:port" in NAPTR regexp/
# replacement fields. Intentionally conservative — only extracts the
# host portion.
_SIP_URI_RE = re.compile(
    r"sips?:(?:[^@]+@)?([a-zA-Z0-9._-]+[a-zA-Z0-9])",
    re.IGNORECASE,
)


@register_collector
class SipDiscoveryCollector(Collector):
    """Discover SIP/VoIP infrastructure via DNS SRV and NAPTR records.

    Tier-1 passive collector. Only performs standard DNS queries —
    no active probing of discovered endpoints.
    """

    collector_id: str = "sip-discovery"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None
    technique_ids: ClassVar[list[str]] = ["T1046"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        if HAS_DNSPYTHON:
            self._resolver = _dns_asyncresolver.Resolver()
            self._resolver.lifetime = config.request_timeout_seconds
        else:
            self._resolver = None  # type: ignore[assignment]

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Discover SIP infrastructure for a DOMAIN seed.

        Skips non-DOMAIN seeds. Queries each SRV service prefix and
        NAPTR records at the domain root. On NXDOMAIN or NoAnswer,
        the record type is silently skipped (not an error — most
        domains have no SIP records). Individual query failures are
        logged and skipped without failing the whole expansion.
        """
        if not HAS_DNSPYTHON:
            msg = "dnspython not installed; install expose[collectors-dns]"
            raise CollectorError(msg)

        if seed.seed_type != SeedType.DOMAIN:
            return

        domain = seed.value
        canonical_domain = canonicalize_domain(domain)

        # Query SRV records for each service prefix.
        for service_prefix, protocol in _SRV_SERVICES:
            async for obs in self._query_srv(
                domain, canonical_domain, service_prefix, protocol
            ):
                yield obs

        # Query NAPTR records at the domain root.
        async for obs in self._query_naptr(domain, canonical_domain):
            yield obs

    async def _query_srv(
        self,
        domain: str,
        canonical_domain: str,
        service_prefix: str,
        protocol: str,
    ) -> AsyncIterator[Observation]:
        """Query a single SRV record prefix and yield observations."""
        qname = f"{service_prefix}.{domain}"
        try:
            answer = await self._resolver.resolve(qname, "SRV")
        except (
            _dns_resolver.NXDOMAIN,
            _dns_resolver.NoAnswer,
            _dns_resolver.NoNameservers,
            _dns_name.EmptyLabel,
        ):
            return
        except _dns_resolver.LifetimeTimeout:
            logger.debug("SRV query timed out for %s", qname)
            return
        except Exception:
            logger.debug(
                "Unexpected SRV resolution error for %s",
                qname,
                exc_info=True,
            )
            return

        for rr in answer:
            target = canonicalize_domain(str(rr.target))
            # Skip the root domain placeholder (empty target means "no
            # service available" per RFC 2782).
            if not target or target == ".":
                continue

            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.DNS_RECORD,
                subject=ObservationSubject(
                    identifier_type=ExtendedIdentifierType.DOMAIN,
                    identifier_value=target,
                ),
                observed_at=datetime.now(UTC),
                structured_payload={
                    "source": "dns_srv",
                    "service": service_prefix,
                    "target": target,
                    "port": rr.port,
                    "priority": rr.priority,
                    "weight": rr.weight,
                    "protocol": protocol,
                    "seed_domain": canonical_domain,
                },
            )

    async def _query_naptr(
        self,
        domain: str,
        canonical_domain: str,
    ) -> AsyncIterator[Observation]:
        """Query NAPTR records at the domain root and yield observations.

        NAPTR records may contain SIP URIs in their replacement or
        regexp fields. When found, the domain/IP portion is extracted
        and emitted as an observation.
        """
        try:
            answer = await self._resolver.resolve(domain, "NAPTR")
        except (
            _dns_resolver.NXDOMAIN,
            _dns_resolver.NoAnswer,
            _dns_resolver.NoNameservers,
            _dns_name.EmptyLabel,
        ):
            return
        except _dns_resolver.LifetimeTimeout:
            logger.debug("NAPTR query timed out for %s", domain)
            return
        except Exception:
            logger.debug(
                "Unexpected NAPTR resolution error for %s",
                domain,
                exc_info=True,
            )
            return

        for rr in answer:
            service = str(getattr(rr, "service", "")).lower()
            flags = str(getattr(rr, "flags", "")).lower()
            replacement = str(getattr(rr, "replacement", ""))
            regexp = str(getattr(rr, "regexp", ""))

            # Check if this NAPTR record is SIP-related.
            is_sip = any(
                marker in service
                for marker in ("sip", "e2u+sip", "sips")
            )
            if not is_sip:
                # Also check the regexp field for SIP URIs.
                if not _SIP_URI_RE.search(regexp):
                    continue

            # Extract domains from the replacement field.
            extracted_domains: list[str] = []
            if replacement and replacement != ".":
                cleaned = canonicalize_domain(replacement)
                if cleaned and cleaned != ".":
                    extracted_domains.append(cleaned)

            # Extract domains from the regexp field.
            for match in _SIP_URI_RE.finditer(regexp):
                host = match.group(1)
                cleaned = canonicalize_domain(host)
                if cleaned and cleaned != ".":
                    extracted_domains.append(cleaned)

            for extracted in extracted_domains:
                yield Observation(
                    collector_id=self.collector_id,
                    collector_version=self.collector_version,
                    tenant_id=self.config.tenant_id,
                    observation_type=ObservationType.DNS_RECORD,
                    subject=ObservationSubject(
                        identifier_type=ExtendedIdentifierType.DOMAIN,
                        identifier_value=extracted,
                    ),
                    observed_at=datetime.now(UTC),
                    structured_payload={
                        "source": "dns_naptr",
                        "service": service,
                        "flags": flags,
                        "replacement": replacement,
                        "regexp": regexp,
                        "order": getattr(rr, "order", None),
                        "preference": getattr(rr, "preference", None),
                        "extracted_domain": extracted,
                        "seed_domain": canonical_domain,
                    },
                )

    async def health_check(self) -> CollectorHealthCheck:
        """Probe DNS resolution by attempting an SRV query.

        The query targets ``_sip._tcp.example.com``. Whether it returns
        records, NXDOMAIN, or NoAnswer, the DNS resolver is functional.
        Only actual resolver failures (timeout, network unreachable)
        indicate a problem.

        Returns a ``CollectorHealthCheck`` with SUCCESS or FAILURE
        status. Does not raise.
        """
        if not HAS_DNSPYTHON:
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(UTC),
                error_message=(
                    "dnspython not installed; install expose[collectors-dns]"
                ),
            )

        start = datetime.now(UTC)
        try:
            await self._resolver.resolve(_HEALTH_CHECK_DOMAIN, "SRV")
        except (
            _dns_resolver.NXDOMAIN,
            _dns_resolver.NoAnswer,
            _dns_resolver.NoNameservers,
        ):
            # These are valid DNS responses — the resolver is working.
            pass
        except Exception as exc:
            elapsed_ms = (datetime.now(UTC) - start).total_seconds() * 1000
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=start,
                latency_ms=elapsed_ms,
                error_message=str(exc),
            )

        elapsed_ms = (datetime.now(UTC) - start).total_seconds() * 1000
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=start,
            latency_ms=elapsed_ms,
        )


__all__ = [
    "HAS_DNSPYTHON",
    "SipDiscoveryCollector",
]

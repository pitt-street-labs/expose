"""DNS Zone Transfer (AXFR) collector (Tier 3, active, attribution-gated).

This collector attempts AXFR zone transfers against the authoritative
nameservers for a given domain seed. Zone transfers are a legitimate DNS
mechanism that allows secondary nameservers to replicate zone data from a
primary, but misconfigured nameservers sometimes allow AXFR from any source
-- exposing every DNS record in the zone.

Most well-configured nameservers will refuse AXFR requests (REFUSED,
NOTAUTH, or timeout). This is the expected case and is recorded as an
informational observation ("zone transfer properly denied"). When a
transfer succeeds, it is a critical finding: every record in the zone is
exposed, and the collector emits one observation per record plus a
summary observation.

This is a Tier-3 (active, attribution-gated) collector: the dispatcher
is responsible for ensuring that Tier-3 dispatch gating (SPEC section
6.3 / ADR-008) is satisfied before calling ``expand()``. This collector
does NOT self-gate.

The ``dnspython`` library is an optional dependency (installed via the
``expose[collectors-dns]`` extra). The module imports cleanly even when
``dnspython`` is absent; ``expand()`` raises ``CollectorError`` with an
actionable message if invoked without the library.

Credential requirements: none. AXFR uses standard DNS over TCP and does
not require API keys.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

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
    import dns.exception as _dns_exception
    import dns.name as _dns_name
    import dns.query as _dns_query
    import dns.resolver as _dns_resolver
    import dns.zone as _dns_zone

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

logger = logging.getLogger(__name__)

# AXFR timeout per nameserver attempt (seconds).
_AXFR_TIMEOUT = 10.0

# Well-known domain used for health checks.
_HEALTH_CHECK_DOMAIN = "dns.google"


@register_collector
class ZoneTransferCollector(Collector):
    """Attempt DNS zone transfers (AXFR) against authoritative nameservers.

    Tier-3 active collector. Dispatch gating is the dispatcher's
    responsibility per SPEC section 6.3 -- this collector does not import
    or call ``assert_tier_3_dispatch_allowed``.
    """

    collector_id: str = "dns-zone-transfer"
    display_name: str = "DNS Zone Transfer (AXFR)"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_3
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        if HAS_DNSPYTHON:
            self._resolver = _dns_asyncresolver.Resolver()
            self._resolver.lifetime = config.request_timeout_seconds
        else:
            self._resolver = None  # type: ignore[assignment]

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Attempt AXFR against each authoritative NS for a DOMAIN seed.

        Skips non-DOMAIN seeds. For each nameserver:
        - On AXFR refused/denied: emits an informational observation
        - On AXFR success: emits one observation per zone record plus a
          critical summary observation
        - On timeout or other error: emits an informational observation
        """
        if not HAS_DNSPYTHON:
            msg = "dnspython not installed; install expose[collectors-dns]"
            raise CollectorError(msg)

        if seed.seed_type != SeedType.DOMAIN:
            return

        domain = seed.value
        canonical_domain = canonicalize_domain(domain)

        # Step 1: Resolve NS records for the domain.
        nameservers = await self._resolve_nameservers(domain)
        if not nameservers:
            return

        # Step 2: Attempt AXFR against each nameserver.
        for ns in nameservers:
            async for obs in self._attempt_axfr(domain, canonical_domain, ns):
                yield obs

    async def _resolve_nameservers(self, domain: str) -> list[str]:
        """Resolve NS records for the domain, returning a list of NS hostnames.

        Returns an empty list on any resolution failure.
        """
        try:
            ns_answers = await self._resolver.resolve(domain, "NS")
            return [str(ns.target).rstrip(".") for ns in ns_answers]
        except (
            _dns_resolver.NXDOMAIN,
            _dns_resolver.NoAnswer,
            _dns_resolver.NoNameservers,
            _dns_name.EmptyLabel,
            _dns_resolver.LifetimeTimeout,
        ):
            logger.debug("NS resolution failed for %s", domain)
            return []
        except Exception:
            logger.debug("Unexpected NS resolution error for %s", domain, exc_info=True)
            return []

    async def _attempt_axfr(
        self,
        domain: str,
        canonical_domain: str,
        ns: str,
    ) -> AsyncIterator[Observation]:
        """Attempt AXFR against a single nameserver.

        Yields informational observation on denial/timeout, or per-record
        observations plus a critical summary on success.
        """
        # Resolve the NS hostname to an IP address.
        try:
            ns_ip = str((await self._resolver.resolve(ns, "A"))[0])
        except Exception:
            logger.debug("Could not resolve NS %s to an IP", ns)
            yield self._make_denied_observation(
                canonical_domain,
                ns,
                note=f"Could not resolve nameserver {ns} to an IP address",
            )
            return

        # Attempt the AXFR (synchronous in dnspython -- offload to thread).
        try:
            zone = await asyncio.to_thread(
                _dns_zone.from_xfr,
                _dns_query.xfr(ns_ip, domain, timeout=_AXFR_TIMEOUT),
            )
        except _dns_exception.FormError:
            # AXFR refused -- this is the expected, secure behavior.
            yield self._make_denied_observation(
                canonical_domain,
                ns,
                note="Zone transfer properly denied",
            )
            return
        except Exception as exc:
            # Timeout, connection refused, or other network error.
            yield self._make_denied_observation(
                canonical_domain,
                ns,
                note=f"Zone transfer failed: {type(exc).__name__}",
            )
            return

        # AXFR succeeded -- this is a critical finding.
        record_count = 0
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                record_count += 1
                yield self._make_record_observation(
                    canonical_domain, ns, name, rdataset
                )

        yield self._make_success_summary_observation(
            canonical_domain, ns, record_count
        )

    def _make_denied_observation(
        self,
        canonical_domain: str,
        nameserver: str,
        *,
        note: str,
    ) -> Observation:
        """Build an informational observation for a denied/failed AXFR."""
        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.DNS_RECORD,
            subject=ObservationSubject(
                identifier_type=ExtendedIdentifierType.DOMAIN,
                identifier_value=canonical_domain,
            ),
            observed_at=datetime.now(UTC),
            structured_payload={
                "axfr_status": "denied",
                "nameserver": nameserver,
                "severity": "info",
                "note": note,
            },
        )

    def _make_record_observation(
        self,
        canonical_domain: str,
        nameserver: str,
        name: Any,
        rdataset: Any,
    ) -> Observation:
        """Build an observation for a single record from a successful AXFR."""
        record_name = str(name)
        rdtype = str(rdataset.rdtype).replace("RdataType.", "")
        records = [str(rdata) for rdata in rdataset]

        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.DNS_RECORD,
            subject=ObservationSubject(
                identifier_type=ExtendedIdentifierType.DOMAIN,
                identifier_value=canonical_domain,
            ),
            observed_at=datetime.now(UTC),
            structured_payload={
                "axfr_status": "success",
                "nameserver": nameserver,
                "record_name": record_name,
                "record_type": rdtype,
                "record_values": records,
                "severity": "critical",
            },
        )

    def _make_success_summary_observation(
        self,
        canonical_domain: str,
        nameserver: str,
        record_count: int,
    ) -> Observation:
        """Build a critical summary observation for a successful AXFR."""
        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.DNS_RECORD,
            subject=ObservationSubject(
                identifier_type=ExtendedIdentifierType.DOMAIN,
                identifier_value=canonical_domain,
            ),
            observed_at=datetime.now(UTC),
            structured_payload={
                "axfr_status": "success",
                "nameserver": nameserver,
                "severity": "critical",
                "record_count": record_count,
                "note": "Zone transfer allowed — full zone exposed",
            },
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
                checked_at=datetime.now(UTC),
                error_message="dnspython not installed; install expose[collectors-dns]",
            )

        start = datetime.now(UTC)
        try:
            await self._resolver.resolve(_HEALTH_CHECK_DOMAIN, "A")
            elapsed_ms = (datetime.now(UTC) - start).total_seconds() * 1000
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.SUCCESS,
                checked_at=start,
                latency_ms=elapsed_ms,
            )
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


__all__ = [
    "HAS_DNSPYTHON",
    "ZoneTransferCollector",
]

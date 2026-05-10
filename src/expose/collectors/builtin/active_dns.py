"""Active DNS resolution collector (Tier 3, per SPEC.md section 6.3).

This collector performs active DNS resolution against target domains,
querying A, AAAA, CNAME, MX, NS, TXT, and SOA record types. It is a
Tier-3 (active, attribution-gated) collector: the dispatcher is
responsible for ensuring that Tier-3 dispatch gating (SPEC section 6.3 /
ADR-008) is satisfied before calling ``expand()``. This collector does
NOT self-gate.

The ``dnspython`` library is an optional dependency (installed via the
``expose[collectors-dns]`` extra). The module imports cleanly even when
``dnspython`` is absent; ``expand()`` raises ``CollectorError`` with an
actionable message if invoked without the library.

Credential requirements: none. DNS resolution uses the system's
configured resolver and does not require API keys.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorError,
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
from expose.sanitization.text import SanitizationFieldKind, sanitize_field
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

try:
    import dns.asyncresolver as _dns_asyncresolver
    import dns.name as _dns_name
    import dns.resolver as _dns_resolver

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

logger = logging.getLogger(__name__)

# Record types to query, in resolution order.
_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")

# Well-known domain used for health checks. Google's public DNS service
# has both A and AAAA records and is highly available.
_HEALTH_CHECK_DOMAIN = "dns.google"


@register_collector
class ActiveDnsCollector(Collector):
    """Resolve DNS records for a domain seed.

    Tier-3 active collector. Dispatch gating is the dispatcher's
    responsibility per SPEC section 6.3 — this collector does not import
    or call ``assert_tier_3_dispatch_allowed``.
    """

    collector_id: str = "active-dns-resolve"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_3
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        if HAS_DNSPYTHON:
            self._resolver = _dns_asyncresolver.Resolver()
            self._resolver.lifetime = config.request_timeout_seconds
            self._apply_egress_profile()
        else:
            self._resolver = None  # type: ignore[assignment]

    def _apply_egress_profile(self) -> None:
        """Apply DNS resolver kwargs from the egress profile, if configured."""
        egress_profile = self.config.extra.get("egress_profile")
        if egress_profile is not None:
            from expose.egress.base import EgressProfile  # noqa: PLC0415

            if isinstance(egress_profile, EgressProfile):
                resolver_kwargs = egress_profile.configure_dns_resolver()
                if "nameservers" in resolver_kwargs:
                    self._resolver.nameservers = resolver_kwargs["nameservers"]

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Resolve DNS records for a DOMAIN seed.

        Skips non-DOMAIN seeds. On NXDOMAIN, emits no observations (not
        an error). On timeout or resolver unreachable, raises
        ``CollectorSourceUnreachableError``. Individual record-type
        failures (e.g., ``NoAnswer`` for TXT) are skipped without failing
        the whole expansion.
        """
        if not HAS_DNSPYTHON:
            msg = "dnspython not installed; install expose[collectors-dns]"
            raise CollectorError(msg)

        if seed.seed_type != SeedType.DOMAIN:
            return

        domain = seed.value
        canonical_domain = canonicalize_domain(domain)

        for rdtype in _RECORD_TYPES:
            try:
                answer = await self._resolver.resolve(domain, rdtype)
            except _dns_resolver.NXDOMAIN:
                # Domain does not exist. Emit nothing for any record type.
                return
            except (
                _dns_resolver.NoAnswer,
                _dns_resolver.NoNameservers,
                _dns_name.EmptyLabel,
            ):
                # This specific record type has no answer; skip it.
                continue
            except _dns_resolver.LifetimeTimeout as exc:
                msg = f"DNS resolution timed out for {domain!r}"
                raise CollectorSourceUnreachableError(msg) from exc
            except Exception as exc:
                # Catch-all for unexpected resolver errors (network
                # unreachable, OS-level failures). Surface as source
                # unreachable so the dispatcher can record the failure.
                msg = f"DNS resolution failed for {domain!r}: {exc}"
                raise CollectorSourceUnreachableError(msg) from exc

            observation = self._build_observation(
                canonical_domain, rdtype, answer
            )
            if observation is not None:
                yield observation

    def _build_observation(
        self,
        canonical_domain: str,
        rdtype: str,
        answer: Any,
    ) -> Observation | None:
        """Build an Observation from a successful DNS answer."""
        payload: dict[str, Any] = {"record_type": rdtype}

        if rdtype in ("A", "AAAA"):
            values = [canonicalize_ip(str(rr)) for rr in answer]
            payload["values"] = values
            payload["ttl"] = answer.rrset.ttl if answer.rrset is not None else None

        elif rdtype == "CNAME":
            target = canonicalize_domain(str(answer[0].target))
            payload["target"] = target

        elif rdtype == "MX":
            exchanges = [
                {
                    "priority": rr.preference,
                    "exchange": canonicalize_domain(str(rr.exchange)),
                }
                for rr in answer
            ]
            payload["exchanges"] = exchanges

        elif rdtype == "NS":
            nameservers = [
                canonicalize_domain(str(rr.target)) for rr in answer
            ]
            payload["nameservers"] = nameservers

        elif rdtype == "TXT":
            raw_values = [
                b"".join(rr.strings).decode("utf-8", errors="replace")
                for rr in answer
            ]
            sanitized_values = [
                sanitize_field(v, SanitizationFieldKind.DNS_TXT_RECORD).value
                for v in raw_values
            ]
            payload["values"] = sanitized_values

        elif rdtype == "SOA":
            soa = answer[0]
            payload["mname"] = canonicalize_domain(str(soa.mname))
            payload["rname"] = canonicalize_domain(str(soa.rname))
            payload["serial"] = soa.serial
            payload["refresh"] = soa.refresh
            payload["retry"] = soa.retry
            payload["expire"] = soa.expire
            payload["minimum"] = soa.minimum

        else:  # pragma: no cover
            return None

        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.DNS_RESOLUTION,
            subject=ObservationSubject(
                identifier_type=ExtendedIdentifierType.DOMAIN,
                identifier_value=canonical_domain,
            ),
            observed_at=datetime.now(UTC),
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
    "ActiveDnsCollector",
]

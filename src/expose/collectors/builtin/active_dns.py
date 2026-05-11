"""Active DNS resolution collector (Tier 3, per SPEC.md section 6.3).

This collector performs active DNS resolution against target domains,
querying A, AAAA, CNAME, MX, NS, TXT, and SOA record types. It also
performs supplementary security checks:

- **Wildcard DNS detection**: resolves ``*.domain`` to detect wildcard
  records (attack surface signal — wildcard DNS can mask subdomain
  enumeration and cause dangling-record issues).
- **Zone transfer (AXFR) attempt**: tries an AXFR against the first
  authoritative nameserver and flags whether the transfer succeeded
  (critical misconfiguration) or was properly denied.
- **DNSSEC validation**: queries for DNSKEY records to determine
  whether the domain has DNSSEC deployed.

It is a Tier-3 (active, attribution-gated) collector: the dispatcher is
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
    import dns.exception as _dns_exception
    import dns.name as _dns_name
    import dns.query as _dns_query
    import dns.resolver as _dns_resolver
    import dns.zone as _dns_zone

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
    collector_version: str = "0.2.0"
    tier: CollectorTier = CollectorTier.TIER_3
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None
    technique_ids: ClassVar[list[str]] = ["T1596.001"]

    # Timeout for zone transfer attempts (seconds).
    _AXFR_TIMEOUT: ClassVar[float] = 10.0

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        if HAS_DNSPYTHON:
            self._resolver = _dns_asyncresolver.Resolver()
            self._resolver.lifetime = config.request_timeout_seconds
            self._apply_egress_profile()
        else:
            self._resolver = None  # type: ignore[assignment]

    def _apply_egress_profile(self) -> None:
        """Apply DNS resolver kwargs from the egress profile, if configured.

        Handles all known kwargs returned by egress profiles:
        - ``nameservers``: list of IP addresses (may be empty for
          dns-through-proxy profiles like SOCKS5h / Tor).
        - ``port``: non-standard DNS port (e.g. DoH forwarder on
          egress host).
        - ``source``: source IP to bind outgoing DNS queries.
        """
        egress_profile = self.config.extra.get("egress_profile")
        if egress_profile is not None:
            from expose.egress.base import EgressProfile  # noqa: PLC0415

            if isinstance(egress_profile, EgressProfile):
                resolver_kwargs = egress_profile.configure_dns_resolver()
                if "nameservers" in resolver_kwargs:
                    self._resolver.nameservers = resolver_kwargs["nameservers"]
                if "port" in resolver_kwargs:
                    self._resolver.port = resolver_kwargs["port"]
                if "source" in resolver_kwargs:
                    self._resolver.source = resolver_kwargs["source"]

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Resolve DNS records for a DOMAIN seed.

        Skips non-DOMAIN seeds. On NXDOMAIN, emits no observations (not
        an error). On timeout or resolver unreachable, raises
        ``CollectorSourceUnreachableError``. Individual record-type
        failures (e.g., ``NoAnswer`` for TXT) are skipped without failing
        the whole expansion.

        All record types are resolved concurrently via ``asyncio.gather``
        for lower latency.
        """
        if not HAS_DNSPYTHON:
            msg = "dnspython not installed; install expose[collectors-dns]"
            raise CollectorError(msg)

        if seed.seed_type != SeedType.DOMAIN:
            return

        domain = seed.value
        canonical_domain = canonicalize_domain(domain)

        # Resolve all record types in parallel.  Each coroutine returns
        # (rdtype, answer) on success or raises an exception that is caught
        # individually via the _sentinel wrapper.
        _NXDOMAIN_SENTINEL = object()
        _SKIP_SENTINEL = object()

        async def _resolve_one(rdtype: str) -> tuple[str, Any]:
            """Resolve a single record type, returning sentinels for expected errors."""
            try:
                answer = await self._resolver.resolve(domain, rdtype)
                return (rdtype, answer)
            except _dns_resolver.NXDOMAIN:
                return (rdtype, _NXDOMAIN_SENTINEL)
            except (
                _dns_resolver.NoAnswer,
                _dns_resolver.NoNameservers,
                _dns_name.EmptyLabel,
            ):
                return (rdtype, _SKIP_SENTINEL)
            except _dns_resolver.LifetimeTimeout as exc:
                msg = f"DNS resolution timed out for {domain!r}"
                raise CollectorSourceUnreachableError(msg) from exc
            except Exception as exc:
                msg = f"DNS resolution failed for {domain!r}: {exc}"
                raise CollectorSourceUnreachableError(msg) from exc

        results = await asyncio.gather(
            *[_resolve_one(rt) for rt in _RECORD_TYPES],
        )

        nxdomain = False
        ns_list: list[str] = []

        for rdtype, answer in results:
            if answer is _NXDOMAIN_SENTINEL:
                # Domain does not exist. Emit nothing.
                nxdomain = True
                break
            if answer is _SKIP_SENTINEL:
                continue

            # Capture NS hostnames for zone transfer attempt later.
            if rdtype == "NS":
                ns_list = [str(rr.target).rstrip(".") for rr in answer]

            observation = self._build_observation(
                canonical_domain, rdtype, answer
            )
            if observation is not None:
                yield observation

        if nxdomain:
            return

        # --- Supplementary security checks ---
        # Run wildcard detection and DNSSEC check concurrently.
        wildcard_obs, dnssec_obs = await asyncio.gather(
            self._check_wildcard(domain, canonical_domain),
            self._check_dnssec(domain, canonical_domain),
        )
        if wildcard_obs is not None:
            yield wildcard_obs
        if dnssec_obs is not None:
            yield dnssec_obs

        # Zone transfer attempt (uses first NS, if any).
        axfr_obs = await self._check_zone_transfer(
            domain, canonical_domain, ns_list
        )
        if axfr_obs is not None:
            yield axfr_obs

    def _build_observation(
        self,
        canonical_domain: str,
        rdtype: str,
        answer: Any,
    ) -> Observation | None:
        """Build an Observation from a successful DNS answer.

        Every payload includes ``_collector_id`` so downstream lead
        scoring can identify the originating collector without inspecting
        the outer ``Observation.collector_id`` field.
        """
        payload: dict[str, Any] = {
            "_collector_id": self.collector_id,
            "record_type": rdtype,
        }

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

    # --- Supplementary security checks ------------------------------------

    async def _check_wildcard(
        self,
        domain: str,
        canonical_domain: str,
    ) -> Observation | None:
        """Detect wildcard DNS by resolving ``*.domain``.

        Wildcard DNS is an attack surface signal: it can mask subdomain
        takeover, make subdomain enumeration unreliable, and indicate
        hosting configurations that respond to arbitrary subdomains.

        Returns an observation if the wildcard query succeeds (positive
        detection) or ``None`` if the domain does not have wildcard DNS
        (the normal, expected case). Errors are silently swallowed to
        avoid failing the main expansion.
        """
        wildcard_qname = f"*.{domain}"
        try:
            answer = await self._resolver.resolve(wildcard_qname, "A")
            # Wildcard responded -- this IS a finding.
            values = [canonicalize_ip(str(rr)) for rr in answer]
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
                structured_payload={
                    "_collector_id": self.collector_id,
                    "record_type": "WILDCARD",
                    "wildcard_detected": True,
                    "wildcard_values": values,
                    "severity": "warning",
                    "note": (
                        "Wildcard DNS detected — all unregistered "
                        "subdomains resolve to the same address(es)"
                    ),
                },
            )
        except (
            _dns_resolver.NXDOMAIN,
            _dns_resolver.NoAnswer,
            _dns_resolver.NoNameservers,
            _dns_name.EmptyLabel,
            _dns_resolver.LifetimeTimeout,
        ):
            # No wildcard -- expected, secure behavior.
            return None
        except Exception:
            logger.debug(
                "Wildcard check failed for %s (non-fatal)", domain, exc_info=True
            )
            return None

    async def _check_dnssec(
        self,
        domain: str,
        canonical_domain: str,
    ) -> Observation | None:
        """Check for DNSSEC deployment by querying DNSKEY records.

        If DNSKEY records exist, the domain has DNSSEC configured (though
        this does not validate the chain of trust — only presence). The
        absence of DNSSEC is an informational finding, not a
        vulnerability, but is useful for attack surface profiling.

        Errors are silently swallowed to avoid failing the main
        expansion.
        """
        try:
            answer = await self._resolver.resolve(domain, "DNSKEY")
            # DNSKEY found -- DNSSEC is configured.
            key_count = sum(1 for _ in answer)
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
                structured_payload={
                    "_collector_id": self.collector_id,
                    "record_type": "DNSSEC",
                    "dnssec_enabled": True,
                    "dnskey_count": key_count,
                    "severity": "info",
                    "note": "DNSSEC is configured (DNSKEY records present)",
                },
            )
        except (
            _dns_resolver.NXDOMAIN,
            _dns_resolver.NoAnswer,
            _dns_resolver.NoNameservers,
            _dns_name.EmptyLabel,
        ):
            # No DNSKEY -- DNSSEC not deployed.
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
                structured_payload={
                    "_collector_id": self.collector_id,
                    "record_type": "DNSSEC",
                    "dnssec_enabled": False,
                    "dnskey_count": 0,
                    "severity": "info",
                    "note": "DNSSEC is not configured (no DNSKEY records)",
                },
            )
        except _dns_resolver.LifetimeTimeout:
            logger.debug("DNSSEC check timed out for %s (non-fatal)", domain)
            return None
        except Exception:
            logger.debug(
                "DNSSEC check failed for %s (non-fatal)", domain, exc_info=True
            )
            return None

    async def _check_zone_transfer(
        self,
        domain: str,
        canonical_domain: str,
        ns_list: list[str],
    ) -> Observation | None:
        """Attempt a lightweight AXFR probe against the first nameserver.

        This is a quick signal check — the dedicated ``dns-zone-transfer``
        collector provides full zone enumeration. Here we only care about
        the binary signal: was the transfer allowed or denied?

        Returns an observation indicating the result, or ``None`` if no
        nameservers were found or the probe could not be completed.
        """
        if not ns_list:
            return None

        target_ns = ns_list[0]

        # Resolve the nameserver hostname to an IP.
        try:
            ns_ip = str((await self._resolver.resolve(target_ns, "A"))[0])
        except Exception:
            logger.debug(
                "Could not resolve NS %s for AXFR probe (non-fatal)", target_ns
            )
            return None

        # Attempt the AXFR in a thread (dnspython AXFR is synchronous).
        try:
            await asyncio.to_thread(
                _dns_zone.from_xfr,
                _dns_query.xfr(ns_ip, domain, timeout=self._AXFR_TIMEOUT),
            )
        except _dns_exception.FormError:
            # Transfer refused -- expected, secure behavior.
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
                structured_payload={
                    "_collector_id": self.collector_id,
                    "record_type": "AXFR",
                    "axfr_allowed": False,
                    "nameserver": target_ns,
                    "severity": "info",
                    "note": "Zone transfer properly denied",
                },
            )
        except Exception:
            # Timeout, connection refused, or other error.
            logger.debug(
                "AXFR probe against %s failed (non-fatal)", target_ns, exc_info=True
            )
            return None

        # If we reach here, the AXFR succeeded — critical finding.
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
            structured_payload={
                "_collector_id": self.collector_id,
                "record_type": "AXFR",
                "axfr_allowed": True,
                "nameserver": target_ns,
                "severity": "critical",
                "note": (
                    "Zone transfer allowed — full zone data exposed. "
                    "Run the dns-zone-transfer collector for full enumeration."
                ),
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
    "ActiveDnsCollector",
]

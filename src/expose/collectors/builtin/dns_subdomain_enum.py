"""DNS subdomain enumeration collector (Tier 3, per SPEC.md section 6.3).

This collector performs wordlist-based subdomain discovery against apex
domains. For each word in the configured wordlist, it resolves
``{word}.{apex}`` via A/AAAA queries in parallel. It is a Tier-3 (active,
attribution-gated) collector: the dispatcher is responsible for ensuring
that Tier-3 dispatch gating (SPEC section 6.3 / ADR-008) is satisfied
before calling ``expand()``. This collector does NOT self-gate.

**Wildcard detection:** Before enumeration, the collector resolves a
random, very-unlikely-to-exist subdomain. If it resolves, the domain
uses wildcard DNS. All subsequent results whose resolved IPs exactly
match the wildcard set are filtered out as false positives.

**Rate limiting:** Concurrent queries are bounded by an
``asyncio.Semaphore`` (default: 50 concurrent) to avoid flooding the
resolver or triggering upstream rate limits.

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
from pathlib import Path
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
from expose.sanitization.canonicalize import canonicalize_domain, canonicalize_ip
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

try:
    import dns.asyncresolver as _dns_asyncresolver
    import dns.name as _dns_name
    import dns.resolver as _dns_resolver

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

logger = logging.getLogger(__name__)

# Well-known domain used for health checks.
_HEALTH_CHECK_DOMAIN = "dns.google"

# Default maximum concurrent DNS queries.
_DEFAULT_MAX_CONCURRENT = 50

# Default wordlist path relative to the repository root.
_DEFAULT_WORDLIST = (
    Path(__file__).resolve().parents[4] / "examples" / "wordlists" / "subdomains-5000.txt"
)

# Random subdomain prefix for wildcard detection. Deliberately long and
# nonsensical to ensure it would never exist as a real record.
_WILDCARD_PROBE_PREFIX = "expose-wildcard-probe-7f3a9b2c1d4e"


def load_wordlist(path: Path) -> list[str]:
    """Load subdomain prefixes from a wordlist file.

    Blank lines and lines starting with ``#`` are ignored. Whitespace is
    stripped from each entry. Duplicate entries are removed while
    preserving order.
    """
    if not path.is_file():
        logger.warning("Wordlist file not found: %s", path)
        return []

    seen: set[str] = set()
    words: list[str] = []
    with path.open(encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            lower = line.lower()
            if lower not in seen:
                seen.add(lower)
                words.append(lower)
    return words


@register_collector
class SubdomainEnumCollector(Collector):
    """Enumerate subdomains of an apex domain via wordlist-based DNS resolution.

    Tier-3 active collector. Dispatch gating is the dispatcher's
    responsibility per SPEC section 6.3 -- this collector does not import
    or call ``assert_tier_3_dispatch_allowed``.
    """

    collector_id: str = "dns-subdomain-enum"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_3
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

        # Configurable via config.extra.
        wordlist_path = config.extra.get("wordlist_path")
        if wordlist_path is not None:
            self._wordlist_path = Path(wordlist_path)
        else:
            self._wordlist_path = _DEFAULT_WORDLIST

        max_concurrent = config.extra.get("max_concurrent")
        if max_concurrent is not None and isinstance(max_concurrent, int) and max_concurrent > 0:
            self._max_concurrent = max_concurrent
        else:
            self._max_concurrent = _DEFAULT_MAX_CONCURRENT

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Enumerate subdomains for a DOMAIN seed.

        Skips non-DOMAIN seeds. Loads the configured wordlist, performs
        wildcard detection, then resolves each candidate subdomain in
        parallel (bounded by the concurrency semaphore). Yields one
        observation per discovered subdomain.
        """
        if not HAS_DNSPYTHON:
            msg = "dnspython not installed; install expose[collectors-dns]"
            raise CollectorError(msg)

        if seed.seed_type != SeedType.DOMAIN:
            return

        apex = seed.value
        words = load_wordlist(self._wordlist_path)
        if not words:
            return

        # Wildcard detection.
        wildcard_ips = await self._detect_wildcard(apex)

        # Resolve all candidates concurrently with semaphore.
        semaphore = asyncio.Semaphore(self._max_concurrent)
        tasks = [self._resolve_subdomain(word, apex, semaphore, wildcard_ips) for word in words]
        results = await asyncio.gather(*tasks)

        for obs in results:
            if obs is not None:
                yield obs

    async def _detect_wildcard(self, apex: str) -> frozenset[str]:
        """Probe for wildcard DNS by resolving a random subdomain.

        Returns a frozenset of IPs if a wildcard is detected (the probe
        subdomain resolved), or an empty frozenset if no wildcard.
        """
        probe_fqdn = f"{_WILDCARD_PROBE_PREFIX}.{apex}"
        try:
            answer = await self._resolver.resolve(probe_fqdn, "A")
            ips = frozenset(canonicalize_ip(str(rr)) for rr in answer)
            logger.info(
                "Wildcard DNS detected for %s — IPs: %s",
                apex,
                ", ".join(sorted(ips)),
            )
            return ips
        except (
            _dns_resolver.NXDOMAIN,
            _dns_resolver.NoAnswer,
            _dns_resolver.NoNameservers,
            _dns_resolver.LifetimeTimeout,
            _dns_name.EmptyLabel,
            Exception,
        ):
            return frozenset()

    async def _resolve_cname(self, fqdn: str) -> list[str]:
        """Resolve CNAME records for ``fqdn``, returning the chain.

        Returns an empty list if no CNAME exists or resolution fails.
        """
        try:
            cname_answer = await self._resolver.resolve(fqdn, "CNAME")
            return [canonicalize_domain(str(rr.target)) for rr in cname_answer]
        except Exception:
            logger.debug("CNAME lookup failed for %s (expected for most subdomains)", fqdn)
            return []

    async def _resolve_address(self, fqdn: str, rdtype: str) -> tuple[list[str], int | None]:
        """Resolve A or AAAA records, returning (ips, ttl).

        Raises ``_dns_resolver.NXDOMAIN`` if the domain does not exist.
        Returns ``([], None)`` for other failures.
        """
        try:
            answer = await self._resolver.resolve(fqdn, rdtype)
            ips = [canonicalize_ip(str(rr)) for rr in answer]
            ttl = answer.rrset.ttl if answer.rrset is not None else None
            return ips, ttl
        except _dns_resolver.NXDOMAIN:
            raise
        except Exception:
            logger.debug("%s lookup failed for %s", rdtype, fqdn)
            return [], None

    async def _resolve_subdomain(
        self,
        word: str,
        apex: str,
        semaphore: asyncio.Semaphore,
        wildcard_ips: frozenset[str],
    ) -> Observation | None:
        """Resolve a single candidate subdomain under the semaphore.

        Returns an ``Observation`` if the subdomain resolves and is not
        a wildcard match, otherwise ``None``.
        """
        fqdn = f"{word}.{apex}"

        async with semaphore:
            cname_chain = await self._resolve_cname(fqdn)

            # Resolve A records.
            resolved_ips: list[str] = []
            ttl: int | None = None
            try:
                a_ips, a_ttl = await self._resolve_address(fqdn, "A")
                resolved_ips.extend(a_ips)
                ttl = a_ttl
            except _dns_resolver.NXDOMAIN:
                # If we have a CNAME chain, the FQDN exists even without
                # an A record at this name. Otherwise, it truly doesn't exist.
                if not cname_chain:
                    return None

            # If A failed (non-NXDOMAIN) and no CNAME, nothing to report.
            if not resolved_ips and not cname_chain:
                return None

            # Also try AAAA.
            try:
                aaaa_ips, aaaa_ttl = await self._resolve_address(fqdn, "AAAA")
                resolved_ips.extend(aaaa_ips)
                if ttl is None:
                    ttl = aaaa_ttl
            except _dns_resolver.NXDOMAIN:
                pass

            if not resolved_ips and not cname_chain:
                return None

            # Wildcard filtering: if all resolved IPs are a subset of
            # the wildcard IPs, this is a false positive.
            if wildcard_ips and resolved_ips:
                resolved_set = frozenset(resolved_ips)
                if resolved_set.issubset(wildcard_ips):
                    return None

            return self._build_observation(fqdn, resolved_ips, cname_chain, ttl)

    def _build_observation(
        self,
        fqdn: str,
        resolved_ips: list[str],
        cname_chain: list[str],
        ttl: int | None,
    ) -> Observation:
        """Build an Observation for a discovered subdomain."""
        canonical = canonicalize_domain(fqdn)
        payload: dict[str, Any] = {
            "subdomain": canonical,
            "resolved_ips": resolved_ips,
        }
        if cname_chain:
            payload["cname_chain"] = cname_chain
        if ttl is not None:
            payload["ttl"] = ttl

        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.DNS_RESOLUTION,
            subject=ObservationSubject(
                identifier_type=ExtendedIdentifierType.DOMAIN,
                identifier_value=canonical,
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
    "SubdomainEnumCollector",
    "load_wordlist",
]

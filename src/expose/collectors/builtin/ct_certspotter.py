"""Certificate Transparency collector — CertSpotter / SSLMate (Tier 1, passive).

Queries the CertSpotter API for certificate issuances matching a domain seed.

**Domain search** (``?domain=example.com&include_subdomains=true&expand=dns_names``):
  Returns certificates whose SANs match the domain, including subdomains.

CertSpotter aggregates Certificate Transparency log entries and provides a
free, no-auth-required API for basic access. It serves as the ultimate free
backup to crt.sh for CT enumeration.

No credentials required. Rate limited to 100 queries/hour by the upstream
API; we self-limit to 60/minute to stay well within that budget.

Seed types: DOMAIN only. Other seed types are skipped with a warning.

For each certificate returned, we emit one ``CT_LOG_ENTRY`` observation per
unique discovered domain name (filtering out wildcard SANs like
``*.example.com``). The ``tbs_sha256`` fingerprint from CertSpotter is used
as the observation subject identifier — this is the TBS (to-be-signed)
certificate hash, suitable for deduplication.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, ClassVar

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
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

_CERTSPOTTER_API_BASE = "https://api.certspotter.com/v1/issuances"

# === In-memory TTL cache =====================================================
# Caches successful CertSpotter responses so repeated scans for the same
# domain within the TTL window do not depend on CertSpotter availability.
_CACHE_TTL_SECONDS = 3600  # 1 hour

# Cache entry: (timestamp_monotonic, response_entries)
_domain_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}


def _cache_get(key: str) -> list[dict[str, Any]] | None:
    """Return cached entries if present and not expired, else None."""
    entry = _domain_cache.get(key)
    if entry is None:
        return None
    ts, data = entry
    if (time.monotonic() - ts) > _CACHE_TTL_SECONDS:
        del _domain_cache[key]
        return None
    return data


def _cache_put(key: str, data: list[dict[str, Any]]) -> None:
    """Store entries in the cache with the current monotonic timestamp."""
    _domain_cache[key] = (time.monotonic(), data)


def clear_certspotter_cache() -> None:
    """Clear all cached CertSpotter responses. Useful for testing."""
    _domain_cache.clear()


def _is_wildcard(name: str) -> bool:
    """Return True if ``name`` is a wildcard DNS name (e.g. ``*.example.com``)."""
    return name.startswith("*.")


@register_collector
class CertSpotterCollector(Collector):
    """Certificate Transparency collector using CertSpotter / SSLMate (Tier 1)."""

    collector_id: str = "ct-certspotter"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = 60
    technique_ids: ClassVar[list[str]] = ["T1596.003"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        if seed.seed_type == SeedType.DOMAIN:
            async for obs in self._expand_domain(seed):
                yield obs
        else:
            logger.warning(
                "ct-certspotter: skipping unsupported seed type %s (value=%r)",
                seed.seed_type,
                seed.value,
            )

    async def _expand_domain(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query CertSpotter by domain with subdomain inclusion."""
        domain = seed.value.strip().lower()

        # Check cache first.
        cached = _cache_get(domain)
        if cached is not None:
            logger.debug(
                "ct-certspotter: cache hit for domain %r (%d entries)",
                domain,
                len(cached),
            )
            entries = cached
        else:
            params = {
                "domain": domain,
                "include_subdomains": "true",
                "expand": "dns_names",
            }

            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(self.config.request_timeout_seconds),
                    headers={"User-Agent": self.config.user_agent},
                ) as client:
                    response = await client.get(_CERTSPOTTER_API_BASE, params=params)

                    # 429 = rate limited — raise a clear error.
                    if response.status_code == 429:  # noqa: PLR2004
                        retry_after = response.headers.get("Retry-After", "unknown")
                        msg = (
                            f"CertSpotter rate-limited for domain {domain!r} "
                            f"(Retry-After: {retry_after})"
                        )
                        raise CollectorSourceUnreachableError(msg)

                    response.raise_for_status()
            except CollectorSourceUnreachableError:
                raise
            except httpx.HTTPStatusError as exc:
                msg = (
                    f"CertSpotter returned HTTP {exc.response.status_code} "
                    f"for domain {domain!r}"
                )
                raise CollectorSourceUnreachableError(msg) from exc
            except httpx.HTTPError as exc:
                msg = f"CertSpotter unreachable for domain {domain!r}: {exc}"
                raise CollectorSourceUnreachableError(msg) from exc

            try:
                raw: Any = response.json()
            except Exception as exc:
                msg = (
                    f"CertSpotter returned malformed JSON for domain "
                    f"{domain!r}: {exc}"
                )
                raise CollectorSourceUnreachableError(msg) from exc

            if not isinstance(raw, list):
                msg = (
                    f"CertSpotter returned {type(raw).__name__} instead of "
                    f"JSON array for domain {domain!r}"
                )
                raise CollectorSourceUnreachableError(msg)

            entries = raw
            # Cache successful responses.
            _cache_put(domain, entries)

        if not entries:
            return

        # Collect all unique non-wildcard domain names across all certs,
        # and emit one observation per unique domain, tagged with the cert
        # that first introduced it.
        seen_domains: set[str] = set()

        for entry in entries:
            dns_names: list[str] = entry.get("dns_names", [])
            issuer_raw: str = str(entry.get("issuer", {}) if isinstance(entry.get("issuer"), dict) else entry.get("issuer", ""))
            not_before: str = str(entry.get("not_before", ""))
            not_after: str = str(entry.get("not_after", ""))
            tbs_sha256: str = str(entry.get("tbs_sha256", ""))

            for name in dns_names:
                name_lower = name.strip().lower()
                if not name_lower:
                    continue
                if _is_wildcard(name_lower):
                    continue
                if name_lower in seen_domains:
                    continue
                seen_domains.add(name_lower)

                try:
                    yield Observation(
                        collector_id=self.collector_id,
                        collector_version=self.collector_version,
                        tenant_id=self.config.tenant_id,
                        observation_type=ObservationType.CT_LOG_ENTRY,
                        subject=ObservationSubject(
                            identifier_type=IdentifierType.DOMAIN,
                            identifier_value=name_lower,
                        ),
                        observed_at=datetime.now(tz=UTC),
                        structured_payload={
                            "source": "certspotter",
                            "issuer": issuer_raw,
                            "not_before": not_before,
                            "not_after": not_after,
                            "tbs_sha256": tbs_sha256,
                            "dns_names": dns_names,
                        },
                    )
                except Exception as exc:
                    logger.warning(
                        "ct-certspotter: failed to build observation for "
                        "domain %s from cert %s: %s",
                        name_lower,
                        tbs_sha256,
                        exc,
                        exc_info=True,
                    )

    async def health_check(self) -> CollectorHealthCheck:
        start = datetime.now(tz=UTC)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0),
                headers={"User-Agent": self.config.user_agent},
            ) as client:
                response = await client.get(
                    _CERTSPOTTER_API_BASE,
                    params={"domain": "example.com", "expand": "dns_names"},
                )
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
                error_message=f"CertSpotter returned HTTP {response.status_code}",
            )
        except httpx.HTTPError as exc:
            elapsed_ms = (datetime.now(tz=UTC) - start).total_seconds() * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=start,
                latency_ms=elapsed_ms,
                error_message=f"CertSpotter unreachable: {exc}",
            )

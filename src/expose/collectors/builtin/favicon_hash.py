"""Favicon hash collector (Tier 2, passive, targeted).

Fetches ``favicon.ico`` (and ``apple-touch-icon.png`` as fallback) from
discovered web assets, computes a SHA-256 hash via the FIPS adapter
(ADR-010), and emits an ``HTTP_RESPONSE`` observation with the hash in
the structured payload.

Same favicon hash across different hosts implies the same operator or
application — useful for cluster-correlation and technology fingerprinting
downstream.

A stub MurmurHash3 field is included in the payload for future Shodan-
compatible correlation once the ``mmh3`` dependency is added.

Seed types: DOMAIN, IP.  Other seed types are skipped silently.

No credentials required.  Rate limiting is belt-and-braces via the
framework-level limiter; this collector does not self-limit beyond the
upstream httpx timeout.
"""

from __future__ import annotations

import logging
import time
import warnings
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from typing import ClassVar

import httpx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorHealthCheck,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import register_collector
from expose.collectors.tiers import CollectorTier
from expose.crypto.fips_adapter import compute_sha256_hex
from expose.sanitization.canonicalize import canonicalize_domain, canonicalize_ip
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

# Paths to probe for favicon, in priority order.
_FAVICON_PATHS = ("/favicon.ico", "/apple-touch-icon.png")

# Health-check target.
_HEALTH_CHECK_URL = "https://www.google.com/favicon.ico"


def _compute_mmh3_hash(data: bytes) -> int:
    """Compute MurmurHash3 for Shodan-compatible correlation.

    Uses base64 encoding of the favicon then mmh3 hash.
    Since mmh3 is not a dependency, this is stubbed and returns 0.
    """
    # Stubbed until mmh3 dependency is added for Shodan correlation.
    return 0


def _resolve_identifier(
    host: str, seed_type: SeedType
) -> tuple[IdentifierType, str]:
    """Determine the identifier type and canonical value for a host string."""
    if seed_type == SeedType.IP:
        canonical = canonicalize_ip(host)
        return IdentifierType.IP, canonical
    canonical = canonicalize_domain(host)
    return IdentifierType.DOMAIN, canonical


@register_collector
class FaviconHashCollector(Collector):
    """Tier-2 passive favicon hash collector.

    Fetches favicon from known web assets and computes a FIPS-validated
    SHA-256 hash for cluster correlation.
    """

    collector_id: str = "favicon-hash"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_2
    requires_credentials: bool = False
    technique_ids: ClassVar[list[str]] = ["T1592.004"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Fetch favicon from the seed host and yield an observation with the hash."""
        if seed.seed_type not in {SeedType.DOMAIN, SeedType.IP}:
            return

        host = seed.value.strip()
        identifier_type, canonical_value = _resolve_identifier(host, seed.seed_type)

        # Try HTTPS first, then HTTP.
        schemes = ["https", "http"]
        for scheme in schemes:
            base_url = f"{scheme}://{host}"
            result = await self._try_fetch_favicon(base_url)
            if result is not None:
                favicon_bytes, favicon_url, content_type = result
                sha256_hash = compute_sha256_hex(favicon_bytes)
                mmh3_hash = _compute_mmh3_hash(favicon_bytes)

                yield Observation(
                    collector_id=self.collector_id,
                    collector_version=self.collector_version,
                    tenant_id=self.config.tenant_id,
                    observation_type=ObservationType.HTTP_RESPONSE,
                    subject=ObservationSubject(
                        identifier_type=identifier_type,
                        identifier_value=canonical_value,
                    ),
                    observed_at=datetime.now(tz=UTC),
                    structured_payload={
                        "favicon_sha256": sha256_hash,
                        "favicon_mmh3": mmh3_hash,
                        "favicon_size_bytes": len(favicon_bytes),
                        "favicon_url": favicon_url,
                        "favicon_content_type": content_type,
                    },
                    evidence_blob=favicon_bytes,
                    evidence_blob_content_type=content_type,
                )
                return  # One favicon is enough.

        # No favicon found on any scheme/path — not an error, just no data.
        logger.debug("favicon-hash: no favicon found for host %s", host)

    async def _try_fetch_favicon(
        self, base_url: str
    ) -> tuple[bytes, str, str] | None:
        """Try to fetch a favicon from the given base URL.

        Returns (bytes, url, content_type) or None if not found.
        """
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")
            try:
                async with httpx.AsyncClient(
                    verify=False,  # noqa: S501
                    timeout=self.config.request_timeout_seconds,
                    follow_redirects=True,
                    headers={"User-Agent": self.config.user_agent},
                ) as client:
                    for path in _FAVICON_PATHS:
                        url = base_url + path
                        try:
                            resp = await client.get(url)
                            if (
                                resp.status_code == 200  # noqa: PLR2004
                                and len(resp.content) > 0
                            ):
                                ct = resp.headers.get(
                                    "content-type", "image/x-icon"
                                )
                                return resp.content, str(resp.url), ct
                        except httpx.HTTPError:
                            continue
            except httpx.HTTPError:
                return None
        return None

    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe — fetch Google's favicon."""
        start = time.monotonic()
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=DeprecationWarning)
                warnings.filterwarnings(
                    "ignore", message="Unverified HTTPS request"
                )
                async with httpx.AsyncClient(verify=False) as client:  # noqa: S501
                    resp = await client.get(
                        _HEALTH_CHECK_URL,
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
    "FaviconHashCollector",
]

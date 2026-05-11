"""Certificate Transparency collector — Censys Certificates API v2 (Tier 1, passive).

Provides subdomain discovery via Censys's Certificate Transparency search,
serving as an alternate CT source when crt.sh is unavailable (502/timeout).

Queries the Censys Search API v2 certificates endpoint for certificates
matching a domain, extracting Subject Alternative Names (SANs) as subdomain
entities — the same discovery capability as the crt.sh collector.

API endpoint:
    GET /v2/certificates/search?q=parsed.names:{domain}&per_page=100

Authentication: HTTP Basic with ``censys_api_id`` : ``censys_api_secret``.

Credential slots:
    ``censys_api_id``     — Censys API ID (required).
    ``censys_api_secret`` — Censys API secret (required).

Seed types: DOMAIN. Other seed types are skipped with a warning.

Rate limiting:
    Censys free tier: 2 requests/second — the collector self-limits via
    ``asyncio.sleep`` between API calls.

Distinct from ``scan_censys.py`` which searches the Censys *hosts* endpoint
for port/service discovery. This collector searches the *certificates*
endpoint for CT-based subdomain enumeration.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx

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
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

# === API configuration ========================================================
_CENSYS_BASE = "https://search.censys.io/api/v2"
_CERTS_SEARCH_URL = f"{_CENSYS_BASE}/certificates/search"

# Rate limit: 2 requests/second -> 0.5s between calls.
_REQUEST_INTERVAL = 0.5


@register_collector
class CensysCertCollector(Collector):
    """Certificate Transparency collector using Censys Certificates API v2."""

    collector_id: str = "ct-censys"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = True

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        id_cred = self.config.credentials.get("censys_api_id")
        secret_cred = self.config.credentials.get("censys_api_secret")
        self._api_id: str | None = id_cred.secret_value if id_cred else None
        self._api_secret: str | None = secret_cred.secret_value if secret_cred else None

    # === expand ===============================================================
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query Censys certificates for CT-based subdomain discovery."""
        if seed.seed_type != SeedType.DOMAIN:
            if seed.seed_type not in {SeedType.IP, SeedType.ASN, SeedType.CIDR}:
                logger.warning(
                    "ct-censys: skipping unsupported seed type %s (value=%r)",
                    seed.seed_type,
                    seed.value,
                )
            return

        if not self._api_id or not self._api_secret:
            logger.warning(
                "ct-censys: credentials not configured — skipping seed %r",
                seed.value,
            )
            return

        domain = seed.value.strip()
        async for obs in self._search_certificates(domain):
            yield obs

    # === Certificate search ===================================================
    async def _search_certificates(self, domain: str) -> AsyncIterator[Observation]:
        """Search Censys for certificates with SANs matching a domain."""
        query = f"parsed.names: {domain}"

        try:
            data = await self._api_get(
                _CERTS_SEARCH_URL,
                params={"q": query, "per_page": "100"},
            )
        except CollectorError as exc:
            logger.warning(
                "ct-censys: certificate search failed for %r: %s", domain, exc
            )
            return

        hits = data.get("result", {}).get("hits", [])
        if not hits:
            return

        # Extract unique subdomains from all certificate SANs.
        seen_domains: set[str] = set()

        for cert in hits:
            fingerprint = cert.get("fingerprint_sha256", "")
            names = cert.get("parsed", {}).get("names", [])
            issuer_dn = (
                cert.get("parsed", {})
                .get("issuer_dn", "")
            )
            subject_dn = (
                cert.get("parsed", {})
                .get("subject_dn", "")
            )
            validity = cert.get("parsed", {}).get("validity", {})
            not_before = validity.get("start", "")
            not_after = validity.get("end", "")

            # Emit per-certificate CT_LOG_ENTRY observation.
            sanitized_names: list[str] = []
            for name in names:
                name_lower = name.strip().lower()
                if not name_lower:
                    continue
                sanitized_names.append(name_lower)

            if fingerprint or sanitized_names:
                yield Observation(
                    collector_id=self.collector_id,
                    collector_version=self.collector_version,
                    tenant_id=self.config.tenant_id,
                    observation_type=ObservationType.CT_LOG_ENTRY,
                    subject=ObservationSubject(
                        identifier_type=IdentifierType.DOMAIN,
                        identifier_value=domain.lower(),
                    ),
                    observed_at=datetime.now(tz=UTC),
                    structured_payload={
                        "source": "censys_certificates",
                        "_collector_id": self.collector_id,
                        "fingerprint_sha256": fingerprint,
                        "issuer_dn": issuer_dn,
                        "subject_dn": subject_dn,
                        "sans": sanitized_names,
                        "not_before": not_before,
                        "not_after": not_after,
                        "search_domain": domain,
                    },
                )

            # Track unique non-wildcard subdomains for summary.
            for name_lower in sanitized_names:
                if "." in name_lower and not name_lower.startswith("*"):
                    seen_domains.add(name_lower)

        # Log discovery summary.
        if seen_domains:
            logger.info(
                "ct-censys: discovered %d unique subdomains for %r from %d certs",
                len(seen_domains),
                domain,
                len(hits),
            )

        await asyncio.sleep(_REQUEST_INTERVAL)

    # === HTTP helper ==========================================================
    async def _api_get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Issue a GET against the Censys API with Basic auth."""
        async with httpx.AsyncClient(
            timeout=self.config.request_timeout_seconds,
            headers={"User-Agent": self.config.user_agent},
            auth=(self._api_id or "", self._api_secret or ""),
        ) as client:
            try:
                resp = await client.get(url, params=params)
            except httpx.HTTPError as exc:
                msg = f"Censys certificates request failed: {exc}"
                raise CollectorError(msg) from exc

            if resp.status_code == 429:  # noqa: PLR2004
                msg = "Censys rate limit exceeded"
                raise CollectorError(msg)

            if resp.status_code == 401:  # noqa: PLR2004
                msg = "Censys authentication failed (401)"
                raise CollectorError(msg)

            if resp.status_code == 403:  # noqa: PLR2004
                msg = "Censys authentication failed (403)"
                raise CollectorError(msg)

            if resp.status_code != 200:  # noqa: PLR2004
                msg = f"Censys returned HTTP {resp.status_code}"
                raise CollectorError(msg)

            try:
                data: dict[str, Any] = resp.json()
            except Exception as exc:
                msg = "Censys returned malformed JSON"
                raise CollectorError(msg) from exc

        return data

    # === health_check =========================================================
    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe against the Censys certificates API."""
        start = time.monotonic()

        if not self._api_id or not self._api_secret:
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                latency_ms=0.0,
                error_message="Censys credentials not configured",
            )

        try:
            await self._api_get(
                _CERTS_SEARCH_URL,
                params={"q": "parsed.names: example.com", "per_page": "1"},
            )
        except CollectorError as exc:
            latency = (time.monotonic() - start) * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                latency_ms=latency,
                error_message=str(exc),
            )

        latency = (time.monotonic() - start) * 1000.0
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=datetime.now(tz=UTC),
            latency_ms=latency,
        )


__all__ = [
    "CensysCertCollector",
]

"""Internet-wide scan collector — Censys Search API v2 (Tier 1, passive).

Queries the Censys Search API v2 for host data associated with an IP address
or domain. Returns observations about open ports, service names, TLS
certificates, banners, and OS fingerprints discovered by Censys's
internet-wide scanning infrastructure.

Credential slots:
    ``censys_api_id``     — Censys API ID (required).
    ``censys_api_secret`` — Censys API secret (required).

Both must be present for the collector to operate. If either is missing,
``expand`` yields nothing and logs a warning.

Seed types: DOMAIN, IP. Other seed types are skipped silently.

Rate limiting:
    Censys free tier: 2 requests/second — the collector self-limits via
    ``asyncio.sleep`` between API calls.

Censys API v2 endpoints:
    GET /v2/hosts/{ip}                   — host detail lookup
    GET /v2/hosts/search?q=...           — search by TLS certificate name
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

# === API base URL =============================================================
_CENSYS_BASE = "https://search.censys.io/api/v2"

# Rate limit: 2 requests/second → 0.5s between calls.
_REQUEST_INTERVAL = 0.5


@register_collector
class CensysScanCollector(Collector):
    """Tier-1 internet-wide scan collector (Censys Search API v2)."""

    collector_id: str = "scan-censys"
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
        """Query Censys for host and certificate data."""
        if seed.seed_type not in {SeedType.DOMAIN, SeedType.IP}:
            return

        if not self._api_id or not self._api_secret:
            logger.warning(
                "scan-censys: credentials not configured — skipping seed %r",
                seed.value,
            )
            return

        value = seed.value.strip()

        if seed.seed_type == SeedType.IP:
            async for obs in self._query_host(value):
                yield obs
        else:
            # DOMAIN seed: search for hosts with TLS certs matching the domain.
            async for obs in self._search_domain(value):
                yield obs

    # === Domain search ========================================================
    async def _search_domain(self, domain: str) -> AsyncIterator[Observation]:
        """Search Censys for hosts with TLS certificates matching a domain."""
        query = f"services.tls.certificates.leaf_data.names: {domain}"
        url = f"{_CENSYS_BASE}/hosts/search"

        try:
            data = await self._api_get(url, params={"q": query, "per_page": "100"})
        except CollectorError as exc:
            logger.warning("scan-censys: domain search failed for %r: %s", domain, exc)
            return

        for hit in data.get("result", {}).get("hits", []):
            ip = hit.get("ip", "")
            if not ip:
                continue

            services = hit.get("services", [])
            for svc in services:
                yield self._service_to_observation(
                    ip=ip,
                    service=svc,
                    subject_type=IdentifierType.DOMAIN,
                    subject_value=domain.lower(),
                    source_url=f"{_CENSYS_BASE}/hosts/search?q={query}",
                    extra={"search_domain": domain, "host_ip": ip},
                )

            # Also yield per-host summary observation.
            yield self._host_summary_observation(
                hit,
                subject_type=IdentifierType.DOMAIN,
                subject_value=domain.lower(),
                source_url=f"{_CENSYS_BASE}/hosts/search?q={query}",
            )

        await asyncio.sleep(_REQUEST_INTERVAL)

    # === Host lookup ==========================================================
    async def _query_host(self, ip: str) -> AsyncIterator[Observation]:
        """Direct host lookup by IP."""
        url = f"{_CENSYS_BASE}/hosts/{ip}"

        try:
            data = await self._api_get(url)
        except CollectorError as exc:
            logger.warning("scan-censys: host lookup failed for %r: %s", ip, exc)
            return

        result = data.get("result", {})
        services = result.get("services", [])

        for svc in services:
            yield self._service_to_observation(
                ip=ip,
                service=svc,
                subject_type=IdentifierType.IP,
                subject_value=ip,
                source_url=f"{_CENSYS_BASE}/hosts/{ip}",
            )

        # Host summary observation.
        if result:
            yield self._host_summary_observation(
                result,
                subject_type=IdentifierType.IP,
                subject_value=ip,
                source_url=f"{_CENSYS_BASE}/hosts/{ip}",
            )

        await asyncio.sleep(_REQUEST_INTERVAL)

    # === Observation builders =================================================
    def _service_to_observation(
        self,
        *,
        ip: str,
        service: dict[str, Any],
        subject_type: IdentifierType,
        subject_value: str,
        source_url: str,
        extra: dict[str, Any] | None = None,
    ) -> Observation:
        """Convert a Censys service entry to a PORT_SCAN_RESULT observation."""
        port = service.get("port", 0)
        service_name = service.get("service_name", "UNKNOWN")
        transport = service.get("transport_protocol", "TCP")
        banner = service.get("banner", "")

        tls_info: dict[str, Any] = {}
        tls = service.get("tls", {})
        if tls:
            cert = tls.get("certificates", {}).get("leaf_data", {})
            tls_info = {
                "subject_dn": cert.get("subject_dn", ""),
                "issuer_dn": cert.get("issuer_dn", ""),
                "names": cert.get("names", []),
                "fingerprint": cert.get("fingerprint", ""),
            }

        payload: dict[str, Any] = {
            "source": "censys",
            "_collector_id": self.collector_id,
            "source_url": source_url,
            "ip": ip,
            "port": port,
            "service_name": service_name,
            "transport_protocol": transport,
            "banner": banner,
        }
        if tls_info:
            payload["tls"] = tls_info
        if extra:
            payload.update(extra)

        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.PORT_SCAN_RESULT,
            subject=ObservationSubject(
                identifier_type=subject_type,
                identifier_value=subject_value,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload=payload,
        )

    def _host_summary_observation(
        self,
        host_data: dict[str, Any],
        *,
        subject_type: IdentifierType,
        subject_value: str,
        source_url: str,
    ) -> Observation:
        """Create a SCANNER_HOST observation with host-level summary."""
        ip = host_data.get("ip", "")
        os_info = host_data.get("operating_system", {})
        location = host_data.get("location", {})
        autonomous_system = host_data.get("autonomous_system", {})
        last_updated = host_data.get("last_updated_at", "")

        services = host_data.get("services", [])
        ports = sorted({s.get("port", 0) for s in services})

        payload: dict[str, Any] = {
            "source": "censys",
            "_collector_id": self.collector_id,
            "source_url": source_url,
            "ip": ip,
            "ports": ports,
            "os": os_info if isinstance(os_info, dict) else {"product": str(os_info)},
            "location": {
                "country": location.get("country", ""),
                "city": location.get("city", ""),
            },
            "autonomous_system": {
                "asn": autonomous_system.get("asn", 0),
                "name": autonomous_system.get("name", ""),
                "bgp_prefix": autonomous_system.get("bgp_prefix", ""),
            },
            "last_updated_at": last_updated,
        }

        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.SCANNER_HOST,
            subject=ObservationSubject(
                identifier_type=subject_type,
                identifier_value=subject_value,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload=payload,
        )

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
                msg = f"Censys request failed: {exc}"
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
        """Quick reachability probe against the Censys API."""
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
            # Use a minimal search as a connectivity check.
            await self._api_get(
                f"{_CENSYS_BASE}/hosts/search",
                params={"q": "ip: 1.1.1.1", "per_page": "1"},
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
    "CensysScanCollector",
]

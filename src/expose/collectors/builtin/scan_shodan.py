"""Internet-wide scan collector — Shodan API (Tier 1, passive).

Queries the Shodan API for host data associated with an IP address or domain.
Returns observations about open ports, banners, known vulnerabilities (CVEs),
hostnames, OS, and ISP information discovered by Shodan's internet-wide
scanning infrastructure.

Credential slots:
    ``shodan_api_key`` — Shodan API key (required).

If the key is absent, ``expand`` yields nothing and logs a warning.

Seed types: DOMAIN, IP. Other seed types are skipped silently.

Rate limiting:
    Shodan free tier: 1 request/second — the collector self-limits via
    ``asyncio.sleep`` between API calls.

Shodan API endpoints:
    GET /shodan/host/{ip}?key={key}              — host detail lookup
    GET /dns/resolve?hostnames={domain}&key={key} — domain-to-IP resolution
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
_SHODAN_BASE = "https://api.shodan.io"

# Rate limit: 1 request/second.
_REQUEST_INTERVAL = 1.0


@register_collector
class ShodanScanCollector(Collector):
    """Tier-1 internet-wide scan collector (Shodan API)."""

    collector_id: str = "scan-shodan"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = True

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        api_cred = self.config.credentials.get("shodan_api_key")
        self._api_key: str | None = api_cred.secret_value if api_cred else None

    # === expand ===============================================================
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query Shodan for host and vulnerability data."""
        if seed.seed_type not in {SeedType.DOMAIN, SeedType.IP}:
            return

        if not self._api_key:
            logger.warning(
                "scan-shodan: API key not configured — skipping seed %r",
                seed.value,
            )
            return

        value = seed.value.strip()

        if seed.seed_type == SeedType.IP:
            async for obs in self._query_host(
                value,
                subject_type=IdentifierType.IP,
                subject_value=value,
            ):
                yield obs
        else:
            # DOMAIN seed: resolve domain to IP first, then host lookup.
            async for obs in self._query_domain(value):
                yield obs

    # === Domain resolution + host lookup ======================================
    async def _query_domain(self, domain: str) -> AsyncIterator[Observation]:
        """Resolve domain via Shodan DNS, then look up each IP."""
        url = f"{_SHODAN_BASE}/dns/resolve"
        try:
            data = await self._api_get(url, params={"hostnames": domain})
        except CollectorError as exc:
            logger.warning("scan-shodan: DNS resolve failed for %r: %s", domain, exc)
            return

        ip = data.get(domain)
        if not ip:
            logger.warning("scan-shodan: no IP resolved for domain %r", domain)
            return

        await asyncio.sleep(_REQUEST_INTERVAL)

        async for obs in self._query_host(
            ip,
            subject_type=IdentifierType.DOMAIN,
            subject_value=domain.lower(),
            resolved_ip=ip,
        ):
            yield obs

    # === Host lookup ==========================================================
    async def _query_host(
        self,
        ip: str,
        *,
        subject_type: IdentifierType,
        subject_value: str,
        resolved_ip: str | None = None,
    ) -> AsyncIterator[Observation]:
        """Direct host lookup by IP."""
        url = f"{_SHODAN_BASE}/shodan/host/{ip}"

        try:
            data = await self._api_get(url)
        except CollectorError as exc:
            logger.warning("scan-shodan: host lookup failed for %r: %s", ip, exc)
            return

        source_url = f"{_SHODAN_BASE}/shodan/host/{ip}"

        # Yield per-service observations.
        for svc in data.get("data", []):
            yield self._service_to_observation(
                ip=ip,
                service=svc,
                subject_type=subject_type,
                subject_value=subject_value,
                source_url=source_url,
                resolved_ip=resolved_ip,
            )

        # Host summary observation.
        yield self._host_summary_observation(
            data,
            ip=ip,
            subject_type=subject_type,
            subject_value=subject_value,
            source_url=source_url,
            resolved_ip=resolved_ip,
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
        resolved_ip: str | None = None,
    ) -> Observation:
        """Convert a Shodan service (banner) entry to a PORT_SCAN_RESULT observation."""
        port = service.get("port", 0)
        transport = service.get("transport", "tcp")
        product = service.get("product", "")
        banner = service.get("data", "")
        module = service.get("_shodan", {}).get("module", "")
        vulns = list(service.get("vulns", {}).keys()) if service.get("vulns") else []

        ssl_info: dict[str, Any] = {}
        ssl = service.get("ssl", {})
        if ssl:
            cert = ssl.get("cert", {})
            ssl_info = {
                "subject": cert.get("subject", {}),
                "issuer": cert.get("issuer", {}),
                "serial": cert.get("serial"),
                "fingerprint": cert.get("fingerprint", {}),
                "expires": cert.get("expires", ""),
            }

        payload: dict[str, Any] = {
            "source": "shodan",
            "_collector_id": self.collector_id,
            "source_url": source_url,
            "ip": ip,
            "port": port,
            "transport": transport,
            "product": product,
            "banner": banner,
            "module": module,
            "vulns": vulns,
        }
        if ssl_info:
            payload["ssl"] = ssl_info
        if resolved_ip:
            payload["resolved_ip"] = resolved_ip

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
        ip: str,
        subject_type: IdentifierType,
        subject_value: str,
        source_url: str,
        resolved_ip: str | None = None,
    ) -> Observation:
        """Create a SCANNER_HOST observation with host-level summary."""
        os_val = host_data.get("os", "")
        isp = host_data.get("isp", "")
        org = host_data.get("org", "")
        hostnames = host_data.get("hostnames", [])
        vulns_all = host_data.get("vulns", [])
        last_update = host_data.get("last_update", "")

        ports = sorted(host_data.get("ports", []))

        payload: dict[str, Any] = {
            "source": "shodan",
            "_collector_id": self.collector_id,
            "source_url": source_url,
            "ip": ip,
            "ports": ports,
            "os": os_val,
            "isp": isp,
            "org": org,
            "hostnames": hostnames,
            "vulns": vulns_all,
            "last_update": last_update,
        }
        if resolved_ip:
            payload["resolved_ip"] = resolved_ip

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
        """Issue a GET against the Shodan API with API key as query param."""
        request_params = dict(params or {})
        request_params["key"] = self._api_key or ""

        async with httpx.AsyncClient(
            timeout=self.config.request_timeout_seconds,
            headers={"User-Agent": self.config.user_agent},
        ) as client:
            try:
                resp = await client.get(url, params=request_params)
            except httpx.HTTPError as exc:
                msg = f"Shodan request failed: {exc}"
                raise CollectorError(msg) from exc

            if resp.status_code == 429:  # noqa: PLR2004
                msg = "Shodan rate limit exceeded"
                raise CollectorError(msg)

            if resp.status_code == 401:  # noqa: PLR2004
                msg = "Shodan authentication failed (401)"
                raise CollectorError(msg)

            if resp.status_code == 403:  # noqa: PLR2004
                msg = "Shodan authentication failed (403)"
                raise CollectorError(msg)

            if resp.status_code != 200:  # noqa: PLR2004
                msg = f"Shodan returned HTTP {resp.status_code}"
                raise CollectorError(msg)

            try:
                data: dict[str, Any] = resp.json()
            except Exception as exc:
                msg = "Shodan returned malformed JSON"
                raise CollectorError(msg) from exc

        return data

    # === health_check =========================================================
    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe against the Shodan API."""
        start = time.monotonic()

        if not self._api_key:
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                latency_ms=0.0,
                error_message="Shodan API key not configured",
            )

        try:
            await self._api_get(f"{_SHODAN_BASE}/api-info")
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
    "ShodanScanCollector",
]

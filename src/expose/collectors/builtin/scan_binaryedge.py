"""Internet-wide scan collector — BinaryEdge API v2 (Tier 1, passive).

Queries the BinaryEdge API v2 for host data associated with an IP address or
domain. Returns observations about open ports, services, certificates, and
torrent activity discovered by BinaryEdge's internet-wide scanning
infrastructure.

Credential slots:
    ``binaryedge_api_key`` — BinaryEdge API key (required).

If the key is absent, ``expand`` yields nothing and logs a warning.

Seed types: DOMAIN, IP. Other seed types are skipped silently.

Rate limiting:
    BinaryEdge free tier: 1 request/second — the collector self-limits via
    ``asyncio.sleep`` between API calls.

BinaryEdge API v2 endpoints:
    GET /v2/query/ip/{ip}                     — IP host data
    GET /v2/query/domains/subdomain/{domain}  — subdomain enumeration
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
_BE_BASE = "https://api.binaryedge.io/v2"

# Rate limit: 1 request/second.
_REQUEST_INTERVAL = 1.0


@register_collector
class BinaryEdgeScanCollector(Collector):
    """Tier-1 internet-wide scan collector (BinaryEdge API v2)."""

    collector_id: str = "scan-binaryedge"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = True

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        api_cred = self.config.credentials.get("binaryedge_api_key")
        self._api_key: str | None = api_cred.secret_value if api_cred else None

    # === expand ===============================================================
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query BinaryEdge for host and subdomain data."""
        if seed.seed_type not in {SeedType.DOMAIN, SeedType.IP}:
            return

        if not self._api_key:
            logger.warning(
                "scan-binaryedge: API key not configured — skipping seed %r",
                seed.value,
            )
            return

        value = seed.value.strip()

        if seed.seed_type == SeedType.IP:
            async for obs in self._query_ip(value):
                yield obs
        else:
            async for obs in self._query_domain(value):
                yield obs

    # === Domain subdomain enumeration =========================================
    async def _query_domain(self, domain: str) -> AsyncIterator[Observation]:
        """Enumerate subdomains and query each discovered IP."""
        url = f"{_BE_BASE}/query/domains/subdomain/{domain}"

        try:
            data = await self._api_get(url)
        except CollectorError as exc:
            logger.warning("scan-binaryedge: subdomain query failed for %r: %s", domain, exc)
            return

        # Yield subdomain observations.
        subdomains = data.get("events", [])
        for sub in subdomains:
            if not sub:
                continue
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.DNS_RECORD,
                subject=ObservationSubject(
                    identifier_type=IdentifierType.SUBDOMAIN,
                    identifier_value=sub.lower(),
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "source": "binaryedge",
                    "_collector_id": self.collector_id,
                    "source_url": url,
                    "subdomain": sub,
                    "parent_domain": domain.lower(),
                    "seed_expansion": True,
                },
            )

        await asyncio.sleep(_REQUEST_INTERVAL)

    # === IP host query ========================================================
    async def _query_ip(self, ip: str) -> AsyncIterator[Observation]:
        """Query BinaryEdge for host data by IP."""
        url = f"{_BE_BASE}/query/ip/{ip}"

        try:
            data = await self._api_get(url)
        except CollectorError as exc:
            logger.warning("scan-binaryedge: IP query failed for %r: %s", ip, exc)
            return

        source_url = f"{_BE_BASE}/query/ip/{ip}"

        # Process scan events.
        for event in data.get("events", []):
            for result in event.get("results", []):
                yield self._result_to_observation(
                    ip=ip,
                    result=result,
                    event=event,
                    source_url=source_url,
                )

        # Host summary observation.
        yield self._host_summary_observation(
            data,
            ip=ip,
            source_url=source_url,
        )

        await asyncio.sleep(_REQUEST_INTERVAL)

    # === Observation builders =================================================
    def _result_to_observation(
        self,
        *,
        ip: str,
        result: dict[str, Any],
        event: dict[str, Any],
        source_url: str,
    ) -> Observation:
        """Convert a BinaryEdge scan result to a PORT_SCAN_RESULT observation."""
        port = event.get("port", 0)
        target_info = result.get("target", {})
        origin_info = result.get("origin", {})
        result_data = result.get("result", {}).get("data", {})

        service_name = result_data.get("service", {}).get("name", "")
        banner = result_data.get("service", {}).get("banner", "")

        cert_info: dict[str, Any] = {}
        cert = result_data.get("cert_info", {})
        if cert:
            cert_info = {
                "subject": cert.get("subject", {}),
                "issuer": cert.get("issuer", {}),
                "not_before": cert.get("not_before", ""),
                "not_after": cert.get("not_after", ""),
            }

        # Check for torrent activity.
        torrent = result_data.get("torrents", [])

        payload: dict[str, Any] = {
            "source": "binaryedge",
            "_collector_id": self.collector_id,
            "source_url": source_url,
            "ip": ip,
            "port": port,
            "service_name": service_name,
            "banner": banner,
            "target": {
                "ip": target_info.get("ip", ip),
                "port": target_info.get("port", port),
                "protocol": target_info.get("protocol", ""),
            },
            "origin": {
                "type": origin_info.get("type", ""),
                "module": origin_info.get("module", ""),
                "country": origin_info.get("country", ""),
            },
        }
        if cert_info:
            payload["cert_info"] = cert_info
        if torrent:
            payload["torrents"] = torrent

        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.PORT_SCAN_RESULT,
            subject=ObservationSubject(
                identifier_type=IdentifierType.IP,
                identifier_value=ip,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload=payload,
        )

    def _host_summary_observation(
        self,
        host_data: dict[str, Any],
        *,
        ip: str,
        source_url: str,
    ) -> Observation:
        """Create a SCANNER_HOST observation with host-level summary."""
        events = host_data.get("events", [])

        # Collect unique ports from all events.
        ports: list[int] = sorted({e.get("port", 0) for e in events if e.get("port")})

        payload: dict[str, Any] = {
            "source": "binaryedge",
            "_collector_id": self.collector_id,
            "source_url": source_url,
            "ip": ip,
            "ports": ports,
            "total_events": len(events),
        }

        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.SCANNER_HOST,
            subject=ObservationSubject(
                identifier_type=IdentifierType.IP,
                identifier_value=ip,
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
        """Issue a GET against the BinaryEdge API with X-Key auth header."""
        async with httpx.AsyncClient(
            timeout=self.config.request_timeout_seconds,
            headers={
                "User-Agent": self.config.user_agent,
                "X-Key": self._api_key or "",
            },
        ) as client:
            try:
                resp = await client.get(url, params=params)
            except httpx.HTTPError as exc:
                msg = f"BinaryEdge request failed: {exc}"
                raise CollectorError(msg) from exc

            if resp.status_code == 429:  # noqa: PLR2004
                msg = "BinaryEdge rate limit exceeded"
                raise CollectorError(msg)

            if resp.status_code == 401:  # noqa: PLR2004
                msg = "BinaryEdge authentication failed (401)"
                raise CollectorError(msg)

            if resp.status_code == 403:  # noqa: PLR2004
                msg = "BinaryEdge authentication failed (403)"
                raise CollectorError(msg)

            if resp.status_code != 200:  # noqa: PLR2004
                msg = f"BinaryEdge returned HTTP {resp.status_code}"
                raise CollectorError(msg)

            try:
                data: dict[str, Any] = resp.json()
            except Exception as exc:
                msg = "BinaryEdge returned malformed JSON"
                raise CollectorError(msg) from exc

        return data

    # === health_check =========================================================
    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe against the BinaryEdge API."""
        start = time.monotonic()

        if not self._api_key:
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                latency_ms=0.0,
                error_message="BinaryEdge API key not configured",
            )

        try:
            await self._api_get(f"{_BE_BASE}/user/subscription")
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
    "BinaryEdgeScanCollector",
]

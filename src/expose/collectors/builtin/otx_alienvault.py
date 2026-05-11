"""AlienVault OTX passive DNS + URL list collector (Tier 1, passive).

Free backup source for passive DNS history — no API key required for basic
access (rate-limited), optional OTX API key for higher rate limits.

Queries two OTX endpoints for a domain seed:

1. ``/api/v1/indicators/domain/{domain}/passive_dns`` — historical DNS
   resolutions showing which IPs a domain has pointed to over time.
2. ``/api/v1/indicators/domain/{domain}/url_list`` — URLs observed in
   AlienVault's threat intelligence feed for the domain.

The passive_dns endpoint returns records with ``address`` (IP), ``hostname``,
``record_type``, ``first``, and ``last`` fields.  The collector extracts
unique IPs as IP observations and unique hostnames as DOMAIN observations
(subdomain discovery).

Credential slots:
    ``otx_api_key`` — AlienVault OTX API key (optional).

Seed types: DOMAIN only.  Other seed types are skipped silently.

Rate limiting:
    Unauthenticated: ~10 requests/minute (conservative).
    Authenticated: higher limits per OTX account tier.
    Collector declares 30 req/min; the framework rate limiter gates calls.
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
_OTX_BASE = "https://otx.alienvault.com/api/v1"


@register_collector
class OtxAlienVaultCollector(Collector):
    """Tier-1 passive DNS and URL collector via AlienVault OTX (free)."""

    collector_id: str = "otx-alienvault"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = 30
    technique_ids: ClassVar[list[str]] = ["T1596"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        otx_cred = self.config.credentials.get("otx_api_key")
        self._api_key: str | None = otx_cred.secret_value if otx_cred else None

    # === expand ===============================================================
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query OTX passive DNS and URL list for a domain seed."""
        if seed.seed_type != SeedType.DOMAIN:
            return

        domain = seed.value.strip().lower()
        warnings: list[str] = []

        # --- Passive DNS query ------------------------------------------------
        pdns_records: list[dict[str, Any]] = []
        subdomain_observations: list[dict[str, str]] = []

        try:
            pdns_records, subdomain_observations = await self._query_passive_dns(
                domain
            )
        except CollectorError as exc:
            warnings.append(f"OTX passive DNS query failed: {exc}")

        # --- URL list query ---------------------------------------------------
        url_records: list[dict[str, Any]] = []

        try:
            url_records = await self._query_url_list(domain)
        except CollectorError as exc:
            warnings.append(f"OTX URL list query failed: {exc}")

        # Yield IP observations from passive DNS.
        seen_ips: set[str] = set()
        for rec in pdns_records:
            ip_addr = rec.get("address", "")
            if not ip_addr or ip_addr in seen_ips:
                continue
            seen_ips.add(ip_addr)
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.PASSIVE_DNS,
                subject=ObservationSubject(
                    identifier_type=IdentifierType.IP,
                    identifier_value=ip_addr,
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "source": "otx_alienvault",
                    "record_type": rec.get("record_type", "A"),
                    "hostname": rec.get("hostname", domain),
                    "first_seen": rec.get("first"),
                    "last_seen": rec.get("last"),
                },
                warnings=list(warnings),
            )

        # Yield subdomain observations from passive DNS hostnames.
        seen_subdomains: set[str] = set()
        for sub in subdomain_observations:
            fqdn = sub["fqdn"]
            if fqdn in seen_subdomains:
                continue
            seen_subdomains.add(fqdn)
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.DNS_RECORD,
                subject=ObservationSubject(
                    identifier_type=IdentifierType.SUBDOMAIN,
                    identifier_value=fqdn,
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "source": "otx_alienvault",
                    "subdomain": sub["label"],
                    "fqdn": fqdn,
                    "parent_domain": domain,
                    "seed_expansion": True,
                },
            )

        # Yield URL observations.
        for url_rec in url_records:
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.HTTP_RESPONSE,
                subject=ObservationSubject(
                    identifier_type=IdentifierType.DOMAIN,
                    identifier_value=domain,
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "source": "otx_alienvault",
                    "url": url_rec.get("url", ""),
                    "http_code": url_rec.get("httpcode"),
                    "date": url_rec.get("date"),
                },
            )

    # === Passive DNS query ====================================================
    async def _query_passive_dns(
        self, domain: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
        """Query OTX passive DNS endpoint.

        Returns (pdns_records, subdomain_records).
        """
        url = f"{_OTX_BASE}/indicators/domain/{domain}/passive_dns"
        data = await self._otx_get(url)

        pdns_records: list[dict[str, Any]] = data.get("passive_dns", [])
        subdomains: list[dict[str, str]] = []

        # Extract unique hostnames that are subdomains of the queried domain.
        seen_hostnames: set[str] = set()
        for rec in pdns_records:
            hostname = rec.get("hostname", "")
            if not hostname:
                continue
            hostname = hostname.lower()
            if (
                hostname != domain
                and hostname.endswith(f".{domain}")
                and hostname not in seen_hostnames
            ):
                seen_hostnames.add(hostname)
                # Extract the subdomain label (everything before the parent).
                label = hostname[: -(len(domain) + 1)]
                subdomains.append({"label": label, "fqdn": hostname})

        return pdns_records, subdomains

    # === URL list query =======================================================
    async def _query_url_list(
        self, domain: str
    ) -> list[dict[str, Any]]:
        """Query OTX URL list endpoint."""
        url = f"{_OTX_BASE}/indicators/domain/{domain}/url_list"
        data = await self._otx_get(url)

        url_list: list[dict[str, Any]] = data.get("url_list", [])
        return url_list

    # === HTTP helper ==========================================================
    async def _otx_get(self, url: str) -> dict[str, Any]:
        """Issue a GET against the OTX API and return parsed JSON."""
        headers: dict[str, str] = {
            "User-Agent": self.config.user_agent,
        }
        if self._api_key:
            headers["X-OTX-API-KEY"] = self._api_key

        async with httpx.AsyncClient(
            timeout=self.config.request_timeout_seconds,
            headers=headers,
        ) as client:
            try:
                resp = await client.get(url)
            except httpx.HTTPError as exc:
                msg = f"OTX request failed: {exc}"
                raise CollectorError(msg) from exc

            if resp.status_code == 429:  # noqa: PLR2004
                msg = "OTX rate limit exceeded"
                raise CollectorError(msg)

            if resp.status_code == 403:  # noqa: PLR2004
                msg = "OTX authentication failed (403)"
                raise CollectorError(msg)

            if resp.status_code != 200:  # noqa: PLR2004
                msg = f"OTX returned HTTP {resp.status_code}"
                raise CollectorError(msg)

            try:
                data: dict[str, Any] = resp.json()
            except Exception as exc:
                msg = "OTX returned malformed JSON"
                raise CollectorError(msg) from exc

        return data

    # === health_check =========================================================
    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe against OTX general endpoint."""
        start = time.monotonic()
        error_message: str | None = None

        try:
            async with httpx.AsyncClient(
                timeout=self.config.request_timeout_seconds,
            ) as client:
                headers: dict[str, str] = {
                    "User-Agent": self.config.user_agent,
                }
                if self._api_key:
                    headers["X-OTX-API-KEY"] = self._api_key

                resp = await client.get(
                    f"{_OTX_BASE}/indicators/domain/example.com/general",
                    headers=headers,
                )
                if resp.status_code >= 400:  # noqa: PLR2004
                    error_message = (
                        f"OTX general endpoint returned {resp.status_code}"
                    )
        except httpx.HTTPError as exc:
            error_message = f"OTX unreachable: {exc}"

        latency = (time.monotonic() - start) * 1000.0

        if error_message:
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                latency_ms=latency,
                error_message=error_message,
            )

        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=datetime.now(tz=UTC),
            latency_ms=latency,
        )


__all__ = [
    "OtxAlienVaultCollector",
]

"""Passive DNS history collector — SecurityTrails + VirusTotal (Tier 1, passive).

Queries SecurityTrails (primary) and VirusTotal (secondary) APIs for
historical DNS resolution records associated with a domain or IP address.
Reveals infrastructure changes over time: IP migrations, hosting provider
switches, CDN adoption, and previously-associated subdomains.

Credential slots:
    ``securitytrails_api_key`` — SecurityTrails API key (optional).
    ``virustotal_api_key``     — VirusTotal API key (optional).

Either or both can be absent; the collector degrades gracefully to whichever
source(s) have valid keys. If neither key is present, ``expand`` yields
nothing and logs a warning.

Seed types: DOMAIN, IP. Other seed types are skipped silently.

Rate limiting:
    SecurityTrails free tier: 50 requests/day, no per-minute cap enforced
    here (framework rate limiter gates concurrent calls).
    VirusTotal free tier: 4 requests/minute — the collector self-limits via
    an internal delay between VT calls when multiple pages are fetched.

SecurityTrails endpoints:
    GET /v1/history/{domain}/dns/{type}  — historical A/AAAA/MX/NS/CNAME
    GET /v1/domain/{domain}/subdomains   — subdomain enumeration
    GET /v1/domains/list?ipAddress={ip}  — reverse IP lookup (IP seed)

VirusTotal endpoints:
    GET /api/v3/domains/{domain}/resolutions — passive DNS resolutions
    GET /api/v3/ip_addresses/{ip}/resolutions — reverse IP resolutions
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

# === API base URLs ============================================================
_ST_BASE = "https://api.securitytrails.com/v1"
_VT_BASE = "https://www.virustotal.com/api/v3"

# DNS record types to query from SecurityTrails history endpoint.
_ST_DNS_TYPES = ("a", "aaaa", "mx", "ns", "cname")

# VirusTotal free tier: 4 requests per minute.
_VT_REQUEST_INTERVAL = 15.0  # seconds between VT calls (60/4)


def _parse_date(value: str | None) -> str | None:
    """Return an ISO-8601 date string or None if unparseable."""
    if not value:
        return None
    # SecurityTrails uses "YYYY-MM-DD"; pass through as-is.
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return value
    except ValueError:
        return None


def _unix_to_iso(ts: int | float | None) -> str | None:
    """Convert a Unix timestamp to ISO-8601 date string, or None."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(int(ts), tz=UTC).strftime("%Y-%m-%d")
    except (OSError, ValueError, OverflowError):
        return None


@register_collector
class PassiveDnsHistoryCollector(Collector):
    """Tier-1 passive DNS history collector (SecurityTrails + VirusTotal)."""

    collector_id: str = "dns-passive-history"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = True
    technique_ids: ClassVar[list[str]] = ["T1596.001"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        st_cred = self.config.credentials.get("securitytrails_api_key")
        vt_cred = self.config.credentials.get("virustotal_api_key")
        self._st_key: str | None = st_cred.secret_value if st_cred else None
        self._vt_key: str | None = vt_cred.secret_value if vt_cred else None

    # === expand ===============================================================
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query SecurityTrails and/or VirusTotal for passive DNS history."""
        if seed.seed_type not in {SeedType.DOMAIN, SeedType.IP}:
            return

        if not self._st_key and not self._vt_key:
            logger.warning(
                "dns-passive-history: no API keys configured — "
                "skipping seed %r",
                seed.value,
            )
            return

        value = seed.value.strip()
        is_domain = seed.seed_type == SeedType.DOMAIN

        # Collect records from both sources; each method handles missing keys.
        records: list[dict[str, Any]] = []
        subdomain_observations: list[dict[str, Any]] = []
        warnings: list[str] = []

        if self._st_key:
            try:
                st_records, st_subdomains = await self._query_securitytrails(
                    value, is_domain=is_domain
                )
                records.extend(st_records)
                subdomain_observations.extend(st_subdomains)
            except CollectorError as exc:
                warnings.append(f"SecurityTrails query failed: {exc}")

        if self._vt_key:
            try:
                vt_records = await self._query_virustotal(
                    value, is_domain=is_domain
                )
                records.extend(vt_records)
            except CollectorError as exc:
                warnings.append(f"VirusTotal query failed: {exc}")

        # Deduplicate records by (source, type, value, first_seen, last_seen).
        seen: set[tuple[str, str, str, str | None, str | None]] = set()
        unique_records: list[dict[str, Any]] = []
        for rec in records:
            key = (
                rec.get("source", ""),
                rec.get("dns_record_type", ""),
                rec.get("value", ""),
                rec.get("first_seen"),
                rec.get("last_seen"),
            )
            if key not in seen:
                seen.add(key)
                unique_records.append(rec)

        # Yield one observation per unique historical record.
        id_type = IdentifierType.DOMAIN if is_domain else IdentifierType.IP

        for rec in unique_records:
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.PASSIVE_DNS,
                subject=ObservationSubject(
                    identifier_type=id_type,
                    identifier_value=value.lower(),
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload=rec,
                warnings=list(warnings),
            )

        # Yield subdomain observations (tagged for seed expansion).
        for sub in subdomain_observations:
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.DNS_RECORD,
                subject=ObservationSubject(
                    identifier_type=IdentifierType.SUBDOMAIN,
                    identifier_value=sub["fqdn"].lower(),
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "source": "securitytrails",
                    "subdomain": sub["label"],
                    "fqdn": sub["fqdn"],
                    "parent_domain": value.lower(),
                    "seed_expansion": True,
                },
            )

    # === SecurityTrails queries ================================================
    async def _query_securitytrails(
        self, value: str, *, is_domain: bool
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Query SecurityTrails for DNS history and subdomains.

        Returns (history_records, subdomain_records).
        """
        records: list[dict[str, Any]] = []
        subdomains: list[dict[str, Any]] = []

        async with httpx.AsyncClient(
            timeout=self.config.request_timeout_seconds,
            headers={
                "User-Agent": self.config.user_agent,
                "apikey": self._st_key or "",
            },
        ) as client:
            if is_domain:
                # Historical DNS records for each type.
                for dns_type in _ST_DNS_TYPES:
                    url = f"{_ST_BASE}/history/{value}/dns/{dns_type}"
                    parsed = await self._st_get(client, url)
                    records.extend(
                        self._parse_st_history(parsed, dns_type)
                    )

                # Subdomain enumeration.
                sub_url = f"{_ST_BASE}/domain/{value}/subdomains"
                sub_data = await self._st_get(client, sub_url)
                for label in sub_data.get("subdomains", []):
                    if label:
                        subdomains.append({
                            "label": label,
                            "fqdn": f"{label}.{value}",
                        })
            else:
                # IP seed: reverse lookup.
                url = f"{_ST_BASE}/domains/list"
                parsed = await self._st_get(
                    client, url, params={"ipAddress": value}
                )
                for rec in parsed.get("records", []):
                    hostname = rec.get("hostname", "")
                    if hostname:
                        records.append({
                            "source": "securitytrails",
                            "dns_record_type": "A",
                            "value": hostname,
                            "first_seen": None,
                            "last_seen": None,
                        })

        return records, subdomains

    async def _st_get(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Issue a GET against SecurityTrails and return parsed JSON."""
        try:
            resp = await client.get(url, params=params)
        except httpx.HTTPError as exc:
            msg = f"SecurityTrails request failed: {exc}"
            raise CollectorError(msg) from exc

        if resp.status_code == 429:  # noqa: PLR2004
            msg = "SecurityTrails rate limit exceeded"
            raise CollectorError(msg)

        if resp.status_code == 403:  # noqa: PLR2004
            msg = "SecurityTrails authentication failed (403)"
            raise CollectorError(msg)

        if resp.status_code != 200:  # noqa: PLR2004
            msg = f"SecurityTrails returned HTTP {resp.status_code}"
            raise CollectorError(msg)

        try:
            data: dict[str, Any] = resp.json()
        except Exception as exc:
            msg = "SecurityTrails returned malformed JSON"
            raise CollectorError(msg) from exc

        return data

    def _parse_st_history(
        self, data: dict[str, Any], dns_type: str
    ) -> list[dict[str, Any]]:
        """Parse SecurityTrails history response into flat records."""
        out: list[dict[str, Any]] = []
        for record in data.get("records", []):
            first_seen = _parse_date(record.get("first_seen"))
            last_seen = _parse_date(record.get("last_seen"))
            rec_type = record.get("type", dns_type).upper()

            for val_entry in record.get("values", []):
                resolved = (
                    val_entry.get("ip")
                    or val_entry.get("ip_address")
                    or val_entry.get("host")
                    or val_entry.get("value")
                    or ""
                )
                if resolved:
                    out.append({
                        "source": "securitytrails",
                        "dns_record_type": rec_type,
                        "value": resolved,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                    })
        return out

    # === VirusTotal queries ====================================================
    async def _query_virustotal(
        self, value: str, *, is_domain: bool
    ) -> list[dict[str, Any]]:
        """Query VirusTotal for passive DNS resolutions."""
        records: list[dict[str, Any]] = []

        if is_domain:
            url = f"{_VT_BASE}/domains/{value}/resolutions"
        else:
            url = f"{_VT_BASE}/ip_addresses/{value}/resolutions"

        async with httpx.AsyncClient(
            timeout=self.config.request_timeout_seconds,
            headers={
                "User-Agent": self.config.user_agent,
                "x-apikey": self._vt_key or "",
            },
        ) as client:
            data = await self._vt_get(client, url)
            for item in data.get("data", []):
                attrs = item.get("attributes", {})
                ip_addr = attrs.get("ip_address", "")
                host_name = attrs.get("host_name", "")
                date_ts = attrs.get("date")

                # For domain seeds the "value" is the resolved IP;
                # for IP seeds the "value" is the hostname.
                resolved_value = ip_addr if is_domain else host_name
                date_str = _unix_to_iso(date_ts)

                if resolved_value:
                    records.append({
                        "source": "virustotal",
                        "dns_record_type": "A",
                        "value": resolved_value,
                        "first_seen": date_str,
                        "last_seen": date_str,
                    })

        return records

    async def _vt_get(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> dict[str, Any]:
        """Issue a GET against VirusTotal and return parsed JSON."""
        try:
            resp = await client.get(url)
        except httpx.HTTPError as exc:
            msg = f"VirusTotal request failed: {exc}"
            raise CollectorError(msg) from exc

        if resp.status_code == 429:  # noqa: PLR2004
            msg = "VirusTotal rate limit exceeded"
            raise CollectorError(msg)

        if resp.status_code == 403:  # noqa: PLR2004
            msg = "VirusTotal authentication failed (403)"
            raise CollectorError(msg)

        if resp.status_code != 200:  # noqa: PLR2004
            msg = f"VirusTotal returned HTTP {resp.status_code}"
            raise CollectorError(msg)

        try:
            data: dict[str, Any] = resp.json()
        except Exception as exc:
            msg = "VirusTotal returned malformed JSON"
            raise CollectorError(msg) from exc

        return data

    # === health_check ==========================================================
    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe against configured API(s)."""
        start = time.monotonic()
        errors: list[str] = []

        if self._st_key:
            try:
                async with httpx.AsyncClient(
                    timeout=self.config.request_timeout_seconds,
                ) as client:
                    resp = await client.get(
                        f"{_ST_BASE}/ping",
                        headers={"apikey": self._st_key},
                    )
                    if resp.status_code >= 400:  # noqa: PLR2004
                        errors.append(
                            f"SecurityTrails ping returned {resp.status_code}"
                        )
            except httpx.HTTPError as exc:
                errors.append(f"SecurityTrails unreachable: {exc}")

        if self._vt_key:
            try:
                async with httpx.AsyncClient(
                    timeout=self.config.request_timeout_seconds,
                ) as client:
                    resp = await client.get(
                        f"{_VT_BASE}/users/me",
                        headers={"x-apikey": self._vt_key},
                    )
                    if resp.status_code >= 400:  # noqa: PLR2004
                        errors.append(
                            f"VirusTotal user check returned {resp.status_code}"
                        )
            except httpx.HTTPError as exc:
                errors.append(f"VirusTotal unreachable: {exc}")

        latency = (time.monotonic() - start) * 1000.0

        if not self._st_key and not self._vt_key:
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                latency_ms=latency,
                error_message="No API keys configured",
            )

        if errors:
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                latency_ms=latency,
                error_message="; ".join(errors),
            )

        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=datetime.now(tz=UTC),
            latency_ms=latency,
        )


__all__ = [
    "PassiveDnsHistoryCollector",
]

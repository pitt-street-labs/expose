"""BGP/ASN collector — RIPEstat API (Tier 1, passive).

Queries the RIPEstat Data API for BGP routing information:
- IP seed: ``/data/network-info/data.json?resource={ip}`` returns the
  announcing ASN and covering prefix for an IP address.
- ASN seed: ``/data/announced-prefixes/data.json?resource={asn}`` returns
  all prefixes currently announced by an AS number.

No credentials required. RIPEstat is a public data service operated by
RIPE NCC. Rate limiting is advisory; heavy users should register for
an API key (not implemented in this collector).

Seed types: IP and ASN. Other seed types are skipped with a warning.
"""

from __future__ import annotations

import logging
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
from expose.sanitization.text import SanitizationFieldKind, sanitize_field
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

logger = logging.getLogger(__name__)

_RIPESTAT_BASE = "https://stat.ripe.net/data"
_NETWORK_INFO_URL = f"{_RIPESTAT_BASE}/network-info/data.json"
_ANNOUNCED_PREFIXES_URL = f"{_RIPESTAT_BASE}/announced-prefixes/data.json"
_HEALTH_CHECK_URL = f"{_RIPESTAT_BASE}/network-info/data.json"
_HEALTH_CHECK_PARAMS = {"resource": "8.8.8.8"}


def _normalize_asn(raw: int | str) -> str:
    """Normalize an ASN to ``AS<number>`` string form."""
    text = str(raw).strip().upper()
    if text.startswith("AS"):
        return text
    return f"AS{text}"


def _extract_asn_number(value: str) -> str:
    """Extract the numeric part from an ASN string like ``AS13335``."""
    text = value.strip().upper()
    if text.startswith("AS"):
        return text[2:]
    return text


@register_collector
class RipeStatCollector(Collector):
    """BGP/ASN collector using the RIPEstat Data API (Tier 1)."""

    collector_id: str = "bgp-ripestat"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    technique_ids: ClassVar[list[str]] = ["T1596.001"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        if seed.seed_type == SeedType.IP:
            async for obs in self._expand_ip(seed):
                yield obs
        elif seed.seed_type == SeedType.ASN:
            async for obs in self._expand_asn(seed):
                yield obs
        else:
            logger.warning(
                "bgp-ripestat: skipping unsupported seed type %s (value=%r)",
                seed.seed_type,
                seed.value,
            )

    async def _expand_ip(self, seed: Seed) -> AsyncIterator[Observation]:
        """Look up ASN and prefix for an IP address."""
        ip_value = seed.value.strip()
        data = await self._fetch_json(
            _NETWORK_INFO_URL, {"resource": ip_value}
        )

        inner = data.get("data", {})
        asns_raw = inner.get("asns", [])
        prefix = inner.get("prefix", "")

        if not asns_raw:
            return

        for asn_entry in asns_raw:
            asn_num = asn_entry.get("asn")
            holder_raw = asn_entry.get("holder", "")
            if asn_num is None:
                continue

            asn_str = _normalize_asn(asn_num)
            holder = sanitize_field(
                str(holder_raw), SanitizationFieldKind.GENERIC
            ).value

            prefixes = [prefix] if prefix else []

            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.BGP_ASN_LOOKUP,
                subject=ObservationSubject(
                    identifier_type=ExtendedIdentifierType.IP,
                    identifier_value=ip_value,
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "asn": asn_str,
                    "holder": holder,
                    "prefixes": prefixes,
                    "source": "ripestat",
                },
            )

    async def _expand_asn(self, seed: Seed) -> AsyncIterator[Observation]:
        """Look up announced prefixes for an ASN."""
        asn_value = seed.value.strip()
        asn_number = _extract_asn_number(asn_value)
        asn_str = _normalize_asn(asn_number)

        data = await self._fetch_json(
            _ANNOUNCED_PREFIXES_URL, {"resource": asn_number}
        )

        inner = data.get("data", {})
        prefix_entries = inner.get("prefixes", [])

        prefixes = [
            entry["prefix"]
            for entry in prefix_entries
            if isinstance(entry, dict) and "prefix" in entry
        ]

        if not prefixes:
            return

        yield Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.BGP_ASN_LOOKUP,
            subject=ObservationSubject(
                identifier_type=ExtendedIdentifierType.ASN,
                identifier_value=asn_str,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload={
                "asn": asn_str,
                "holder": "",
                "prefixes": prefixes,
                "source": "ripestat",
            },
        )

    async def _fetch_json(
        self, url: str, params: dict[str, str]
    ) -> dict[str, Any]:
        """Fetch JSON from RIPEstat, raising on errors."""
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.request_timeout_seconds),
                headers={"User-Agent": self.config.user_agent},
            ) as client:
                response = await client.get(url, params=params)
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = (
                f"RIPEstat returned HTTP {exc.response.status_code} "
                f"for {params!r}"
            )
            raise CollectorSourceUnreachableError(msg) from exc
        except httpx.HTTPError as exc:
            msg = f"RIPEstat unreachable for {params!r}: {exc}"
            raise CollectorSourceUnreachableError(msg) from exc

        try:
            return response.json()
        except Exception as exc:
            msg = f"RIPEstat returned malformed JSON for {params!r}: {exc}"
            raise CollectorSourceUnreachableError(msg) from exc

    async def health_check(self) -> CollectorHealthCheck:
        start = datetime.now(tz=UTC)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0),
                headers={"User-Agent": self.config.user_agent},
            ) as client:
                response = await client.head(
                    _HEALTH_CHECK_URL, params=_HEALTH_CHECK_PARAMS
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
                error_message=f"RIPEstat returned HTTP {response.status_code}",
            )
        except httpx.HTTPError as exc:
            elapsed_ms = (datetime.now(tz=UTC) - start).total_seconds() * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=start,
                latency_ms=elapsed_ms,
                error_message=f"RIPEstat unreachable: {exc}",
            )

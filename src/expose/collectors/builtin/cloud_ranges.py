"""Cloud IP-range collector — checks IPs/CIDRs against cloud provider manifests.

A Tier 1 passive collector that compares seed IP addresses and CIDR blocks
against the published IP range manifests from AWS, Azure, and GCP. Matches
produce ``CLOUD_IP_RANGE`` observations indicating which cloud provider,
region, and service own a given address.

The collector loads range data from cached JSON files on disk. In production
these files are fetched daily from the provider endpoints:

- AWS:   https://ip-ranges.amazonaws.com/ip-ranges.json
- Azure: https://www.microsoft.com/en-us/download/details.aspx?id=56519
- GCP:   https://www.gstatic.com/ipranges/cloud.json

The ``extra`` config dict accepts ``ranges_dir`` pointing to a directory
containing the cached JSON files:

- ``aws-ip-ranges.json``
- ``azure-ip-ranges.json``
- ``gcp-ip-ranges.json``

Per SPEC §6.1, the collector never makes live network calls during
``expand()`` — all lookups are against the pre-loaded in-memory data.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
from expose.sanitization.canonicalize import canonicalize_cidr, canonicalize_ip
from expose.sanitization.text import SanitizationFieldKind, sanitize_field
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

# Expected cache file names.
_AWS_FILENAME = "aws-ip-ranges.json"
_AZURE_FILENAME = "azure-ip-ranges.json"
_GCP_FILENAME = "gcp-ip-ranges.json"


# === Internal data structures =================================================

class _CloudPrefix:
    """One cloud provider CIDR prefix with associated metadata."""

    __slots__ = ("network", "provider", "region", "service")

    def __init__(
        self,
        network: ipaddress.IPv4Network | ipaddress.IPv6Network,
        provider: str,
        region: str,
        service: str,
    ) -> None:
        self.network = network
        self.provider = provider
        self.region = region
        self.service = service


def _parse_aws(data: dict[str, Any]) -> list[_CloudPrefix]:
    """Parse AWS ip-ranges.json into ``_CloudPrefix`` records."""
    prefixes: list[_CloudPrefix] = []
    for entry in data.get("prefixes", []):
        raw_prefix = entry.get("ip_prefix", "")
        if not raw_prefix:
            continue
        try:
            net = ipaddress.ip_network(raw_prefix, strict=False)
        except ValueError:
            logger.warning("AWS: skipping invalid prefix %r", raw_prefix)
            continue
        prefixes.append(_CloudPrefix(
            network=net,
            provider="aws",
            region=entry.get("region", ""),
            service=entry.get("service", ""),
        ))
    for entry in data.get("ipv6_prefixes", []):
        raw_prefix = entry.get("ipv6_prefix", "")
        if not raw_prefix:
            continue
        try:
            net = ipaddress.ip_network(raw_prefix, strict=False)
        except ValueError:
            logger.warning("AWS: skipping invalid IPv6 prefix %r", raw_prefix)
            continue
        prefixes.append(_CloudPrefix(
            network=net,
            provider="aws",
            region=entry.get("region", ""),
            service=entry.get("service", ""),
        ))
    return prefixes


def _parse_azure(data: dict[str, Any]) -> list[_CloudPrefix]:
    """Parse Azure ServiceTags JSON into ``_CloudPrefix`` records."""
    prefixes: list[_CloudPrefix] = []
    for value in data.get("values", []):
        props = value.get("properties", {})
        region = props.get("region", "")
        service_name = value.get("name", "")
        for addr in props.get("addressPrefixes", []):
            try:
                net = ipaddress.ip_network(addr, strict=False)
            except ValueError:
                logger.warning("Azure: skipping invalid prefix %r", addr)
                continue
            prefixes.append(_CloudPrefix(
                network=net,
                provider="azure",
                region=region,
                service=service_name,
            ))
    return prefixes


def _parse_gcp(data: dict[str, Any]) -> list[_CloudPrefix]:
    """Parse GCP cloud.json into ``_CloudPrefix`` records."""
    prefixes: list[_CloudPrefix] = []
    for entry in data.get("prefixes", []):
        raw_prefix = entry.get("ipv4Prefix", "") or entry.get("ipv6Prefix", "")
        if not raw_prefix:
            continue
        try:
            net = ipaddress.ip_network(raw_prefix, strict=False)
        except ValueError:
            logger.warning("GCP: skipping invalid prefix %r", raw_prefix)
            continue
        prefixes.append(_CloudPrefix(
            network=net,
            provider="gcp",
            region=entry.get("scope", ""),
            service=entry.get("service", ""),
        ))
    return prefixes


def _load_provider_file(path: Path) -> dict[str, Any]:
    """Load and parse a JSON file, raising ``FileNotFoundError`` or
    ``json.JSONDecodeError`` on failure."""
    text = path.read_text(encoding="utf-8")
    result: dict[str, Any] = json.loads(text)
    return result


@register_collector
class CloudRangesCollector(Collector):
    """Check IP/CIDR seeds against AWS, Azure, and GCP IP range manifests.

    Class-level metadata:

    - ``collector_id = "cloud-ranges"``
    - Tier 1 (passive, broad query)
    - No credentials required
    """

    collector_id = "cloud-ranges"
    collector_version = "0.1.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        self._prefixes: list[_CloudPrefix] = []
        self._loaded = False
        self._load_errors: list[str] = []
        self._load_ranges()

    def _ranges_dir(self) -> Path | None:
        """Resolve the cache directory from ``config.extra["ranges_dir"]``."""
        raw = self.config.extra.get("ranges_dir")
        if raw is None:
            return None
        return Path(str(raw))

    def _load_ranges(self) -> None:
        """Load all provider range files from the configured cache directory."""
        ranges_dir = self._ranges_dir()
        if ranges_dir is None:
            self._load_errors.append("No ranges_dir configured in extra")
            return

        parsers: list[tuple[str, Any]] = [
            (_AWS_FILENAME, _parse_aws),
            (_AZURE_FILENAME, _parse_azure),
            (_GCP_FILENAME, _parse_gcp),
        ]

        for filename, parser in parsers:
            filepath = ranges_dir / filename
            try:
                data = _load_provider_file(filepath)
                self._prefixes.extend(parser(data))
            except FileNotFoundError:
                self._load_errors.append(f"Cache file not found: {filepath}")
                logger.warning("cloud-ranges: cache file not found: %s", filepath)
            except json.JSONDecodeError as exc:
                self._load_errors.append(
                    f"Cache file corrupt: {filepath}: {exc}"
                )
                logger.warning(
                    "cloud-ranges: corrupt cache file %s: %s", filepath, exc
                )

        if self._prefixes:
            self._loaded = True

    def _find_matches(
        self,
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> list[_CloudPrefix]:
        """Return all ``_CloudPrefix`` entries whose network contains ``addr``."""
        return [p for p in self._prefixes if addr in p.network]

    def _find_cidr_matches(
        self,
        network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    ) -> list[_CloudPrefix]:
        """Return all ``_CloudPrefix`` entries that overlap with ``network``.

        A match occurs when either network contains the other, or they
        overlap. For EASI purposes, any overlap is relevant — the seed CIDR
        may be a subset of a cloud range (most common) or may span multiple
        cloud ranges.
        """
        return [
            p for p in self._prefixes
            if p.network.overlaps(network)
        ]

    def _make_observation(
        self,
        seed_value: str,
        identifier_type: IdentifierType,
        match: _CloudPrefix,
    ) -> Observation:
        """Build an ``Observation`` for a single cloud range match."""
        sanitized_provider = sanitize_field(
            match.provider, SanitizationFieldKind.GENERIC
        )
        sanitized_region = sanitize_field(
            match.region, SanitizationFieldKind.GENERIC
        )
        sanitized_service = sanitize_field(
            match.service, SanitizationFieldKind.GENERIC
        )
        sanitized_prefix = sanitize_field(
            str(match.network), SanitizationFieldKind.GENERIC
        )

        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.CLOUD_IP_RANGE,
            subject=ObservationSubject(
                identifier_type=identifier_type,
                identifier_value=seed_value,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload={
                "provider": sanitized_provider.value,
                "region": sanitized_region.value,
                "service": sanitized_service.value,
                "prefix": sanitized_prefix.value,
            },
        )

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Check the seed IP/CIDR against cached cloud IP range manifests.

        Accepts ``SeedType.IP`` and ``SeedType.CIDR`` seeds; all other seed
        types are silently skipped (per collector contract — the dispatcher
        is responsible for routing appropriate seeds).
        """
        if seed.seed_type == SeedType.IP:
            canonical = canonicalize_ip(seed.value)
            addr = ipaddress.ip_address(canonical)
            identifier_type = IdentifierType.IP
            for match in self._find_matches(addr):
                yield self._make_observation(canonical, identifier_type, match)

        elif seed.seed_type == SeedType.CIDR:
            canonical = canonicalize_cidr(seed.value)
            network = ipaddress.ip_network(canonical, strict=False)
            identifier_type = IdentifierType.CIDR
            for match in self._find_cidr_matches(network):
                yield self._make_observation(canonical, identifier_type, match)

        # All other seed types: silently skip (no yield, no error).

    async def health_check(self) -> CollectorHealthCheck:
        """Verify that cache files are loaded and parseable.

        Returns ``SUCCESS`` if at least one provider's ranges were loaded,
        ``FAILURE`` if no ranges could be loaded (missing/corrupt files),
        and includes any load errors in the detail.
        """
        now = datetime.now(tz=UTC)

        if self._loaded and not self._load_errors:
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.SUCCESS,
                checked_at=now,
                detail={
                    "prefix_count": len(self._prefixes),
                    "ranges_dir": str(self._ranges_dir()),
                },
            )

        if self._loaded and self._load_errors:
            # Some files loaded, some failed — partial success.
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.PARTIAL_SUCCESS,
                checked_at=now,
                error_message="; ".join(self._load_errors),
                detail={
                    "prefix_count": len(self._prefixes),
                    "ranges_dir": str(self._ranges_dir()),
                    "errors": self._load_errors,
                },
            )

        # Nothing loaded at all.
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.FAILURE,
            checked_at=now,
            error_message="; ".join(self._load_errors) if self._load_errors else "No ranges loaded",
            detail={
                "ranges_dir": str(self._ranges_dir()),
                "errors": self._load_errors,
            },
        )


__all__ = ["CloudRangesCollector"]

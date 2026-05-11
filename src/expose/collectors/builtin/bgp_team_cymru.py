"""BGP/ASN collector — Team Cymru DNS service (Tier 1, passive).

Queries the Team Cymru IP-to-ASN mapping service via DNS TXT lookups:

1. Reverse the IP octets and query ``{reversed}.origin.asn.cymru.com`` TXT.
   Response format: ``"ASN | IP | PREFIX | CC | REGISTRY"``
2. Query ``AS{asn}.asn.cymru.com`` TXT for ASN metadata.
   Response format: ``"ASN | CC | REGISTRY | ALLOCATED | NAME"``

No credentials required. Team Cymru's DNS service is public and widely
used for bulk IP-to-ASN mapping.

Requires ``dnspython`` (same optional dependency as ``active-dns-resolve``).
The module imports cleanly without it; ``expand()`` raises ``CollectorError``
if invoked without the library installed.

Seed types: IP only. Other seed types are skipped with a warning.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from typing import ClassVar

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorError,
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

try:
    import dns.asyncresolver as _dns_asyncresolver
    import dns.resolver as _dns_resolver

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

logger = logging.getLogger(__name__)

_ORIGIN_SUFFIX = "origin.asn.cymru.com"
_ASN_SUFFIX = "asn.cymru.com"
_HEALTH_CHECK_DOMAIN = "origin.asn.cymru.com"


def _reverse_ip(ip: str) -> str:
    """Reverse an IPv4 address for DNS PTR-style lookup.

    ``1.2.3.4`` -> ``4.3.2.1``
    """
    parts = ip.strip().split(".")
    return ".".join(reversed(parts))


def _parse_origin_txt(txt: str) -> dict[str, str]:
    """Parse Team Cymru origin TXT response.

    Format: ``"ASN | IP | PREFIX | CC | REGISTRY"``
    """
    parts = [p.strip() for p in txt.strip('"').split("|")]
    if len(parts) < 5:  # noqa: PLR2004
        return {}
    return {
        "asn": parts[0].strip(),
        "ip": parts[1].strip(),
        "prefix": parts[2].strip(),
        "country": parts[3].strip(),
        "registry": parts[4].strip(),
    }


def _parse_asn_txt(txt: str) -> dict[str, str]:
    """Parse Team Cymru ASN TXT response.

    Format: ``"ASN | CC | REGISTRY | ALLOCATED | NAME"``
    """
    parts = [p.strip() for p in txt.strip('"').split("|")]
    if len(parts) < 5:  # noqa: PLR2004
        return {}
    return {
        "asn": parts[0].strip(),
        "country": parts[1].strip(),
        "registry": parts[2].strip(),
        "allocated": parts[3].strip(),
        "name": parts[4].strip(),
    }


@register_collector
class TeamCymruCollector(Collector):
    """BGP/ASN collector using Team Cymru DNS service (Tier 1)."""

    collector_id: str = "bgp-team-cymru"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    technique_ids: ClassVar[list[str]] = ["T1596.001"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        if HAS_DNSPYTHON:
            self._resolver = _dns_asyncresolver.Resolver()
            self._resolver.lifetime = config.request_timeout_seconds
        else:
            self._resolver = None  # type: ignore[assignment]

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        if not HAS_DNSPYTHON:
            msg = "dnspython not installed; install expose[collectors-dns]"
            raise CollectorError(msg)

        if seed.seed_type != SeedType.IP:
            logger.warning(
                "bgp-team-cymru: skipping unsupported seed type %s (value=%r)",
                seed.seed_type,
                seed.value,
            )
            return

        ip_value = seed.value.strip()

        # Step 1: reverse-IP origin lookup
        reversed_ip = _reverse_ip(ip_value)
        origin_qname = f"{reversed_ip}.{_ORIGIN_SUFFIX}"

        try:
            origin_answer = await self._resolver.resolve(origin_qname, "TXT")
        except _dns_resolver.NXDOMAIN as exc:
            msg = f"Team Cymru origin lookup NXDOMAIN for {ip_value!r}"
            raise CollectorSourceUnreachableError(msg) from exc
        except _dns_resolver.LifetimeTimeout as exc:
            msg = f"Team Cymru DNS timed out for {ip_value!r}"
            raise CollectorSourceUnreachableError(msg) from exc
        except Exception as exc:
            msg = f"Team Cymru DNS failed for {ip_value!r}: {exc}"
            raise CollectorSourceUnreachableError(msg) from exc

        origin_txt = ""
        for rr in origin_answer:
            origin_txt = b"".join(rr.strings).decode("utf-8", errors="replace")
            break

        origin = _parse_origin_txt(origin_txt)
        if not origin:
            return

        asn_raw = origin.get("asn", "")
        if not asn_raw:
            return

        # Step 2: ASN name lookup
        asn_qname = f"AS{asn_raw}.{_ASN_SUFFIX}"
        asn_name = ""
        try:
            asn_answer = await self._resolver.resolve(asn_qname, "TXT")
            for rr in asn_answer:
                asn_txt = b"".join(rr.strings).decode(
                    "utf-8", errors="replace"
                )
                asn_info = _parse_asn_txt(asn_txt)
                asn_name = asn_info.get("name", "")
                break
        except Exception:
            # ASN name lookup is best-effort; proceed without it
            logger.debug(
                "bgp-team-cymru: ASN name lookup failed for AS%s",
                asn_raw,
            )

        asn_str = f"AS{asn_raw}"
        asn_name_sanitized = sanitize_field(
            asn_name, SanitizationFieldKind.GENERIC
        ).value

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
                "asn_name": asn_name_sanitized,
                "prefix": origin.get("prefix", ""),
                "country": origin.get("country", ""),
                "registry": origin.get("registry", ""),
                "source": "team-cymru",
            },
        )

    async def health_check(self) -> CollectorHealthCheck:
        if not HAS_DNSPYTHON:
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                error_message=(
                    "dnspython not installed; install expose[collectors-dns]"
                ),
            )

        start = datetime.now(tz=UTC)
        try:
            await self._resolver.resolve(_HEALTH_CHECK_DOMAIN, "A")
            elapsed_ms = (datetime.now(tz=UTC) - start).total_seconds() * 1000
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.SUCCESS,
                checked_at=start,
                latency_ms=elapsed_ms,
            )
        except Exception as exc:
            elapsed_ms = (datetime.now(tz=UTC) - start).total_seconds() * 1000
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=start,
                latency_ms=elapsed_ms,
                error_message=f"Team Cymru DNS unreachable: {exc}",
            )


__all__ = [
    "HAS_DNSPYTHON",
    "TeamCymruCollector",
]

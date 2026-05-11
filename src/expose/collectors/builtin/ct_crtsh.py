"""Certificate Transparency collector — crt.sh (Tier 1, passive).

Queries the crt.sh JSON API for certificates matching a domain seed or
an organization seed.

**Domain search** (``?q=%25.domain.com&output=json``):
  Returns certificates whose SAN or CN match the wildcard pattern.

**Organization search** (``?O=OrgName&output=json``):
  Returns certificates issued to the named organization across *any*
  domain. This surfaces shadow-IT, M&A remnant certs, and subsidiary
  infrastructure that would not appear via domain-only CT enumeration.

crt.sh aggregates CT log entries from Google, Cloudflare, and DigiCert
logs; results include pre-certificates and final certificates.

No credentials required. Rate limiting is advisory (crt.sh has no
published API contract but will return 429 or TCP RST under heavy load).

Seed types: DOMAIN, ORGANIZATION. Other seed types are skipped with a
warning.

Per ADR-010, we do NOT compute SHA-256 fingerprints from PEM here — the
FIPS adapter is required for that. Instead we use the certificate serial
number (hex, lowercase) as a proxy identifier. This is sufficient for
deduplication and cross-referencing within a single CT-log collector run;
true fingerprint computation happens when the FIPS adapter lands and the
PEM is available.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

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
from expose.sanitization.text import (
    SanitizationFieldKind,
    SanitizedField,
    sanitize_field,
)
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType, IdentifierType

logger = logging.getLogger(__name__)

_CRT_SH_BASE_URL = "https://crt.sh/"
_CRT_SH_JSON_URL = "https://crt.sh/"

_SAN_BYTE_CAP = 255

# Maximum number of unique domains to extract from org-name search results.
# crt.sh can return thousands of certs for large CAs; cap to avoid flooding
# the pipeline with low-value seeds.
_ORG_SEARCH_DOMAIN_CAP = 200


def _parse_sans(name_value: str) -> list[str]:
    """Split newline-separated SAN values, strip whitespace, drop empties."""
    return [s.strip() for s in name_value.split("\n") if s.strip()]


def _sanitize_san(san: str) -> SanitizedField:
    """Sanitize a single SAN value and enforce the 255-byte cap."""
    return sanitize_field(san, SanitizationFieldKind.CERT_SAN)


def _normalize_serial(serial: str) -> str:
    """Lowercase hex serial number, strip leading zeros for consistency."""
    return serial.strip().lower()


def _build_observation(
    entry: dict[str, Any],
    *,
    collector_id: str,
    collector_version: str,
    tenant_id: Any,
) -> Observation:
    """Build an Observation from a single crt.sh JSON entry."""
    serial_raw: str = str(entry.get("serial_number", ""))
    serial = _normalize_serial(serial_raw)

    common_name_raw: str = str(entry.get("common_name", ""))
    issuer_name_raw: str = str(entry.get("issuer_name", ""))
    name_value_raw: str = str(entry.get("name_value", ""))
    not_before: str = str(entry.get("not_before", ""))
    not_after: str = str(entry.get("not_after", ""))

    common_name_san = sanitize_field(common_name_raw, SanitizationFieldKind.CERT_SAN)
    issuer_name_san = sanitize_field(issuer_name_raw, SanitizationFieldKind.GENERIC)

    raw_sans = _parse_sans(name_value_raw)
    san_results = [_sanitize_san(s) for s in raw_sans]
    sanitized_sans = [r.value for r in san_results]

    warnings: list[str] = []
    if common_name_san.flags:
        warnings.append(
            f"common_name sanitization flags: {[f.value for f in common_name_san.flags]}"
        )
    if issuer_name_san.flags:
        warnings.append(
            f"issuer_name sanitization flags: {[f.value for f in issuer_name_san.flags]}"
        )
    for i, sr in enumerate(san_results):
        if sr.flags:
            warnings.append(
                f"san[{i}] sanitization flags: {[f.value for f in sr.flags]}"
            )

    return Observation(
        collector_id=collector_id,
        collector_version=collector_version,
        tenant_id=tenant_id,
        observation_type=ObservationType.CT_LOG_ENTRY,
        subject=ObservationSubject(
            identifier_type=ExtendedIdentifierType.CERTIFICATE_FINGERPRINT,
            identifier_value=serial,
        ),
        observed_at=datetime.now(tz=UTC),
        structured_payload={
            "issuer_name": issuer_name_san.value,
            "common_name": common_name_san.value,
            "sans": sanitized_sans,
            "not_before": not_before,
            "not_after": not_after,
            "serial_number": serial,
        },
        warnings=warnings,
    )


@register_collector
class CrtShCollector(Collector):
    """Certificate Transparency collector using crt.sh (Tier 1)."""

    collector_id: str = "ct-crtsh"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        if seed.seed_type == SeedType.DOMAIN:
            async for obs in self._expand_domain(seed):
                yield obs
        elif seed.seed_type == SeedType.ORGANIZATION:
            async for obs in self._expand_organization(seed):
                yield obs
        else:
            logger.warning(
                "ct-crtsh: skipping unsupported seed type %s (value=%r)",
                seed.seed_type,
                seed.value,
            )

    async def _expand_domain(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query crt.sh by domain wildcard (``?q=%25.domain.com``)."""
        domain = seed.value.strip()
        url = _CRT_SH_JSON_URL
        params = {"q": f"%.{domain}", "output": "json"}

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.request_timeout_seconds),
                headers={"User-Agent": self.config.user_agent},
            ) as client:
                response = await client.get(url, params=params)
                # 404 means "no certificates for this domain" — valid empty result
                if response.status_code == 404:
                    return
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = (
                f"crt.sh returned HTTP {exc.response.status_code} "
                f"for domain {domain!r}"
            )
            raise CollectorSourceUnreachableError(msg) from exc
        except httpx.HTTPError as exc:
            msg = f"crt.sh unreachable for domain {domain!r}: {exc}"
            raise CollectorSourceUnreachableError(msg) from exc

        try:
            raw: Any = response.json()
        except Exception as exc:
            msg = f"crt.sh returned malformed JSON for domain {domain!r}: {exc}"
            raise CollectorSourceUnreachableError(msg) from exc

        if not isinstance(raw, list):
            msg = (
                f"crt.sh returned {type(raw).__name__} instead of "
                f"JSON array for domain {domain!r}"
            )
            raise CollectorSourceUnreachableError(msg)

        entries: list[dict[str, Any]] = raw

        seen_serials: set[str] = set()
        for entry in entries:
            serial_raw = str(entry.get("serial_number", ""))
            serial = _normalize_serial(serial_raw)
            if not serial:
                continue
            if serial in seen_serials:
                continue
            seen_serials.add(serial)

            try:
                obs = _build_observation(
                    entry,
                    collector_id=self.collector_id,
                    collector_version=self.collector_version,
                    tenant_id=self.config.tenant_id,
                )
                yield obs
            except Exception as exc:
                logger.warning(
                    "ct-crtsh: failed to build observation for serial %s: %s",
                    serial,
                    exc,
                    exc_info=True,
                )

    async def _expand_organization(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query crt.sh by organization name (``?O=OrgName&output=json``).

        Extracts unique domain names from certificate SANs and common names,
        emitting one observation per discovered domain. This surfaces shadow-IT
        and M&A remnant domains that would not appear via domain-only CT search.
        """
        org_name = seed.value.strip()
        if not org_name:
            return

        url = _CRT_SH_JSON_URL
        params = {"O": org_name, "output": "json"}

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.request_timeout_seconds),
                headers={"User-Agent": self.config.user_agent},
            ) as client:
                response = await client.get(url, params=params)
                if response.status_code == 404:
                    return
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = (
                f"crt.sh returned HTTP {exc.response.status_code} "
                f"for organization {org_name!r}"
            )
            raise CollectorSourceUnreachableError(msg) from exc
        except httpx.HTTPError as exc:
            msg = f"crt.sh unreachable for organization {org_name!r}: {exc}"
            raise CollectorSourceUnreachableError(msg) from exc

        try:
            raw: Any = response.json()
        except Exception as exc:
            msg = (
                f"crt.sh returned malformed JSON for organization "
                f"{org_name!r}: {exc}"
            )
            raise CollectorSourceUnreachableError(msg) from exc

        if not isinstance(raw, list):
            msg = (
                f"crt.sh returned {type(raw).__name__} instead of "
                f"JSON array for organization {org_name!r}"
            )
            raise CollectorSourceUnreachableError(msg)

        entries: list[dict[str, Any]] = raw

        # Extract unique domain names from SANs and common_name fields.
        unique_domains: set[str] = set()
        for entry in entries:
            cn_raw = str(entry.get("common_name", "")).strip()
            if cn_raw and "." in cn_raw and not cn_raw.startswith("*"):
                unique_domains.add(cn_raw.lower())
            name_value_raw = str(entry.get("name_value", ""))
            for san in _parse_sans(name_value_raw):
                san_lower = san.strip().lower()
                if san_lower and "." in san_lower and not san_lower.startswith("*"):
                    unique_domains.add(san_lower)
            if len(unique_domains) >= _ORG_SEARCH_DOMAIN_CAP:
                break

        # Emit one observation per discovered domain, keyed by the domain name.
        for domain in sorted(unique_domains):
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.CT_LOG_ENTRY,
                subject=ObservationSubject(
                    identifier_type=IdentifierType.DOMAIN,
                    identifier_value=domain,
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "discovery_method": "ct_org_search",
                    "organization": org_name,
                    "domain": domain,
                    "source_entry_count": len(entries),
                },
            )

    async def health_check(self) -> CollectorHealthCheck:
        start = datetime.now(tz=UTC)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0),
                headers={"User-Agent": self.config.user_agent},
            ) as client:
                response = await client.head(_CRT_SH_BASE_URL)
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
                error_message=f"crt.sh returned HTTP {response.status_code}",
            )
        except httpx.HTTPError as exc:
            elapsed_ms = (datetime.now(tz=UTC) - start).total_seconds() * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=start,
                latency_ms=elapsed_ms,
                error_message=f"crt.sh unreachable: {exc}",
            )

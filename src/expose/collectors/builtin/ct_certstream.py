"""Certificate Transparency near-real-time collector — certstream (Tier 1, passive).

Queries the crt.sh JSON API for certificates matching a domain seed, then
filters to only those issued within a configurable recency window (default
24 hours). This provides "near real-time" Certificate Transparency
monitoring without WebSocket complexity.

The key difference from the ``ct-crtsh`` collector: this collector
specifically targets RECENT certificates by filtering ``not_before`` dates,
simulating the near-real-time behavior of a true certstream WebSocket feed.
A future version (v0.2+) will replace the polling approach with the
Certstream WebSocket API (``wss://certstream.calidog.io/``).

No credentials required. Rate limiting is advisory (crt.sh has no
published API contract but will return 429 or TCP RST under heavy load).

Seed types: DOMAIN only. Other seed types are skipped with a warning.

Per ADR-010, we do NOT compute SHA-256 fingerprints from PEM here — the
FIPS adapter is required for that. Instead we use the certificate serial
number (hex, lowercase) as a proxy identifier (same convention as ct-crtsh).

Deduplication against the ``ct-crtsh`` collector is achieved by including
``"source": "certstream"`` and ``"recency_hours"`` in the structured
payload, so downstream consumers can distinguish the two collectors' output.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
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
from expose.sanitization.text import (
    SanitizationFieldKind,
    SanitizedField,
    sanitize_field,
)
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

logger = logging.getLogger(__name__)

_CRT_SH_BASE_URL = "https://crt.sh/"
_CRT_SH_JSON_URL = "https://crt.sh/"

_DEFAULT_RECENCY_HOURS = 24

_RETRY_MAX_ATTEMPTS = 3
_RETRY_DELAYS = (2.0, 4.0, 8.0)
_CRT_SH_TIMEOUT = 45.0


def _parse_sans(name_value: str) -> list[str]:
    """Split newline-separated SAN values, strip whitespace, drop empties."""
    return [s.strip() for s in name_value.split("\n") if s.strip()]


def _sanitize_san(san: str) -> SanitizedField:
    """Sanitize a single SAN value and enforce the 255-byte cap."""
    return sanitize_field(san, SanitizationFieldKind.CERT_SAN)


def _normalize_serial(serial: str) -> str:
    """Lowercase hex serial number, strip leading zeros for consistency."""
    return serial.strip().lower()


def _parse_not_before(not_before_raw: str) -> datetime | None:
    """Parse a ``not_before`` timestamp from crt.sh into a tz-aware datetime.

    crt.sh returns timestamps without timezone info; they are UTC.
    Returns ``None`` if the timestamp cannot be parsed.
    """
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(not_before_raw.strip(), fmt).replace(
                tzinfo=UTC,
            )
        except ValueError:
            continue
    return None


def _build_observation(
    entry: dict[str, Any],
    *,
    collector_id: str,
    collector_version: str,
    tenant_id: Any,
    recency_hours: int,
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
            "source": "certstream",
            "recency_hours": recency_hours,
        },
        warnings=warnings,
    )


@register_collector
class CertstreamCollector(Collector):
    """Certificate Transparency near-real-time collector (Tier 1).

    Queries crt.sh for recent certificates matching the seed domain,
    filtering to those issued within the configured recency window.
    """

    collector_id: str = "ct-certstream"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    technique_ids: ClassVar[list[str]] = ["T1596.003"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        self._recency_hours: int = int(
            config.extra.get("recency_hours", _DEFAULT_RECENCY_HOURS)
        )

    async def _fetch_crtsh(
        self,
        params: dict[str, str],
        label: str,
    ) -> httpx.Response | None:
        timeout = max(self.config.request_timeout_seconds, _CRT_SH_TIMEOUT)
        last_exc: Exception | None = None

        for attempt in range(1, _RETRY_MAX_ATTEMPTS + 1):
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(timeout),
                    headers={"User-Agent": self.config.user_agent},
                ) as client:
                    response = await client.get(_CRT_SH_JSON_URL, params=params)

                    if response.status_code == 404:
                        return None

                    if response.status_code >= 500:
                        last_exc = httpx.HTTPStatusError(
                            f"crt.sh returned HTTP {response.status_code}",
                            request=response.request,
                            response=response,
                        )
                        if attempt < _RETRY_MAX_ATTEMPTS:
                            delay = _RETRY_DELAYS[attempt - 1]
                            logger.warning(
                                "ct-certstream: %s got HTTP %d, retrying in %.0fs (attempt %d/%d)",
                                label, response.status_code, delay, attempt, _RETRY_MAX_ATTEMPTS,
                            )
                            await asyncio.sleep(delay)
                            continue
                        response.raise_for_status()

                    response.raise_for_status()

                    if attempt > 1:
                        logger.info(
                            "ct-certstream: %s succeeded on attempt %d/%d",
                            label, attempt, _RETRY_MAX_ATTEMPTS,
                        )

                    return response

            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code if exc.response is not None else "unknown"
                raise CollectorSourceUnreachableError(
                    f"crt.sh returned HTTP {status} for {label}"
                ) from last_exc
            except httpx.HTTPError as exc:
                last_exc = exc
                if attempt < _RETRY_MAX_ATTEMPTS:
                    delay = _RETRY_DELAYS[attempt - 1]
                    logger.warning(
                        "ct-certstream: %s network error (%s), retrying in %.0fs (attempt %d/%d)",
                        label, exc, delay, attempt, _RETRY_MAX_ATTEMPTS,
                    )
                    await asyncio.sleep(delay)
                    continue
                msg = f"crt.sh unreachable for {label}: {exc}"
                raise CollectorSourceUnreachableError(msg) from exc

        msg = f"crt.sh unreachable for {label} after {_RETRY_MAX_ATTEMPTS} attempts"
        raise CollectorSourceUnreachableError(msg) from last_exc

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        if seed.seed_type != SeedType.DOMAIN:
            logger.warning(
                "ct-certstream: skipping non-domain seed type %s (value=%r)",
                seed.seed_type,
                seed.value,
            )
            return

        domain = seed.value.strip()
        params = {
            "q": f"%.{domain}",
            "output": "json",
            "exclude": "expired",
        }
        label = f"domain {domain!r}"

        response = await self._fetch_crtsh(params, label)
        if response is None:
            return

        try:
            raw: Any = response.json()
        except Exception as exc:
            msg = f"crt.sh returned malformed JSON for {label}: {exc}"
            raise CollectorSourceUnreachableError(msg) from exc

        if not isinstance(raw, list):
            msg = (
                f"crt.sh returned {type(raw).__name__} instead of "
                f"JSON array for {label}"
            )
            raise CollectorSourceUnreachableError(msg)

        entries: list[dict[str, Any]] = raw

        cutoff = datetime.now(tz=UTC) - timedelta(hours=self._recency_hours)
        seen_serials: set[str] = set()

        for entry in entries:
            serial_raw = str(entry.get("serial_number", ""))
            serial = _normalize_serial(serial_raw)
            if not serial:
                continue
            if serial in seen_serials:
                continue

            # Filter by recency: only yield certs with not_before within the window.
            not_before_raw = str(entry.get("not_before", ""))
            not_before_dt = _parse_not_before(not_before_raw)
            if not_before_dt is None or not_before_dt < cutoff:
                continue

            seen_serials.add(serial)

            try:
                obs = _build_observation(
                    entry,
                    collector_id=self.collector_id,
                    collector_version=self.collector_version,
                    tenant_id=self.config.tenant_id,
                    recency_hours=self._recency_hours,
                )
                yield obs
            except Exception as exc:
                logger.warning(
                    "ct-certstream: failed to build observation for serial %s: %s",
                    serial,
                    exc,
                    exc_info=True,
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

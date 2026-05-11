"""Dark web indicators collector (Tier 3, active, requires authorization).

Queries public dark web aggregator APIs (Have I Been Pwned, IntelX,
DeHashed) via the ``DarkWebEnricher`` for breach data, leaked credentials,
and dark web mentions associated with DOMAIN seeds.

This is a Tier-3 collector: the dispatcher is responsible for ensuring
that Tier-3 dispatch gating (SPEC section 6.3 / ADR-008) is satisfied
before calling ``expand()``. This collector does NOT self-gate.

MITRE ATT&CK: T1597 (Search Closed Sources) -- the collector queries
aggregated dark web intelligence from public APIs that index closed
sources (paste sites, dark web forums, breach databases).

Credential slots (resolved via CredentialResolver):
    ``hibp_api_key``     -- Have I Been Pwned API key (required)
    ``intelx_api_key``   -- IntelX API key (optional)
    ``dehashed_email``   -- DeHashed account email (optional)
    ``dehashed_api_key`` -- DeHashed API key (optional)

Seed types: DOMAIN only. Other seed types are skipped silently.
(EMAIL seed type support deferred until SeedType.EMAIL is added to the
base framework.)

FIPS gate compliance: This module does NOT import ``hashlib``, ``secrets``,
or ``Crypto``. All HTTP is via ``httpx`` (stdlib TLS) inside DarkWebEnricher.
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
    CollectorHealthCheck,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import register_collector
from expose.collectors.tiers import CollectorTier
from expose.modules.threat_context.dark_web import (
    DarkWebEnricher,
    ThreatIndicator,
)
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

# HIBP health check endpoint (public, no auth needed).
_HIBP_HEALTH_URL = "https://haveibeenpwned.com/api/v3/breaches?domain=example.com"


@register_collector
class DarkWebIndicatorsCollector(Collector):
    """Tier-3 dark web indicators collector.

    Queries public dark web aggregators for breach data and threat
    intelligence associated with DOMAIN seeds. Delegates actual API
    calls to ``DarkWebEnricher``.
    """

    collector_id: str = "dark-web-indicators"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_3
    requires_credentials: bool = True
    rate_limit_per_minute: int | None = 10
    technique_ids: ClassVar[list[str]] = ["T1597"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        self._enricher = self._build_enricher()

    def _build_enricher(self) -> DarkWebEnricher:
        """Construct a DarkWebEnricher from resolved credentials."""
        hibp_cred = self.config.credentials.get("hibp_api_key")
        intelx_cred = self.config.credentials.get("intelx_api_key")
        dehashed_email_cred = self.config.credentials.get("dehashed_email")
        dehashed_key_cred = self.config.credentials.get("dehashed_api_key")

        return DarkWebEnricher(
            hibp_api_key=hibp_cred.secret_value if hibp_cred else None,
            intelx_api_key=intelx_cred.secret_value if intelx_cred else None,
            dehashed_email=(
                dehashed_email_cred.secret_value if dehashed_email_cred else None
            ),
            dehashed_api_key=(
                dehashed_key_cred.secret_value if dehashed_key_cred else None
            ),
            timeout_seconds=self.config.request_timeout_seconds,
            user_agent=self.config.user_agent,
        )

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query dark web aggregators for a DOMAIN seed.

        Skips non-DOMAIN seeds. Emits one ``DARK_WEB_MENTION`` observation
        per threat indicator found.
        """
        if seed.seed_type != SeedType.DOMAIN:
            return

        domain = seed.value.strip().lower()
        if not domain:
            return

        indicators = await self._enricher.enrich_domain(domain)

        for indicator in indicators:
            yield self._indicator_to_observation(indicator, domain)

    def _indicator_to_observation(
        self, indicator: ThreatIndicator, domain: str
    ) -> Observation:
        """Convert a ThreatIndicator to an Observation."""
        payload: dict[str, Any] = {
            "indicator_type": indicator.indicator_type.value,
            "source": indicator.source,
            "confidence": indicator.confidence,
            "description": indicator.description,
        }

        if indicator.first_seen is not None:
            payload["first_seen"] = indicator.first_seen.isoformat()
        if indicator.last_seen is not None:
            payload["last_seen"] = indicator.last_seen.isoformat()
        if indicator.raw_data:
            payload["raw_data"] = indicator.raw_data

        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.DARK_WEB_MENTION,
            subject=ObservationSubject(
                identifier_type=IdentifierType.DOMAIN,
                identifier_value=domain,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload=payload,
        )

    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe using HIBP public breaches endpoint.

        The HIBP breaches endpoint does not require authentication for
        a basic GET, making it suitable as a health check target. Returns
        a CollectorHealthCheck with SUCCESS or FAILURE status.
        """
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(
                timeout=self.config.request_timeout_seconds,
            ) as client:
                resp = await client.get(
                    _HIBP_HEALTH_URL,
                    headers={"User-Agent": self.config.user_agent},
                )
            latency = (time.monotonic() - start) * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=(
                    CollectorStatus.SUCCESS
                    if resp.status_code < 400  # noqa: PLR2004
                    else CollectorStatus.FAILURE
                ),
                checked_at=datetime.now(tz=UTC),
                latency_ms=latency,
            )
        except Exception as exc:
            latency = (time.monotonic() - start) * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                latency_ms=latency,
                error_message=str(exc),
            )


__all__ = [
    "DarkWebIndicatorsCollector",
]

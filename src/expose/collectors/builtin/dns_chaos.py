"""ProjectDiscovery Chaos subdomain discovery collector (Tier 1, passive).

Queries the ProjectDiscovery Chaos API for known subdomains of a target
domain. The public endpoint (``dns.projectdiscovery.io``) provides a
curated, continuously-updated dataset of subdomains collected from
various public sources.

Endpoint: ``GET https://dns.projectdiscovery.io/dns/{domain}/subdomains``
Response: JSON with a ``subdomains`` list (or ``domain`` + ``subdomains``
keys depending on the endpoint version).

The API offers enhanced results with an API key (``Authorization`` header),
but the public tier provides useful subdomain discovery without credentials.
When an API key is provided via ``credentials["api_key"]``, it is sent in
the ``Authorization`` header for expanded results.

Tier 1 / passive: queries a third-party aggregation API. No direct
contact with the target domain.
"""

from __future__ import annotations

import logging
import time
import warnings as _warnings_mod
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from typing import ClassVar

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
from expose.sanitization.canonicalize import canonicalize_domain
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

_CHAOS_BASE_URL = "https://dns.projectdiscovery.io/dns"


@register_collector
class DnsChaosCollector(Collector):
    """Tier-1 ProjectDiscovery Chaos subdomain discovery collector.

    Queries the Chaos public API for subdomains of the seed domain.
    Optionally uses an API key for expanded results when available.
    """

    collector_id: str = "dns-chaos"
    collector_version: str = "0.1.0"
    display_name: str = "ProjectDiscovery Chaos Subdomains"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = 30
    technique_ids: ClassVar[list[str]] = ["T1596.001"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)

    def _get_auth_headers(self) -> dict[str, str]:
        """Build authorization headers if an API key credential is available.

        Returns an empty dict when no key is configured (public-tier access).
        """
        api_key_cred = self.config.credentials.get("api_key")
        if api_key_cred is not None and api_key_cred.secret_value:
            return {"Authorization": api_key_cred.secret_value}
        return {}

    # ------------------------------------------------------------------
    # expand
    # ------------------------------------------------------------------
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query Chaos API for subdomains of a DOMAIN seed."""
        if seed.seed_type != SeedType.DOMAIN:
            return

        domain = seed.value.strip()
        canonical_domain = canonicalize_domain(domain)
        url = f"{_CHAOS_BASE_URL}/{domain}/subdomains"

        try:
            subdomains = await self._fetch_subdomains(url)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:  # noqa: PLR2004
                # Domain not in the Chaos dataset -- not an error.
                logger.debug(
                    "dns-chaos: domain %s not found in Chaos dataset", domain
                )
                return
            if exc.response.status_code == 403:  # noqa: PLR2004
                # Rate limited or auth required -- degrade gracefully.
                logger.warning(
                    "dns-chaos: access denied for %s (HTTP 403); "
                    "API key may be required for this domain",
                    domain,
                )
                return
            raise
        except httpx.HTTPError as exc:
            logger.warning(
                "dns-chaos: HTTP error querying Chaos for %s: %s",
                domain,
                exc,
            )
            return

        if not subdomains:
            logger.debug(
                "dns-chaos: no subdomains returned for %s", domain
            )
            return

        now = datetime.now(tz=UTC)
        for subdomain_label in subdomains:
            # The API returns subdomain labels (e.g., "www", "mail"),
            # not FQDNs.  Construct the full subdomain.
            if subdomain_label == "@" or not subdomain_label:
                continue
            fqdn = f"{subdomain_label}.{domain}"
            try:
                canonical_fqdn = canonicalize_domain(fqdn)
            except Exception:  # noqa: BLE001
                logger.debug(
                    "dns-chaos: skipping invalid subdomain label %r",
                    subdomain_label,
                )
                continue

            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.DNS_RECORD,
                subject=ObservationSubject(
                    identifier_type=IdentifierType.DOMAIN,
                    identifier_value=canonical_fqdn,
                ),
                observed_at=now,
                structured_payload={
                    "source": "projectdiscovery_chaos",
                    "seed_domain": canonical_domain,
                    "subdomain_label": subdomain_label,
                },
            )

    # ------------------------------------------------------------------
    # health_check
    # ------------------------------------------------------------------
    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe -- query Chaos for example.com."""
        start = time.monotonic()
        url = f"{_CHAOS_BASE_URL}/example.com/subdomains"
        try:
            with _warnings_mod.catch_warnings():
                _warnings_mod.filterwarnings(
                    "ignore", category=DeprecationWarning
                )
                _warnings_mod.filterwarnings(
                    "ignore", message="Unverified HTTPS request"
                )
                async with httpx.AsyncClient(verify=False) as client:  # noqa: S501
                    resp = await client.get(
                        url,
                        timeout=self.config.request_timeout_seconds,
                        headers={
                            "User-Agent": self.config.user_agent,
                            **self._get_auth_headers(),
                        },
                    )
            latency = (time.monotonic() - start) * 1000.0
            # Treat 401/403 as auth failures — the API key is missing or
            # invalid.  Only 2xx/3xx/404 are considered healthy (404 just
            # means the probe domain is not in the dataset).
            if resp.status_code in (401, 403):
                return CollectorHealthCheck(
                    collector_id=self.collector_id,
                    collector_version=self.collector_version,
                    status=CollectorStatus.FAILURE,
                    checked_at=datetime.now(tz=UTC),
                    latency_ms=latency,
                    error_message=(
                        f"Chaos API returned HTTP {resp.status_code} — "
                        "API key may be missing or invalid"
                    ),
                )
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=(
                    CollectorStatus.SUCCESS
                    if resp.status_code < 500  # noqa: PLR2004
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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    async def _fetch_subdomains(self, url: str) -> list[str]:
        """Fetch subdomains from the Chaos API. Returns a list of labels."""
        with _warnings_mod.catch_warnings():
            _warnings_mod.filterwarnings(
                "ignore", category=DeprecationWarning
            )
            _warnings_mod.filterwarnings(
                "ignore", message="Unverified HTTPS request"
            )
            async with httpx.AsyncClient(
                verify=False,  # noqa: S501
                timeout=self.config.request_timeout_seconds,
                follow_redirects=True,
                max_redirects=3,
            ) as client:
                response = await client.get(
                    url,
                    headers={
                        "User-Agent": self.config.user_agent,
                        **self._get_auth_headers(),
                    },
                )

        response.raise_for_status()
        data = response.json()

        # Handle both response formats:
        # Format 1: {"domain": "example.com", "subdomains": ["www", "mail"]}
        # Format 2: {"subdomains": ["www", "mail"]}
        # Format 3: ["www", "mail"]  (plain list)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("subdomains", [])
        return []


__all__ = [
    "DnsChaosCollector",
]

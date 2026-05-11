"""Cloud storage exposure collector — public bucket/blob enumeration.

A Tier-1 passive collector that probes candidate bucket/container names
across AWS S3, Azure Blob Storage, and GCP Cloud Storage to discover
publicly accessible storage resources belonging to a target organization.

The collector:

1. Takes ORGANIZATION or DOMAIN seeds.
2. Generates candidate bucket names via a name-permutation engine
   (org-based and domain-based suffixes).
3. Probes each candidate across all three cloud providers using HTTP HEAD
   requests.
4. If a bucket exists and is publicly listable, parses the listing to
   inventory objects and flag sensitive files.
5. Returns ``CLOUD_IP_RANGE`` observations (the closest existing observation
   type for cloud resource discovery) with cloud-storage-specific structured
   payloads.

Rate limiting: max 5 concurrent probes via ``asyncio.Semaphore`` with a 0.2s
inter-probe delay.

Dependencies: ``httpx`` for async HTTP (in project deps).
"""

from __future__ import annotations

import asyncio
import logging
import time
import warnings
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
from expose.pipeline.bucket_parser import (
    BucketAnalysis,
    classify_objects,
    parse_azure_listing,
    parse_gcp_listing,
    parse_s3_listing,
)
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

# Concurrency and rate-limiting defaults.
_DEFAULT_MAX_CONCURRENT = 5
_DEFAULT_PROBE_DELAY = 0.2  # seconds between probes
_DEFAULT_PROBE_TIMEOUT = 10.0  # per-probe HTTP timeout

# Health-check target — S3 is the most reliably reachable.
_HEALTH_CHECK_URL = "https://s3.amazonaws.com/"

# Cloud provider probe URL templates.
_PROVIDER_URLS: dict[str, str] = {
    "aws": "https://{name}.s3.amazonaws.com/",
    "azure": "https://{name}.blob.core.windows.net/",
    "gcp": "https://storage.googleapis.com/{name}/",
}

# Bucket-name suffixes for the permutation engine.
_SUFFIXES: list[str] = [
    "",
    "-backups",
    "-data",
    "-assets",
    "-staging",
    "-dev",
    "-logs",
    "-config",
    "-media",
    "-static",
    "-public",
    "-cdn",
    "-files",
    "-uploads",
    "-archive",
    "-backup",
    "-prod",
    "-production",
    "-test",
    "-internal",
]

# Common-word blocklist — bare names that are overwhelmingly false positives.
# Only the bare word is blocked; compound names like ``cyberark-dev`` are fine.
_COMMON_WORD_BLOCKLIST: frozenset[str] = frozenset({
    "www",
    "api",
    "cdn",
    "mail",
    "ftp",
    "dev",
    "test",
    "staging",
    "prod",
    "app",
    "static",
    "assets",
    "media",
    "files",
    "data",
    "backup",
    "logs",
    "config",
})


def _extract_org_from_domain(domain: str) -> str:
    """Extract the second-level domain label as the org-like base.

    Strips common prefixes (``www.``, ``api.``, etc.) and returns the label
    immediately before the TLD.  For simple two-label domains this is the
    first label; for deeper subdomains the second-to-last label is used.

    Examples::

        www.cyberark.com      -> cyberark
        api.staging.acme.com  -> acme
        cyberark.com          -> cyberark
        cyberark.co.uk        -> cyberark   (two-part TLD heuristic)
    """
    labels = domain.lower().split(".")
    # Need at least two labels (name + TLD).
    if len(labels) < 2:  # noqa: PLR2004
        return labels[0]

    # Heuristic for two-part TLDs (co.uk, com.au, co.jp, etc.).
    _TWO_PART_TLDS = {"co", "com", "org", "net", "ac", "gov", "edu"}
    if len(labels) >= 3 and labels[-2] in _TWO_PART_TLDS:  # noqa: PLR2004
        # e.g. ["cyberark", "co", "uk"] -> "cyberark"
        return labels[-3]

    # Standard case: label immediately before the TLD.
    # e.g. ["www", "cyberark", "com"] -> "cyberark"
    # e.g. ["cyberark", "com"] -> "cyberark"
    return labels[-2]


def generate_bucket_names(org_name: str, domain: str | None = None) -> list[str]:
    """Generate candidate bucket/container names from org and domain.

    The base name is derived from the organization name (lowercased, spaces
    and underscores replaced with hyphens). Each suffix from ``_SUFFIXES``
    is appended to produce candidates.

    If a domain is provided, the second-level domain label (e.g.,
    ``cyberark`` from ``www.cyberark.com``) is used as an additional base,
    with the first 10 suffixes appended — but only if it differs from the
    org-derived base to avoid duplicate candidates.

    Bare candidates matching ``_COMMON_WORD_BLOCKLIST`` (e.g., ``www``,
    ``dev``, ``api``) are filtered out to reduce false positives.

    Returns a deduplicated list preserving insertion order.
    """
    base = org_name.lower().replace(" ", "-").replace("_", "-")
    candidates: list[str] = [f"{base}{s}" for s in _SUFFIXES]

    if domain:
        domain_base = _extract_org_from_domain(domain)
        # Only add domain-based candidates if they differ from org base.
        if domain_base != base:
            candidates.extend(f"{domain_base}{s}" for s in _SUFFIXES[:10])

    # Deduplicate while preserving order.
    deduped = list(dict.fromkeys(candidates))

    # Filter out bare common-word candidates (false-positive magnets).
    return [c for c in deduped if c not in _COMMON_WORD_BLOCKLIST]


@register_collector
class CloudStorageExposureCollector(Collector):
    """Discover publicly accessible cloud storage buckets/containers.

    Class-level metadata:

    - ``collector_id = "cloud-storage-exposure"``
    - Tier 1 (passive probing via public endpoints)
    - No credentials required
    """

    collector_id: str = "cloud-storage-exposure"
    collector_version: str = "0.1.0"
    display_name: str = "Cloud Storage Exposure"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None
    technique_ids: ClassVar[list[str]] = ["T1526"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        self._max_concurrent: int = int(config.extra.get("max_concurrent", _DEFAULT_MAX_CONCURRENT))
        self._probe_delay: float = float(config.extra.get("probe_delay", _DEFAULT_PROBE_DELAY))
        self._probe_timeout: float = float(
            config.extra.get("probe_timeout", _DEFAULT_PROBE_TIMEOUT)
        )

    # ------------------------------------------------------------------
    # expand
    # ------------------------------------------------------------------
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Probe cloud storage for each candidate bucket name.

        Accepts ``SeedType.ORGANIZATION`` and ``SeedType.DOMAIN`` seeds;
        all other seed types are silently skipped.
        """
        if seed.seed_type == SeedType.ORGANIZATION:
            org_name = seed.value
            domain = seed.properties.get("domain")
        elif seed.seed_type == SeedType.DOMAIN:
            # Extract second-level domain as the org-like base, not the
            # first label (which may be "www", "api", etc.).
            org_name = _extract_org_from_domain(seed.value)
            domain = seed.value
        else:
            return

        candidates = generate_bucket_names(org_name, domain)
        semaphore = asyncio.Semaphore(self._max_concurrent)

        # Probe all candidates concurrently (bounded).
        tasks = [self._probe_bucket(name, semaphore) for name in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.debug("Probe failed: %s", result)
                continue
            if result is None:
                continue

            analysis = result
            yield self._make_observation(seed, analysis)

    # ------------------------------------------------------------------
    # health_check
    # ------------------------------------------------------------------
    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe against S3 endpoint."""
        start = time.monotonic()
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=DeprecationWarning)
                warnings.filterwarnings("ignore", message="Unverified HTTPS request")
                async with httpx.AsyncClient(verify=False) as client:  # noqa: S501
                    resp = await client.head(
                        _HEALTH_CHECK_URL,
                        timeout=self.config.request_timeout_seconds,
                    )
            latency = (time.monotonic() - start) * 1000.0
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
    async def _probe_bucket(
        self,
        name: str,
        semaphore: asyncio.Semaphore,
    ) -> BucketAnalysis | None:
        """Probe a single bucket name across all cloud providers.

        Returns the first ``BucketAnalysis`` for a bucket that exists,
        or ``None`` if the name doesn't exist on any provider.
        """
        async with semaphore:
            for provider, url_template in _PROVIDER_URLS.items():
                url = url_template.format(name=name)
                analysis = await self._probe_single(provider, name, url)
                if analysis is not None:
                    return analysis
                await asyncio.sleep(self._probe_delay)
        return None

    async def _probe_single(
        self,
        provider: str,
        name: str,
        url: str,
    ) -> BucketAnalysis | None:
        """Issue a HEAD (then optionally GET) to a single provider URL.

        Returns a ``BucketAnalysis`` if the bucket exists (HTTP 200 or 403),
        or ``None`` if not found (404 or connection error).
        """
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=DeprecationWarning)
                warnings.filterwarnings("ignore", message="Unverified HTTPS request")
                async with httpx.AsyncClient(
                    verify=False,  # noqa: S501
                    timeout=self._probe_timeout,
                    follow_redirects=True,
                ) as client:
                    client.headers["User-Agent"] = self.config.user_agent
                    resp = await client.head(url)

                    if resp.status_code == 404:  # noqa: PLR2004
                        return None

                    is_public = resp.status_code == 200  # noqa: PLR2004
                    is_listable = False
                    sensitive_objects: list[Any] = []
                    total_objects = 0
                    extracted_endpoints: list[str] = []

                    # If publicly accessible, try to list contents.
                    if is_public:
                        listing_result = await self._try_list_contents(client, provider, name, url)
                        if listing_result is not None:
                            is_listable = True
                            total_objects = listing_result["total_objects"]
                            sensitive_objects = listing_result["sensitive_objects"]
                            extracted_endpoints = listing_result["extracted_endpoints"]

                    return BucketAnalysis(
                        cloud_provider=provider,
                        bucket_name=name,
                        is_public=is_public,
                        is_listable=is_listable,
                        total_objects=total_objects,
                        sensitive_objects=sensitive_objects,
                        extracted_endpoints=extracted_endpoints,
                    )

        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, OSError):
            return None

    async def _try_list_contents(
        self,
        client: httpx.AsyncClient,
        provider: str,
        name: str,
        url: str,
    ) -> dict[str, Any] | None:
        """Attempt to GET and parse a bucket listing.

        Returns a dict with ``total_objects``, ``sensitive_objects``, and
        ``extracted_endpoints`` if the listing is parseable, or ``None``.
        """
        try:
            resp = await client.get(url)
            if resp.status_code != 200:  # noqa: PLR2004
                return None

            body = resp.text
            if provider == "aws":
                objects = parse_s3_listing(body)
            elif provider == "azure":
                objects = parse_azure_listing(body)
            elif provider == "gcp":
                objects = parse_gcp_listing(body)
            else:
                return None

            if not objects:
                return None

            classified = classify_objects(objects)
            sensitive = [obj for obj in classified if obj.is_sensitive]

            return {
                "total_objects": len(objects),
                "sensitive_objects": sensitive,
                "extracted_endpoints": _extract_endpoints(objects, provider, name),
            }

        except Exception:
            logger.debug("Failed to list contents for %s/%s", provider, name)
            return None

    def _make_observation(
        self,
        seed: Seed,
        analysis: BucketAnalysis,
    ) -> Observation:
        """Build an ``Observation`` from a ``BucketAnalysis``."""
        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.CLOUD_IP_RANGE,
            subject=ObservationSubject(
                identifier_type=IdentifierType.CLOUD_RESOURCE_ID,
                identifier_value=f"{analysis.cloud_provider}:{analysis.bucket_name}",
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload={
                "discovery_type": "cloud_storage_exposure",
                "cloud_provider": analysis.cloud_provider,
                "bucket_name": analysis.bucket_name,
                "is_public": analysis.is_public,
                "is_listable": analysis.is_listable,
                "total_objects": analysis.total_objects,
                "sensitive_object_count": len(analysis.sensitive_objects),
                "sensitive_objects": [
                    {
                        "key": obj.key,
                        "size_bytes": obj.size_bytes,
                        "sensitivity_reason": obj.sensitivity_reason,
                    }
                    for obj in analysis.sensitive_objects
                ],
                "extracted_endpoints": analysis.extracted_endpoints,
            },
        )


def _extract_endpoints(
    objects: list[Any],
    provider: str,
    bucket_name: str,
) -> list[str]:
    """Extract direct URLs from object keys for endpoint discovery.

    Returns URLs for objects whose keys suggest API specs or configuration
    files that may contain endpoint information.
    """
    endpoints: list[str] = []
    endpoint_patterns = (
        "swagger.json",
        "swagger.yaml",
        "openapi.json",
        "openapi.yaml",
        "config.json",
        "config.yaml",
    )

    for obj in objects:
        key = obj.key
        if any(key.endswith(p) for p in endpoint_patterns):
            if provider == "aws":
                endpoints.append(f"https://{bucket_name}.s3.amazonaws.com/{key}")
            elif provider == "azure":
                endpoints.append(f"https://{bucket_name}.blob.core.windows.net/{key}")
            elif provider == "gcp":
                endpoints.append(f"https://storage.googleapis.com/{bucket_name}/{key}")

    return endpoints


__all__ = [
    "CloudStorageExposureCollector",
    "generate_bucket_names",
    "_extract_org_from_domain",
    "_COMMON_WORD_BLOCKLIST",
]

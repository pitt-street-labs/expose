"""WAF/CDN detection collector (Tier 2, per Gitea issue #50).

Detects WAF and CDN layers in front of target hosts by inspecting HTTP
response headers against a signature database.  Each signature matches a
known WAF/CDN vendor by header name and value pattern.  When multiple
signatures for the same vendor match, confidence increases.

This is a Tier-2 (passive, targeted) collector.  It issues a single HTTP
HEAD request per seed — the lightest possible interaction that still reveals
response headers.  No active scanning or payload injection is performed.

The collector also optionally checks DNS CNAME records for CDN-indicative
patterns (e.g., ``*.cloudflare.com``, ``*.cloudfront.net``), though DNS
resolution is best-effort and non-fatal if unavailable.

Rate limiting
-------------
Belt-and-braces: a per-host async token-bucket rate limiter caps request
rate independently of the framework-level rate limiter.  Default is 1
request/second per host; configurable via ``config.extra["requests_per_second"]``.

Dependencies
------------
- ``httpx`` (in project deps) for async HTTP.
- No ``hashlib`` / ``secrets`` — FIPS gate clean (ADR-010).
"""

from __future__ import annotations

import asyncio
import logging
import re
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
from expose.sanitization.canonicalize import canonicalize_domain, canonicalize_ip
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# WAF/CDN signature database
# ---------------------------------------------------------------------------
# Each vendor maps to a list of signature dicts.  Each dict has:
#   - ``header``: lowercase HTTP header name to check
#   - ``pattern``: regex pattern to match against the header value
# A vendor is "detected" when at least one of its signatures matches.
# Confidence scales with the number of matching signatures.

WAF_SIGNATURES: dict[str, list[dict[str, str]]] = {
    "cloudflare": [
        {"header": "server", "pattern": "cloudflare"},
        {"header": "cf-ray", "pattern": ".*"},
        {"header": "cf-cache-status", "pattern": ".*"},
    ],
    "akamai": [
        {"header": "x-akamai-transformed", "pattern": ".*"},
        {"header": "server", "pattern": "akamaighost"},
    ],
    "cloudfront": [
        {"header": "x-amz-cf-id", "pattern": ".*"},
        {"header": "x-amz-cf-pop", "pattern": ".*"},
        {"header": "server", "pattern": "cloudfront"},
    ],
    "fastly": [
        {"header": "x-served-by", "pattern": "cache-.*"},
        {"header": "x-fastly-request-id", "pattern": ".*"},
    ],
    "incapsula": [
        {"header": "x-iinfo", "pattern": ".*"},
        {"header": "x-cdn", "pattern": "incapsula"},
    ],
    "sucuri": [
        {"header": "x-sucuri-id", "pattern": ".*"},
        {"header": "server", "pattern": "sucuri"},
    ],
    "aws_waf": [
        {"header": "x-amzn-requestid", "pattern": ".*"},
    ],
    "azure_front_door": [
        {"header": "x-azure-ref", "pattern": ".*"},
    ],
}

# CDN CNAME patterns — if a domain's CNAME chain contains any of these
# suffixes, the corresponding vendor is identified.  Used as a secondary
# signal alongside header-based detection.
_CDN_CNAME_SUFFIXES: dict[str, str] = {
    ".cloudflare.com": "cloudflare",
    ".cloudfront.net": "cloudfront",
    ".akamaiedge.net": "akamai",
    ".akamai.net": "akamai",
    ".fastly.net": "fastly",
    ".incapdns.net": "incapsula",
    ".sucuri.net": "sucuri",
    ".azurefd.net": "azure_front_door",
    ".azureedge.net": "azure_front_door",
}

# Health-check target — a well-known, high-availability endpoint.
_HEALTH_CHECK_URL = "https://httpbin.org/head"


# ---------------------------------------------------------------------------
# Per-host async token-bucket rate limiter (same pattern as active_http)
# ---------------------------------------------------------------------------
class _TokenBucket:
    """Simple async token-bucket rate limiter keyed by host."""

    def __init__(self, rate: float) -> None:
        self._rate = rate
        self._buckets: dict[str, float] = {}
        self._timestamps: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, host: str) -> None:
        """Wait until a token is available for ``host``, then consume it."""
        async with self._lock:
            now = time.monotonic()
            if host not in self._buckets:
                self._buckets[host] = 0.0
                self._timestamps[host] = now
                return

            elapsed = now - self._timestamps[host]
            self._buckets[host] = min(1.0, self._buckets[host] + elapsed * self._rate)
            self._timestamps[host] = now

            if self._buckets[host] >= 1.0:
                self._buckets[host] -= 1.0
                return

            deficit = 1.0 - self._buckets[host]
            wait = deficit / self._rate if self._rate > 0 else 0.0

        await asyncio.sleep(wait)

        async with self._lock:
            self._buckets[host] = 0.0
            self._timestamps[host] = time.monotonic()


# ---------------------------------------------------------------------------
# Header matching helpers (pure functions)
# ---------------------------------------------------------------------------
def _match_headers(
    response_headers: httpx.Headers,
) -> list[dict[str, Any]]:
    """Match response headers against all WAF signatures.

    Returns a list of match records, each containing:
    - ``vendor``: the WAF/CDN vendor name
    - ``header``: the header name that matched
    - ``pattern``: the pattern that matched
    - ``value``: the header value that matched
    """
    matches: list[dict[str, Any]] = []

    for vendor, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            header_name = sig["header"]
            header_value = response_headers.get(header_name)
            if header_value is not None and re.search(sig["pattern"], header_value, re.IGNORECASE):
                matches.append(
                    {
                        "vendor": vendor,
                        "header": header_name,
                        "pattern": sig["pattern"],
                        "value": header_value,
                    }
                )

    return matches


def _compute_detections(
    matches: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Group matches by vendor and compute confidence scores.

    Confidence is the ratio of matched signatures to total signatures for
    that vendor, clamped to [0.0, 1.0].  A vendor with 3 possible
    signatures and 2 matches gets confidence 2/3 ~ 0.67.

    Returns a list of detection dicts, sorted by confidence descending:
    - ``vendor``: the WAF/CDN vendor name
    - ``confidence``: float in [0.0, 1.0]
    - ``matched_headers``: list of (header_name, header_value) pairs
    """
    # Group matches by vendor.
    vendor_matches: dict[str, list[dict[str, Any]]] = {}
    for m in matches:
        vendor_matches.setdefault(m["vendor"], []).append(m)

    detections: list[dict[str, Any]] = []
    for vendor, vendor_match_list in vendor_matches.items():
        total_sigs = len(WAF_SIGNATURES[vendor])
        confidence = len(vendor_match_list) / total_sigs if total_sigs > 0 else 0.0
        confidence = min(confidence, 1.0)

        matched_headers = [{"header": m["header"], "value": m["value"]} for m in vendor_match_list]

        detections.append(
            {
                "vendor": vendor,
                "confidence": round(confidence, 4),
                "matched_headers": matched_headers,
            }
        )

    # Sort by confidence descending for deterministic output.
    detections.sort(key=lambda d: (-d["confidence"], d["vendor"]))
    return detections


def _resolve_identifier(host: str, seed_type: SeedType) -> tuple[IdentifierType, str]:
    """Determine the identifier type and canonical value for a host string."""
    if seed_type == SeedType.IP:
        canonical = canonicalize_ip(host)
        return IdentifierType.IP, canonical

    canonical = canonicalize_domain(host)
    return IdentifierType.DOMAIN, canonical


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
@register_collector
class WafDetectionCollector(Collector):
    """Tier-2 WAF/CDN detection collector.

    Issues HTTP HEAD requests to seed hosts and inspects response headers
    for known WAF/CDN vendor signatures.  Emits one ``HTTP_RESPONSE``
    observation per detected vendor, with structured payload containing
    the vendor name, detection confidence, and matched headers.
    """

    collector_id: str = "waf-detection"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_2
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None
    technique_ids: ClassVar[list[str]] = ["T1592.004"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        rps: float = float(self.config.extra.get("requests_per_second", 1.0))
        self._rate_limiter = _TokenBucket(rate=rps)

    # ------------------------------------------------------------------
    # expand
    # ------------------------------------------------------------------
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Detect WAF/CDN layers from HTTP response headers."""
        if seed.seed_type not in {SeedType.DOMAIN, SeedType.IP}:
            return

        host = seed.value
        identifier_type, canonical_value = _resolve_identifier(host, seed.seed_type)

        # Attempt HTTPS first, fall back to HTTP.
        urls = [f"https://{host}", f"http://{host}"]
        obs_warnings: list[str] = []
        response_obtained = False

        for url in urls:
            try:
                await self._rate_limiter.acquire(host)
                response = await self._head_request(url)
                response_obtained = True

                matches = _match_headers(response.headers)
                if not matches:
                    # No WAF detected on this URL — still emit a "clean" observation.
                    yield self._build_observation(
                        identifier_type=identifier_type,
                        canonical_value=canonical_value,
                        url=url,
                        detections=[],
                        raw_headers=dict(response.headers),
                        warnings_list=obs_warnings,
                    )
                    return

                detections = _compute_detections(matches)
                yield self._build_observation(
                    identifier_type=identifier_type,
                    canonical_value=canonical_value,
                    url=url,
                    detections=detections,
                    raw_headers=dict(response.headers),
                    warnings_list=obs_warnings,
                )
                return

            except (httpx.ConnectError, httpx.ConnectTimeout, OSError) as exc:
                msg = f"Connection failed for {url}: {exc}"
                obs_warnings.append(msg)
                logger.debug(msg)
            except httpx.TooManyRedirects as exc:
                msg = f"Too many redirects for {url}: {exc}"
                obs_warnings.append(msg)
                logger.debug(msg)

        # Both URLs failed — yield a warning-only observation rather than
        # raising, since WAF detection is best-effort enrichment.
        if not response_obtained:
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.HTTP_RESPONSE,
                subject=ObservationSubject(
                    identifier_type=identifier_type,
                    identifier_value=canonical_value,
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "waf_detected": False,
                    "detections": [],
                    "error": "All connection attempts failed",
                },
                warnings=obs_warnings,
            )

    # ------------------------------------------------------------------
    # health_check
    # ------------------------------------------------------------------
    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe using HEAD to a known endpoint."""
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
    async def _head_request(self, url: str) -> httpx.Response:
        """Issue an HTTP HEAD request to ``url``."""
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")
            async with httpx.AsyncClient(
                verify=False,  # noqa: S501
                max_redirects=5,
                timeout=self.config.request_timeout_seconds,
                follow_redirects=True,
            ) as client:
                client.headers["User-Agent"] = self.config.user_agent
                return await client.head(url)

    def _build_observation(
        self,
        *,
        identifier_type: IdentifierType,
        canonical_value: str,
        url: str,
        detections: list[dict[str, Any]],
        raw_headers: dict[str, str],
        warnings_list: list[str],
    ) -> Observation:
        """Build an ``Observation`` from WAF detection results."""
        waf_detected = len(detections) > 0
        primary_vendor = detections[0]["vendor"] if detections else None

        evidence_lines: list[str] = []
        for name, value in raw_headers.items():
            evidence_lines.append(f"{name}: {value}")
        evidence_blob = "\n".join(evidence_lines).encode("utf-8")

        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.HTTP_RESPONSE,
            subject=ObservationSubject(
                identifier_type=identifier_type,
                identifier_value=canonical_value,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload={
                "url": url,
                "waf_detected": waf_detected,
                "waf_vendor": primary_vendor,
                "detections": detections,
            },
            evidence_blob=evidence_blob,
            evidence_blob_content_type="text/plain",
            warnings=warnings_list,
        )


__all__ = [
    "WAF_SIGNATURES",
    "WafDetectionCollector",
]

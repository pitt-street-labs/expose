"""Active HTTP fingerprint collector (Tier 3, per SPEC §6.3 / Sprint 4).

Probes target hosts on ports 80 and 443 to capture HTTP response metadata:
server headers, page titles, security-relevant headers, redirect chains,
and response banners.  Observations flow through the sanitization layer
(SPEC §7) before being emitted.

This is a Tier-3 (active) collector.  Tier-3 dispatch gating is enforced
*upstream* by the dispatcher — this collector does NOT self-gate.

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
    CollectorSourceUnreachableError,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import register_collector
from expose.collectors.tiers import CollectorTier
from expose.sanitization.canonicalize import canonicalize_domain, canonicalize_ip
from expose.sanitization.text import SanitizationFieldKind, sanitize_field
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

# Title extraction regex — simple, no HTML parser dependency per spec.
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Maximum bytes of response body to scan for <title> extraction.
_TITLE_SCAN_CAP = 2048

# Maximum bytes of response body to include in the banner field.
_BANNER_CAP = 4096

# Security-relevant headers to capture from responses.
_SECURITY_HEADERS = frozenset(
    {
        "strict-transport-security",
        "x-frame-options",
        "content-security-policy",
        "x-content-type-options",
        "x-xss-protection",
        "permissions-policy",
    }
)

# Health-check target — a well-known, high-availability endpoint.
_HEALTH_CHECK_URL = "https://httpbin.org/head"


# ---------------------------------------------------------------------------
# Per-host async token-bucket rate limiter
# ---------------------------------------------------------------------------
class _TokenBucket:
    """Simple async token-bucket rate limiter keyed by host.

    Each host gets its own bucket with ``rate`` tokens replenished per second
    and a burst capacity of 1.  Callers ``await bucket.acquire(host)`` before
    issuing a request.
    """

    def __init__(self, rate: float) -> None:
        self._rate = rate
        self._buckets: dict[str, float] = {}  # host -> available tokens
        self._timestamps: dict[str, float] = {}  # host -> last refill time
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

            # Capture deficit under lock before releasing for sleep.
            deficit = 1.0 - self._buckets[host]
            wait = deficit / self._rate if self._rate > 0 else 0.0

        await asyncio.sleep(wait)

        async with self._lock:
            self._buckets[host] = 0.0
            self._timestamps[host] = time.monotonic()


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
@register_collector
class ActiveHttpCollector(Collector):
    """Tier-3 active HTTP fingerprinting collector.

    Probes HTTP (port 80) and HTTPS (port 443) for each seed, emitting
    ``ObservationType.HTTP_RESPONSE`` observations with sanitized metadata.
    """

    collector_id: str = "active-http-fingerprint"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_3
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
        """Probe HTTP/HTTPS on the seed host and yield observations."""
        if seed.seed_type not in {SeedType.DOMAIN, SeedType.IP}:
            return

        host = seed.value
        urls = [f"https://{host}", f"http://{host}"]

        # Determine canonical identifier for observation subject.
        identifier_type, canonical_value = _resolve_identifier(host, seed.seed_type)

        all_failed = True
        warnings_list: list[str] = []

        for url in urls:
            try:
                await self._rate_limiter.acquire(host)
                observation = await self._probe_url(
                    url=url,
                    host=host,
                    identifier_type=identifier_type,
                    canonical_value=canonical_value,
                )
                all_failed = False
                yield observation
            except (httpx.ConnectError, httpx.ConnectTimeout, OSError) as exc:
                msg = f"Connection failed for {url}: {exc}"
                warnings_list.append(msg)
                logger.debug(msg)
            except httpx.TooManyRedirects as exc:
                msg = f"Too many redirects for {url}: {exc}"
                warnings_list.append(msg)
                logger.debug(msg)

        if all_failed:
            raise CollectorSourceUnreachableError(
                f"All probes failed for {host}: {'; '.join(warnings_list)}"
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
                warnings.filterwarnings(
                    "ignore", message="Unverified HTTPS request"
                )
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
    def _egress_httpx_kwargs(self) -> dict[str, Any]:
        """Extract httpx client kwargs from the egress profile, if configured."""
        egress_profile = self.config.extra.get("egress_profile")
        if egress_profile is not None:
            from expose.egress.base import EgressProfile  # noqa: PLC0415

            if isinstance(egress_profile, EgressProfile):
                return egress_profile.configure_httpx_client()
        return {}

    async def _probe_url(
        self,
        *,
        url: str,
        host: str,
        identifier_type: IdentifierType,
        canonical_value: str,
    ) -> Observation:
        """Issue a GET to ``url`` and build an Observation from the response."""
        egress_kwargs = self._egress_httpx_kwargs()
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")
            async with httpx.AsyncClient(
                **egress_kwargs,
                verify=False,  # noqa: S501
                max_redirects=5,
                timeout=self.config.request_timeout_seconds,
                follow_redirects=True,
            ) as client:
                client.headers["User-Agent"] = self.config.user_agent
                response = await client.get(url)

        payload = _build_payload(response)
        evidence = _build_evidence_blob(response)

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
            structured_payload=payload,
            evidence_blob=evidence,
            evidence_blob_content_type="text/plain",
        )


# ---------------------------------------------------------------------------
# Module-level helpers (pure functions, easy to test)
# ---------------------------------------------------------------------------
def _resolve_identifier(
    host: str, seed_type: SeedType
) -> tuple[IdentifierType, str]:
    """Determine the identifier type and canonical value for a host string."""
    if seed_type == SeedType.IP:
        canonical = canonicalize_ip(host)
        return IdentifierType.IP, canonical

    # Domain seed — canonicalize as domain.
    canonical = canonicalize_domain(host)
    return IdentifierType.DOMAIN, canonical


def _extract_title(body_bytes: bytes) -> str | None:
    """Extract ``<title>`` content from the first ``_TITLE_SCAN_CAP`` bytes."""
    try:
        text = body_bytes[:_TITLE_SCAN_CAP].decode("utf-8", errors="replace")
    except Exception:
        return None
    match = _TITLE_RE.search(text)
    if match:
        raw_title = match.group(1).strip()
        if raw_title:
            return sanitize_field(raw_title, SanitizationFieldKind.HTTP_PAGE_TITLE).value
    return None


def _build_redirect_chain(response: httpx.Response) -> list[str]:
    """Build a sanitized list of URLs from the redirect history."""
    chain: list[str] = []
    for r in response.history:
        raw_url = str(r.url)
        sanitized = sanitize_field(raw_url, SanitizationFieldKind.HTTP_REDIRECT_TARGET).value
        chain.append(sanitized)
    return chain


def _extract_security_headers(response: httpx.Response) -> dict[str, str]:
    """Extract security-relevant headers from the response."""
    headers: dict[str, str] = {}
    for name in _SECURITY_HEADERS:
        value = response.headers.get(name)
        if value is not None:
            headers[name] = value
    return headers


def _build_payload(response: httpx.Response) -> dict[str, Any]:
    """Build the ``structured_payload`` dict from a completed response."""
    body = response.content

    # Server header — sanitized, nullable.
    raw_server = response.headers.get("server")
    server_header: str | None = None
    if raw_server is not None:
        server_header = sanitize_field(
            raw_server, SanitizationFieldKind.HTTP_SERVER_HEADER
        ).value

    # Content-Type — sanitized.
    raw_ct = response.headers.get("content-type")
    content_type: str | None = None
    if raw_ct is not None:
        content_type = sanitize_field(raw_ct, SanitizationFieldKind.GENERIC).value

    # Title
    title = _extract_title(body)

    # Security headers
    sec_headers = _extract_security_headers(response)

    # Redirect chain
    redirect_chain = _build_redirect_chain(response)

    # Banner — first _BANNER_CAP bytes, sanitized.
    banner_bytes = body[:_BANNER_CAP]
    banner_text = banner_bytes.decode("utf-8", errors="replace")
    banner = sanitize_field(banner_text, SanitizationFieldKind.HTTP_BANNER).value

    # Final URL — sanitized.
    final_url = sanitize_field(
        str(response.url), SanitizationFieldKind.HTTP_REDIRECT_TARGET
    ).value

    return {
        "url": final_url,
        "status_code": response.status_code,
        "server_header": server_header,
        "content_type": content_type,
        "title": title,
        "headers": sec_headers,
        "redirect_chain": redirect_chain,
        "banner": banner,
    }


def _build_evidence_blob(response: httpx.Response) -> bytes:
    """Serialize raw response headers as the evidence blob."""
    lines: list[str] = []
    for name, value in response.headers.items():
        lines.append(f"{name}: {value}")
    return "\n".join(lines).encode("utf-8")


__all__ = [
    "ActiveHttpCollector",
]

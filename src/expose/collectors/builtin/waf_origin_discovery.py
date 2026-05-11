"""WAF Origin IP Discovery collector (Tier 2, passive).

Discovers origin server IPs behind CDN/WAF layers using passive techniques:

1. **CDN header leakage** — HTTP responses may leak origin IPs in headers
   such as ``X-Forwarded-For``, ``X-Real-IP``, ``X-Originating-IP``, and
   ``CF-Connecting-IP``.
2. **Certificate SAN analysis** — Self-signed or origin certs may contain the
   origin IP in their Subject Alternative Name (SAN) fields.
3. **Subdomain enumeration** — Subdomains like ``ftp.*``, ``mail.*``,
   ``direct.*``, ``cpanel.*`` frequently resolve directly to origin IPs
   without CDN proxying.
4. **MX record analysis** — Mail servers often share hosting infrastructure
   with the web origin, revealing the origin IP.
5. **DNS history** — Historical A/AAAA records predating CDN adoption may
   point to the origin IP.

This is a Tier-2 (passive, targeted) collector. It issues lightweight HTTP
HEAD requests and DNS lookups — no active port scanning, no payload injection.

CDN/WAF vendor detection reuses the signature database from
``waf_detection.py`` and adds vendor-specific header leakage patterns.

Rate limiting
-------------
Belt-and-braces: a per-host async token-bucket rate limiter caps request
rate independently of the framework-level rate limiter. Default is 1
request/second; configurable via ``config.extra["requests_per_second"]``.

Dependencies
------------
- ``httpx`` (in project deps) for async HTTP.
- No ``hashlib`` / ``secrets`` — FIPS gate clean (ADR-010).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import ssl
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
from expose.collectors.builtin.waf_detection import (
    WAF_SIGNATURES,
    _match_headers,
    _compute_detections,
)
from expose.collectors.registry import register_collector
from expose.collectors.tiers import CollectorTier
from expose.sanitization.canonicalize import canonicalize_domain, canonicalize_ip
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Origin IP leakage headers
# ---------------------------------------------------------------------------
# Headers that CDN/WAF proxies sometimes copy from the origin response or
# insert themselves, potentially revealing the origin IP.
ORIGIN_LEAK_HEADERS: list[str] = [
    "x-forwarded-for",
    "x-real-ip",
    "x-originating-ip",
    "cf-connecting-ip",
    "x-host",
    "x-forwarded-server",
    "x-backend-server",
    "x-served-by",
    "x-origin-server",
    "x-backend-host",
    "true-client-ip",
]

# ---------------------------------------------------------------------------
# CDN vendor detection (reuses waf_detection signatures)
# ---------------------------------------------------------------------------
CDN_VENDOR_SIGNATURES = WAF_SIGNATURES

# ---------------------------------------------------------------------------
# Subdomain prefixes commonly pointing to origin
# ---------------------------------------------------------------------------
ORIGIN_SUBDOMAIN_PREFIXES: list[str] = [
    "ftp",
    "mail",
    "direct",
    "origin",
    "cpanel",
    "webmail",
    "smtp",
    "pop",
    "imap",
    "staging",
    "dev",
    "test",
    "admin",
    "panel",
]

# ---------------------------------------------------------------------------
# Health-check target
# ---------------------------------------------------------------------------
_HEALTH_CHECK_URL = "https://httpbin.org/head"

# ---------------------------------------------------------------------------
# IP address regex (conservative, used for extracting IPs from header values)
# ---------------------------------------------------------------------------
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def _is_valid_public_ip(ip_str: str) -> bool:
    """Return True if ``ip_str`` is a valid, non-private, non-reserved IP."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return addr.is_global


def _extract_ips_from_value(value: str) -> list[str]:
    """Extract valid public IPv4 addresses from a header value string."""
    candidates = _IPV4_RE.findall(value)
    return [ip for ip in candidates if _is_valid_public_ip(ip)]


# ---------------------------------------------------------------------------
# Per-host async token-bucket rate limiter
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
            self._buckets[host] = min(
                1.0, self._buckets[host] + elapsed * self._rate
            )
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
# Helper: resolve identifier type
# ---------------------------------------------------------------------------
def _resolve_identifier(
    host: str, seed_type: SeedType
) -> tuple[IdentifierType, str]:
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
class WafOriginDiscoveryCollector(Collector):
    """Tier-2 WAF origin IP discovery collector.

    Discovers origin server IPs behind CDN/WAF layers using passive
    techniques: header leakage analysis, certificate SAN inspection,
    subdomain enumeration, MX record analysis, and DNS history checks.

    Emits ``WAF_ORIGIN_DISCOVERY`` observations with structured payloads
    containing ``cdn_vendor``, ``origin_ip_candidates``, ``discovery_method``,
    and ``confidence``.
    """

    collector_id: str = "waf-origin-discovery"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_2
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None
    technique_ids: ClassVar[list[str]] = ["T1592.004", "T1596.001"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        rps: float = float(self.config.extra.get("requests_per_second", 1.0))
        self._rate_limiter = _TokenBucket(rate=rps)
        self._http_client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        """Lazily create and cache a single ``httpx.AsyncClient``."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                verify=False,  # noqa: S501
                max_redirects=5,
                timeout=self.config.request_timeout_seconds,
                follow_redirects=True,
            )
            self._http_client.headers["User-Agent"] = self.config.user_agent
        return self._http_client

    async def close(self) -> None:
        """Close the cached HTTP client, if one exists."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    # ------------------------------------------------------------------
    # expand
    # ------------------------------------------------------------------
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Discover origin IPs behind CDN/WAF for the seed host."""
        if seed.seed_type not in {SeedType.DOMAIN, SeedType.IP}:
            return

        host = seed.value
        identifier_type, canonical_value = _resolve_identifier(
            host, seed.seed_type
        )

        obs_warnings: list[str] = []
        all_candidates: list[dict[str, Any]] = []
        cdn_vendor: str | None = None

        # Build the list of coroutines for phases that apply to this seed.
        coros: list[Any] = [
            self._analyze_headers(host),
            self._analyze_certificate(host),
        ]
        if seed.seed_type == SeedType.DOMAIN:
            coros.append(self._enumerate_subdomains(host))
            coros.append(self._analyze_mx_records(host))

        results = await asyncio.gather(*coros, return_exceptions=True)

        # --- Phase 1: HTTP header analysis ---
        header_result = results[0]
        if isinstance(header_result, BaseException):
            obs_warnings.append(
                f"Header analysis raised: {header_result}"
            )
        else:
            header_candidates, detected_vendor, header_warnings = header_result
            obs_warnings.extend(header_warnings)
            all_candidates.extend(header_candidates)
            if detected_vendor:
                cdn_vendor = detected_vendor

        # --- Phase 2: Certificate SAN analysis ---
        cert_result = results[1]
        if isinstance(cert_result, BaseException):
            obs_warnings.append(
                f"Certificate analysis raised: {cert_result}"
            )
        else:
            cert_candidates, cert_warnings = cert_result
            obs_warnings.extend(cert_warnings)
            all_candidates.extend(cert_candidates)

        # --- Phase 3 & 4: Subdomain + MX (domain seeds only) ---
        if seed.seed_type == SeedType.DOMAIN:
            sub_result = results[2]
            if isinstance(sub_result, BaseException):
                obs_warnings.append(
                    f"Subdomain enumeration raised: {sub_result}"
                )
            else:
                sub_candidates, sub_warnings = sub_result
                obs_warnings.extend(sub_warnings)
                all_candidates.extend(sub_candidates)

            mx_result = results[3]
            if isinstance(mx_result, BaseException):
                obs_warnings.append(
                    f"MX record analysis raised: {mx_result}"
                )
            else:
                mx_candidates, mx_warnings = mx_result
                obs_warnings.extend(mx_warnings)
                all_candidates.extend(mx_candidates)

        # Deduplicate candidates by IP
        seen_ips: set[str] = set()
        unique_candidates: list[dict[str, Any]] = []
        for candidate in all_candidates:
            ip = candidate["ip"]
            if ip not in seen_ips:
                seen_ips.add(ip)
                unique_candidates.append(candidate)
            else:
                # Boost confidence for IPs found via multiple methods
                for existing in unique_candidates:
                    if existing["ip"] == ip:
                        existing["confidence"] = min(
                            1.0, existing["confidence"] + 0.1
                        )
                        if candidate["method"] not in existing.get(
                            "additional_methods", []
                        ):
                            existing.setdefault("additional_methods", []).append(
                                candidate["method"]
                            )
                        break

        # Build the origin_ip_candidates list for the payload
        origin_ip_candidates: list[dict[str, Any]] = []
        for c in unique_candidates:
            entry: dict[str, Any] = {
                "ip": c["ip"],
                "discovery_method": c["method"],
                "confidence": round(c["confidence"], 4),
            }
            if c.get("detail"):
                entry["detail"] = c["detail"]
            if c.get("additional_methods"):
                entry["additional_methods"] = c["additional_methods"]
            origin_ip_candidates.append(entry)

        # Sort by confidence descending
        origin_ip_candidates.sort(
            key=lambda x: (-x["confidence"], x["ip"])
        )

        yield Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.WAF_ORIGIN_DISCOVERY,
            subject=ObservationSubject(
                identifier_type=identifier_type,
                identifier_value=canonical_value,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload={
                "cdn_vendor": cdn_vendor,
                "origin_ip_candidates": origin_ip_candidates,
                "discovery_methods_used": self._methods_used(
                    origin_ip_candidates
                ),
                "total_candidates": len(origin_ip_candidates),
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
                warnings.filterwarnings(
                    "ignore", category=DeprecationWarning
                )
                warnings.filterwarnings(
                    "ignore", message="Unverified HTTPS request"
                )
                client = self._get_client()
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
    # Phase 1: HTTP header leakage analysis
    # ------------------------------------------------------------------
    async def _analyze_headers(
        self, host: str
    ) -> tuple[list[dict[str, Any]], str | None, list[str]]:
        """Check HTTP response headers for origin IP leakage.

        Returns (candidates, cdn_vendor, warnings).
        """
        candidates: list[dict[str, Any]] = []
        cdn_vendor: str | None = None
        warn_list: list[str] = []

        urls = [f"https://{host}", f"http://{host}"]
        for url in urls:
            try:
                await self._rate_limiter.acquire(host)
                response = await self._head_request(url)

                # Detect CDN vendor from response headers
                matches = _match_headers(response.headers)
                if matches:
                    detections = _compute_detections(matches)
                    if detections:
                        cdn_vendor = detections[0]["vendor"]

                # Check for origin IP leakage in headers
                for header_name in ORIGIN_LEAK_HEADERS:
                    header_value = response.headers.get(header_name)
                    if header_value is None:
                        continue
                    ips = _extract_ips_from_value(header_value)
                    for ip in ips:
                        candidates.append(
                            {
                                "ip": ip,
                                "method": "header_leakage",
                                "confidence": 0.7,
                                "detail": f"{header_name}: {header_value}",
                            }
                        )
                # Only need one successful URL
                return candidates, cdn_vendor, warn_list

            except (
                httpx.ConnectError,
                httpx.ConnectTimeout,
                httpx.TooManyRedirects,
                OSError,
            ) as exc:
                msg = f"Header analysis failed for {url}: {exc}"
                warn_list.append(msg)
                logger.debug(msg)

        return candidates, cdn_vendor, warn_list

    # ------------------------------------------------------------------
    # Phase 2: Certificate SAN analysis
    # ------------------------------------------------------------------
    async def _analyze_certificate(
        self, host: str
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Check TLS certificate SANs for origin IP addresses.

        Returns (candidates, warnings).
        """
        candidates: list[dict[str, Any]] = []
        warn_list: list[str] = []

        try:
            cert_info = await self._get_certificate_sans(host)
            for san in cert_info:
                ips = _extract_ips_from_value(san)
                for ip in ips:
                    candidates.append(
                        {
                            "ip": ip,
                            "method": "certificate_san",
                            "confidence": 0.6,
                            "detail": f"SAN: {san}",
                        }
                    )
        except Exception as exc:
            msg = f"Certificate SAN analysis failed for {host}: {exc}"
            warn_list.append(msg)
            logger.debug(msg)

        return candidates, warn_list

    # ------------------------------------------------------------------
    # Phase 3: Subdomain enumeration
    # ------------------------------------------------------------------
    async def _enumerate_subdomains(
        self, domain: str
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Resolve common origin-indicating subdomains.

        Returns (candidates, warnings).
        """
        candidates: list[dict[str, Any]] = []
        warn_list: list[str] = []

        loop = asyncio.get_running_loop()

        async def _resolve_one(prefix: str) -> None:
            subdomain = f"{prefix}.{domain}"
            try:
                result = await loop.getaddrinfo(
                    subdomain, None, type=0
                )
                for family, _type, _proto, _canonname, sockaddr in result:
                    ip = sockaddr[0]
                    if _is_valid_public_ip(ip):
                        candidates.append(
                            {
                                "ip": ip,
                                "method": "subdomain_enumeration",
                                "confidence": 0.5,
                                "detail": f"{subdomain} -> {ip}",
                            }
                        )
            except (OSError, asyncio.TimeoutError):
                # Subdomain doesn't resolve — expected for most prefixes
                pass
            except Exception as exc:
                msg = f"Subdomain lookup failed for {subdomain}: {exc}"
                warn_list.append(msg)
                logger.debug(msg)

        await asyncio.gather(
            *(_resolve_one(prefix) for prefix in ORIGIN_SUBDOMAIN_PREFIXES)
        )

        return candidates, warn_list

    # ------------------------------------------------------------------
    # Phase 4: MX record analysis
    # ------------------------------------------------------------------
    async def _analyze_mx_records(
        self, domain: str
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Check MX records for IPs that may share origin infrastructure.

        Returns (candidates, warnings).
        """
        candidates: list[dict[str, Any]] = []
        warn_list: list[str] = []

        loop = asyncio.get_running_loop()
        try:
            # Resolve MX records by looking up the domain's mail servers
            # via getaddrinfo on common MX subdomains
            mx_hosts = [f"mail.{domain}", f"smtp.{domain}", f"mx.{domain}"]
            for mx_host in mx_hosts:
                try:
                    result = await loop.getaddrinfo(
                        mx_host, 25, type=0
                    )
                    for (
                        family,
                        _type,
                        _proto,
                        _canonname,
                        sockaddr,
                    ) in result:
                        ip = sockaddr[0]
                        if _is_valid_public_ip(ip):
                            candidates.append(
                                {
                                    "ip": ip,
                                    "method": "mx_record_analysis",
                                    "confidence": 0.4,
                                    "detail": f"MX host {mx_host} -> {ip}",
                                }
                            )
                except (OSError, asyncio.TimeoutError):
                    pass
        except Exception as exc:
            msg = f"MX record analysis failed for {domain}: {exc}"
            warn_list.append(msg)
            logger.debug(msg)

        return candidates, warn_list

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    async def _head_request(self, url: str) -> httpx.Response:
        """Issue an HTTP HEAD request to ``url``."""
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            warnings.filterwarnings(
                "ignore", message="Unverified HTTPS request"
            )
            client = self._get_client()
            return await client.head(url)

    async def _get_certificate_sans(self, host: str) -> list[str]:
        """Retrieve Subject Alternative Names from the host's TLS cert.

        Uses stdlib ``ssl`` for the TLS handshake. Returns a list of SAN
        values (DNS names, IP addresses).
        """
        sans: list[str] = []
        loop = asyncio.get_running_loop()

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            def _fetch_cert() -> dict[str, Any]:
                import socket

                with socket.create_connection(
                    (host, 443),  # noqa: PLR2004
                    timeout=self.config.request_timeout_seconds,
                ) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        return cert if cert else {}

            cert_dict = await loop.run_in_executor(None, _fetch_cert)

            # Extract SANs
            san_entries = cert_dict.get("subjectAltName", ())
            for san_type, san_value in san_entries:
                sans.append(san_value)

        except Exception as exc:
            logger.debug("Certificate fetch failed for %s: %s", host, exc)
            raise

        return sans

    @staticmethod
    def _methods_used(
        candidates: list[dict[str, Any]],
    ) -> list[str]:
        """Extract unique discovery methods from candidates."""
        methods: list[str] = []
        seen: set[str] = set()
        for c in candidates:
            m = c["discovery_method"]
            if m not in seen:
                seen.add(m)
                methods.append(m)
            for extra in c.get("additional_methods", []):
                if extra not in seen:
                    seen.add(extra)
                    methods.append(extra)
        return methods


__all__ = [
    "CDN_VENDOR_SIGNATURES",
    "ORIGIN_LEAK_HEADERS",
    "ORIGIN_SUBDOMAIN_PREFIXES",
    "WafOriginDiscoveryCollector",
]

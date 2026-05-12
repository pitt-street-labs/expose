"""Vendor CVE history collector (Tier 1, passive).

Pulls historical CVE data from the NVD API v2.0 for vendor/product combinations
detected via active-http-fingerprint observations.  Categorizes vulnerabilities
by CWE weakness class and computes per-vendor vulnerability distribution profiles.

This is a Tier-1 (passive, broad query) collector -- it queries only the public
NVD API and does not contact the target.  The collector relies on the entity's
``technologies`` and ``server_header`` properties (populated by the
active-http-fingerprint collector) to identify vendor+product+version tuples
which are then mapped to CPE strings for NVD lookup.

Data flow:
1. Read entity properties from the seed's ``properties`` dict for technology
   fingerprints (``technologies``, ``server_header``).
2. Map server headers / technology strings to CPE 2.3 names using a built-in
   mapping table covering the top 20+ web servers and frameworks.
3. Query NVD API v2.0 (``/rest/json/cves/2.0``) for each CPE match.
4. For each CVE: extract CWE IDs, CVSS base score, EPSS score (if available),
   and CISA KEV membership.
5. Compute per-vendor CWE distribution (e.g., "Apache httpd: CWE-79 18%").
6. Emit one ``SCANNER_HOST`` observation per vendor/product with the full
   vulnerability distribution profile in ``structured_payload``.

Rate limiting:
    NVD API allows 5 requests per 30 seconds without an API key, 50 requests
    per 30 seconds with a key.  A token-bucket rate limiter enforces this.

Credential slots:
    ``nvd_api_key`` -- NVD API key (optional; increases rate limit).

Seed types: DOMAIN, IP.  Other seed types are skipped silently.

MITRE ATT&CK: T1592 (Gather Victim Host Information) -- the collector queries
public vulnerability databases for known weaknesses in detected software.

FIPS gate compliance: This module does NOT import ``hashlib``, ``secrets``,
or ``Crypto``.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
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
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# NVD API
# ---------------------------------------------------------------------------
_NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Health-check: lightweight call with resultsPerPage=1
_NVD_HEALTH_URL = _NVD_CVE_API_URL

# Maximum CVEs to retrieve per product query (NVD default page is 2000).
_MAX_RESULTS_PER_PAGE = 200

# EPSS threshold for "high exploitation probability".
_EPSS_HIGH_THRESHOLD = 0.5

# Default user agent.
_DEFAULT_USER_AGENT = "EXPOSE/0.1 (attack-surface-intelligence)"


# ---------------------------------------------------------------------------
# CWE name mapping (top CWE IDs for web/server software)
# ---------------------------------------------------------------------------
CWE_NAMES: dict[str, str] = {
    "CWE-79": "Improper Neutralization of Input During Web Page Generation (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
    "CWE-20": "Improper Input Validation",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-264": "Permissions, Privileges, and Access Controls",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-125": "Out-of-bounds Read",
    "CWE-787": "Out-of-bounds Write",
    "CWE-416": "Use After Free",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)",
    "CWE-94": "Improper Control of Generation of Code (Code Injection)",
    "CWE-269": "Improper Privilege Management",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-772": "Missing Release of Resource after Effective Lifetime",
    "CWE-NVD-noinfo": "Insufficient Information",
    "CWE-noinfo": "Insufficient Information",
}


# ---------------------------------------------------------------------------
# CPE mapping table -- maps common server header patterns to CPE 2.3 strings
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CpeMapping:
    """Mapping from a server header regex to CPE 2.3 vendor/product."""

    pattern: re.Pattern[str]
    vendor: str
    product: str
    cpe_vendor: str
    cpe_product: str


# Each entry: (regex_pattern, display_vendor, display_product, cpe_vendor, cpe_product)
# ORDER MATTERS — more specific patterns must come before generic ones.
# e.g., "Apache-Coyote" and "Apache Tomcat" must match before bare "Apache".
_CPE_MAPPING_DEFS: list[tuple[str, str, str, str, str]] = [
    # Tomcat (must precede generic Apache)
    (r"(?:Apache-Coyote|Apache Tomcat)(?:/(\d[\d.]*))?", "Apache", "Tomcat",
     "apache", "tomcat"),
    # Apache HTTP Server
    (r"Apache(?:/(\d[\d.]*))?", "Apache", "HTTP Server", "apache", "http_server"),
    # nginx
    (r"nginx(?:/(\d[\d.]*))?", "F5", "nginx", "f5", "nginx"),
    # Microsoft IIS
    (r"Microsoft-IIS(?:/(\d[\d.]*))?", "Microsoft", "Internet Information Services",
     "microsoft", "internet_information_services"),
    # LiteSpeed
    (r"LiteSpeed(?:/(\d[\d.]*))?", "LiteSpeed", "LiteSpeed Web Server",
     "litespeedtech", "litespeed_web_server"),
    # Caddy
    (r"Caddy(?:/(\d[\d.]*))?", "Caddy", "Caddy", "caddyserver", "caddy"),
    # OpenResty (nginx-based)
    (r"openresty(?:/(\d[\d.]*))?", "OpenResty", "OpenResty", "openresty", "openresty"),
    # Jetty
    (r"Jetty(?:\((\d[\d.]*)\))?", "Eclipse", "Jetty", "eclipse", "jetty"),
    # gunicorn
    (r"gunicorn(?:/(\d[\d.]*))?", "Gunicorn", "gunicorn", "gunicorn", "gunicorn"),
    # Envoy
    (r"envoy(?:/(\d[\d.]*))?", "Envoyproxy", "Envoy", "envoyproxy", "envoy"),
    # Cloudflare
    (r"cloudflare", "Cloudflare", "Cloudflare", "cloudflare", "cloudflare"),
    # AmazonS3
    (r"AmazonS3", "Amazon", "S3", "amazon", "s3"),
    # Node.js Express
    (r"Express(?:/(\d[\d.]*))?", "Expressjs", "Express", "expressjs", "express"),
    # PHP
    (r"PHP(?:/(\d[\d.]*))?", "PHP", "PHP", "php", "php"),
    # Werkzeug (Flask)
    (r"Werkzeug(?:/(\d[\d.]*))?", "Pallets", "Werkzeug", "palletsprojects", "werkzeug"),
    # Cherokee
    (r"Cherokee(?:/(\d[\d.]*))?", "Cherokee", "Cherokee", "cherokee-project", "cherokee"),
    # HAProxy
    (r"HAProxy(?:/(\d[\d.]*))?", "HAProxy", "HAProxy", "haproxy", "haproxy"),
    # Kestrel (ASP.NET)
    (r"Kestrel(?:/(\d[\d.]*))?", "Microsoft", "Kestrel", "microsoft", "kestrel"),
    # Tengine (Alibaba nginx fork)
    (r"Tengine(?:/(\d[\d.]*))?", "Alibaba", "Tengine", "alibaba", "tengine"),
    # Lighttpd
    (r"lighttpd(?:/(\d[\d.]*))?", "Lighttpd", "lighttpd", "lighttpd", "lighttpd"),
    # Varnish
    (r"Varnish(?:/(\d[\d.]*))?", "Varnish", "Varnish Cache",
     "varnish-cache", "varnish_cache"),
    # Traefik
    (r"Traefik(?:/(\d[\d.]*))?", "Traefik", "Traefik", "traefik", "traefik"),
    # Cowboy (Erlang)
    (r"Cowboy(?:/(\d[\d.]*))?", "Cowboy", "Cowboy", "ninenines", "cowboy"),
    # Undertow (WildFly)
    (r"Undertow(?:/(\d[\d.]*))?", "Red Hat", "Undertow", "redhat", "undertow"),
    # Uvicorn
    (r"uvicorn(?:/(\d[\d.]*))?", "Uvicorn", "Uvicorn", "encode", "uvicorn"),
]

# Compile all patterns once at module load.
CPE_MAPPINGS: list[CpeMapping] = [
    CpeMapping(
        pattern=re.compile(pat, re.IGNORECASE),
        vendor=vendor,
        product=product,
        cpe_vendor=cpe_vendor,
        cpe_product=cpe_product,
    )
    for pat, vendor, product, cpe_vendor, cpe_product in _CPE_MAPPING_DEFS
]


# ---------------------------------------------------------------------------
# Product detection result
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DetectedProduct:
    """A vendor/product/version tuple extracted from fingerprint data."""

    vendor: str
    product: str
    version: str | None
    cpe_vendor: str
    cpe_product: str


# ---------------------------------------------------------------------------
# Known EOL versions (a selection of well-known EOL product versions)
# ---------------------------------------------------------------------------
_EOL_VERSIONS: dict[str, set[str]] = {
    "apache:http_server": {
        "2.2", "2.0", "1.3", "2.2.34", "2.2.31", "2.2.32", "2.2.29",
        "2.4.6", "2.4.7", "2.4.10", "2.4.12", "2.4.16", "2.4.17",
        "2.4.18", "2.4.20", "2.4.23", "2.4.25", "2.4.27", "2.4.29",
    },
    "f5:nginx": {
        "1.0", "1.2", "1.4", "1.6", "1.8", "1.10", "1.12", "1.14",
        "1.16", "1.18", "1.14.0", "1.14.1", "1.14.2", "1.16.0", "1.16.1",
        "1.18.0",
    },
    "microsoft:internet_information_services": {
        "6.0", "7.0", "7.5", "8.0", "8.5",
    },
    "php:php": {
        "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0",
        "5.6.40", "7.0.33", "7.1.33", "7.2.34", "7.3.33", "7.4.33",
        "8.0.30",
    },
}


# ---------------------------------------------------------------------------
# Token bucket rate limiter for NVD API
# ---------------------------------------------------------------------------
class NvdTokenBucket:
    """Async token-bucket rate limiter for the NVD API.

    Without an API key: 5 requests per 30 seconds (1 token every 6s).
    With an API key:   50 requests per 30 seconds (1 token every 0.6s).

    The bucket starts full so the first ``burst_size`` requests go through
    immediately; subsequent requests wait for token replenishment.
    """

    def __init__(self, *, has_api_key: bool = False) -> None:
        if has_api_key:
            self._rate = 50.0 / 30.0  # ~1.67 tokens/sec
            self._burst = 10
        else:
            self._rate = 5.0 / 30.0  # ~0.167 tokens/sec
            self._burst = 2
        self._tokens = float(self._burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available, then consume it."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                float(self._burst),
                self._tokens + elapsed * self._rate,
            )
            self._last_refill = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return

            deficit = 1.0 - self._tokens
            wait = deficit / self._rate if self._rate > 0 else 0.0

        await asyncio.sleep(wait)

        async with self._lock:
            self._tokens = 0.0
            self._last_refill = time.monotonic()


# ---------------------------------------------------------------------------
# Pure-function helpers (easy to test in isolation)
# ---------------------------------------------------------------------------
def parse_server_header(header: str) -> DetectedProduct | None:
    """Map a server header string to a ``DetectedProduct``.

    Iterates the CPE mapping table and returns the first match, extracting
    the version from the regex capture group if present.

    Returns ``None`` if no mapping matches.
    """
    if not header or not header.strip():
        return None

    header = header.strip()

    for mapping in CPE_MAPPINGS:
        m = mapping.pattern.search(header)
        if m:
            version: str | None = None
            if m.lastindex and m.lastindex >= 1:
                version = m.group(1)
            return DetectedProduct(
                vendor=mapping.vendor,
                product=mapping.product,
                version=version,
                cpe_vendor=mapping.cpe_vendor,
                cpe_product=mapping.cpe_product,
            )

    return None


def build_cpe_string(product: DetectedProduct) -> str:
    """Build a CPE 2.3 URI string for a detected product.

    Format: ``cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*``

    If version is unknown, uses ``*`` as the version wildcard.
    """
    version = product.version if product.version else "*"
    return (
        f"cpe:2.3:a:{product.cpe_vendor}:{product.cpe_product}"
        f":{version}:*:*:*:*:*:*:*"
    )


def detect_products_from_properties(
    properties: dict[str, Any],
) -> list[DetectedProduct]:
    """Extract vendor/product/version tuples from entity properties.

    Reads ``server_header`` and ``technologies`` from the properties dict
    (as populated by active-http-fingerprint observations) and returns
    deduplicated product detections.
    """
    products: list[DetectedProduct] = []
    seen: set[tuple[str, str, str | None]] = set()

    # From server_header.
    server_header = properties.get("server_header")
    if server_header and isinstance(server_header, str):
        p = parse_server_header(server_header)
        if p:
            key = (p.cpe_vendor, p.cpe_product, p.version)
            if key not in seen:
                seen.add(key)
                products.append(p)

    # From technologies list.
    technologies = properties.get("technologies")
    if technologies and isinstance(technologies, list):
        for tech in technologies:
            if isinstance(tech, str):
                p = parse_server_header(tech)
                if p:
                    key = (p.cpe_vendor, p.cpe_product, p.version)
                    if key not in seen:
                        seen.add(key)
                        products.append(p)

    return products


def is_version_eol(product: DetectedProduct) -> bool:
    """Check if a detected product version is known to be end-of-life.

    Uses a static lookup table of well-known EOL versions.  Returns False
    if the version is unknown or not in the table (conservative).
    """
    if not product.version:
        return False

    key = f"{product.cpe_vendor}:{product.cpe_product}"
    eol_set = _EOL_VERSIONS.get(key)
    if not eol_set:
        return False

    # Check exact version or major.minor prefix.
    if product.version in eol_set:
        return True

    # Check major.minor prefix (e.g., "2.4.41" matches "2.4" if "2.4" is EOL).
    parts = product.version.split(".")
    for i in range(len(parts) - 1, 0, -1):
        prefix = ".".join(parts[:i])
        if prefix in eol_set:
            return True

    return False


def extract_cwe_ids(cve_item: dict[str, Any]) -> list[str]:
    """Extract CWE IDs from a single NVD CVE item.

    The NVD API v2.0 structure is:
    ``cve.weaknesses[].description[].value`` where lang == "en".
    """
    cwe_ids: list[str] = []

    cve = cve_item.get("cve", {})
    if not isinstance(cve, dict):
        return cwe_ids

    weaknesses = cve.get("weaknesses", [])
    if not isinstance(weaknesses, list):
        return cwe_ids

    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        descriptions = weakness.get("description", [])
        if not isinstance(descriptions, list):
            continue
        for desc in descriptions:
            if not isinstance(desc, dict):
                continue
            if desc.get("lang") == "en":
                value = desc.get("value", "")
                if value and isinstance(value, str):
                    cwe_ids.append(value)

    return cwe_ids


def extract_cvss_score(cve_item: dict[str, Any]) -> float | None:
    """Extract the CVSS base score from a CVE item.

    Prefers CVSS v3.1, falls back to v3.0, then v2.0.
    """
    cve = cve_item.get("cve", {})
    if not isinstance(cve, dict):
        return None

    metrics = cve.get("metrics", {})
    if not isinstance(metrics, dict):
        return None

    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key, [])
        if isinstance(metric_list, list) and metric_list:
            first = metric_list[0]
            if isinstance(first, dict):
                cvss_data = first.get("cvssData", {})
                if isinstance(cvss_data, dict):
                    score = cvss_data.get("baseScore")
                    if score is not None:
                        try:
                            return float(score)
                        except (TypeError, ValueError):
                            pass
    return None


def extract_cve_id(cve_item: dict[str, Any]) -> str | None:
    """Extract the CVE ID from a vulnerability item."""
    cve = cve_item.get("cve", {})
    if isinstance(cve, dict):
        cve_id = cve.get("id")
        if isinstance(cve_id, str):
            return cve_id
    return None


def compute_cwe_distribution(
    cve_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Compute CWE frequency distribution from a list of CVE items.

    Returns a sorted list (descending by count) of dicts with keys:
    ``cwe_id``, ``cwe_name``, ``count``, ``percentage``.
    """
    cwe_counts: dict[str, int] = {}

    for item in cve_items:
        cwe_ids = extract_cwe_ids(item)
        for cwe_id in cwe_ids:
            cwe_counts[cwe_id] = cwe_counts.get(cwe_id, 0) + 1

    total = sum(cwe_counts.values())
    if total == 0:
        return []

    distribution: list[dict[str, Any]] = []
    for cwe_id, count in sorted(
        cwe_counts.items(), key=lambda x: x[1], reverse=True
    ):
        distribution.append({
            "cwe_id": cwe_id,
            "cwe_name": CWE_NAMES.get(cwe_id, cwe_id),
            "count": count,
            "percentage": round(count / total * 100.0, 1),
        })

    return distribution


def compute_avg_cvss(cve_items: list[dict[str, Any]]) -> float | None:
    """Compute average CVSS base score across CVE items."""
    scores: list[float] = []
    for item in cve_items:
        score = extract_cvss_score(item)
        if score is not None:
            scores.append(score)
    if not scores:
        return None
    return round(sum(scores) / len(scores), 2)


# ---------------------------------------------------------------------------
# CISA KEV and EPSS helpers
# ---------------------------------------------------------------------------
@dataclass
class VulnEnrichment:
    """Aggregated enrichment counters for a set of CVEs."""

    kev_count: int = 0
    epss_high_count: int = 0
    kev_cve_ids: list[str] = field(default_factory=list)


def count_kev_and_epss(
    cve_items: list[dict[str, Any]],
    kev_cve_ids: set[str] | None = None,
    epss_scores: dict[str, float] | None = None,
) -> VulnEnrichment:
    """Count CVEs in CISA KEV and with EPSS > threshold.

    ``kev_cve_ids`` is an optional set of CVE IDs known to be in the CISA KEV.
    ``epss_scores`` is an optional mapping of CVE ID -> EPSS probability.

    Both are injected externally (from seed properties or future enrichment);
    the NVD API itself does not include KEV or EPSS data.
    """
    enrichment = VulnEnrichment()
    kev = kev_cve_ids or set()
    epss = epss_scores or {}

    for item in cve_items:
        cve_id = extract_cve_id(item)
        if not cve_id:
            continue
        if cve_id in kev:
            enrichment.kev_count += 1
            enrichment.kev_cve_ids.append(cve_id)
        score = epss.get(cve_id, 0.0)
        if score > _EPSS_HIGH_THRESHOLD:
            enrichment.epss_high_count += 1

    return enrichment


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
@register_collector
class VendorCveHistoryCollector(Collector):
    """Tier-1 passive vendor CVE history collector.

    Queries the NVD API v2.0 for historical CVE data associated with
    vendor/product combinations detected from HTTP fingerprints.  Computes
    CWE weakness distribution profiles and enrichment data.
    """

    collector_id: str = "vendor-cve-history"
    collector_version: str = "0.1.0"
    display_name: str = "Vendor CVE History"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = 10
    technique_ids: ClassVar[list[str]] = ["T1592"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        nvd_cred = self.config.credentials.get("nvd_api_key")
        self._api_key: str | None = nvd_cred.secret_value if nvd_cred else None
        self._rate_limiter = NvdTokenBucket(has_api_key=bool(self._api_key))

    # ------------------------------------------------------------------
    # expand
    # ------------------------------------------------------------------
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query NVD for CVE history of detected products.

        Reads ``technologies`` and ``server_header`` from the seed's
        properties to identify products, then queries NVD for each.
        """
        if seed.seed_type not in {SeedType.DOMAIN, SeedType.IP}:
            return

        identifier_value = seed.value.strip().lower()
        identifier_type = (
            IdentifierType.IP
            if seed.seed_type == SeedType.IP
            else IdentifierType.DOMAIN
        )

        # Detect products from seed properties.
        products = detect_products_from_properties(seed.properties)
        if not products:
            return

        # Optional enrichment data from seed properties.
        kev_cve_ids: set[str] | None = None
        raw_kev = seed.properties.get("kev_cve_ids")
        if isinstance(raw_kev, (list, set)):
            kev_cve_ids = set(raw_kev)

        epss_scores: dict[str, float] | None = None
        raw_epss = seed.properties.get("epss_scores")
        if isinstance(raw_epss, dict):
            epss_scores = raw_epss

        warnings_list: list[str] = []

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.request_timeout_seconds),
            headers=self._build_headers(),
        ) as client:
            for product in products:
                try:
                    obs = await self._query_product(
                        client=client,
                        product=product,
                        identifier_type=identifier_type,
                        identifier_value=identifier_value,
                        kev_cve_ids=kev_cve_ids,
                        epss_scores=epss_scores,
                        warnings_list=warnings_list,
                    )
                    if obs is not None:
                        yield obs
                except Exception as exc:
                    msg = (
                        f"NVD query failed for {product.vendor} "
                        f"{product.product}: {exc}"
                    )
                    warnings_list.append(msg)
                    logger.debug(msg)

    # ------------------------------------------------------------------
    # health_check
    # ------------------------------------------------------------------
    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe against the NVD API."""
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0),
                headers=self._build_headers(),
            ) as client:
                resp = await client.get(
                    _NVD_HEALTH_URL,
                    params={"resultsPerPage": "1", "startIndex": "0"},
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
        except httpx.HTTPError as exc:
            latency = (time.monotonic() - start) * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                latency_ms=latency,
                error_message=f"NVD API unreachable: {exc}",
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers for NVD API requests."""
        headers: dict[str, str] = {
            "User-Agent": self.config.extra.get("user_agent", _DEFAULT_USER_AGENT),
        }
        if self._api_key:
            headers["apiKey"] = self._api_key
        return headers

    async def _query_product(
        self,
        *,
        client: httpx.AsyncClient,
        product: DetectedProduct,
        identifier_type: IdentifierType,
        identifier_value: str,
        kev_cve_ids: set[str] | None,
        epss_scores: dict[str, float] | None,
        warnings_list: list[str],
    ) -> Observation | None:
        """Query NVD for a single product and build an observation."""
        cpe_string = build_cpe_string(product)

        # Rate limit before the request.
        await self._rate_limiter.acquire()

        params: dict[str, str] = {
            "cpeName": cpe_string,
            "resultsPerPage": str(_MAX_RESULTS_PER_PAGE),
        }

        try:
            resp = await client.get(_NVD_CVE_API_URL, params=params)
        except httpx.HTTPError as exc:
            warnings_list.append(
                f"NVD request failed for CPE {cpe_string}: {exc}"
            )
            return None

        if resp.status_code == 403:  # noqa: PLR2004
            warnings_list.append("NVD API rate limited (403)")
            return None

        if resp.status_code == 404:  # noqa: PLR2004
            return None

        if resp.status_code != 200:  # noqa: PLR2004
            warnings_list.append(
                f"NVD API returned HTTP {resp.status_code} for CPE {cpe_string}"
            )
            return None

        try:
            data = resp.json()
        except Exception:
            warnings_list.append("NVD API returned malformed JSON")
            return None

        if not isinstance(data, dict):
            return None

        cve_items = data.get("vulnerabilities", [])
        if not isinstance(cve_items, list):
            cve_items = []

        total_cves = data.get("totalResults", len(cve_items))
        if not isinstance(total_cves, int):
            total_cves = len(cve_items)

        # Compute CWE distribution.
        cwe_dist = compute_cwe_distribution(cve_items)

        # Top predicted weakness.
        top_weakness = cwe_dist[0]["cwe_id"] if cwe_dist else None

        # EOL status.
        eol_status = is_version_eol(product)

        # CVSS average.
        avg_cvss = compute_avg_cvss(cve_items)

        # KEV and EPSS enrichment.
        enrichment = count_kev_and_epss(
            cve_items,
            kev_cve_ids=kev_cve_ids,
            epss_scores=epss_scores,
        )

        payload: dict[str, Any] = {
            "_collector_id": "vendor-cve-history",
            "vendor_name": product.vendor,
            "product_name": product.product,
            "product_version": product.version,
            "cpe_string": cpe_string,
            "total_cves": total_cves,
            "cwe_distribution": cwe_dist,
            "top_predicted_weakness": top_weakness,
            "eol_status": eol_status,
            "avg_cvss_score": avg_cvss,
            "kev_count": enrichment.kev_count,
            "epss_high_count": enrichment.epss_high_count,
            "patch_velocity_days": None,  # Requires per-CVE patch-date data
        }

        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.SCANNER_HOST,
            subject=ObservationSubject(
                identifier_type=identifier_type,
                identifier_value=identifier_value,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload=payload,
            warnings=list(warnings_list),
        )


__all__ = [
    "VendorCveHistoryCollector",
]

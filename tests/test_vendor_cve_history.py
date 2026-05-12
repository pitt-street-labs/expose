"""Tests for the vendor-cve-history collector (Tier 1).

Exercises CPE mapping, CWE distribution computation, NVD API response parsing,
rate limiting, observation format, and edge cases via ``respx`` mocks.

Coverage (30+ tests):

 1.  Collector metadata (ID, tier, version, credentials)
 2.  CPE mapping — Apache, nginx, IIS, PHP, LiteSpeed, Tomcat, Caddy, etc.
 3.  CPE mapping — version extraction from headers
 4.  CPE mapping — unknown headers return None
 5.  CPE string construction with and without version
 6.  Product detection from properties dict
 7.  CWE distribution computation — basic
 8.  CWE distribution computation — empty input
 9.  CWE distribution computation — multiple CWEs per CVE
10.  CWE distribution — sorting by frequency
11.  CVSS score extraction — v3.1, v3.0, v2.0 fallback
12.  CVE ID extraction
13.  KEV and EPSS enrichment counting
14.  EOL version detection
15.  NVD API response parsing — full pipeline
16.  NVD API 403 rate limit graceful
17.  NVD API 500 error graceful
18.  NVD API connection error graceful
19.  NVD API malformed JSON graceful
20.  Non-DOMAIN/IP seeds skipped
21.  No products detected yields nothing
22.  Health check success
23.  Health check failure (HTTP error)
24.  Health check failure (connection error)
25.  Registration in default registry
26.  API key passed in header
27.  No API key still works
28.  Observation format validation
29.  Rate limiter token bucket behavior
30.  Multiple products emitted as separate observations
31.  Deduplication of detected products
32.  Case-insensitive header matching
33.  IP seed type handling
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch
from uuid import UUID

import httpx
import pytest
import respx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorCredential,
    CollectorHealthCheck,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.vendor_cve_history import (
    CWE_NAMES,
    DetectedProduct,
    NvdTokenBucket,
    VendorCveHistoryCollector,
    build_cpe_string,
    compute_avg_cvss,
    compute_cwe_distribution,
    count_kev_and_epss,
    detect_products_from_properties,
    extract_cve_id,
    extract_cvss_score,
    extract_cwe_ids,
    is_version_eol,
    parse_server_header,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-0000000d0e01")
RUN_ID = UUID("018f1f00-0000-7000-8000-0000000d0e02")


def _config(
    nvd_key: str | None = None,
) -> CollectorConfig:
    creds: dict[str, CollectorCredential] = {}
    if nvd_key:
        creds["nvd_api_key"] = CollectorCredential(
            name="nvd_api_key", secret_value=nvd_key
        )
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=5.0,
        credentials=creds,
    )


async def _collect(
    seed: Seed,
    config: CollectorConfig | None = None,
) -> list[Observation]:
    cfg = config or _config()
    collector = VendorCveHistoryCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# === Canned NVD API responses ================================================

_NVD_RESPONSE_APACHE = {
    "resultsPerPage": 3,
    "startIndex": 0,
    "totalResults": 3,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "published": "2021-10-05T15:15:00.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A flaw in Apache HTTP Server 2.4.49 path traversal.",
                    }
                ],
                "weaknesses": [
                    {
                        "source": "cna@apache.org",
                        "type": "Primary",
                        "description": [
                            {"lang": "en", "value": "CWE-22"}
                        ],
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                            }
                        }
                    ]
                },
                "references": [],
            }
        },
        {
            "cve": {
                "id": "CVE-2021-42013",
                "published": "2021-10-07T15:15:00.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Another path traversal in Apache HTTP Server.",
                    }
                ],
                "weaknesses": [
                    {
                        "source": "cna@apache.org",
                        "type": "Primary",
                        "description": [
                            {"lang": "en", "value": "CWE-22"}
                        ],
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "references": [],
            }
        },
        {
            "cve": {
                "id": "CVE-2021-44790",
                "published": "2021-12-20T12:15:00.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Buffer overflow in mod_lua.",
                    }
                ],
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {"lang": "en", "value": "CWE-787"}
                        ],
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "references": [],
            }
        },
    ],
}

_NVD_EMPTY_RESPONSE = {
    "resultsPerPage": 0,
    "startIndex": 0,
    "totalResults": 0,
    "vulnerabilities": [],
}


def _mock_nvd(
    cpe: str | None = None,
    response_data: dict | None = None,
    status_code: int = 200,
) -> None:
    """Set up respx mock for NVD API."""
    data = response_data if response_data is not None else _NVD_EMPTY_RESPONSE
    respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
        return_value=httpx.Response(status_code, json=data)
    )


# ==============================================================================
# 1. Collector metadata
# ==============================================================================
class TestCollectorMetadata:
    def test_collector_id(self) -> None:
        assert VendorCveHistoryCollector.collector_id == "vendor-cve-history"

    def test_collector_version(self) -> None:
        assert VendorCveHistoryCollector.collector_version == "0.1.0"

    def test_tier_is_tier_1(self) -> None:
        assert VendorCveHistoryCollector.tier == CollectorTier.TIER_1

    def test_requires_credentials_false(self) -> None:
        assert VendorCveHistoryCollector.requires_credentials is False

    def test_is_subclass_of_collector_abc(self) -> None:
        assert issubclass(VendorCveHistoryCollector, Collector)

    def test_display_name(self) -> None:
        assert VendorCveHistoryCollector.display_name == "Vendor CVE History"


# ==============================================================================
# 2. CPE mapping — common server headers
# ==============================================================================
class TestCpeMappingCommonHeaders:
    def test_apache_with_version(self) -> None:
        result = parse_server_header("Apache/2.4.41")
        assert result is not None
        assert result.vendor == "Apache"
        assert result.product == "HTTP Server"
        assert result.version == "2.4.41"
        assert result.cpe_vendor == "apache"
        assert result.cpe_product == "http_server"

    def test_apache_without_version(self) -> None:
        result = parse_server_header("Apache")
        assert result is not None
        assert result.vendor == "Apache"
        assert result.version is None

    def test_nginx_with_version(self) -> None:
        result = parse_server_header("nginx/1.18.0")
        assert result is not None
        assert result.vendor == "F5"
        assert result.product == "nginx"
        assert result.version == "1.18.0"
        assert result.cpe_vendor == "f5"
        assert result.cpe_product == "nginx"

    def test_iis_with_version(self) -> None:
        result = parse_server_header("Microsoft-IIS/10.0")
        assert result is not None
        assert result.vendor == "Microsoft"
        assert result.product == "Internet Information Services"
        assert result.version == "10.0"
        assert result.cpe_vendor == "microsoft"
        assert result.cpe_product == "internet_information_services"

    def test_litespeed(self) -> None:
        result = parse_server_header("LiteSpeed/5.4.12")
        assert result is not None
        assert result.vendor == "LiteSpeed"
        assert result.version == "5.4.12"

    def test_tomcat(self) -> None:
        result = parse_server_header("Apache-Coyote/1.1")
        assert result is not None
        assert result.vendor == "Apache"
        assert result.product == "Tomcat"

    def test_caddy(self) -> None:
        result = parse_server_header("Caddy/2.6.4")
        assert result is not None
        assert result.vendor == "Caddy"
        assert result.version == "2.6.4"

    def test_php(self) -> None:
        result = parse_server_header("PHP/8.1.2")
        assert result is not None
        assert result.vendor == "PHP"
        assert result.version == "8.1.2"

    def test_gunicorn(self) -> None:
        result = parse_server_header("gunicorn/20.1.0")
        assert result is not None
        assert result.vendor == "Gunicorn"
        assert result.version == "20.1.0"

    def test_openresty(self) -> None:
        result = parse_server_header("openresty/1.21.4.1")
        assert result is not None
        assert result.vendor == "OpenResty"
        assert result.version == "1.21.4.1"

    def test_lighttpd(self) -> None:
        result = parse_server_header("lighttpd/1.4.67")
        assert result is not None
        assert result.vendor == "Lighttpd"
        assert result.version == "1.4.67"

    def test_envoy(self) -> None:
        result = parse_server_header("envoy/1.25.0")
        assert result is not None
        assert result.vendor == "Envoyproxy"
        assert result.version == "1.25.0"


# ==============================================================================
# 3. CPE mapping — version extraction
# ==============================================================================
class TestCpeMappingVersionExtraction:
    def test_version_with_multiple_dots(self) -> None:
        result = parse_server_header("Apache/2.4.41.1")
        assert result is not None
        assert result.version == "2.4.41.1"

    def test_apache_with_os_suffix(self) -> None:
        """Apache headers often include OS: 'Apache/2.4.41 (Ubuntu)'."""
        result = parse_server_header("Apache/2.4.41 (Ubuntu)")
        assert result is not None
        assert result.version == "2.4.41"

    def test_nginx_with_trailing_info(self) -> None:
        result = parse_server_header("nginx/1.18.0 (Ubuntu)")
        assert result is not None
        assert result.version == "1.18.0"


# ==============================================================================
# 4. CPE mapping — unknown headers
# ==============================================================================
class TestCpeMappingUnknownHeaders:
    def test_unknown_server_returns_none(self) -> None:
        assert parse_server_header("SomeUnknownServer/1.0") is None

    def test_empty_string_returns_none(self) -> None:
        assert parse_server_header("") is None

    def test_whitespace_only_returns_none(self) -> None:
        assert parse_server_header("   ") is None

    def test_none_string_returns_none(self) -> None:
        # Type annotation says str but test robustness.
        assert parse_server_header("") is None


# ==============================================================================
# 5. CPE string construction
# ==============================================================================
class TestCpeStringConstruction:
    def test_cpe_with_version(self) -> None:
        product = DetectedProduct(
            vendor="Apache",
            product="HTTP Server",
            version="2.4.41",
            cpe_vendor="apache",
            cpe_product="http_server",
        )
        assert build_cpe_string(product) == (
            "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
        )

    def test_cpe_without_version(self) -> None:
        product = DetectedProduct(
            vendor="Apache",
            product="HTTP Server",
            version=None,
            cpe_vendor="apache",
            cpe_product="http_server",
        )
        assert build_cpe_string(product) == (
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        )

    def test_cpe_nginx(self) -> None:
        product = DetectedProduct(
            vendor="F5",
            product="nginx",
            version="1.18.0",
            cpe_vendor="f5",
            cpe_product="nginx",
        )
        assert build_cpe_string(product) == (
            "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"
        )

    def test_cpe_iis(self) -> None:
        product = DetectedProduct(
            vendor="Microsoft",
            product="Internet Information Services",
            version="10.0",
            cpe_vendor="microsoft",
            cpe_product="internet_information_services",
        )
        assert build_cpe_string(product) == (
            "cpe:2.3:a:microsoft:internet_information_services"
            ":10.0:*:*:*:*:*:*:*"
        )


# ==============================================================================
# 6. Product detection from properties
# ==============================================================================
class TestProductDetection:
    def test_detect_from_server_header(self) -> None:
        props = {"server_header": "Apache/2.4.41"}
        products = detect_products_from_properties(props)
        assert len(products) == 1
        assert products[0].vendor == "Apache"
        assert products[0].version == "2.4.41"

    def test_detect_from_technologies(self) -> None:
        props = {"technologies": ["nginx/1.18.0", "PHP/8.1.2"]}
        products = detect_products_from_properties(props)
        assert len(products) == 2
        vendors = {p.vendor for p in products}
        assert "F5" in vendors
        assert "PHP" in vendors

    def test_detect_deduplication(self) -> None:
        """Same product in both server_header and technologies."""
        props = {
            "server_header": "Apache/2.4.41",
            "technologies": ["Apache/2.4.41"],
        }
        products = detect_products_from_properties(props)
        assert len(products) == 1

    def test_detect_empty_properties(self) -> None:
        products = detect_products_from_properties({})
        assert products == []

    def test_detect_unknown_technologies(self) -> None:
        props = {"technologies": ["SomeUnknown/1.0", "AnotherUnknown"]}
        products = detect_products_from_properties(props)
        assert products == []


# ==============================================================================
# 7. CWE distribution computation — basic
# ==============================================================================
class TestCweDistributionBasic:
    def test_single_cwe(self) -> None:
        items = [
            {
                "cve": {
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-79"}
                            ]
                        }
                    ]
                }
            }
        ]
        dist = compute_cwe_distribution(items)
        assert len(dist) == 1
        assert dist[0]["cwe_id"] == "CWE-79"
        assert dist[0]["count"] == 1
        assert dist[0]["percentage"] == 100.0
        assert "XSS" in dist[0]["cwe_name"]

    def test_two_different_cwes(self) -> None:
        items = [
            {
                "cve": {
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-79"}
                            ]
                        }
                    ]
                }
            },
            {
                "cve": {
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-22"}
                            ]
                        }
                    ]
                }
            },
        ]
        dist = compute_cwe_distribution(items)
        assert len(dist) == 2
        for entry in dist:
            assert entry["count"] == 1
            assert entry["percentage"] == 50.0


# ==============================================================================
# 8. CWE distribution — empty input
# ==============================================================================
class TestCweDistributionEmpty:
    def test_empty_list(self) -> None:
        assert compute_cwe_distribution([]) == []

    def test_items_with_no_weaknesses(self) -> None:
        items = [{"cve": {"weaknesses": []}}]
        assert compute_cwe_distribution(items) == []

    def test_items_with_missing_cve(self) -> None:
        items = [{}]
        assert compute_cwe_distribution(items) == []


# ==============================================================================
# 9. CWE distribution — multiple CWEs per CVE
# ==============================================================================
class TestCweDistributionMultipleCwes:
    def test_multiple_cwes_in_one_cve(self) -> None:
        items = [
            {
                "cve": {
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-79"},
                            ]
                        },
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-89"},
                            ]
                        },
                    ]
                }
            },
        ]
        dist = compute_cwe_distribution(items)
        assert len(dist) == 2
        ids = {d["cwe_id"] for d in dist}
        assert ids == {"CWE-79", "CWE-89"}


# ==============================================================================
# 10. CWE distribution — sorting by frequency
# ==============================================================================
class TestCweDistributionSorting:
    def test_sorted_descending_by_count(self) -> None:
        items = []
        # 3 CWE-79, 1 CWE-22, 2 CWE-400
        for _ in range(3):
            items.append({
                "cve": {
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": "CWE-79"}]}
                    ]
                }
            })
        items.append({
            "cve": {
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-22"}]}
                ]
            }
        })
        for _ in range(2):
            items.append({
                "cve": {
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": "CWE-400"}]}
                    ]
                }
            })

        dist = compute_cwe_distribution(items)
        assert dist[0]["cwe_id"] == "CWE-79"
        assert dist[0]["count"] == 3
        assert dist[1]["cwe_id"] == "CWE-400"
        assert dist[1]["count"] == 2
        assert dist[2]["cwe_id"] == "CWE-22"
        assert dist[2]["count"] == 1


# ==============================================================================
# 11. CVSS score extraction
# ==============================================================================
class TestCvssScoreExtraction:
    def test_cvss_v31(self) -> None:
        item = {
            "cve": {
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                    ]
                }
            }
        }
        assert extract_cvss_score(item) == 7.5

    def test_cvss_v30_fallback(self) -> None:
        item = {
            "cve": {
                "metrics": {
                    "cvssMetricV30": [
                        {"cvssData": {"baseScore": 6.1, "baseSeverity": "MEDIUM"}}
                    ]
                }
            }
        }
        assert extract_cvss_score(item) == 6.1

    def test_cvss_v2_fallback(self) -> None:
        item = {
            "cve": {
                "metrics": {
                    "cvssMetricV2": [
                        {"cvssData": {"baseScore": 5.0}}
                    ]
                }
            }
        }
        assert extract_cvss_score(item) == 5.0

    def test_no_metrics(self) -> None:
        item = {"cve": {"metrics": {}}}
        assert extract_cvss_score(item) is None

    def test_empty_item(self) -> None:
        assert extract_cvss_score({}) is None


# ==============================================================================
# 12. CVE ID extraction
# ==============================================================================
class TestCveIdExtraction:
    def test_extract_cve_id(self) -> None:
        item = {"cve": {"id": "CVE-2021-41773"}}
        assert extract_cve_id(item) == "CVE-2021-41773"

    def test_missing_cve_key(self) -> None:
        assert extract_cve_id({}) is None

    def test_missing_id(self) -> None:
        assert extract_cve_id({"cve": {}}) is None


# ==============================================================================
# 13. KEV and EPSS enrichment counting
# ==============================================================================
class TestKevAndEpss:
    def test_kev_count(self) -> None:
        items = [
            {"cve": {"id": "CVE-2021-41773"}},
            {"cve": {"id": "CVE-2021-42013"}},
            {"cve": {"id": "CVE-2021-44790"}},
        ]
        kev = {"CVE-2021-41773", "CVE-2021-42013"}
        result = count_kev_and_epss(items, kev_cve_ids=kev)
        assert result.kev_count == 2
        assert set(result.kev_cve_ids) == {"CVE-2021-41773", "CVE-2021-42013"}

    def test_epss_high_count(self) -> None:
        items = [
            {"cve": {"id": "CVE-2021-41773"}},
            {"cve": {"id": "CVE-2021-42013"}},
            {"cve": {"id": "CVE-2021-44790"}},
        ]
        epss = {
            "CVE-2021-41773": 0.97,
            "CVE-2021-42013": 0.3,
            "CVE-2021-44790": 0.85,
        }
        result = count_kev_and_epss(items, epss_scores=epss)
        assert result.epss_high_count == 2

    def test_no_enrichment_data(self) -> None:
        items = [{"cve": {"id": "CVE-2021-41773"}}]
        result = count_kev_and_epss(items)
        assert result.kev_count == 0
        assert result.epss_high_count == 0


# ==============================================================================
# 14. EOL version detection
# ==============================================================================
class TestEolDetection:
    def test_apache_eol_version(self) -> None:
        p = DetectedProduct(
            vendor="Apache", product="HTTP Server", version="2.2.34",
            cpe_vendor="apache", cpe_product="http_server",
        )
        assert is_version_eol(p) is True

    def test_apache_current_version(self) -> None:
        p = DetectedProduct(
            vendor="Apache", product="HTTP Server", version="2.4.58",
            cpe_vendor="apache", cpe_product="http_server",
        )
        assert is_version_eol(p) is False

    def test_nginx_eol(self) -> None:
        p = DetectedProduct(
            vendor="F5", product="nginx", version="1.18.0",
            cpe_vendor="f5", cpe_product="nginx",
        )
        assert is_version_eol(p) is True

    def test_no_version(self) -> None:
        p = DetectedProduct(
            vendor="Apache", product="HTTP Server", version=None,
            cpe_vendor="apache", cpe_product="http_server",
        )
        assert is_version_eol(p) is False

    def test_unknown_product(self) -> None:
        p = DetectedProduct(
            vendor="Unknown", product="Unknown", version="1.0",
            cpe_vendor="unknown", cpe_product="unknown",
        )
        assert is_version_eol(p) is False

    def test_php_eol_major_minor(self) -> None:
        """PHP 7.4 major.minor prefix matches EOL list."""
        p = DetectedProduct(
            vendor="PHP", product="PHP", version="7.4.99",
            cpe_vendor="php", cpe_product="php",
        )
        assert is_version_eol(p) is True

    def test_iis_eol(self) -> None:
        p = DetectedProduct(
            vendor="Microsoft", product="IIS", version="7.5",
            cpe_vendor="microsoft",
            cpe_product="internet_information_services",
        )
        assert is_version_eol(p) is True


# ==============================================================================
# 15. NVD API response parsing — full pipeline
# ==============================================================================
class TestNvdResponseParsing:
    @respx.mock
    async def test_full_pipeline_apache(self) -> None:
        """Full pipeline: detect Apache, query NVD, emit observation."""
        _mock_nvd(response_data=_NVD_RESPONSE_APACHE)

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"server_header": "Apache/2.4.49"},
        )
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        payload = obs.structured_payload

        assert payload["_collector_id"] == "vendor-cve-history"
        assert payload["vendor_name"] == "Apache"
        assert payload["product_name"] == "HTTP Server"
        assert payload["product_version"] == "2.4.49"
        assert payload["total_cves"] == 3
        assert isinstance(payload["cwe_distribution"], list)
        assert len(payload["cwe_distribution"]) == 2  # CWE-22 and CWE-787

        # CWE-22 has 2 occurrences (higher frequency).
        cwe_22 = [
            d for d in payload["cwe_distribution"] if d["cwe_id"] == "CWE-22"
        ]
        assert len(cwe_22) == 1
        assert cwe_22[0]["count"] == 2

    @respx.mock
    async def test_observation_format(self) -> None:
        """Observation carries all required fields."""
        _mock_nvd(response_data=_NVD_RESPONSE_APACHE)

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"server_header": "Apache/2.4.49"},
        )
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]

        assert obs.collector_id == "vendor-cve-history"
        assert obs.collector_version == "0.1.0"
        assert obs.tenant_id == TENANT_ID
        assert obs.observation_type == ObservationType.SCANNER_HOST
        assert obs.subject.identifier_type == IdentifierType.DOMAIN
        assert obs.subject.identifier_value == "example.com"

    @respx.mock
    async def test_empty_nvd_response(self) -> None:
        """Empty NVD response still emits an observation with zero counts."""
        _mock_nvd(response_data=_NVD_EMPTY_RESPONSE)

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"server_header": "Apache/2.4.58"},
        )
        observations = await _collect(seed)

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert payload["total_cves"] == 0
        assert payload["cwe_distribution"] == []
        assert payload["top_predicted_weakness"] is None


# ==============================================================================
# 16. NVD API 403 rate limit graceful
# ==============================================================================
class TestNvd403:
    @respx.mock
    async def test_403_returns_no_observation(self) -> None:
        _mock_nvd(status_code=403)

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"server_header": "Apache/2.4.49"},
        )
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 17. NVD API 500 error graceful
# ==============================================================================
class TestNvd500:
    @respx.mock
    async def test_500_returns_no_observation(self) -> None:
        _mock_nvd(status_code=500)

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"server_header": "Apache/2.4.49"},
        )
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 18. NVD API connection error graceful
# ==============================================================================
class TestNvdConnectionError:
    @respx.mock
    async def test_connection_error_graceful(self) -> None:
        respx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
        ).mock(side_effect=httpx.ConnectError("DNS failed"))

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"server_header": "Apache/2.4.49"},
        )
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 19. NVD API malformed JSON graceful
# ==============================================================================
class TestNvdMalformedJson:
    @respx.mock
    async def test_malformed_json_graceful(self) -> None:
        respx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
        ).mock(return_value=httpx.Response(200, text="not json"))

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"server_header": "Apache/2.4.49"},
        )
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 20. Non-DOMAIN/IP seeds skipped
# ==============================================================================
class TestSeedTypeFiltering:
    async def test_organization_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        observations = await _collect(seed)
        assert observations == []

    async def test_cidr_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.CIDR, value="192.0.2.0/24")
        observations = await _collect(seed)
        assert observations == []

    async def test_asn_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 21. No products detected yields nothing
# ==============================================================================
class TestNoProductsDetected:
    async def test_no_properties(self) -> None:
        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)
        assert observations == []

    async def test_unknown_server_header(self) -> None:
        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"server_header": "SomeUnknown/1.0"},
        )
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 22. Health check success
# ==============================================================================
class TestHealthCheckSuccess:
    @respx.mock
    async def test_health_check_success(self) -> None:
        respx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
        ).mock(return_value=httpx.Response(200, json=_NVD_EMPTY_RESPONSE))

        collector = VendorCveHistoryCollector(_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "vendor-cve-history"
        assert result.error_message is None

    @respx.mock
    async def test_health_check_latency_non_negative(self) -> None:
        respx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
        ).mock(return_value=httpx.Response(200, json=_NVD_EMPTY_RESPONSE))

        collector = VendorCveHistoryCollector(_config())
        result = await collector.health_check()
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0


# ==============================================================================
# 23. Health check failure (HTTP error)
# ==============================================================================
class TestHealthCheckHttpFailure:
    @respx.mock
    async def test_health_check_http_500(self) -> None:
        respx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
        ).mock(return_value=httpx.Response(500))

        collector = VendorCveHistoryCollector(_config())
        result = await collector.health_check()
        assert result.status == CollectorStatus.FAILURE


# ==============================================================================
# 24. Health check failure (connection error)
# ==============================================================================
class TestHealthCheckConnectionFailure:
    @respx.mock
    async def test_health_check_connection_error(self) -> None:
        respx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
        ).mock(side_effect=httpx.ConnectError("timeout"))

        collector = VendorCveHistoryCollector(_config())
        result = await collector.health_check()
        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "unreachable" in result.error_message.lower()


# ==============================================================================
# 25. Registration in default registry
# ==============================================================================
class TestRegistration:
    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("vendor-cve-history")
        cls = DEFAULT_REGISTRY.get("vendor-cve-history")
        assert cls is VendorCveHistoryCollector


# ==============================================================================
# 26. API key passed in header
# ==============================================================================
class TestApiKeyHandling:
    @respx.mock
    async def test_api_key_sent_in_header(self) -> None:
        _mock_nvd(response_data=_NVD_RESPONSE_APACHE)

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"server_header": "Apache/2.4.49"},
        )
        cfg = _config(nvd_key="test-nvd-key-123")
        await _collect(seed, cfg)

        # Verify the request was made with the apiKey header.
        request = respx.calls[0].request
        assert request.headers.get("apikey") == "test-nvd-key-123"


# ==============================================================================
# 27. No API key still works
# ==============================================================================
class TestNoApiKey:
    @respx.mock
    async def test_no_api_key_works(self) -> None:
        _mock_nvd(response_data=_NVD_RESPONSE_APACHE)

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"server_header": "Apache/2.4.49"},
        )
        cfg = _config()
        observations = await _collect(seed, cfg)
        assert len(observations) == 1

        # Verify no apiKey header was sent.
        request = respx.calls[0].request
        assert "apikey" not in request.headers


# ==============================================================================
# 28. Observation format validation
# ==============================================================================
class TestObservationFormat:
    @respx.mock
    async def test_payload_keys_present(self) -> None:
        """All required payload keys are present."""
        _mock_nvd(response_data=_NVD_RESPONSE_APACHE)

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"server_header": "Apache/2.4.49"},
        )
        observations = await _collect(seed)
        payload = observations[0].structured_payload

        required_keys = {
            "_collector_id",
            "vendor_name",
            "product_name",
            "product_version",
            "cpe_string",
            "total_cves",
            "cwe_distribution",
            "top_predicted_weakness",
            "eol_status",
            "avg_cvss_score",
            "kev_count",
            "epss_high_count",
            "patch_velocity_days",
        }
        assert required_keys.issubset(set(payload.keys()))

    @respx.mock
    async def test_top_predicted_weakness_is_highest_cwe(self) -> None:
        """top_predicted_weakness is the CWE with highest count."""
        _mock_nvd(response_data=_NVD_RESPONSE_APACHE)

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"server_header": "Apache/2.4.49"},
        )
        observations = await _collect(seed)
        payload = observations[0].structured_payload

        # CWE-22 has 2 occurrences (highest in the mock data).
        assert payload["top_predicted_weakness"] == "CWE-22"

    @respx.mock
    async def test_avg_cvss_computed(self) -> None:
        """Average CVSS is correctly computed from mock data."""
        _mock_nvd(response_data=_NVD_RESPONSE_APACHE)

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"server_header": "Apache/2.4.49"},
        )
        observations = await _collect(seed)
        payload = observations[0].structured_payload

        # Scores: 7.5, 9.8, 9.8 → avg = 9.03
        expected_avg = round((7.5 + 9.8 + 9.8) / 3, 2)
        assert payload["avg_cvss_score"] == expected_avg


# ==============================================================================
# 29. Rate limiter token bucket behavior
# ==============================================================================
class TestTokenBucket:
    async def test_first_requests_immediate(self) -> None:
        """First burst_size requests go through immediately."""
        bucket = NvdTokenBucket(has_api_key=False)
        # Burst is 2 for no-key; first 2 should be near-instant.
        start = asyncio.get_event_loop().time()
        await bucket.acquire()
        await bucket.acquire()
        elapsed = asyncio.get_event_loop().time() - start
        assert elapsed < 1.0

    async def test_api_key_increases_rate(self) -> None:
        """With API key, burst is higher."""
        bucket = NvdTokenBucket(has_api_key=True)
        # Burst is 10 for key.
        start = asyncio.get_event_loop().time()
        for _ in range(10):
            await bucket.acquire()
        elapsed = asyncio.get_event_loop().time() - start
        assert elapsed < 1.0

    def test_rate_without_key(self) -> None:
        bucket = NvdTokenBucket(has_api_key=False)
        assert bucket._rate == 5.0 / 30.0
        assert bucket._burst == 2

    def test_rate_with_key(self) -> None:
        bucket = NvdTokenBucket(has_api_key=True)
        assert bucket._rate == 50.0 / 30.0
        assert bucket._burst == 10


# ==============================================================================
# 30. Multiple products emitted as separate observations
# ==============================================================================
class TestMultipleProducts:
    @respx.mock
    async def test_multiple_products_yield_multiple_observations(self) -> None:
        """Each detected product emits its own observation."""
        _mock_nvd(response_data=_NVD_RESPONSE_APACHE)

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={
                "server_header": "Apache/2.4.49",
                "technologies": ["PHP/8.1.2"],
            },
        )
        observations = await _collect(seed)

        assert len(observations) == 2
        vendors = {o.structured_payload["vendor_name"] for o in observations}
        assert "Apache" in vendors
        assert "PHP" in vendors


# ==============================================================================
# 31. Deduplication of detected products
# ==============================================================================
class TestProductDeduplication:
    @respx.mock
    async def test_duplicate_products_not_repeated(self) -> None:
        """Same product from server_header and technologies yields one obs."""
        _mock_nvd(response_data=_NVD_RESPONSE_APACHE)

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={
                "server_header": "Apache/2.4.49",
                "technologies": ["Apache/2.4.49"],
            },
        )
        observations = await _collect(seed)
        assert len(observations) == 1


# ==============================================================================
# 32. Case-insensitive header matching
# ==============================================================================
class TestCaseInsensitive:
    def test_apache_lowercase(self) -> None:
        result = parse_server_header("apache/2.4.41")
        assert result is not None
        assert result.vendor == "Apache"

    def test_nginx_uppercase(self) -> None:
        result = parse_server_header("NGINX/1.18.0")
        assert result is not None
        assert result.vendor == "F5"

    def test_iis_mixed_case(self) -> None:
        result = parse_server_header("microsoft-iis/10.0")
        assert result is not None
        assert result.vendor == "Microsoft"


# ==============================================================================
# 33. IP seed type handling
# ==============================================================================
class TestIpSeedType:
    @respx.mock
    async def test_ip_seed_produces_ip_observation(self) -> None:
        """IP seed yields observation with IP identifier type."""
        _mock_nvd(response_data=_NVD_RESPONSE_APACHE)

        seed = Seed(
            seed_type=SeedType.IP,
            value="192.168.1.1",
            properties={"server_header": "Apache/2.4.49"},
        )
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.subject.identifier_type == IdentifierType.IP
        assert obs.subject.identifier_value == "192.168.1.1"


# ==============================================================================
# 34. CWE name lookup
# ==============================================================================
class TestCweNameLookup:
    def test_known_cwe_has_name(self) -> None:
        assert "CWE-79" in CWE_NAMES
        assert "XSS" in CWE_NAMES["CWE-79"]

    def test_unknown_cwe_uses_id_as_name(self) -> None:
        items = [
            {
                "cve": {
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": "CWE-999999"}]}
                    ]
                }
            }
        ]
        dist = compute_cwe_distribution(items)
        assert dist[0]["cwe_name"] == "CWE-999999"


# ==============================================================================
# 35. Average CVSS computation
# ==============================================================================
class TestAvgCvss:
    def test_avg_cvss_basic(self) -> None:
        items = [
            {"cve": {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]}}},
            {"cve": {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}},
        ]
        result = compute_avg_cvss(items)
        assert result == 8.65

    def test_avg_cvss_no_scores(self) -> None:
        items = [{"cve": {"metrics": {}}}]
        assert compute_avg_cvss(items) is None

    def test_avg_cvss_empty(self) -> None:
        assert compute_avg_cvss([]) is None


# ==============================================================================
# 36. KEV enrichment with seed properties
# ==============================================================================
class TestKevEnrichmentViaSeedProperties:
    @respx.mock
    async def test_kev_count_from_seed_properties(self) -> None:
        """KEV CVE IDs passed via seed properties are counted."""
        _mock_nvd(response_data=_NVD_RESPONSE_APACHE)

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={
                "server_header": "Apache/2.4.49",
                "kev_cve_ids": ["CVE-2021-41773", "CVE-2021-42013"],
            },
        )
        observations = await _collect(seed)
        payload = observations[0].structured_payload
        assert payload["kev_count"] == 2

    @respx.mock
    async def test_epss_count_from_seed_properties(self) -> None:
        """EPSS scores passed via seed properties are counted."""
        _mock_nvd(response_data=_NVD_RESPONSE_APACHE)

        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={
                "server_header": "Apache/2.4.49",
                "epss_scores": {
                    "CVE-2021-41773": 0.97,
                    "CVE-2021-42013": 0.3,
                    "CVE-2021-44790": 0.85,
                },
            },
        )
        observations = await _collect(seed)
        payload = observations[0].structured_payload
        assert payload["epss_high_count"] == 2


# ==============================================================================
# 37. CWE extraction edge cases
# ==============================================================================
class TestCweExtractionEdgeCases:
    def test_non_english_descriptions_skipped(self) -> None:
        """Only English CWE descriptions are extracted."""
        item = {
            "cve": {
                "weaknesses": [
                    {
                        "description": [
                            {"lang": "es", "value": "CWE-79"},
                            {"lang": "en", "value": "CWE-22"},
                        ]
                    }
                ]
            }
        }
        cwe_ids = extract_cwe_ids(item)
        assert cwe_ids == ["CWE-22"]

    def test_empty_weakness_value_skipped(self) -> None:
        item = {
            "cve": {
                "weaknesses": [
                    {"description": [{"lang": "en", "value": ""}]}
                ]
            }
        }
        cwe_ids = extract_cwe_ids(item)
        assert cwe_ids == []

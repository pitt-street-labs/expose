"""Tests for the waf-origin-discovery collector (Tier 2).

Exercises origin IP discovery logic via ``respx`` and stdlib mocks — no live
network calls. Coverage:

1.  CDN header detection per vendor (Cloudflare, Akamai, CloudFront, Fastly,
    Incapsula, Sucuri)
2.  Origin IP discovery via header leakage (mocked responses)
3.  Rate limiting inherited from framework
4.  Collector registration in __init__.py
5.  Certificate SAN analysis (mocked)
6.  Subdomain enumeration (mocked DNS)
7.  MX record analysis (mocked DNS)
8.  Confidence boosting on multi-method discovery
9.  Non-domain/IP seed skipped
10. Health check success and failure
11. Observation type is WAF_ORIGIN_DISCOVERY
12. Technique IDs are correct
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import httpx
import pytest
import respx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorHealthCheck,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.waf_detection import WAF_SIGNATURES
from expose.collectors.builtin.waf_origin_discovery import (
    CDN_VENDOR_SIGNATURES,
    ORIGIN_LEAK_HEADERS,
    ORIGIN_SUBDOMAIN_PREFIXES,
    WafOriginDiscoveryCollector,
    _extract_ips_from_value,
    _is_valid_public_ip,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

# Deterministic test IDs.
TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000E001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000E002")


def _config(**extra: object) -> CollectorConfig:
    """Build a CollectorConfig with test defaults."""
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=5.0,
        extra=dict(extra),  # type: ignore[arg-type]
    )


async def _collect(
    seed: Seed, config: CollectorConfig | None = None
) -> list[Observation]:
    """Run expand() and collect all observations into a list."""
    cfg = config or _config()
    collector = WafOriginDiscoveryCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# ======================================================================
# Collector metadata
# ======================================================================
class TestCollectorMetadata:
    def test_collector_tier(self) -> None:
        """WAF origin discovery collector is Tier 2."""
        assert WafOriginDiscoveryCollector.tier == CollectorTier.TIER_2

    def test_collector_id(self) -> None:
        """Collector ID is 'waf-origin-discovery'."""
        assert WafOriginDiscoveryCollector.collector_id == "waf-origin-discovery"

    def test_collector_version(self) -> None:
        """Collector version is set."""
        assert WafOriginDiscoveryCollector.collector_version == "0.1.0"

    def test_is_subclass_of_collector_abc(self) -> None:
        """WafOriginDiscoveryCollector is a subclass of the Collector ABC."""
        assert issubclass(WafOriginDiscoveryCollector, Collector)

    def test_requires_no_credentials(self) -> None:
        """WAF origin discovery does not require API credentials."""
        assert WafOriginDiscoveryCollector.requires_credentials is False

    def test_technique_ids(self) -> None:
        """Technique IDs are T1592.004 and T1596.001."""
        assert WafOriginDiscoveryCollector.technique_ids == [
            "T1592.004",
            "T1596.001",
        ]


# ======================================================================
# Collector registration
# ======================================================================
class TestCollectorRegistration:
    def test_registered_in_default_registry(self) -> None:
        """waf-origin-discovery is registered in DEFAULT_REGISTRY."""
        assert DEFAULT_REGISTRY.is_registered("waf-origin-discovery")

    def test_registry_returns_correct_class(self) -> None:
        """Registry returns WafOriginDiscoveryCollector for the ID."""
        cls = DEFAULT_REGISTRY.get("waf-origin-discovery")
        assert cls is WafOriginDiscoveryCollector


# ======================================================================
# CDN header detection — Cloudflare
# ======================================================================
class TestCloudflareVendorDetection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_cloudflare_detected_via_headers(self) -> None:
        """Cloudflare CDN detected from cf-ray header."""
        respx.head("https://example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "server": "cloudflare",
                    "cf-ray": "8a1b2c3d4e5f-IAD",
                    "cf-cache-status": "HIT",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["cdn_vendor"] == "cloudflare"


# ======================================================================
# CDN header detection — Akamai
# ======================================================================
class TestAkamaiVendorDetection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_akamai_detected_via_headers(self) -> None:
        """Akamai CDN detected from x-akamai-transformed header."""
        respx.head("https://akamai.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "x-akamai-transformed": "9 12345 0 pmb=mRUM,2",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="akamai.example.com")
        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["cdn_vendor"] == "akamai"


# ======================================================================
# CDN header detection — CloudFront
# ======================================================================
class TestCloudFrontVendorDetection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_cloudfront_detected_via_headers(self) -> None:
        """CloudFront detected from x-amz-cf-id header."""
        respx.head("https://cf.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "x-amz-cf-id": "abc123==",
                    "server": "CloudFront",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="cf.example.com")
        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["cdn_vendor"] == "cloudfront"


# ======================================================================
# CDN header detection — Fastly
# ======================================================================
class TestFastlyVendorDetection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_fastly_detected_via_headers(self) -> None:
        """Fastly detected from x-served-by header with cache- prefix."""
        respx.head("https://fast.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "x-served-by": "cache-iad-kiad7000123-IAD",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="fast.example.com")
        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["cdn_vendor"] == "fastly"


# ======================================================================
# CDN header detection — Incapsula/Imperva
# ======================================================================
class TestIncapsulaVendorDetection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_incapsula_detected_via_headers(self) -> None:
        """Incapsula detected from x-iinfo header."""
        respx.head("https://inc.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "x-iinfo": "7-12345678-0 0NNN RT(1234567890 0)",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="inc.example.com")
        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["cdn_vendor"] == "incapsula"


# ======================================================================
# CDN header detection — Sucuri
# ======================================================================
class TestSucuriVendorDetection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_sucuri_detected_via_headers(self) -> None:
        """Sucuri detected from x-sucuri-id header."""
        respx.head("https://sucuri.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "x-sucuri-id": "12345",
                    "server": "Sucuri",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="sucuri.example.com")
        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["cdn_vendor"] == "sucuri"


# ======================================================================
# Origin IP discovery via header leakage
# ======================================================================
class TestHeaderLeakageDiscovery:
    @respx.mock
    @pytest.mark.asyncio
    async def test_origin_ip_from_x_forwarded_for(self) -> None:
        """Origin IP discovered via X-Forwarded-For header."""
        respx.head("https://leak.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "server": "cloudflare",
                    "cf-ray": "abc123",
                    "x-forwarded-for": "8.8.4.4, 10.0.0.1",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="leak.example.com")
        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        candidates = obs.structured_payload["origin_ip_candidates"]
        ips = [c["ip"] for c in candidates]
        # 8.8.4.4 is public, 10.0.0.1 is private (filtered out)
        assert "8.8.4.4" in ips
        assert "10.0.0.1" not in ips
        assert candidates[0]["discovery_method"] == "header_leakage"
        assert candidates[0]["confidence"] == 0.7

    @respx.mock
    @pytest.mark.asyncio
    async def test_origin_ip_from_x_real_ip(self) -> None:
        """Origin IP discovered via X-Real-IP header."""
        respx.head("https://realip.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "server": "cloudflare",
                    "cf-ray": "abc123",
                    "x-real-ip": "1.1.1.1",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="realip.example.com")
        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        candidates = observations[0].structured_payload["origin_ip_candidates"]
        assert any(c["ip"] == "1.1.1.1" for c in candidates)

    @respx.mock
    @pytest.mark.asyncio
    async def test_origin_ip_from_x_originating_ip(self) -> None:
        """Origin IP discovered via X-Originating-IP header."""
        respx.head("https://origip.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "x-originating-ip": "9.9.9.9",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="origip.example.com")
        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        candidates = observations[0].structured_payload["origin_ip_candidates"]
        assert any(c["ip"] == "9.9.9.9" for c in candidates)

    @respx.mock
    @pytest.mark.asyncio
    async def test_private_ips_filtered_out(self) -> None:
        """Private/reserved IPs are not included in candidates."""
        respx.head("https://private.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "x-forwarded-for": "192.168.1.1, 10.0.0.5, 172.16.0.1",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="private.example.com")
        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        candidates = observations[0].structured_payload["origin_ip_candidates"]
        # All IPs are private — no candidates
        assert len(candidates) == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_leak_headers_yields_empty_candidates(self) -> None:
        """No origin IP leak headers yields empty candidates."""
        respx.head("https://clean.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "server": "cloudflare",
                    "cf-ray": "abc123",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="clean.example.com")
        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["origin_ip_candidates"] == []
        assert observations[0].structured_payload["cdn_vendor"] == "cloudflare"


# ======================================================================
# Rate limiting inherited from framework
# ======================================================================
class TestRateLimiting:
    def test_rate_limiter_initialized_from_config(self) -> None:
        """Rate limiter is initialized from config.extra."""
        cfg = _config(requests_per_second=5.0)
        collector = WafOriginDiscoveryCollector(cfg)
        assert collector._rate_limiter._rate == 5.0

    def test_default_rate_limiter(self) -> None:
        """Default rate limiter is 1.0 req/sec."""
        cfg = _config()
        collector = WafOriginDiscoveryCollector(cfg)
        assert collector._rate_limiter._rate == 1.0


# ======================================================================
# Observation type and structure
# ======================================================================
class TestObservationStructure:
    @respx.mock
    @pytest.mark.asyncio
    async def test_observation_type_is_waf_origin_discovery(self) -> None:
        """Observation type is WAF_ORIGIN_DISCOVERY."""
        respx.head("https://struct.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"server": "nginx"},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="struct.example.com")
        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.observation_type == ObservationType.WAF_ORIGIN_DISCOVERY
        assert obs.collector_id == "waf-origin-discovery"
        assert obs.tenant_id == TENANT_ID

    @respx.mock
    @pytest.mark.asyncio
    async def test_payload_structure(self) -> None:
        """Payload contains required keys: cdn_vendor, origin_ip_candidates,
        discovery_methods_used, total_candidates."""
        respx.head("https://payload.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "server": "cloudflare",
                    "cf-ray": "abc",
                    "x-forwarded-for": "104.16.132.229",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="payload.example.com")
        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        payload = observations[0].structured_payload
        assert "cdn_vendor" in payload
        assert "origin_ip_candidates" in payload
        assert "discovery_methods_used" in payload
        assert "total_candidates" in payload
        assert payload["cdn_vendor"] == "cloudflare"
        assert payload["total_candidates"] == 1
        assert "header_leakage" in payload["discovery_methods_used"]


# ======================================================================
# Seed type filtering
# ======================================================================
class TestSeedTypeFiltering:
    @pytest.mark.asyncio
    async def test_organization_seed_skipped(self) -> None:
        """Seeds that are not DOMAIN or IP are silently skipped."""
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="ACME Corp")
        observations = await _collect(seed)
        assert observations == []

    @pytest.mark.asyncio
    async def test_cidr_seed_skipped(self) -> None:
        """CIDR seeds are skipped."""
        seed = Seed(seed_type=SeedType.CIDR, value="192.0.2.0/24")
        observations = await _collect(seed)
        assert observations == []

    @pytest.mark.asyncio
    async def test_asn_seed_skipped(self) -> None:
        """ASN seeds are skipped."""
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_uses_ip_identifier_type(self) -> None:
        """An IP seed produces observations with IdentifierType.IP."""
        respx.head("https://192.0.2.1").mock(
            return_value=httpx.Response(
                200,
                headers={"server": "nginx"},
            )
        )

        seed = Seed(seed_type=SeedType.IP, value="192.0.2.1")
        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.subject.identifier_type == IdentifierType.IP
        assert obs.subject.identifier_value == "192.0.2.1"


# ======================================================================
# Health check
# ======================================================================
class TestHealthCheck:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Successful HEAD returns SUCCESS status."""
        respx.head("https://httpbin.org/head").mock(
            return_value=httpx.Response(200)
        )

        collector = WafOriginDiscoveryCollector(_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "waf-origin-discovery"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_connection_error(self) -> None:
        """Connection error returns FAILURE status with error message."""
        respx.head("https://httpbin.org/head").mock(
            side_effect=httpx.ConnectError("DNS resolution failed")
        )

        collector = WafOriginDiscoveryCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "DNS resolution failed" in result.error_message

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_5xx(self) -> None:
        """A 500 response means FAILURE."""
        respx.head("https://httpbin.org/head").mock(
            return_value=httpx.Response(500)
        )

        collector = WafOriginDiscoveryCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE


# ======================================================================
# Connection failure
# ======================================================================
class TestConnectionFailure:
    @respx.mock
    @pytest.mark.asyncio
    async def test_all_connections_fail_yields_observation_with_warnings(
        self,
    ) -> None:
        """When all HTTP connections fail, observation still emitted with warnings."""
        respx.head("https://dead.example.com").mock(
            side_effect=httpx.ConnectError("refused")
        )
        respx.head("http://dead.example.com").mock(
            side_effect=httpx.ConnectTimeout("timed out")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="dead.example.com")
        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["cdn_vendor"] is None
        assert len(obs.warnings) >= 2


# ======================================================================
# Helper function unit tests
# ======================================================================
class TestHelperFunctions:
    def test_is_valid_public_ip_public(self) -> None:
        """Public IP returns True."""
        assert _is_valid_public_ip("8.8.8.8") is True

    def test_is_valid_public_ip_private(self) -> None:
        """Private IP returns False."""
        assert _is_valid_public_ip("192.168.1.1") is False
        assert _is_valid_public_ip("10.0.0.1") is False
        assert _is_valid_public_ip("172.16.0.1") is False

    def test_is_valid_public_ip_loopback(self) -> None:
        """Loopback IP returns False."""
        assert _is_valid_public_ip("127.0.0.1") is False

    def test_is_valid_public_ip_invalid(self) -> None:
        """Invalid IP string returns False."""
        assert _is_valid_public_ip("not-an-ip") is False
        assert _is_valid_public_ip("") is False

    def test_extract_ips_from_value_single(self) -> None:
        """Single IP extracted from value."""
        ips = _extract_ips_from_value("8.8.8.8")
        assert ips == ["8.8.8.8"]

    def test_extract_ips_from_value_multiple(self) -> None:
        """Multiple IPs extracted from comma-separated value."""
        ips = _extract_ips_from_value("8.8.8.8, 1.1.1.1")
        assert "8.8.8.8" in ips
        assert "1.1.1.1" in ips

    def test_extract_ips_filters_private(self) -> None:
        """Private IPs are filtered from extraction results."""
        ips = _extract_ips_from_value("192.168.1.1, 8.8.4.4")
        assert ips == ["8.8.4.4"]

    def test_extract_ips_no_match(self) -> None:
        """No IPs in value returns empty list."""
        ips = _extract_ips_from_value("no-ips-here")
        assert ips == []


# ======================================================================
# Data structure validation
# ======================================================================
class TestDataStructures:
    def test_cdn_vendor_signatures_matches_waf_detection(self) -> None:
        """CDN_VENDOR_SIGNATURES is the same as WAF_SIGNATURES."""
        assert CDN_VENDOR_SIGNATURES is WAF_SIGNATURES

    def test_origin_leak_headers_are_lowercase(self) -> None:
        """All leak headers should be lowercase."""
        for h in ORIGIN_LEAK_HEADERS:
            assert h == h.lower(), f"Header {h!r} should be lowercase"

    def test_origin_subdomain_prefixes_not_empty(self) -> None:
        """At least some subdomain prefixes are configured."""
        assert len(ORIGIN_SUBDOMAIN_PREFIXES) > 0

    def test_expected_prefixes_present(self) -> None:
        """Key subdomain prefixes are present."""
        expected = {"ftp", "mail", "direct", "origin", "cpanel"}
        assert expected.issubset(set(ORIGIN_SUBDOMAIN_PREFIXES))


# ======================================================================
# Certificate SAN analysis (mocked)
# ======================================================================
class TestCertificateSanAnalysis:
    @respx.mock
    @pytest.mark.asyncio
    async def test_cert_san_with_ip(self) -> None:
        """IP address in certificate SAN yields a candidate."""
        respx.head("https://cert.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"server": "nginx"},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="cert.example.com")

        # Mock _analyze_certificate to return an IP found in SANs
        mock_cert_result = (
            [
                {
                    "ip": "104.16.132.229",
                    "method": "certificate_san",
                    "confidence": 0.6,
                    "detail": "SAN: 104.16.132.229",
                }
            ],
            [],
        )

        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=mock_cert_result,
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        candidates = observations[0].structured_payload["origin_ip_candidates"]
        assert any(c["ip"] == "104.16.132.229" for c in candidates)
        cert_candidates = [
            c for c in candidates if c["discovery_method"] == "certificate_san"
        ]
        assert len(cert_candidates) >= 1
        assert cert_candidates[0]["confidence"] == 0.6


# ======================================================================
# Subdomain enumeration (mocked)
# ======================================================================
class TestSubdomainEnumeration:
    @respx.mock
    @pytest.mark.asyncio
    async def test_subdomain_discovery(self) -> None:
        """Subdomain resolving to public IP yields a candidate."""
        respx.head("https://sub.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"server": "nginx"},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="sub.example.com")

        mock_sub_result = (
            [
                {
                    "ip": "104.26.10.77",
                    "method": "subdomain_enumeration",
                    "confidence": 0.5,
                    "detail": "ftp.sub.example.com -> 104.26.10.77",
                }
            ],
            [],
        )

        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=mock_sub_result,
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        candidates = observations[0].structured_payload["origin_ip_candidates"]
        sub_candidates = [
            c
            for c in candidates
            if c["discovery_method"] == "subdomain_enumeration"
        ]
        assert len(sub_candidates) >= 1
        assert sub_candidates[0]["ip"] == "104.26.10.77"
        assert sub_candidates[0]["confidence"] == 0.5

    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_skips_subdomain_enumeration(self) -> None:
        """IP seed does not run subdomain enumeration."""
        respx.head("https://192.0.2.1").mock(
            return_value=httpx.Response(200, headers={"server": "nginx"})
        )

        seed = Seed(seed_type=SeedType.IP, value="192.0.2.1")

        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ) as mock_sub:
            observations = await _collect(seed)

        # Should NOT have been called for IP seeds
        mock_sub.assert_not_called()


# ======================================================================
# MX record analysis (mocked)
# ======================================================================
class TestMxRecordAnalysis:
    @respx.mock
    @pytest.mark.asyncio
    async def test_mx_discovery(self) -> None:
        """MX record resolving to public IP yields a candidate."""
        respx.head("https://mx.example.com").mock(
            return_value=httpx.Response(200, headers={"server": "nginx"})
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="mx.example.com")

        mock_mx_result = (
            [
                {
                    "ip": "104.26.11.25",
                    "method": "mx_record_analysis",
                    "confidence": 0.4,
                    "detail": "MX host mail.mx.example.com -> 104.26.11.25",
                }
            ],
            [],
        )

        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=mock_mx_result,
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        candidates = observations[0].structured_payload["origin_ip_candidates"]
        mx_candidates = [
            c
            for c in candidates
            if c["discovery_method"] == "mx_record_analysis"
        ]
        assert len(mx_candidates) >= 1
        assert mx_candidates[0]["ip"] == "104.26.11.25"
        assert mx_candidates[0]["confidence"] == 0.4


# ======================================================================
# Multi-method confidence boosting
# ======================================================================
class TestConfidenceBoosting:
    @respx.mock
    @pytest.mark.asyncio
    async def test_same_ip_from_two_methods_boosts_confidence(self) -> None:
        """Same IP found via header leakage and subdomain gets confidence boost."""
        respx.head("https://multi.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "server": "cloudflare",
                    "cf-ray": "abc",
                    "x-forwarded-for": "104.16.132.229",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="multi.example.com")

        # Subdomain also resolves to the same IP
        mock_sub_result = (
            [
                {
                    "ip": "104.16.132.229",
                    "method": "subdomain_enumeration",
                    "confidence": 0.5,
                    "detail": "ftp.multi.example.com -> 104.16.132.229",
                }
            ],
            [],
        )

        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=mock_sub_result,
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=([], []),
        ):
            observations = await _collect(seed)

        assert len(observations) == 1
        candidates = observations[0].structured_payload["origin_ip_candidates"]
        ip_50 = [c for c in candidates if c["ip"] == "104.16.132.229"]
        assert len(ip_50) == 1
        # Original header_leakage confidence 0.7 + 0.1 boost = 0.8
        assert ip_50[0]["confidence"] == 0.8
        assert "subdomain_enumeration" in ip_50[0].get(
            "additional_methods", []
        )


# ======================================================================
# Candidates sorted by confidence
# ======================================================================
class TestCandidateSorting:
    @respx.mock
    @pytest.mark.asyncio
    async def test_candidates_sorted_by_confidence_descending(self) -> None:
        """Candidates are sorted by confidence descending."""
        respx.head("https://sort.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "server": "cloudflare",
                    "cf-ray": "abc",
                    "x-forwarded-for": "104.16.132.229",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="sort.example.com")

        mock_cert = (
            [
                {
                    "ip": "104.26.10.99",
                    "method": "certificate_san",
                    "confidence": 0.6,
                    "detail": "SAN: 104.26.10.99",
                }
            ],
            [],
        )
        mock_mx = (
            [
                {
                    "ip": "104.26.11.25",
                    "method": "mx_record_analysis",
                    "confidence": 0.4,
                    "detail": "MX host -> 104.26.11.25",
                }
            ],
            [],
        )

        with patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_certificate",
            new_callable=AsyncMock,
            return_value=mock_cert,
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_enumerate_subdomains",
            new_callable=AsyncMock,
            return_value=([], []),
        ), patch.object(
            WafOriginDiscoveryCollector,
            "_analyze_mx_records",
            new_callable=AsyncMock,
            return_value=mock_mx,
        ):
            observations = await _collect(seed)

        candidates = observations[0].structured_payload["origin_ip_candidates"]
        confidences = [c["confidence"] for c in candidates]
        assert confidences == sorted(confidences, reverse=True)

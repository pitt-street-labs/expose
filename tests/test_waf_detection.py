"""Tests for the waf-detection collector (Tier 2, per Gitea issue #50).

Exercises WAF/CDN detection logic via ``respx`` mocks — no live network
calls.  Coverage:

1.  Cloudflare detection (cf-ray header)
2.  Akamai detection (x-akamai-transformed header)
3.  CloudFront detection (x-amz-cf-id header)
4.  Fastly detection (x-served-by header with cache- prefix)
5.  No WAF detected (plain server)
6.  Multiple WAF indicators from same vendor increase confidence
7.  Unknown headers don't trigger false positives
8.  Collector tier is TIER_2
9.  Collector_id is "waf-detection"
10. expand returns list of Observations
11. WAF_SIGNATURES data structure validation
12. Empty response headers (no match)
13. IP seed uses IP identifier type
14. Non-domain/IP seed skipped
15. Health check success and failure
16. Incapsula detection
17. Sucuri detection
18. Azure Front Door detection
19. AWS WAF detection
20. Connection failure yields warning observation
"""

from __future__ import annotations

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
from expose.collectors.builtin.waf_detection import (
    WAF_SIGNATURES,
    WafDetectionCollector,
    _compute_detections,
    _match_headers,
)
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

# Deterministic test IDs.
TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000D001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000D002")


def _config(**extra: object) -> CollectorConfig:
    """Build a CollectorConfig with test defaults."""
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=5.0,
        extra=dict(extra),  # type: ignore[arg-type]
    )


async def _collect(seed: Seed, config: CollectorConfig | None = None) -> list[Observation]:
    """Run expand() and collect all observations into a list."""
    cfg = config or _config()
    collector = WafDetectionCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# ======================================================================
# 1. Cloudflare detection (cf-ray header)
# ======================================================================
class TestCloudflareDetection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_cloudflare_detected_via_cf_ray(self) -> None:
        """cf-ray header triggers Cloudflare detection."""
        respx.head("https://example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "server": "cloudflare",
                    "cf-ray": "8a1b2c3d4e5f-IAD",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["waf_detected"] is True
        assert obs.structured_payload["waf_vendor"] == "cloudflare"
        assert len(obs.structured_payload["detections"]) == 1
        detection = obs.structured_payload["detections"][0]
        assert detection["vendor"] == "cloudflare"
        assert detection["confidence"] > 0.0
        assert any(h["header"] == "cf-ray" for h in detection["matched_headers"])


# ======================================================================
# 2. Akamai detection (x-akamai-transformed header)
# ======================================================================
class TestAkamaiDetection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_akamai_detected_via_header(self) -> None:
        """x-akamai-transformed header triggers Akamai detection."""
        respx.head("https://target.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "x-akamai-transformed": "9 12345 0 pmb=mRUM,2",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="target.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["waf_detected"] is True
        assert obs.structured_payload["waf_vendor"] == "akamai"


# ======================================================================
# 3. CloudFront detection (x-amz-cf-id header)
# ======================================================================
class TestCloudFrontDetection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_cloudfront_detected_via_cf_id(self) -> None:
        """x-amz-cf-id header triggers CloudFront detection."""
        respx.head("https://cdn.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "x-amz-cf-id": "abc123==",
                    "x-amz-cf-pop": "IAD55-P1",
                    "server": "CloudFront",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="cdn.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["waf_detected"] is True
        assert obs.structured_payload["waf_vendor"] == "cloudfront"
        detection = obs.structured_payload["detections"][0]
        # All three CloudFront signatures match.
        assert detection["confidence"] == 1.0
        assert len(detection["matched_headers"]) == 3


# ======================================================================
# 4. Fastly detection
# ======================================================================
class TestFastlyDetection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_fastly_detected_via_x_served_by(self) -> None:
        """x-served-by header with cache- prefix triggers Fastly detection."""
        respx.head("https://fast.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "x-served-by": "cache-iad-kiad7000123-IAD",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="fast.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["waf_detected"] is True
        assert obs.structured_payload["waf_vendor"] == "fastly"


# ======================================================================
# 5. No WAF detected (plain server)
# ======================================================================
class TestNoWafDetected:
    @respx.mock
    @pytest.mark.asyncio
    async def test_plain_server_no_waf(self) -> None:
        """A plain nginx/Apache server without WAF headers yields no detection."""
        respx.head("https://plain.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "server": "nginx/1.25.0",
                    "content-type": "text/html",
                    "x-powered-by": "Express",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="plain.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["waf_detected"] is False
        assert obs.structured_payload["waf_vendor"] is None
        assert obs.structured_payload["detections"] == []


# ======================================================================
# 6. Multiple WAF indicators from same vendor increase confidence
# ======================================================================
class TestMultipleIndicators:
    @respx.mock
    @pytest.mark.asyncio
    async def test_multiple_cloudflare_headers_increase_confidence(self) -> None:
        """All three Cloudflare signatures matching yields confidence 1.0."""
        respx.head("https://multi.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "server": "cloudflare",
                    "cf-ray": "8a1b2c3d4e5f-IAD",
                    "cf-cache-status": "HIT",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="multi.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        detection = observations[0].structured_payload["detections"][0]
        assert detection["vendor"] == "cloudflare"
        # 3/3 signatures matched.
        assert detection["confidence"] == 1.0
        assert len(detection["matched_headers"]) == 3

    @respx.mock
    @pytest.mark.asyncio
    async def test_single_cloudflare_header_lower_confidence(self) -> None:
        """Only cf-ray matching yields confidence 1/3 ~ 0.3333."""
        respx.head("https://single.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "cf-ray": "8a1b2c3d4e5f-IAD",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="single.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        detection = observations[0].structured_payload["detections"][0]
        assert detection["vendor"] == "cloudflare"
        assert detection["confidence"] == pytest.approx(1 / 3, abs=0.01)
        assert len(detection["matched_headers"]) == 1


# ======================================================================
# 7. Unknown headers don't trigger false positives
# ======================================================================
class TestFalsePositives:
    @respx.mock
    @pytest.mark.asyncio
    async def test_unknown_headers_no_false_positive(self) -> None:
        """Custom headers that don't match WAF signatures yield no detection."""
        respx.head("https://custom.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "x-custom-waf": "proprietary-waf-v2",
                    "x-request-id": "abc-123",
                    "server": "gunicorn/20.1.0",
                },
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="custom.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["waf_detected"] is False
        assert observations[0].structured_payload["detections"] == []

    def test_x_served_by_without_cache_prefix_no_fastly(self) -> None:
        """x-served-by without 'cache-' prefix should not match Fastly."""
        headers = httpx.Headers({"x-served-by": "app-server-01"})
        matches = _match_headers(headers)
        vendor_names = {m["vendor"] for m in matches}
        assert "fastly" not in vendor_names


# ======================================================================
# 8. Collector tier is TIER_2
# ======================================================================
class TestCollectorMetadata:
    def test_collector_tier(self) -> None:
        """WAF detection collector is Tier 2."""
        assert WafDetectionCollector.tier == CollectorTier.TIER_2

    def test_collector_id(self) -> None:
        """Collector ID is 'waf-detection'."""
        assert WafDetectionCollector.collector_id == "waf-detection"

    def test_collector_version(self) -> None:
        """Collector version is set."""
        assert WafDetectionCollector.collector_version == "0.1.0"

    def test_is_subclass_of_collector_abc(self) -> None:
        """WafDetectionCollector is a subclass of the Collector ABC."""
        assert issubclass(WafDetectionCollector, Collector)

    def test_requires_no_credentials(self) -> None:
        """WAF detection does not require API credentials."""
        assert WafDetectionCollector.requires_credentials is False


# ======================================================================
# 9. expand returns list of Observations
# ======================================================================
class TestExpandReturnType:
    @respx.mock
    @pytest.mark.asyncio
    async def test_expand_yields_observation_instances(self) -> None:
        """expand() yields Observation instances."""
        respx.head("https://obs.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"server": "nginx"},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="obs.example.com")
        observations = await _collect(seed)

        assert len(observations) >= 1
        for obs in observations:
            assert isinstance(obs, Observation)
            assert obs.observation_type == ObservationType.HTTP_RESPONSE
            assert obs.tenant_id == TENANT_ID
            assert obs.collector_id == "waf-detection"


# ======================================================================
# 10. WAF_SIGNATURES data structure validation
# ======================================================================
class TestWafSignaturesStructure:
    def test_signatures_is_dict(self) -> None:
        """WAF_SIGNATURES is a dict mapping vendor names to signature lists."""
        assert isinstance(WAF_SIGNATURES, dict)
        assert len(WAF_SIGNATURES) > 0

    def test_each_vendor_has_signatures(self) -> None:
        """Every vendor has at least one signature."""
        for vendor, sigs in WAF_SIGNATURES.items():
            assert isinstance(sigs, list), f"{vendor} signatures should be a list"
            assert len(sigs) > 0, f"{vendor} should have at least one signature"

    def test_each_signature_has_required_keys(self) -> None:
        """Each signature dict has 'header' and 'pattern' keys."""
        for vendor, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                assert "header" in sig, f"{vendor} signature missing 'header'"
                assert "pattern" in sig, f"{vendor} signature missing 'pattern'"
                assert isinstance(sig["header"], str)
                assert isinstance(sig["pattern"], str)

    def test_expected_vendors_present(self) -> None:
        """All expected WAF/CDN vendors are represented."""
        expected = {
            "cloudflare",
            "akamai",
            "cloudfront",
            "fastly",
            "incapsula",
            "sucuri",
            "aws_waf",
            "azure_front_door",
        }
        assert expected == set(WAF_SIGNATURES.keys())

    def test_header_names_are_lowercase(self) -> None:
        """All header names in signatures should be lowercase."""
        for vendor, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                assert sig["header"] == sig["header"].lower(), (
                    f"{vendor}: header {sig['header']!r} should be lowercase"
                )


# ======================================================================
# 11. Empty response headers (no match)
# ======================================================================
class TestEmptyHeaders:
    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_headers_no_detection(self) -> None:
        """A response with minimal/empty headers yields no WAF detection."""
        respx.head("https://empty.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="empty.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["waf_detected"] is False

    def test_match_headers_with_empty_headers(self) -> None:
        """_match_headers returns empty list for empty headers."""
        headers = httpx.Headers({})
        matches = _match_headers(headers)
        assert matches == []


# ======================================================================
# 12. IP seed uses IP identifier type
# ======================================================================
class TestIpSeed:
    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_uses_ip_identifier_type(self) -> None:
        """An IP seed produces observations with IdentifierType.IP."""
        respx.head("https://192.0.2.1").mock(
            return_value=httpx.Response(
                200,
                headers={"cf-ray": "abc123"},
            )
        )

        seed = Seed(seed_type=SeedType.IP, value="192.0.2.1")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.subject.identifier_type == IdentifierType.IP
        assert obs.subject.identifier_value == "192.0.2.1"
        assert obs.structured_payload["waf_detected"] is True


# ======================================================================
# 13. Non-domain/IP seed skipped
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


# ======================================================================
# 14. Health check
# ======================================================================
class TestHealthCheck:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Successful HEAD returns SUCCESS status."""
        respx.head("https://httpbin.org/head").mock(return_value=httpx.Response(200))

        collector = WafDetectionCollector(_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "waf-detection"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_connection_error(self) -> None:
        """Connection error returns FAILURE status with error message."""
        respx.head("https://httpbin.org/head").mock(
            side_effect=httpx.ConnectError("DNS resolution failed")
        )

        collector = WafDetectionCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "DNS resolution failed" in result.error_message

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_5xx(self) -> None:
        """A 500 response means FAILURE."""
        respx.head("https://httpbin.org/head").mock(return_value=httpx.Response(500))

        collector = WafDetectionCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE


# ======================================================================
# 15. Incapsula detection
# ======================================================================
class TestIncapsulaDetection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_incapsula_detected_via_x_iinfo(self) -> None:
        """x-iinfo header triggers Incapsula detection."""
        respx.head("https://inc.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"x-iinfo": "7-12345678-0 0NNN RT(1234567890 0)"},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="inc.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["waf_vendor"] == "incapsula"


# ======================================================================
# 16. Sucuri detection
# ======================================================================
class TestSucuriDetection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_sucuri_detected_via_header(self) -> None:
        """x-sucuri-id header triggers Sucuri detection."""
        respx.head("https://sucuri.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"x-sucuri-id": "12345"},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="sucuri.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["waf_vendor"] == "sucuri"


# ======================================================================
# 17. Azure Front Door detection
# ======================================================================
class TestAzureFrontDoorDetection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_azure_front_door_detected(self) -> None:
        """x-azure-ref header triggers Azure Front Door detection."""
        respx.head("https://azure.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"x-azure-ref": "0abc123=="},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="azure.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["waf_vendor"] == "azure_front_door"


# ======================================================================
# 18. AWS WAF detection
# ======================================================================
class TestAwsWafDetection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_aws_waf_detected_via_request_id(self) -> None:
        """x-amzn-requestid header triggers AWS WAF detection."""
        respx.head("https://aws.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"x-amzn-requestid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="aws.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["waf_vendor"] == "aws_waf"


# ======================================================================
# 19. Connection failure yields warning observation
# ======================================================================
class TestConnectionFailure:
    @respx.mock
    @pytest.mark.asyncio
    async def test_all_connections_fail_yields_warning_observation(self) -> None:
        """When all connections fail, a warning observation is emitted."""
        respx.head("https://dead.example.com").mock(side_effect=httpx.ConnectError("refused"))
        respx.head("http://dead.example.com").mock(side_effect=httpx.ConnectTimeout("timed out"))

        seed = Seed(seed_type=SeedType.DOMAIN, value="dead.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["waf_detected"] is False
        assert obs.structured_payload["error"] == "All connection attempts failed"
        assert len(obs.warnings) == 2


# ======================================================================
# 20. HTTPS fallback to HTTP
# ======================================================================
class TestHttpsFallback:
    @respx.mock
    @pytest.mark.asyncio
    async def test_https_fails_falls_back_to_http(self) -> None:
        """If HTTPS fails, HTTP is tried and its result returned."""
        respx.head("https://httponly.example.com").mock(
            side_effect=httpx.ConnectError("TLS handshake failed")
        )
        respx.head("http://httponly.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"cf-ray": "fallback-test"},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="httponly.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["waf_detected"] is True
        assert obs.structured_payload["waf_vendor"] == "cloudflare"
        # The HTTPS failure is recorded as a warning.
        assert len(obs.warnings) == 1
        assert "TLS handshake failed" in obs.warnings[0]


# ======================================================================
# Helper function unit tests
# ======================================================================
class TestMatchHeadersHelper:
    def test_match_returns_correct_vendor(self) -> None:
        """_match_headers returns the correct vendor for known headers."""
        headers = httpx.Headers(
            {
                "cf-ray": "abc123",
                "server": "cloudflare",
            }
        )
        matches = _match_headers(headers)
        vendors = {m["vendor"] for m in matches}
        assert "cloudflare" in vendors

    def test_no_match_returns_empty(self) -> None:
        """_match_headers returns empty list for unrecognized headers."""
        headers = httpx.Headers(
            {
                "server": "Apache/2.4",
                "x-custom": "value",
            }
        )
        matches = _match_headers(headers)
        assert matches == []


class TestComputeDetectionsHelper:
    def test_detections_sorted_by_confidence_descending(self) -> None:
        """_compute_detections sorts by confidence descending."""
        matches = [
            {"vendor": "cloudflare", "header": "cf-ray", "pattern": ".*", "value": "abc"},
            {
                "vendor": "cloudflare",
                "header": "server",
                "pattern": "cloudflare",
                "value": "cloudflare",
            },
            {"vendor": "cloudflare", "header": "cf-cache-status", "pattern": ".*", "value": "HIT"},
            {
                "vendor": "fastly",
                "header": "x-served-by",
                "pattern": "cache-.*",
                "value": "cache-iad",
            },
        ]
        detections = _compute_detections(matches)

        assert len(detections) == 2
        # Cloudflare has 3/3 = 1.0, Fastly has 1/2 = 0.5.
        assert detections[0]["vendor"] == "cloudflare"
        assert detections[0]["confidence"] == 1.0
        assert detections[1]["vendor"] == "fastly"
        assert detections[1]["confidence"] == 0.5

    def test_empty_matches_returns_empty(self) -> None:
        """_compute_detections returns empty list for no matches."""
        detections = _compute_detections([])
        assert detections == []

"""Tests for the active-http-fingerprint collector (Tier 3, Sprint 4).

Exercises HTTP fingerprinting logic via ``respx`` mocks — no live network
calls.  Coverage:

1.  Happy path: domain seed yields HTTP_RESPONSE observation
2.  HTTPS probe: TLS endpoint captured
3.  Redirect chain: redirects followed & chain recorded
4.  Max redirects exceeded: TooManyRedirects handled gracefully
5.  Partial failure: one port down, other succeeds
6.  Total failure: both ports unreachable -> CollectorSourceUnreachableError
7.  Server header sanitization: malicious content sanitized
8.  Title extraction from HTML body
9.  Non-domain/IP seed skipped
10. Health check: success and failure paths
11. Banner cap: body >4096 bytes truncated
12. IP seed: identifier_type=IP, canonical value
"""

from unittest.mock import MagicMock
from uuid import UUID

import httpx
import pytest
import respx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorHealthCheck,
    CollectorSourceUnreachableError,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.active_http import ActiveHttpCollector
from expose.collectors.tiers import CollectorTier
from expose.egress.base import EgressProfile, EgressProfileType
from expose.egress.direct import DirectEgressProfile
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


async def _collect(
    seed: Seed, config: CollectorConfig | None = None
) -> list[Observation]:
    """Run expand() and collect all observations into a list."""
    cfg = config or _config()
    collector = ActiveHttpCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# ======================================================================
# 1. Happy path — domain seed, HTTP 200
# ======================================================================
class TestHappyPath:
    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_seed_yields_http_response_observations(self) -> None:
        """A domain seed that responds on both ports yields two observations."""
        respx.get("https://example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"server": "nginx/1.25.0", "content-type": "text/html"},
                content=b"<html><title>Example</title></html>",
            )
        )
        respx.get("http://example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"server": "nginx/1.25.0", "content-type": "text/html"},
                content=b"<html><title>Example</title></html>",
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        assert len(observations) == 2
        for obs in observations:
            assert obs.observation_type == ObservationType.HTTP_RESPONSE
            assert obs.tenant_id == TENANT_ID
            assert obs.collector_id == "active-http-fingerprint"
            assert obs.subject.identifier_type == IdentifierType.DOMAIN
            assert obs.subject.identifier_value == "example.com"
            assert obs.structured_payload["status_code"] == 200
            assert obs.structured_payload["server_header"] == "nginx/1.25.0"
            assert obs.structured_payload["title"] == "Example"
            assert obs.evidence_blob is not None
            assert obs.evidence_blob_content_type == "text/plain"


# ======================================================================
# 2. HTTPS probe — TLS connection captured
# ======================================================================
class TestHttpsProbe:
    @respx.mock
    @pytest.mark.asyncio
    async def test_https_probe_captures_response(self) -> None:
        """HTTPS endpoint is probed and observation emitted."""
        respx.get("https://secure.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "server": "Apache/2.4",
                    "strict-transport-security": "max-age=63072000",
                },
                content=b"secure page",
            )
        )
        # HTTP port fails.
        respx.get("http://secure.example.com").mock(
            side_effect=httpx.ConnectError("refused")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="secure.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert "https://secure.example.com" in obs.structured_payload["url"]
        assert obs.structured_payload["headers"]["strict-transport-security"] == "max-age=63072000"


# ======================================================================
# 3. Redirect chain recorded
# ======================================================================
class TestRedirectChain:
    @respx.mock
    @pytest.mark.asyncio
    async def test_redirect_chain_is_recorded(self) -> None:
        """Three redirects followed; chain captured in payload."""
        # Mock a real redirect sequence with distinct URLs so respx
        # follows each hop via httpx's built-in redirect handling.
        respx.get("https://example.com").mock(
            return_value=httpx.Response(
                301,
                headers={"location": "https://www.example.com/step2"},
            )
        )
        respx.get("https://www.example.com/step2").mock(
            return_value=httpx.Response(
                302,
                headers={"location": "https://www.example.com/step3"},
            )
        )
        respx.get("https://www.example.com/step3").mock(
            return_value=httpx.Response(
                200,
                headers={"server": "nginx"},
                content=b"<html><title>Final</title></html>",
            )
        )
        respx.get("http://example.com").mock(
            side_effect=httpx.ConnectError("refused")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        chain = obs.structured_payload["redirect_chain"]
        assert len(chain) == 2
        assert "https://example.com" in chain[0]
        assert "step2" in chain[1]


# ======================================================================
# 4. Max redirects exceeded — graceful handling
# ======================================================================
class TestMaxRedirects:
    @respx.mock
    @pytest.mark.asyncio
    async def test_too_many_redirects_handled_gracefully(self) -> None:
        """TooManyRedirects on one URL is a warning, not a crash.

        If the other URL also fails, CollectorSourceUnreachableError is raised.
        """
        respx.get("https://loop.example.com").mock(
            side_effect=httpx.TooManyRedirects(
                "Exceeded max redirects",
                request=httpx.Request("GET", "https://loop.example.com"),
            )
        )
        respx.get("http://loop.example.com").mock(
            side_effect=httpx.TooManyRedirects(
                "Exceeded max redirects",
                request=httpx.Request("GET", "http://loop.example.com"),
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="loop.example.com")

        with pytest.raises(CollectorSourceUnreachableError) as exc_info:
            await _collect(seed)
        assert "loop.example.com" in str(exc_info.value)


# ======================================================================
# 5. Partial failure — one port down, other succeeds
# ======================================================================
class TestPartialFailure:
    @respx.mock
    @pytest.mark.asyncio
    async def test_one_port_fails_other_succeeds(self) -> None:
        """Connection refused on HTTPS but HTTP succeeds — partial success."""
        respx.get("https://partial.example.com").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        respx.get("http://partial.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"server": "lighttpd/1.4"},
                content=b"OK",
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="partial.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["status_code"] == 200
        assert obs.structured_payload["server_header"] == "lighttpd/1.4"


# ======================================================================
# 6. Total failure — both ports unreachable
# ======================================================================
class TestTotalFailure:
    @respx.mock
    @pytest.mark.asyncio
    async def test_all_probes_fail_raises_source_unreachable(self) -> None:
        """Both HTTPS and HTTP fail -> CollectorSourceUnreachableError."""
        respx.get("https://dead.example.com").mock(
            side_effect=httpx.ConnectError("refused")
        )
        respx.get("http://dead.example.com").mock(
            side_effect=httpx.ConnectTimeout("timed out")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="dead.example.com")
        with pytest.raises(CollectorSourceUnreachableError) as exc_info:
            await _collect(seed)
        assert "dead.example.com" in str(exc_info.value)


# ======================================================================
# 7. Server header sanitization
# ======================================================================
class TestServerHeaderSanitization:
    @respx.mock
    @pytest.mark.asyncio
    async def test_malicious_server_header_sanitized(self) -> None:
        """Control characters in the Server header are stripped."""
        respx.get("https://evil.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"server": "evil\x00server\x01header"},
                content=b"OK",
            )
        )
        respx.get("http://evil.example.com").mock(
            side_effect=httpx.ConnectError("refused")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="evil.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        # Control chars should be stripped.
        assert "\x00" not in obs.structured_payload["server_header"]
        assert "\x01" not in obs.structured_payload["server_header"]
        assert "evilserverheader" in obs.structured_payload["server_header"]


# ======================================================================
# 8. Title extraction from HTML body
# ======================================================================
class TestTitleExtraction:
    @respx.mock
    @pytest.mark.asyncio
    async def test_html_title_extracted_from_body(self) -> None:
        """<title> tag content is extracted and sanitized."""
        html = b"<html><head><title>  My Page Title  </title></head><body></body></html>"
        respx.get("https://titled.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content=html,
            )
        )
        respx.get("http://titled.example.com").mock(
            side_effect=httpx.ConnectError("refused")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="titled.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["title"] == "My Page Title"

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_title_yields_none(self) -> None:
        """Response without <title> tag yields null title."""
        respx.get("https://notitle.example.com").mock(
            return_value=httpx.Response(200, content=b"plain text, no HTML")
        )
        respx.get("http://notitle.example.com").mock(
            side_effect=httpx.ConnectError("refused")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="notitle.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["title"] is None


# ======================================================================
# 9. Non-domain/IP seed skipped
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
# 10. Health check
# ======================================================================
class TestHealthCheck:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Successful HEAD returns SUCCESS status."""
        respx.head("https://httpbin.org/head").mock(
            return_value=httpx.Response(200)
        )

        collector = ActiveHttpCollector(_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "active-http-fingerprint"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_connection_error(self) -> None:
        """Connection error returns FAILURE status with error message."""
        respx.head("https://httpbin.org/head").mock(
            side_effect=httpx.ConnectError("DNS resolution failed")
        )

        collector = ActiveHttpCollector(_config())
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

        collector = ActiveHttpCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE


# ======================================================================
# 11. Banner cap — body >4096 bytes truncated
# ======================================================================
class TestBannerCap:
    @respx.mock
    @pytest.mark.asyncio
    async def test_long_body_banner_truncated(self) -> None:
        """Response body >4096 bytes is truncated in the banner field."""
        long_body = b"A" * 8192
        respx.get("https://big.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "text/plain"},
                content=long_body,
            )
        )
        respx.get("http://big.example.com").mock(
            side_effect=httpx.ConnectError("refused")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="big.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        banner = observations[0].structured_payload["banner"]
        # The banner should be at most 4096 bytes (the sanitization layer
        # applies its own HTTP_BANNER cap which is also 4096).
        assert len(banner.encode("utf-8")) <= 4096


# ======================================================================
# 12. IP seed — identifier type and canonical value
# ======================================================================
class TestIpSeed:
    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_uses_ip_identifier_type(self) -> None:
        """An IP seed produces observations with IdentifierType.IP."""
        respx.get("https://192.0.2.1").mock(
            return_value=httpx.Response(
                200,
                headers={"server": "test"},
                content=b"OK",
            )
        )
        respx.get("http://192.0.2.1").mock(
            side_effect=httpx.ConnectError("refused")
        )

        seed = Seed(seed_type=SeedType.IP, value="192.0.2.1")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.subject.identifier_type == IdentifierType.IP
        assert obs.subject.identifier_value == "192.0.2.1"


# ======================================================================
# Collector metadata
# ======================================================================
class TestCollectorMetadata:
    def test_collector_class_attributes(self) -> None:
        """Verify class-level metadata on ActiveHttpCollector."""
        assert ActiveHttpCollector.collector_id == "active-http-fingerprint"
        assert ActiveHttpCollector.collector_version == "0.1.0"
        assert ActiveHttpCollector.tier == CollectorTier.TIER_3
        assert ActiveHttpCollector.requires_credentials is False

    def test_collector_is_subclass_of_collector_abc(self) -> None:
        assert issubclass(ActiveHttpCollector, Collector)


# ======================================================================
# 13. Egress profile integration
# ======================================================================
class TestEgressProfileIntegration:
    @respx.mock
    @pytest.mark.asyncio
    async def test_works_without_egress_profile(self) -> None:
        """Backward compatibility: collector works with no egress_profile in extra."""
        respx.get("https://example.com").mock(
            return_value=httpx.Response(200, content=b"OK")
        )
        respx.get("http://example.com").mock(
            side_effect=httpx.ConnectError("refused")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        # Config with no egress_profile key at all.
        observations = await _collect(seed, _config())

        assert len(observations) == 1
        assert observations[0].structured_payload["status_code"] == 200

    @respx.mock
    @pytest.mark.asyncio
    async def test_direct_egress_profile_works(self) -> None:
        """DirectEgressProfile passes through without altering behavior."""
        respx.get("https://example.com").mock(
            return_value=httpx.Response(
                200,
                headers={"server": "nginx"},
                content=b"<html><title>Direct</title></html>",
            )
        )
        respx.get("http://example.com").mock(
            side_effect=httpx.ConnectError("refused")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(egress_profile=DirectEgressProfile())
        observations = await _collect(seed, cfg)

        assert len(observations) == 1
        assert observations[0].structured_payload["title"] == "Direct"

    @pytest.mark.asyncio
    async def test_egress_profile_configure_httpx_client_called(self) -> None:
        """The egress profile's configure_httpx_client method is invoked."""
        mock_profile = MagicMock(spec=EgressProfile)
        mock_profile.profile_type = EgressProfileType.DIRECT
        mock_profile.configure_httpx_client.return_value = {}

        cfg = _config(egress_profile=mock_profile)
        collector = ActiveHttpCollector(cfg)

        # Call the internal helper directly to verify it delegates.
        result = collector._egress_httpx_kwargs()

        mock_profile.configure_httpx_client.assert_called_once()
        assert result == {}

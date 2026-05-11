"""Tests for the bgp-he-toolkit BGP/ASN collector.

Uses respx to mock all HTTP interactions — NO live network calls.
Fixtures in tests/fixtures/collectors/bgp_he_toolkit/ provide canned
HE BGP Toolkit HTML pages.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import httpx
import pytest
import respx

from expose.collectors.base import (
    CollectorConfig,
    CollectorHealthCheck,
    CollectorSourceUnreachableError,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.bgp_he_toolkit import (
    HeToolkitCollector,
    _parse_asn_and_holder,
    _parse_prefixes,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000ca01")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000ca02")

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "collectors" / "bgp_he_toolkit"

_HE_BASE_URL = "https://bgp.he.net"


def _load_fixture(name: str) -> str:
    return (FIXTURES_DIR / name).read_text()


def _make_config(
    *,
    timeout: float = 30.0,
    rate_limit: int | None = None,
) -> CollectorConfig:
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=timeout,
        rate_limit_per_minute=rate_limit,
    )


def _make_ip_seed(ip: str = "1.1.1.1") -> Seed:
    return Seed(seed_type=SeedType.IP, value=ip)


def _make_asn_seed(asn: str = "AS13335") -> Seed:
    return Seed(seed_type=SeedType.ASN, value=asn)


async def _collect_all(
    collector: HeToolkitCollector, seed: Seed
) -> list[Observation]:
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


class TestHeToolkitMetadata:
    """Verify class-level metadata attributes."""

    def test_collector_id(self) -> None:
        assert HeToolkitCollector.collector_id == "bgp-he-toolkit"

    def test_collector_version(self) -> None:
        assert HeToolkitCollector.collector_version == "0.1.0"

    def test_tier(self) -> None:
        assert HeToolkitCollector.tier == CollectorTier.TIER_1

    def test_requires_credentials(self) -> None:
        assert HeToolkitCollector.requires_credentials is False


class TestHeToolkitParsers:
    """Unit tests for internal HTML parsing functions."""

    def test_parse_asn_and_holder_from_h1(self) -> None:
        html = '<h1>AS13335 - CLOUDFLARENET</h1>'
        asn, holder = _parse_asn_and_holder(html)
        assert asn == "AS13335"
        assert holder == "CLOUDFLARENET"

    def test_parse_asn_and_holder_from_link(self) -> None:
        html = '<a href="/AS64496">AS64496</a>'
        asn, holder = _parse_asn_and_holder(html)
        assert asn == "AS64496"
        assert holder == ""

    def test_parse_asn_and_holder_not_found(self) -> None:
        html = "<html><body>No ASN here</body></html>"
        asn, holder = _parse_asn_and_holder(html)
        assert asn == ""
        assert holder == ""

    def test_parse_prefixes(self) -> None:
        html = (
            '<a href="/net/1.1.1.0/24">1.1.1.0/24</a>\n'
            '<a href="/net/104.16.0.0/13">104.16.0.0/13</a>\n'
        )
        prefixes = _parse_prefixes(html)
        assert "1.1.1.0/24" in prefixes
        assert "104.16.0.0/13" in prefixes

    def test_parse_prefixes_deduplicates(self) -> None:
        html = (
            '<a href="/net/1.1.1.0/24">1.1.1.0/24</a>\n'
            '<a href="/net/1.1.1.0/24">1.1.1.0/24</a>\n'
        )
        prefixes = _parse_prefixes(html)
        assert prefixes == ["1.1.1.0/24"]

    def test_parse_prefixes_ipv6(self) -> None:
        html = '<a href="/net/2606:4700::/32">2606:4700::/32</a>\n'
        prefixes = _parse_prefixes(html)
        assert "2606:4700::/32" in prefixes


class TestHeToolkitExpandIPHappyPath:
    """Test 1: IP seed dispatched, observations yielded."""

    @respx.mock
    async def test_ip_seed_yields_observation(self) -> None:
        fixture = _load_fixture("ip_page.html")
        respx.get(f"{_HE_BASE_URL}/ip/1.1.1.1").mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = HeToolkitCollector(_make_config())
        results = await _collect_all(collector, _make_ip_seed("1.1.1.1"))

        assert len(results) == 1

    @respx.mock
    async def test_ip_observation_fields(self) -> None:
        fixture = _load_fixture("ip_page.html")
        respx.get(f"{_HE_BASE_URL}/ip/1.1.1.1").mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = HeToolkitCollector(_make_config())
        results = await _collect_all(collector, _make_ip_seed("1.1.1.1"))

        obs = results[0]
        assert obs.collector_id == "bgp-he-toolkit"
        assert obs.collector_version == "0.1.0"
        assert obs.tenant_id == TENANT_ID
        assert obs.observation_type == ObservationType.BGP_ASN_LOOKUP
        assert obs.subject.identifier_type == ExtendedIdentifierType.IP
        assert obs.subject.identifier_value == "1.1.1.1"

    @respx.mock
    async def test_ip_payload_content(self) -> None:
        fixture = _load_fixture("ip_page.html")
        respx.get(f"{_HE_BASE_URL}/ip/1.1.1.1").mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = HeToolkitCollector(_make_config())
        results = await _collect_all(collector, _make_ip_seed("1.1.1.1"))

        payload = results[0].structured_payload
        assert payload["asn"] == "AS13335"
        assert payload["holder"] == "CLOUDFLARENET"
        assert "1.1.1.0/24" in payload["prefixes"]
        assert "104.16.0.0/13" in payload["prefixes"]
        assert payload["source"] == "he-toolkit"


class TestHeToolkitExpandASNHappyPath:
    """Test 1b: ASN seed dispatched, observations yielded."""

    @respx.mock
    async def test_asn_seed_yields_observation(self) -> None:
        fixture = _load_fixture("asn_page.html")
        respx.get(f"{_HE_BASE_URL}/AS13335").mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = HeToolkitCollector(_make_config())
        results = await _collect_all(collector, _make_asn_seed("AS13335"))

        assert len(results) == 1

    @respx.mock
    async def test_asn_payload_content(self) -> None:
        fixture = _load_fixture("asn_page.html")
        respx.get(f"{_HE_BASE_URL}/AS13335").mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = HeToolkitCollector(_make_config())
        results = await _collect_all(collector, _make_asn_seed("AS13335"))

        payload = results[0].structured_payload
        assert payload["asn"] == "AS13335"
        assert payload["holder"] == "CLOUDFLARENET"
        assert "1.1.1.0/24" in payload["prefixes"]
        assert "2606:4700::/32" in payload["prefixes"]
        assert payload["source"] == "he-toolkit"

    @respx.mock
    async def test_asn_subject_is_asn_type(self) -> None:
        fixture = _load_fixture("asn_page.html")
        respx.get(f"{_HE_BASE_URL}/AS13335").mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = HeToolkitCollector(_make_config())
        results = await _collect_all(collector, _make_asn_seed("AS13335"))

        obs = results[0]
        assert obs.subject.identifier_type == ExtendedIdentifierType.ASN
        assert obs.subject.identifier_value == "AS13335"


class TestHeToolkitNonMatchingSeed:
    """Test 2: non-matching seed type skipped."""

    @respx.mock
    async def test_domain_seed_yields_nothing(self) -> None:
        collector = HeToolkitCollector(_make_config())
        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        results = await _collect_all(collector, seed)
        assert results == []

    @respx.mock
    async def test_organization_seed_yields_nothing(self) -> None:
        collector = HeToolkitCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Cloudflare Inc")
        results = await _collect_all(collector, seed)
        assert results == []


class TestHeToolkitHealthCheck:
    """Test 3: health check success and Test 4: health check failure."""

    @respx.mock
    async def test_healthy_returns_success(self) -> None:
        respx.head(f"{_HE_BASE_URL}/").mock(
            return_value=httpx.Response(200),
        )

        collector = HeToolkitCollector(_make_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "bgp-he-toolkit"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    async def test_unhealthy_returns_failure(self) -> None:
        respx.head(f"{_HE_BASE_URL}/").mock(
            return_value=httpx.Response(503, text="Service Unavailable"),
        )

        collector = HeToolkitCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "503" in result.error_message

    @respx.mock
    async def test_network_error_returns_failure(self) -> None:
        respx.head(f"{_HE_BASE_URL}/").mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        collector = HeToolkitCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "unreachable" in result.error_message


class TestHeToolkitSourceUnreachable:
    """Test 5: source unreachable raises CollectorSourceUnreachableError."""

    @respx.mock
    async def test_connection_error_raises(self) -> None:
        respx.get(f"{_HE_BASE_URL}/ip/1.1.1.1").mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        collector = HeToolkitCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="unreachable"
        ):
            await _collect_all(collector, _make_ip_seed())

    @respx.mock
    async def test_http_500_raises(self) -> None:
        respx.get(f"{_HE_BASE_URL}/ip/1.1.1.1").mock(
            return_value=httpx.Response(500, text="Internal Server Error"),
        )

        collector = HeToolkitCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="500"
        ):
            await _collect_all(collector, _make_ip_seed())

    @respx.mock
    async def test_timeout_raises(self) -> None:
        respx.get(f"{_HE_BASE_URL}/ip/1.1.1.1").mock(
            side_effect=httpx.ReadTimeout("read timed out"),
        )

        collector = HeToolkitCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="unreachable"
        ):
            await _collect_all(collector, _make_ip_seed())

    @respx.mock
    async def test_no_asn_in_html_yields_nothing(self) -> None:
        html = "<html><body>No ASN information found</body></html>"
        respx.get(f"{_HE_BASE_URL}/ip/192.0.2.99").mock(
            return_value=httpx.Response(200, text=html),
        )

        collector = HeToolkitCollector(_make_config())
        results = await _collect_all(
            collector, _make_ip_seed("192.0.2.99")
        )
        assert results == []


class TestHeToolkitRegistration:
    """Verify the collector is registered in the default registry."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("bgp-he-toolkit")
        cls = DEFAULT_REGISTRY.get("bgp-he-toolkit")
        assert cls is HeToolkitCollector

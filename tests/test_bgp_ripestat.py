"""Tests for the bgp-ripestat BGP/ASN collector.

Uses respx to mock all HTTP interactions — NO live network calls.
Fixtures in tests/fixtures/collectors/bgp_ripestat/ provide canned
RIPEstat JSON responses.
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
from expose.collectors.builtin.bgp_ripestat import RipeStatCollector
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000ca01")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000ca02")

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "collectors" / "bgp_ripestat"

_RIPESTAT_BASE = "https://stat.ripe.net/data"
_NETWORK_INFO_URL = f"{_RIPESTAT_BASE}/network-info/data.json"
_ANNOUNCED_PREFIXES_URL = f"{_RIPESTAT_BASE}/announced-prefixes/data.json"


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
    collector: RipeStatCollector, seed: Seed
) -> list[Observation]:
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


class TestRipeStatMetadata:
    """Verify class-level metadata attributes."""

    def test_collector_id(self) -> None:
        assert RipeStatCollector.collector_id == "bgp-ripestat"

    def test_collector_version(self) -> None:
        assert RipeStatCollector.collector_version == "0.1.0"

    def test_tier(self) -> None:
        assert RipeStatCollector.tier == CollectorTier.TIER_1

    def test_requires_credentials(self) -> None:
        assert RipeStatCollector.requires_credentials is False


class TestRipeStatExpandIPHappyPath:
    """Test 1: IP seed dispatched, observations yielded."""

    @respx.mock
    async def test_ip_seed_yields_observation(self) -> None:
        fixture = _load_fixture("network_info_ip.json")
        respx.get(_NETWORK_INFO_URL).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = RipeStatCollector(_make_config())
        results = await _collect_all(collector, _make_ip_seed("1.1.1.1"))

        assert len(results) == 1

    @respx.mock
    async def test_ip_observation_fields(self) -> None:
        fixture = _load_fixture("network_info_ip.json")
        respx.get(_NETWORK_INFO_URL).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = RipeStatCollector(_make_config())
        results = await _collect_all(collector, _make_ip_seed("1.1.1.1"))

        obs = results[0]
        assert obs.collector_id == "bgp-ripestat"
        assert obs.collector_version == "0.1.0"
        assert obs.tenant_id == TENANT_ID
        assert obs.observation_type == ObservationType.BGP_ASN_LOOKUP
        assert obs.subject.identifier_type == ExtendedIdentifierType.IP
        assert obs.subject.identifier_value == "1.1.1.1"

    @respx.mock
    async def test_ip_payload_content(self) -> None:
        fixture = _load_fixture("network_info_ip.json")
        respx.get(_NETWORK_INFO_URL).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = RipeStatCollector(_make_config())
        results = await _collect_all(collector, _make_ip_seed("1.1.1.1"))

        payload = results[0].structured_payload
        assert payload["asn"] == "AS13335"
        assert payload["holder"] == "CLOUDFLARENET"
        assert payload["prefixes"] == ["1.1.1.0/24"]
        assert payload["source"] == "ripestat"


class TestRipeStatExpandASNHappyPath:
    """Test 1b: ASN seed dispatched, observations yielded."""

    @respx.mock
    async def test_asn_seed_yields_observation(self) -> None:
        fixture = _load_fixture("announced_prefixes_asn.json")
        respx.get(_ANNOUNCED_PREFIXES_URL).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = RipeStatCollector(_make_config())
        results = await _collect_all(collector, _make_asn_seed("AS13335"))

        assert len(results) == 1

    @respx.mock
    async def test_asn_payload_content(self) -> None:
        fixture = _load_fixture("announced_prefixes_asn.json")
        respx.get(_ANNOUNCED_PREFIXES_URL).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = RipeStatCollector(_make_config())
        results = await _collect_all(collector, _make_asn_seed("AS13335"))

        payload = results[0].structured_payload
        assert payload["asn"] == "AS13335"
        assert payload["source"] == "ripestat"
        assert "1.1.1.0/24" in payload["prefixes"]
        assert "104.16.0.0/13" in payload["prefixes"]
        assert "2606:4700::/32" in payload["prefixes"]
        assert len(payload["prefixes"]) == 3

    @respx.mock
    async def test_asn_subject_is_asn_type(self) -> None:
        fixture = _load_fixture("announced_prefixes_asn.json")
        respx.get(_ANNOUNCED_PREFIXES_URL).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = RipeStatCollector(_make_config())
        results = await _collect_all(collector, _make_asn_seed("AS13335"))

        obs = results[0]
        assert obs.subject.identifier_type == ExtendedIdentifierType.ASN
        assert obs.subject.identifier_value == "AS13335"


class TestRipeStatNonMatchingSeed:
    """Test 2: non-matching seed type skipped."""

    @respx.mock
    async def test_domain_seed_yields_nothing(self) -> None:
        collector = RipeStatCollector(_make_config())
        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        results = await _collect_all(collector, seed)
        assert results == []

    @respx.mock
    async def test_organization_seed_yields_nothing(self) -> None:
        collector = RipeStatCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Cloudflare Inc")
        results = await _collect_all(collector, seed)
        assert results == []


class TestRipeStatHealthCheck:
    """Test 3: health check success and Test 4: health check failure."""

    @respx.mock
    async def test_healthy_returns_success(self) -> None:
        respx.head(_NETWORK_INFO_URL).mock(
            return_value=httpx.Response(200),
        )

        collector = RipeStatCollector(_make_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "bgp-ripestat"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    async def test_unhealthy_returns_failure(self) -> None:
        respx.head(_NETWORK_INFO_URL).mock(
            return_value=httpx.Response(503, text="Service Unavailable"),
        )

        collector = RipeStatCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "503" in result.error_message

    @respx.mock
    async def test_network_error_returns_failure(self) -> None:
        respx.head(_NETWORK_INFO_URL).mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        collector = RipeStatCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "unreachable" in result.error_message


class TestRipeStatSourceUnreachable:
    """Test 5: source unreachable raises CollectorSourceUnreachableError."""

    @respx.mock
    async def test_connection_error_raises(self) -> None:
        respx.get(_NETWORK_INFO_URL).mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        collector = RipeStatCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="unreachable"
        ):
            await _collect_all(collector, _make_ip_seed())

    @respx.mock
    async def test_http_500_raises(self) -> None:
        respx.get(_NETWORK_INFO_URL).mock(
            return_value=httpx.Response(500, text="Internal Server Error"),
        )

        collector = RipeStatCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="500"
        ):
            await _collect_all(collector, _make_ip_seed())

    @respx.mock
    async def test_timeout_raises(self) -> None:
        respx.get(_NETWORK_INFO_URL).mock(
            side_effect=httpx.ReadTimeout("read timed out"),
        )

        collector = RipeStatCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="unreachable"
        ):
            await _collect_all(collector, _make_ip_seed())

    @respx.mock
    async def test_empty_asns_yields_nothing(self) -> None:
        fixture = _load_fixture("network_info_empty.json")
        respx.get(_NETWORK_INFO_URL).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = RipeStatCollector(_make_config())
        results = await _collect_all(collector, _make_ip_seed("192.0.2.99"))
        assert results == []


class TestRipeStatRegistration:
    """Verify the collector is registered in the default registry."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("bgp-ripestat")
        cls = DEFAULT_REGISTRY.get("bgp-ripestat")
        assert cls is RipeStatCollector

"""Tests for the bgp-team-cymru BGP/ASN collector.

Mocks dnspython resolver calls — NO live DNS queries.

The Team Cymru collector uses DNS TXT queries, not HTTP. Tests mock the
dns.asyncresolver.Resolver to return canned responses.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest

from expose.collectors.base import (
    CollectorConfig,
    CollectorHealthCheck,
    CollectorSourceUnreachableError,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.bgp_team_cymru import (
    HAS_DNSPYTHON,
    TeamCymruCollector,
    _parse_asn_txt,
    _parse_origin_txt,
    _reverse_ip,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

if HAS_DNSPYTHON:
    import dns.resolver as _dns_resolver

pytestmark = [pytest.mark.filterwarnings("default::DeprecationWarning")]

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000ca01")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000ca02")


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


async def _collect_all(
    collector: TeamCymruCollector, seed: Seed
) -> list[Observation]:
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


def _mock_txt_rr(text: str) -> MagicMock:
    """Build a mock DNS TXT RR with the given text payload."""
    rr = MagicMock()
    rr.strings = [text.encode("utf-8")]
    return rr


def _mock_txt_answer(texts: list[str]) -> MagicMock:
    """Build a mock DNS answer with one or more TXT records."""
    answer = MagicMock()
    answer.__iter__ = lambda self: iter([_mock_txt_rr(t) for t in texts])
    return answer


def _mock_a_answer() -> MagicMock:
    """Build a mock DNS A answer for health check."""
    return MagicMock()


class TestTeamCymruMetadata:
    """Verify class-level metadata attributes."""

    def test_collector_id(self) -> None:
        assert TeamCymruCollector.collector_id == "bgp-team-cymru"

    def test_collector_version(self) -> None:
        assert TeamCymruCollector.collector_version == "0.1.0"

    def test_tier(self) -> None:
        assert TeamCymruCollector.tier == CollectorTier.TIER_1

    def test_requires_credentials(self) -> None:
        assert TeamCymruCollector.requires_credentials is False


class TestTeamCymruHelpers:
    """Unit tests for internal parsing helpers."""

    def test_reverse_ip(self) -> None:
        assert _reverse_ip("1.2.3.4") == "4.3.2.1"

    def test_reverse_ip_simple(self) -> None:
        assert _reverse_ip("192.168.1.1") == "1.1.168.192"

    def test_parse_origin_txt(self) -> None:
        result = _parse_origin_txt(
            "13335 | 1.1.1.1 | 1.1.1.0/24 | US | arin"
        )
        assert result["asn"] == "13335"
        assert result["prefix"] == "1.1.1.0/24"
        assert result["country"] == "US"
        assert result["registry"] == "arin"

    def test_parse_origin_txt_short(self) -> None:
        result = _parse_origin_txt("13335 | 1.1.1.1")
        assert result == {}

    def test_parse_asn_txt(self) -> None:
        result = _parse_asn_txt(
            "13335 | US | arin | 2010-07-14 | CLOUDFLARENET"
        )
        assert result["asn"] == "13335"
        assert result["name"] == "CLOUDFLARENET"
        assert result["country"] == "US"
        assert result["registry"] == "arin"


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestTeamCymruExpandHappyPath:
    """Test 1: IP seed dispatched, observation yielded with correct payload."""

    async def test_ip_seed_yields_observation(self) -> None:
        collector = TeamCymruCollector(_make_config())

        origin_answer = _mock_txt_answer(
            ["13335 | 1.1.1.1 | 1.1.1.0/24 | US | arin"]
        )
        asn_answer = _mock_txt_answer(
            ["13335 | US | arin | 2010-07-14 | CLOUDFLARENET"]
        )

        async def _mock_resolve(qname: str, rdtype: str) -> MagicMock:
            qname_str = str(qname)
            if "origin.asn.cymru.com" in qname_str:
                return origin_answer
            if "asn.cymru.com" in qname_str:
                return asn_answer
            msg = f"unexpected query: {qname_str}"
            raise RuntimeError(msg)

        collector._resolver.resolve = AsyncMock(side_effect=_mock_resolve)

        results = await _collect_all(collector, _make_ip_seed("1.1.1.1"))
        assert len(results) == 1

    async def test_observation_fields(self) -> None:
        collector = TeamCymruCollector(_make_config())

        origin_answer = _mock_txt_answer(
            ["13335 | 1.1.1.1 | 1.1.1.0/24 | US | arin"]
        )
        asn_answer = _mock_txt_answer(
            ["13335 | US | arin | 2010-07-14 | CLOUDFLARENET"]
        )

        async def _mock_resolve(qname: str, rdtype: str) -> MagicMock:
            qname_str = str(qname)
            if "origin.asn.cymru.com" in qname_str:
                return origin_answer
            if "asn.cymru.com" in qname_str:
                return asn_answer
            msg = f"unexpected query: {qname_str}"
            raise RuntimeError(msg)

        collector._resolver.resolve = AsyncMock(side_effect=_mock_resolve)

        results = await _collect_all(collector, _make_ip_seed("1.1.1.1"))
        obs = results[0]

        assert obs.collector_id == "bgp-team-cymru"
        assert obs.collector_version == "0.1.0"
        assert obs.tenant_id == TENANT_ID
        assert obs.observation_type == ObservationType.BGP_ASN_LOOKUP
        assert obs.subject.identifier_type == ExtendedIdentifierType.IP
        assert obs.subject.identifier_value == "1.1.1.1"

    async def test_payload_content(self) -> None:
        collector = TeamCymruCollector(_make_config())

        origin_answer = _mock_txt_answer(
            ["13335 | 1.1.1.1 | 1.1.1.0/24 | US | arin"]
        )
        asn_answer = _mock_txt_answer(
            ["13335 | US | arin | 2010-07-14 | CLOUDFLARENET"]
        )

        async def _mock_resolve(qname: str, rdtype: str) -> MagicMock:
            qname_str = str(qname)
            if "origin.asn.cymru.com" in qname_str:
                return origin_answer
            if "asn.cymru.com" in qname_str:
                return asn_answer
            msg = f"unexpected query: {qname_str}"
            raise RuntimeError(msg)

        collector._resolver.resolve = AsyncMock(side_effect=_mock_resolve)

        results = await _collect_all(collector, _make_ip_seed("1.1.1.1"))
        payload = results[0].structured_payload

        assert payload["asn"] == "AS13335"
        assert payload["asn_name"] == "CLOUDFLARENET"
        assert payload["prefix"] == "1.1.1.0/24"
        assert payload["country"] == "US"
        assert payload["registry"] == "arin"
        assert payload["source"] == "team-cymru"


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestTeamCymruNonMatchingSeed:
    """Test 2: non-matching seed type (DOMAIN, ASN) skipped."""

    async def test_domain_seed_yields_nothing(self) -> None:
        collector = TeamCymruCollector(_make_config())
        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        results = await _collect_all(collector, seed)
        assert results == []

    async def test_asn_seed_yields_nothing(self) -> None:
        collector = TeamCymruCollector(_make_config())
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        results = await _collect_all(collector, seed)
        assert results == []

    async def test_organization_seed_yields_nothing(self) -> None:
        collector = TeamCymruCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Cloudflare Inc")
        results = await _collect_all(collector, seed)
        assert results == []


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestTeamCymruHealthCheck:
    """Test 3: health check success, Test 4: health check failure."""

    async def test_healthy_returns_success(self) -> None:
        collector = TeamCymruCollector(_make_config())
        collector._resolver.resolve = AsyncMock(
            return_value=_mock_a_answer()
        )

        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "bgp-team-cymru"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    async def test_dns_failure_returns_failure(self) -> None:
        collector = TeamCymruCollector(_make_config())
        collector._resolver.resolve = AsyncMock(
            side_effect=Exception("DNS resolution failed")
        )

        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "unreachable" in result.error_message


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestTeamCymruSourceUnreachable:
    """Test 5: source unreachable raises CollectorSourceUnreachableError."""

    async def test_nxdomain_raises(self) -> None:
        collector = TeamCymruCollector(_make_config())
        collector._resolver.resolve = AsyncMock(
            side_effect=_dns_resolver.NXDOMAIN()
        )

        with pytest.raises(
            CollectorSourceUnreachableError, match="NXDOMAIN"
        ):
            await _collect_all(collector, _make_ip_seed("192.0.2.1"))

    async def test_timeout_raises(self) -> None:
        collector = TeamCymruCollector(_make_config())
        collector._resolver.resolve = AsyncMock(
            side_effect=_dns_resolver.LifetimeTimeout()
        )

        with pytest.raises(
            CollectorSourceUnreachableError, match="timed out"
        ):
            await _collect_all(collector, _make_ip_seed("192.0.2.1"))

    async def test_generic_dns_error_raises(self) -> None:
        collector = TeamCymruCollector(_make_config())
        collector._resolver.resolve = AsyncMock(
            side_effect=OSError("Network is unreachable")
        )

        with pytest.raises(
            CollectorSourceUnreachableError, match="DNS failed"
        ):
            await _collect_all(collector, _make_ip_seed("192.0.2.1"))


class TestTeamCymruRegistration:
    """Verify the collector is registered in the default registry."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("bgp-team-cymru")
        cls = DEFAULT_REGISTRY.get("bgp-team-cymru")
        assert cls is TeamCymruCollector

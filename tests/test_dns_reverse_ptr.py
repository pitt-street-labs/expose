"""Tests for the dns-reverse-ptr reverse PTR lookup collector.

Mocks dnspython resolver calls -- NO live DNS queries.

The reverse PTR collector uses DNS PTR queries, not HTTP. Tests mock the
dns.asyncresolver.Resolver to return canned responses.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest

from expose.collectors.base import (
    CollectorConfig,
    CollectorHealthCheck,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.dns_reverse_ptr import (
    HAS_DNSPYTHON,
    ReversePtrCollector,
    _ip_to_reverse,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

if HAS_DNSPYTHON:
    import dns.resolver as _dns_resolver

pytestmark = [pytest.mark.filterwarnings("default::DeprecationWarning")]

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000bb01")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000bb02")


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
    collector: ReversePtrCollector, seed: Seed
) -> list[Observation]:
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


def _mock_ptr_rr(hostname: str) -> MagicMock:
    """Build a mock DNS PTR RR with the given hostname."""
    rr = MagicMock()
    rr.target = MagicMock()
    rr.target.__str__ = lambda self: hostname + "."
    return rr


def _mock_ptr_answer(hostnames: list[str]) -> MagicMock:
    """Build a mock DNS answer with one or more PTR records."""
    answer = MagicMock()
    answer.__iter__ = lambda self: iter([_mock_ptr_rr(h) for h in hostnames])
    return answer


def _mock_a_answer() -> MagicMock:
    """Build a mock DNS A answer for health check."""
    return MagicMock()


# === Metadata tests ===========================================================


class TestReversePtrMetadata:
    """Verify class-level metadata attributes."""

    def test_collector_id(self) -> None:
        assert ReversePtrCollector.collector_id == "dns-reverse-ptr"

    def test_collector_version(self) -> None:
        assert ReversePtrCollector.collector_version == "0.1.0"

    def test_tier(self) -> None:
        assert ReversePtrCollector.tier == CollectorTier.TIER_2

    def test_display_name(self) -> None:
        assert ReversePtrCollector.display_name == "DNS Reverse PTR Lookup"

    def test_requires_credentials(self) -> None:
        assert ReversePtrCollector.requires_credentials is False


# === Seed type filtering ======================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestReversePtrSeedFiltering:
    """Only IP seeds should be expanded; all others return empty."""

    async def test_domain_seed_yields_nothing(self) -> None:
        collector = ReversePtrCollector(_make_config())
        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        results = await _collect_all(collector, seed)
        assert results == []

    async def test_asn_seed_yields_nothing(self) -> None:
        collector = ReversePtrCollector(_make_config())
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        results = await _collect_all(collector, seed)
        assert results == []

    async def test_organization_seed_yields_nothing(self) -> None:
        collector = ReversePtrCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Cloudflare Inc")
        results = await _collect_all(collector, seed)
        assert results == []

    async def test_cidr_seed_yields_nothing(self) -> None:
        collector = ReversePtrCollector(_make_config())
        seed = Seed(seed_type=SeedType.CIDR, value="192.168.0.0/24")
        results = await _collect_all(collector, seed)
        assert results == []


# === Reverse name construction ================================================


class TestIpToReverse:
    """Unit tests for the _ip_to_reverse helper."""

    def test_ipv4_reverse(self) -> None:
        assert _ip_to_reverse("1.2.3.4") == "4.3.2.1.in-addr.arpa"

    def test_ipv4_common(self) -> None:
        assert _ip_to_reverse("192.168.1.1") == "1.1.168.192.in-addr.arpa"

    def test_ipv6_nibble_format(self) -> None:
        result = _ip_to_reverse("2001:db8::1")
        # Full expansion: 2001:0db8:0000:0000:0000:0000:0000:0001
        # Nibble reversed: 1.0.0.0...8.b.d.0.1.0.0.2.ip6.arpa
        assert result.endswith(".ip6.arpa")
        assert result.startswith("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0")
        assert result.endswith("8.b.d.0.1.0.0.2.ip6.arpa")

    def test_ipv6_full_address(self) -> None:
        result = _ip_to_reverse("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert result.endswith(".ip6.arpa")
        # Should have 32 nibbles + 32 dots + ".ip6.arpa"
        parts = result.replace(".ip6.arpa", "").split(".")
        assert len(parts) == 32

    def test_invalid_ip_raises(self) -> None:
        with pytest.raises(ValueError):
            _ip_to_reverse("not-an-ip")

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError):
            _ip_to_reverse("")


# === Happy path: PTR response =================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestReversePtrHappyPath:
    """Test PTR lookups that return valid hostnames."""

    async def test_single_ptr_yields_observation(self) -> None:
        collector = ReversePtrCollector(_make_config())
        ptr_answer = _mock_ptr_answer(["one.one.one.one"])
        collector._resolver.resolve = AsyncMock(return_value=ptr_answer)

        results = await _collect_all(collector, _make_ip_seed("1.1.1.1"))
        assert len(results) == 1

    async def test_observation_fields(self) -> None:
        collector = ReversePtrCollector(_make_config())
        ptr_answer = _mock_ptr_answer(["dns.google"])
        collector._resolver.resolve = AsyncMock(return_value=ptr_answer)

        results = await _collect_all(collector, _make_ip_seed("8.8.8.8"))
        obs = results[0]

        assert obs.collector_id == "dns-reverse-ptr"
        assert obs.collector_version == "0.1.0"
        assert obs.tenant_id == TENANT_ID
        assert obs.observation_type == ObservationType.DNS_RECORD
        assert obs.subject.identifier_type == ExtendedIdentifierType.IP
        assert obs.subject.identifier_value == "8.8.8.8"

    async def test_payload_content(self) -> None:
        collector = ReversePtrCollector(_make_config())
        ptr_answer = _mock_ptr_answer(["dns.google"])
        collector._resolver.resolve = AsyncMock(return_value=ptr_answer)

        results = await _collect_all(collector, _make_ip_seed("8.8.8.8"))
        payload = results[0].structured_payload

        assert payload["record_type"] == "PTR"
        assert payload["reverse_name"] == "8.8.8.8.in-addr.arpa"
        assert payload["ip"] == "8.8.8.8"
        assert payload["hostname"] == "dns.google"
        assert payload["is_new_domain_seed"] is True

    async def test_multiple_ptr_records(self) -> None:
        collector = ReversePtrCollector(_make_config())
        ptr_answer = _mock_ptr_answer(["host1.example.com", "host2.example.com"])
        collector._resolver.resolve = AsyncMock(return_value=ptr_answer)

        results = await _collect_all(collector, _make_ip_seed("10.0.0.1"))
        assert len(results) == 2
        hostnames = {r.structured_payload["hostname"] for r in results}
        assert hostnames == {"host1.example.com", "host2.example.com"}

    async def test_hostname_trailing_dot_stripped(self) -> None:
        """PTR records end with a dot in DNS; verify it's stripped."""
        collector = ReversePtrCollector(_make_config())
        ptr_answer = _mock_ptr_answer(["mail.example.com"])
        collector._resolver.resolve = AsyncMock(return_value=ptr_answer)

        results = await _collect_all(collector, _make_ip_seed("10.0.0.2"))
        # The mock adds a dot, _ip_to_reverse strips it
        assert results[0].structured_payload["hostname"] == "mail.example.com"


# === Error handling ===========================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestReversePtrErrorHandling:
    """Test error conditions: NXDOMAIN, timeout, invalid IP."""

    async def test_nxdomain_returns_empty(self) -> None:
        """NXDOMAIN is normal (no PTR record) -- should return empty, not raise."""
        collector = ReversePtrCollector(_make_config())
        collector._resolver.resolve = AsyncMock(
            side_effect=_dns_resolver.NXDOMAIN()
        )

        results = await _collect_all(collector, _make_ip_seed("192.0.2.1"))
        assert results == []

    async def test_timeout_returns_empty(self) -> None:
        """Timeout should return empty, not raise."""
        collector = ReversePtrCollector(_make_config())
        collector._resolver.resolve = AsyncMock(
            side_effect=_dns_resolver.LifetimeTimeout()
        )

        results = await _collect_all(collector, _make_ip_seed("192.0.2.1"))
        assert results == []

    async def test_no_answer_returns_empty(self) -> None:
        collector = ReversePtrCollector(_make_config())
        collector._resolver.resolve = AsyncMock(
            side_effect=_dns_resolver.NoAnswer()
        )

        results = await _collect_all(collector, _make_ip_seed("192.0.2.1"))
        assert results == []

    async def test_generic_error_returns_empty(self) -> None:
        """Generic exceptions should return empty, not crash."""
        collector = ReversePtrCollector(_make_config())
        collector._resolver.resolve = AsyncMock(
            side_effect=OSError("Network is unreachable")
        )

        results = await _collect_all(collector, _make_ip_seed("192.0.2.1"))
        assert results == []

    async def test_invalid_ip_returns_empty(self) -> None:
        """An invalid IP value should be handled gracefully."""
        collector = ReversePtrCollector(_make_config())

        results = await _collect_all(
            collector,
            Seed(seed_type=SeedType.IP, value="not-an-ip"),
        )
        assert results == []


# === Health check =============================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestReversePtrHealthCheck:
    """Health check success and failure."""

    async def test_healthy_returns_success(self) -> None:
        collector = ReversePtrCollector(_make_config())
        collector._resolver.resolve = AsyncMock(
            return_value=_mock_a_answer()
        )

        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "dns-reverse-ptr"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    async def test_dns_failure_returns_failure(self) -> None:
        collector = ReversePtrCollector(_make_config())
        collector._resolver.resolve = AsyncMock(
            side_effect=Exception("DNS resolution failed")
        )

        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "failed" in result.error_message.lower()


# === Registration =============================================================


class TestReversePtrRegistration:
    """Verify the collector is registered in the default registry."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("dns-reverse-ptr")
        cls = DEFAULT_REGISTRY.get("dns-reverse-ptr")
        assert cls is ReversePtrCollector

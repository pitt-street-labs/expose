"""Tests for the dns-blacklist DNSBL collector.

Mocks dnspython resolver calls — NO live DNS queries.

The DNSBL collector uses DNS A + TXT queries to check whether an IP is
listed on well-known spam/abuse blacklists.  Tests mock the async resolver
to return canned responses.
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
from expose.collectors.builtin.dns_blacklist import (
    DNSBL_PROVIDERS,
    HAS_DNSPYTHON,
    DnsBlacklistCollector,
    _resolve_severity,
    _reverse_ip,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

if HAS_DNSPYTHON:
    import dns.resolver as _dns_resolver

pytestmark = [pytest.mark.filterwarnings("default::DeprecationWarning")]

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000db01")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000db02")


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


def _make_ip_seed(ip: str = "192.0.2.1") -> Seed:
    return Seed(seed_type=SeedType.IP, value=ip)


async def _collect_all(collector: DnsBlacklistCollector, seed: Seed) -> list[Observation]:
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


def _mock_a_rr(address: str = "127.0.0.2") -> MagicMock:
    """Build a mock DNS A record with the given address."""
    rr = MagicMock()
    rr.__str__ = lambda self: address
    return rr


def _mock_a_answer(address: str = "127.0.0.2") -> MagicMock:
    """Build a mock DNS A answer with one A record."""
    answer = MagicMock()
    answer.__iter__ = lambda self: iter([_mock_a_rr(address)])
    return answer


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


# ============================================================================
# Metadata tests
# ============================================================================


class TestDnsBlacklistMetadata:
    """Verify class-level metadata attributes."""

    def test_collector_id(self) -> None:
        assert DnsBlacklistCollector.collector_id == "dns-blacklist"

    def test_collector_version(self) -> None:
        assert DnsBlacklistCollector.collector_version == "0.1.0"

    def test_tier(self) -> None:
        assert DnsBlacklistCollector.tier == CollectorTier.TIER_1

    def test_display_name(self) -> None:
        assert DnsBlacklistCollector.display_name == "DNS Blacklist Check"

    def test_requires_credentials(self) -> None:
        assert DnsBlacklistCollector.requires_credentials is False


# ============================================================================
# Seed-type filtering
# ============================================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestDnsBlacklistSeedFiltering:
    """Non-IP seed types must return empty observation streams."""

    async def test_domain_seed_yields_nothing(self) -> None:
        collector = DnsBlacklistCollector(_make_config())
        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        results = await _collect_all(collector, seed)
        assert results == []

    async def test_asn_seed_yields_nothing(self) -> None:
        collector = DnsBlacklistCollector(_make_config())
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        results = await _collect_all(collector, seed)
        assert results == []

    async def test_organization_seed_yields_nothing(self) -> None:
        collector = DnsBlacklistCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="ACME Corp")
        results = await _collect_all(collector, seed)
        assert results == []

    async def test_cidr_seed_yields_nothing(self) -> None:
        collector = DnsBlacklistCollector(_make_config())
        seed = Seed(seed_type=SeedType.CIDR, value="192.0.2.0/24")
        results = await _collect_all(collector, seed)
        assert results == []


# ============================================================================
# IP reversal
# ============================================================================


class TestIpReversal:
    """Verify IP address reversal for DNSBL format."""

    def test_reverse_simple(self) -> None:
        assert _reverse_ip("1.2.3.4") == "4.3.2.1"

    def test_reverse_real_ip(self) -> None:
        assert _reverse_ip("192.168.1.100") == "100.1.168.192"

    def test_reverse_with_whitespace(self) -> None:
        assert _reverse_ip("  10.0.0.1  ") == "1.0.0.10"


# ============================================================================
# DNSBL_PROVIDERS structure validation
# ============================================================================


class TestDnsblProviders:
    """Validate the structure of the DNSBL_PROVIDERS list."""

    def test_providers_is_nonempty_list(self) -> None:
        assert isinstance(DNSBL_PROVIDERS, list)
        assert len(DNSBL_PROVIDERS) > 0

    def test_each_provider_has_zone_and_name(self) -> None:
        for provider in DNSBL_PROVIDERS:
            assert "zone" in provider, f"Missing 'zone' in {provider}"
            assert "name" in provider, f"Missing 'name' in {provider}"
            assert isinstance(provider["zone"], str)
            assert isinstance(provider["name"], str)

    def test_each_provider_has_severity(self) -> None:
        """Every provider must have either a severity_map or default_severity."""
        for provider in DNSBL_PROVIDERS:
            has_map = "severity_map" in provider
            has_default = "default_severity" in provider
            assert has_map or has_default, f"Provider {provider['name']} lacks severity config"

    def test_spamhaus_has_severity_map(self) -> None:
        spamhaus = next(p for p in DNSBL_PROVIDERS if p["zone"] == "zen.spamhaus.org")
        assert "severity_map" in spamhaus
        smap = spamhaus["severity_map"]
        assert "127.0.0.2" in smap
        assert "127.0.0.4" in smap


# ============================================================================
# Severity mapping
# ============================================================================


class TestSeverityMapping:
    """Verify _resolve_severity correctly maps return codes."""

    def test_spamhaus_sbl(self) -> None:
        spamhaus = next(p for p in DNSBL_PROVIDERS if p["zone"] == "zen.spamhaus.org")
        listing_type, severity = _resolve_severity(spamhaus, "127.0.0.2")
        assert listing_type == "sbl"
        assert severity == "high"

    def test_spamhaus_xbl_critical(self) -> None:
        spamhaus = next(p for p in DNSBL_PROVIDERS if p["zone"] == "zen.spamhaus.org")
        listing_type, severity = _resolve_severity(spamhaus, "127.0.0.4")
        assert listing_type == "xbl"
        assert severity == "critical"

    def test_spamhaus_pbl_info(self) -> None:
        spamhaus = next(p for p in DNSBL_PROVIDERS if p["zone"] == "zen.spamhaus.org")
        listing_type, severity = _resolve_severity(spamhaus, "127.0.0.10")
        assert listing_type == "pbl"
        assert severity == "info"

    def test_spamhaus_unknown_code_falls_back(self) -> None:
        """Unknown Spamhaus code falls back to default 'medium'."""
        spamhaus = next(p for p in DNSBL_PROVIDERS if p["zone"] == "zen.spamhaus.org")
        listing_type, severity = _resolve_severity(spamhaus, "127.0.0.99")
        assert listing_type == "listed"
        assert severity == "medium"

    def test_barracuda_default_severity(self) -> None:
        barracuda = next(p for p in DNSBL_PROVIDERS if p["zone"] == "b.barracudacentral.org")
        listing_type, severity = _resolve_severity(barracuda, "127.0.0.2")
        assert listing_type == "listed"
        assert severity == "medium"

    def test_abusix_default_severity(self) -> None:
        abusix = next(p for p in DNSBL_PROVIDERS if p["zone"] == "combined.abuse.ch")
        listing_type, severity = _resolve_severity(abusix, "127.0.0.2")
        assert listing_type == "listed"
        assert severity == "high"


# ============================================================================
# Listed IP — observation generated
# ============================================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestDnsBlacklistListed:
    """Mock a listed IP and verify observations are produced."""

    async def test_listed_ip_yields_observations(self) -> None:
        collector = DnsBlacklistCollector(_make_config())

        a_answer = _mock_a_answer("127.0.0.2")
        txt_answer = _mock_txt_answer(["https://www.spamhaus.org/sbl/query/SBL123"])

        async def _mock_resolve(qname: str, rdtype: str) -> MagicMock:
            if rdtype == "A":
                return a_answer
            if rdtype == "TXT":
                return txt_answer
            msg = f"unexpected rdtype: {rdtype}"
            raise RuntimeError(msg)

        collector._resolver.resolve = AsyncMock(side_effect=_mock_resolve)

        results = await _collect_all(collector, _make_ip_seed("192.0.2.1"))
        # Should get one observation per provider (all report listed)
        assert len(results) == len(DNSBL_PROVIDERS)

    async def test_observation_fields(self) -> None:
        collector = DnsBlacklistCollector(_make_config())

        a_answer = _mock_a_answer("127.0.0.2")
        txt_answer = _mock_txt_answer(["Listed for spam"])

        async def _mock_resolve(qname: str, rdtype: str) -> MagicMock:
            if rdtype == "A":
                return a_answer
            if rdtype == "TXT":
                return txt_answer
            msg = f"unexpected rdtype: {rdtype}"
            raise RuntimeError(msg)

        collector._resolver.resolve = AsyncMock(side_effect=_mock_resolve)

        results = await _collect_all(collector, _make_ip_seed("192.0.2.1"))
        obs = results[0]

        assert obs.collector_id == "dns-blacklist"
        assert obs.collector_version == "0.1.0"
        assert obs.tenant_id == TENANT_ID
        assert obs.observation_type == ObservationType.DNS_RECORD
        assert obs.subject.identifier_type == ExtendedIdentifierType.IP
        assert obs.subject.identifier_value == "192.0.2.1"

    async def test_payload_content(self) -> None:
        collector = DnsBlacklistCollector(_make_config())

        a_answer = _mock_a_answer("127.0.0.4")
        txt_answer = _mock_txt_answer(["https://www.spamhaus.org/xbl/query/XBL456"])

        # Return specific answers for Spamhaus only, NXDOMAIN for others
        async def _mock_resolve(qname: str, rdtype: str) -> MagicMock:
            qname_str = str(qname)
            if "zen.spamhaus.org" in qname_str:
                if rdtype == "A":
                    return a_answer
                if rdtype == "TXT":
                    return txt_answer
            if rdtype == "A":
                raise _dns_resolver.NXDOMAIN()
            raise _dns_resolver.NXDOMAIN()

        collector._resolver.resolve = AsyncMock(side_effect=_mock_resolve)

        results = await _collect_all(collector, _make_ip_seed("192.0.2.1"))
        assert len(results) == 1

        payload = results[0].structured_payload
        assert payload["blacklist_name"] == "Spamhaus ZEN"
        assert payload["blacklist_zone"] == "zen.spamhaus.org"
        assert payload["listed"] is True
        assert payload["return_code"] == "127.0.0.4"
        assert payload["listing_type"] == "xbl"
        assert payload["severity"] == "critical"
        assert "XBL456" in payload["txt_reason"]
        assert payload["source"] == "dnsbl"


# ============================================================================
# Clean IP — no observations
# ============================================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestDnsBlacklistClean:
    """Mock a clean IP (NXDOMAIN from all) and verify empty results."""

    async def test_clean_ip_yields_nothing(self) -> None:
        collector = DnsBlacklistCollector(_make_config())

        collector._resolver.resolve = AsyncMock(side_effect=_dns_resolver.NXDOMAIN())

        results = await _collect_all(collector, _make_ip_seed("198.51.100.1"))
        assert results == []


# ============================================================================
# Multiple blacklists listing same IP
# ============================================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestDnsBlacklistMultipleListings:
    """When multiple blacklists list the same IP, each produces an observation."""

    async def test_two_providers_two_observations(self) -> None:
        collector = DnsBlacklistCollector(_make_config())

        a_answer = _mock_a_answer("127.0.0.2")
        txt_answer = _mock_txt_answer(["Spam source"])

        # List on Spamhaus and Barracuda only
        async def _mock_resolve(qname: str, rdtype: str) -> MagicMock:
            qname_str = str(qname)
            if "zen.spamhaus.org" in qname_str or "b.barracudacentral.org" in qname_str:
                if rdtype == "A":
                    return a_answer
                if rdtype == "TXT":
                    return txt_answer
            if rdtype == "A":
                raise _dns_resolver.NXDOMAIN()
            raise _dns_resolver.NXDOMAIN()

        collector._resolver.resolve = AsyncMock(side_effect=_mock_resolve)

        results = await _collect_all(collector, _make_ip_seed("192.0.2.1"))
        assert len(results) == 2

        names = {r.structured_payload["blacklist_name"] for r in results}
        assert "Spamhaus ZEN" in names
        assert "Barracuda BRBL" in names


# ============================================================================
# TXT record parsing
# ============================================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestDnsBlacklistTxtParsing:
    """Verify TXT record content is captured in the observation."""

    async def test_txt_reason_in_payload(self) -> None:
        collector = DnsBlacklistCollector(_make_config())

        a_answer = _mock_a_answer("127.0.0.2")
        txt_reason = "Listed for sending spam; see https://example.com/lookup"
        txt_answer = _mock_txt_answer([txt_reason])

        # Only list on first provider for simplicity
        call_count = 0

        async def _mock_resolve(qname: str, rdtype: str) -> MagicMock:
            nonlocal call_count
            qname_str = str(qname)
            if "zen.spamhaus.org" in qname_str:
                if rdtype == "A":
                    return a_answer
                if rdtype == "TXT":
                    return txt_answer
            if rdtype == "A":
                raise _dns_resolver.NXDOMAIN()
            raise _dns_resolver.NXDOMAIN()

        collector._resolver.resolve = AsyncMock(side_effect=_mock_resolve)

        results = await _collect_all(collector, _make_ip_seed("192.0.2.1"))
        assert len(results) == 1
        assert "sending spam" in results[0].structured_payload["txt_reason"]

    async def test_txt_failure_still_yields_observation(self) -> None:
        """If the TXT query fails, the observation should still be emitted."""
        collector = DnsBlacklistCollector(_make_config())

        a_answer = _mock_a_answer("127.0.0.2")

        async def _mock_resolve(qname: str, rdtype: str) -> MagicMock:
            qname_str = str(qname)
            if "zen.spamhaus.org" in qname_str:
                if rdtype == "A":
                    return a_answer
                if rdtype == "TXT":
                    raise _dns_resolver.NXDOMAIN()
            if rdtype == "A":
                raise _dns_resolver.NXDOMAIN()
            raise _dns_resolver.NXDOMAIN()

        collector._resolver.resolve = AsyncMock(side_effect=_mock_resolve)

        results = await _collect_all(collector, _make_ip_seed("192.0.2.1"))
        assert len(results) == 1
        # txt_reason should be empty but observation still present
        assert results[0].structured_payload["txt_reason"] == ""


# ============================================================================
# Timeout resilience
# ============================================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestDnsBlacklistTimeoutResilience:
    """Timeout on one provider must not block others."""

    async def test_timeout_on_one_provider_others_still_work(self) -> None:
        collector = DnsBlacklistCollector(_make_config())

        a_answer = _mock_a_answer("127.0.0.2")
        txt_answer = _mock_txt_answer(["Listed"])

        async def _mock_resolve(qname: str, rdtype: str) -> MagicMock:
            qname_str = str(qname)
            # Spamhaus times out
            if "zen.spamhaus.org" in qname_str:
                raise _dns_resolver.LifetimeTimeout()
            # Barracuda lists the IP
            if "b.barracudacentral.org" in qname_str:
                if rdtype == "A":
                    return a_answer
                if rdtype == "TXT":
                    return txt_answer
            # All others: not listed
            raise _dns_resolver.NXDOMAIN()

        collector._resolver.resolve = AsyncMock(side_effect=_mock_resolve)

        results = await _collect_all(collector, _make_ip_seed("192.0.2.1"))
        # Only Barracuda should produce a result
        assert len(results) == 1
        assert results[0].structured_payload["blacklist_name"] == "Barracuda BRBL"


# ============================================================================
# Health check
# ============================================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestDnsBlacklistHealthCheck:
    """Verify health check success and failure paths."""

    async def test_healthy_returns_success(self) -> None:
        collector = DnsBlacklistCollector(_make_config())
        collector._resolver.resolve = AsyncMock(return_value=_mock_a_answer())

        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "dns-blacklist"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    async def test_dns_failure_returns_failure(self) -> None:
        collector = DnsBlacklistCollector(_make_config())
        collector._resolver.resolve = AsyncMock(side_effect=Exception("DNS resolution failed"))

        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "DNSBL probe failed" in result.error_message


# ============================================================================
# Registry
# ============================================================================


class TestDnsBlacklistRegistration:
    """Verify the collector is registered in the default registry."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("dns-blacklist")
        cls = DEFAULT_REGISTRY.get("dns-blacklist")
        assert cls is DnsBlacklistCollector

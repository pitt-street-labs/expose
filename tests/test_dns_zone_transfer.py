"""Tests for the dns-zone-transfer collector.

Exercises all code paths with fully mocked DNS resolution and AXFR
transfer -- no live DNS queries or zone transfers are ever issued.

Coverage:
    1.  Collector ID and tier are correct
    2.  Only expands DOMAIN seeds (IP, ORG, ASN skipped)
    3.  Mock AXFR refused (FormError) -> informational observation
    4.  Mock AXFR success -> all records as observations + critical summary
    5.  Mock NS resolution failure -> empty list
    6.  Timeout on AXFR -> informational observation
    7.  Multiple NS servers tried sequentially
    8.  Record types parsed (A, AAAA, MX, CNAME, TXT, NS, SOA)
    9.  dnspython not available -> CollectorError
   10.  Health check success and failure paths
   11.  NS hostname resolution failure -> informational observation
   12.  Connection refused on AXFR -> informational observation
   13.  Registration in default registry
   14.  Display name attribute
   15.  Health check without dnspython
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import dns.asyncresolver as _dns_ar
import dns.exception as _dns_exception
import dns.resolver as _dns_resolver
import pytest

from expose.collectors.base import (
    CollectorConfig,
    CollectorError,
    CollectorHealthCheck,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.dns_zone_transfer import (
    HAS_DNSPYTHON,
    ZoneTransferCollector,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

# Suppress DeprecationWarnings from dnspython internals if present.
pytestmark = [
    pytest.mark.filterwarnings("default::DeprecationWarning"),
]

# Synthetic IDs reused across tests (matches project conventions).
TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000E001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000E002")


def _config() -> CollectorConfig:
    """Build a minimal CollectorConfig for test use."""
    return CollectorConfig(tenant_id=TENANT_ID, run_id=RUN_ID)


# === Mock helpers =============================================================


def _make_ns_answer(nameservers: list[str]) -> MagicMock:
    """Build a mock DNS answer for NS records."""
    records = []
    for ns in nameservers:
        rr = MagicMock()
        rr.target = MagicMock()
        rr.target.__str__ = lambda self, _ns=ns: _ns
        records.append(rr)
    answer = MagicMock()
    answer.__iter__ = lambda self: iter(records)
    return answer


def _make_a_answer(ips: list[str]) -> MagicMock:
    """Build a mock DNS answer for A records (used for NS IP resolution)."""
    records = []
    for ip in ips:
        rr = MagicMock()
        rr.__str__ = lambda self, _ip=ip: _ip
        records.append(rr)
    answer = MagicMock()
    answer.__iter__ = lambda self: iter(records)
    answer.__getitem__ = lambda self, idx: records[idx]
    return answer


def _make_mock_zone(records: dict[str, list[tuple[str, list[str]]]]) -> MagicMock:
    """Build a mock dns.zone.Zone object.

    ``records`` maps record names to a list of (rdtype, [values]) tuples.
    Example::

        _make_mock_zone({
            "@": [("SOA", ["ns1.example.com. admin.example.com. 1 3600 900 604800 86400"])],
            "www": [("A", ["93.184.216.34"])],
            "mail": [("MX", ["10 mail.example.com."])],
        })
    """
    zone = MagicMock()
    nodes: dict[Any, MagicMock] = {}

    for name_str, rdatasets_spec in records.items():
        name = MagicMock()
        name.__str__ = lambda self, _n=name_str: _n
        node = MagicMock()
        rdatasets = []

        for rdtype_str, values in rdatasets_spec:
            rdataset = MagicMock()
            rdtype_mock = MagicMock()
            rdtype_mock.__str__ = lambda self, _rt=rdtype_str: _rt
            rdataset.rdtype = rdtype_mock
            rdata_records = []
            for v in values:
                rdata = MagicMock()
                rdata.__str__ = lambda self, _v=v: _v
                rdata_records.append(rdata)
            rdataset.__iter__ = lambda self, _recs=rdata_records: iter(_recs)
            rdatasets.append(rdataset)

        node.rdatasets = rdatasets
        nodes[name] = node

    zone.nodes = nodes
    return zone


def _mock_resolver_for_zone_transfer(
    ns_answers: MagicMock | Exception | None = None,
    ns_ip_answers: MagicMock | Exception | None = None,
) -> MagicMock:
    """Create a mock async resolver for zone transfer tests.

    ``ns_answers``: response for NS record queries (or exception to raise).
    ``ns_ip_answers``: response for A record queries on NS hostnames (or exception).
    """
    resolver = MagicMock()
    resolver.lifetime = 30.0

    async def _resolve(domain: str, rdtype: str, **kwargs: Any) -> Any:
        if rdtype == "NS":
            if isinstance(ns_answers, BaseException):
                raise ns_answers
            if isinstance(ns_answers, type) and issubclass(ns_answers, BaseException):
                raise ns_answers()
            if ns_answers is None:
                raise _dns_ar.NoAnswer
            return ns_answers
        if rdtype == "A":
            if isinstance(ns_ip_answers, BaseException):
                raise ns_ip_answers
            if isinstance(ns_ip_answers, type) and issubclass(ns_ip_answers, BaseException):
                raise ns_ip_answers()
            if ns_ip_answers is None:
                raise _dns_ar.NoAnswer
            return ns_ip_answers
        raise _dns_ar.NoAnswer

    resolver.resolve = AsyncMock(side_effect=_resolve)
    return resolver


# === Tests ====================================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestZoneTransferMetadata:
    """Test 1: Collector ID, tier, and display name are correct."""

    def test_collector_id(self) -> None:
        assert ZoneTransferCollector.collector_id == "dns-zone-transfer"

    def test_tier(self) -> None:
        assert ZoneTransferCollector.tier == CollectorTier.TIER_3

    def test_display_name(self) -> None:
        assert ZoneTransferCollector.display_name == "DNS Zone Transfer (AXFR)"

    def test_version(self) -> None:
        assert ZoneTransferCollector.collector_version == "0.1.0"

    def test_no_credentials_required(self) -> None:
        assert ZoneTransferCollector.requires_credentials is False


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestZoneTransferSeedFiltering:
    """Test 2: Only DOMAIN seeds are expanded; others return empty."""

    async def test_ip_seed_skipped(self) -> None:
        collector = ZoneTransferCollector(_config())
        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_organization_seed_skipped(self) -> None:
        collector = ZoneTransferCollector(_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="ACME Corp")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_asn_seed_skipped(self) -> None:
        collector = ZoneTransferCollector(_config())
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_cidr_seed_skipped(self) -> None:
        collector = ZoneTransferCollector(_config())
        seed = Seed(seed_type=SeedType.CIDR, value="10.0.0.0/8")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestZoneTransferDenied:
    """Test 3: AXFR refused (FormError) produces informational observation."""

    async def test_form_error_produces_denied_observation(self) -> None:
        collector = ZoneTransferCollector(_config())
        collector._resolver = _mock_resolver_for_zone_transfer(
            ns_answers=_make_ns_answer(["ns1.example.com."]),
            ns_ip_answers=_make_a_answer(["198.51.100.1"]),
        )

        with patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_zone.from_xfr",
            side_effect=_dns_exception.FormError,
        ), patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_query.xfr",
        ):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.collector_id == "dns-zone-transfer"
        assert obs.observation_type == ObservationType.DNS_RECORD
        assert obs.subject.identifier_type == ExtendedIdentifierType.DOMAIN
        assert obs.subject.identifier_value == "example.com"
        assert obs.structured_payload["axfr_status"] == "denied"
        assert obs.structured_payload["severity"] == "info"
        assert obs.structured_payload["nameserver"] == "ns1.example.com"
        assert "properly denied" in obs.structured_payload["note"]
        assert obs.tenant_id == TENANT_ID


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestZoneTransferSuccess:
    """Test 4: Successful AXFR produces per-record + summary observations."""

    async def test_successful_axfr_produces_records_and_summary(self) -> None:
        zone_data = {
            "@": [("SOA", ["ns1.example.com. admin.example.com. 1 3600 900 604800 86400"])],
            "www": [("A", ["93.184.216.34"])],
            "mail": [("MX", ["10 mail.example.com."])],
        }
        mock_zone = _make_mock_zone(zone_data)

        collector = ZoneTransferCollector(_config())
        collector._resolver = _mock_resolver_for_zone_transfer(
            ns_answers=_make_ns_answer(["ns1.example.com."]),
            ns_ip_answers=_make_a_answer(["198.51.100.1"]),
        )

        with patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_zone.from_xfr",
            return_value=mock_zone,
        ), patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_query.xfr",
        ):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        # 3 records (SOA, A, MX) + 1 summary = 4 total
        assert len(observations) == 4

        # All observations should be DNS_RECORD type.
        for obs in observations:
            assert obs.observation_type == ObservationType.DNS_RECORD
            assert obs.collector_id == "dns-zone-transfer"
            assert obs.tenant_id == TENANT_ID

        # Last observation should be the summary.
        summary = observations[-1]
        assert summary.structured_payload["axfr_status"] == "success"
        assert summary.structured_payload["record_count"] == 3
        assert summary.structured_payload["severity"] == "critical"
        assert "full zone exposed" in summary.structured_payload["note"]

        # Record observations should have record details.
        record_obs = observations[:-1]
        record_names = {obs.structured_payload["record_name"] for obs in record_obs}
        assert "@" in record_names
        assert "www" in record_names
        assert "mail" in record_names

        for obs in record_obs:
            assert obs.structured_payload["axfr_status"] == "success"
            assert obs.structured_payload["severity"] == "critical"
            assert "nameserver" in obs.structured_payload
            assert "record_type" in obs.structured_payload
            assert "record_values" in obs.structured_payload


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestZoneTransferNsResolutionFailure:
    """Test 5: NS resolution failure returns empty observations."""

    async def test_nxdomain_ns_returns_empty(self) -> None:
        collector = ZoneTransferCollector(_config())
        collector._resolver = _mock_resolver_for_zone_transfer(
            ns_answers=_dns_resolver.NXDOMAIN(),
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="nonexistent.invalid")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_timeout_ns_returns_empty(self) -> None:
        collector = ZoneTransferCollector(_config())
        collector._resolver = _mock_resolver_for_zone_transfer(
            ns_answers=_dns_resolver.LifetimeTimeout(),
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="slow.example.com")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_noanswer_ns_returns_empty(self) -> None:
        collector = ZoneTransferCollector(_config())
        collector._resolver = _mock_resolver_for_zone_transfer(
            ns_answers=_dns_resolver.NoAnswer(),
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestZoneTransferTimeout:
    """Test 6: Timeout on AXFR produces informational observation."""

    async def test_timeout_produces_informational_observation(self) -> None:
        collector = ZoneTransferCollector(_config())
        collector._resolver = _mock_resolver_for_zone_transfer(
            ns_answers=_make_ns_answer(["ns1.example.com."]),
            ns_ip_answers=_make_a_answer(["198.51.100.1"]),
        )

        with patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_zone.from_xfr",
            side_effect=TimeoutError("AXFR timed out"),
        ), patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_query.xfr",
        ):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["axfr_status"] == "denied"
        assert obs.structured_payload["severity"] == "info"
        assert "TimeoutError" in obs.structured_payload["note"]


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestZoneTransferMultipleNs:
    """Test 7: Multiple NS servers are tried sequentially."""

    async def test_multiple_ns_all_denied(self) -> None:
        collector = ZoneTransferCollector(_config())
        collector._resolver = _mock_resolver_for_zone_transfer(
            ns_answers=_make_ns_answer(["ns1.example.com.", "ns2.example.com."]),
            ns_ip_answers=_make_a_answer(["198.51.100.1"]),
        )

        with patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_zone.from_xfr",
            side_effect=_dns_exception.FormError,
        ), patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_query.xfr",
        ):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        # One denied observation per NS.
        assert len(observations) == 2
        ns_names = {obs.structured_payload["nameserver"] for obs in observations}
        assert "ns1.example.com" in ns_names
        assert "ns2.example.com" in ns_names
        for obs in observations:
            assert obs.structured_payload["axfr_status"] == "denied"

    async def test_one_success_one_denied(self) -> None:
        """First NS denies, second NS allows AXFR."""
        zone_data = {
            "www": [("A", ["93.184.216.34"])],
        }
        mock_zone = _make_mock_zone(zone_data)

        call_count = 0

        def _from_xfr_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise _dns_exception.FormError
            return mock_zone

        collector = ZoneTransferCollector(_config())
        collector._resolver = _mock_resolver_for_zone_transfer(
            ns_answers=_make_ns_answer(["ns1.example.com.", "ns2.example.com."]),
            ns_ip_answers=_make_a_answer(["198.51.100.1"]),
        )

        with patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_zone.from_xfr",
            side_effect=_from_xfr_side_effect,
        ), patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_query.xfr",
        ):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        # 1 denied + 1 record + 1 summary = 3
        assert len(observations) == 3
        denied = [o for o in observations if o.structured_payload["axfr_status"] == "denied"]
        success = [o for o in observations if o.structured_payload["axfr_status"] == "success"]
        assert len(denied) == 1
        assert len(success) == 2  # 1 record + 1 summary


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestZoneTransferRecordTypes:
    """Test 8: Various DNS record types are parsed from successful AXFR."""

    async def test_all_major_record_types(self) -> None:
        zone_data = {
            "@": [
                ("SOA", ["ns1.example.com. admin.example.com. 1 3600 900 604800 86400"]),
                ("NS", ["ns1.example.com.", "ns2.example.com."]),
            ],
            "www": [("A", ["93.184.216.34"])],
            "ipv6": [("AAAA", ["2001:db8::1"])],
            "mail": [("MX", ["10 mail.example.com."])],
            "alias": [("CNAME", ["www.example.com."])],
            "info": [("TXT", ["v=spf1 include:_spf.google.com ~all"])],
        }
        mock_zone = _make_mock_zone(zone_data)

        collector = ZoneTransferCollector(_config())
        collector._resolver = _mock_resolver_for_zone_transfer(
            ns_answers=_make_ns_answer(["ns1.example.com."]),
            ns_ip_answers=_make_a_answer(["198.51.100.1"]),
        )

        with patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_zone.from_xfr",
            return_value=mock_zone,
        ), patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_query.xfr",
        ):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        # 7 rdatasets (6 names, @ has 2 rdatasets) + 1 summary = 8
        assert len(observations) == 8

        # Verify all record types appear.
        record_obs = observations[:-1]
        record_types = {obs.structured_payload["record_type"] for obs in record_obs}
        assert "SOA" in record_types
        assert "NS" in record_types
        assert "A" in record_types
        assert "AAAA" in record_types
        assert "MX" in record_types
        assert "CNAME" in record_types
        assert "TXT" in record_types

        # Summary should have correct count.
        summary = observations[-1]
        assert summary.structured_payload["record_count"] == 7


class TestZoneTransferMissingDnspython:
    """Test 9: CollectorError when dnspython is not available."""

    async def test_expand_raises_collector_error(self) -> None:
        with patch(
            "expose.collectors.builtin.dns_zone_transfer.HAS_DNSPYTHON", False,
        ):
            collector = ZoneTransferCollector(_config())
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            with pytest.raises(CollectorError, match="dnspython not installed"):
                _ = [obs async for obs in collector.expand(seed)]


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestZoneTransferHealthCheck:
    """Test 10: Health check success and failure paths."""

    async def test_health_check_success(self) -> None:
        collector = ZoneTransferCollector(_config())
        mock_resolver = MagicMock()
        mock_resolver.lifetime = 30.0
        mock_resolver.resolve = AsyncMock(return_value=_make_a_answer(["8.8.8.8"]))
        collector._resolver = mock_resolver

        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "dns-zone-transfer"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    async def test_health_check_failure(self) -> None:
        collector = ZoneTransferCollector(_config())
        mock_resolver = MagicMock()
        mock_resolver.lifetime = 30.0
        mock_resolver.resolve = AsyncMock(side_effect=_dns_resolver.LifetimeTimeout)
        collector._resolver = mock_resolver

        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    async def test_health_check_without_dnspython(self) -> None:
        with patch(
            "expose.collectors.builtin.dns_zone_transfer.HAS_DNSPYTHON", False,
        ):
            collector = ZoneTransferCollector(_config())
            result = await collector.health_check()

            assert result.status == CollectorStatus.FAILURE
            assert "dnspython not installed" in (result.error_message or "")


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestZoneTransferNsIpResolutionFailure:
    """Test 11: NS hostname IP resolution failure -> informational observation."""

    async def test_ns_ip_unresolvable(self) -> None:
        collector = ZoneTransferCollector(_config())
        collector._resolver = _mock_resolver_for_zone_transfer(
            ns_answers=_make_ns_answer(["ns1.example.com."]),
            ns_ip_answers=_dns_resolver.NoAnswer(),
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["axfr_status"] == "denied"
        assert obs.structured_payload["severity"] == "info"
        assert "Could not resolve" in obs.structured_payload["note"]


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestZoneTransferConnectionRefused:
    """Test 12: Connection refused on AXFR -> informational observation."""

    async def test_connection_refused(self) -> None:
        collector = ZoneTransferCollector(_config())
        collector._resolver = _mock_resolver_for_zone_transfer(
            ns_answers=_make_ns_answer(["ns1.example.com."]),
            ns_ip_answers=_make_a_answer(["198.51.100.1"]),
        )

        with patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_zone.from_xfr",
            side_effect=ConnectionRefusedError("Connection refused"),
        ), patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_query.xfr",
        ):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["axfr_status"] == "denied"
        assert obs.structured_payload["severity"] == "info"
        assert "ConnectionRefusedError" in obs.structured_payload["note"]


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestZoneTransferRegistration:
    """Test 13: Verify the collector registers correctly in the default registry."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("dns-zone-transfer")
        cls = DEFAULT_REGISTRY.get("dns-zone-transfer")
        assert cls is ZoneTransferCollector

    def test_metadata_correct(self) -> None:
        assert ZoneTransferCollector.collector_id == "dns-zone-transfer"
        assert ZoneTransferCollector.collector_version == "0.1.0"
        assert ZoneTransferCollector.tier == CollectorTier.TIER_3
        assert ZoneTransferCollector.requires_credentials is False


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestZoneTransferEmptyZone:
    """Test 14: Successful AXFR with empty zone produces only summary."""

    async def test_empty_zone(self) -> None:
        mock_zone = MagicMock()
        mock_zone.nodes = {}

        collector = ZoneTransferCollector(_config())
        collector._resolver = _mock_resolver_for_zone_transfer(
            ns_answers=_make_ns_answer(["ns1.example.com."]),
            ns_ip_answers=_make_a_answer(["198.51.100.1"]),
        )

        with patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_zone.from_xfr",
            return_value=mock_zone,
        ), patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_query.xfr",
        ):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        # Only the summary observation.
        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["axfr_status"] == "success"
        assert obs.structured_payload["record_count"] == 0
        assert obs.structured_payload["severity"] == "critical"


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestZoneTransferSubjectFields:
    """Test 15: Subject fields are correctly populated on all observations."""

    async def test_subject_uses_canonical_domain(self) -> None:
        collector = ZoneTransferCollector(_config())
        collector._resolver = _mock_resolver_for_zone_transfer(
            ns_answers=_make_ns_answer(["ns1.example.com."]),
            ns_ip_answers=_make_a_answer(["198.51.100.1"]),
        )

        with patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_zone.from_xfr",
            side_effect=_dns_exception.FormError,
        ), patch(
            "expose.collectors.builtin.dns_zone_transfer._dns_query.xfr",
        ):
            seed = Seed(seed_type=SeedType.DOMAIN, value="EXAMPLE.COM")
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        # canonicalize_domain lowercases.
        assert obs.subject.identifier_value == "example.com"
        assert obs.subject.identifier_type == ExtendedIdentifierType.DOMAIN

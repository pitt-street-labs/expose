"""Tests for the active-dns-resolve collector.

Exercises all code paths with a fully mocked DNS resolver — no live DNS
queries are ever issued. The mock strategy patches the ``Resolver`` class
returned by ``dns.asyncresolver`` so that ``ActiveDnsCollector.__init__``
constructs our mock instead of a real resolver.

Coverage:
    1. Happy path: A record resolution
    2. Happy path: AAAA, MX, NS record types
    3. TXT record sanitization via SanitizationFieldKind.DNS_TXT_RECORD
    4. NXDOMAIN produces no observations, no error
    5. Timeout raises CollectorSourceUnreachableError
    6. Non-domain seed is skipped
    7. dnspython not available: CollectorError raised
    8. Health check success and failure paths
    9. CNAME resolution
   10. SOA record resolution
   11. NoAnswer for a record type skips without failing
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import dns.asyncresolver as _dns_ar
import dns.resolver as _dns_resolver
import pytest

from expose.collectors.base import (
    CollectorConfig,
    CollectorError,
    CollectorHealthCheck,
    CollectorSourceUnreachableError,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.active_dns import (
    HAS_DNSPYTHON,
    ActiveDnsCollector,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.egress.base import EgressProfile, EgressProfileType
from expose.egress.direct import DirectEgressProfile
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

# Suppress DeprecationWarnings from dnspython internals if present.
pytestmark = [
    pytest.mark.filterwarnings("default::DeprecationWarning"),
]

# Synthetic IDs reused across tests (matches project conventions).
TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000D001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000D002")


def _config() -> CollectorConfig:
    """Build a minimal CollectorConfig for test use."""
    return CollectorConfig(tenant_id=TENANT_ID, run_id=RUN_ID)


# === Mock helpers =============================================================


def _make_a_answer(ips: list[str], ttl: int = 300) -> MagicMock:
    """Build a mock DNS answer for A / AAAA records."""
    records = []
    for ip in ips:
        rr = MagicMock()
        rr.__str__ = lambda self, _ip=ip: _ip
        records.append(rr)
    answer = MagicMock()
    answer.__iter__ = lambda self: iter(records)
    answer.rrset = MagicMock()
    answer.rrset.ttl = ttl
    return answer


def _make_cname_answer(target: str) -> MagicMock:
    """Build a mock DNS answer for a CNAME record."""
    rr = MagicMock()
    rr.target = MagicMock()
    rr.target.__str__ = lambda self: target
    answer = MagicMock()
    answer.__getitem__ = lambda self, idx: rr
    answer.__iter__ = lambda self: iter([rr])
    return answer


def _make_mx_answer(exchanges: list[tuple[int, str]]) -> MagicMock:
    """Build a mock DNS answer for MX records."""
    records = []
    for priority, exchange in exchanges:
        rr = MagicMock()
        rr.preference = priority
        rr.exchange = MagicMock()
        rr.exchange.__str__ = lambda self, _e=exchange: _e
        records.append(rr)
    answer = MagicMock()
    answer.__iter__ = lambda self: iter(records)
    return answer


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


def _make_txt_answer(values: list[str]) -> MagicMock:
    """Build a mock DNS answer for TXT records."""
    records = []
    for v in values:
        rr = MagicMock()
        rr.strings = [v.encode("utf-8")]
        records.append(rr)
    answer = MagicMock()
    answer.__iter__ = lambda self: iter(records)
    return answer


def _make_soa_answer(
    mname: str = "ns1.example.com.",
    rname: str = "admin.example.com.",
    serial: int = 2026051001,
    refresh: int = 3600,
    retry: int = 900,
    expire: int = 604800,
    minimum: int = 86400,
) -> MagicMock:
    """Build a mock DNS answer for a SOA record."""
    soa = MagicMock()
    soa.mname = MagicMock()
    soa.mname.__str__ = lambda self: mname
    soa.rname = MagicMock()
    soa.rname.__str__ = lambda self: rname
    soa.serial = serial
    soa.refresh = refresh
    soa.retry = retry
    soa.expire = expire
    soa.minimum = minimum
    answer = MagicMock()
    answer.__getitem__ = lambda self, idx: soa
    answer.__iter__ = lambda self: iter([soa])
    return answer


def _mock_resolver_factory(
    answers: dict[str, Any] | None = None,
) -> MagicMock:
    """Create a mock Resolver whose ``resolve`` returns preconfigured answers.

    ``answers`` maps record-type strings ("A", "AAAA", ...) to either a
    mock answer object or an exception class to raise.
    """
    resolver = MagicMock()
    resolver.lifetime = 30.0

    async def _resolve(
        domain: str,
        rdtype: str,
        **kwargs: Any,
    ) -> Any:
        if answers is None:
            raise _dns_ar.NoAnswer
        entry = answers.get(rdtype)
        if entry is None:
            raise _dns_ar.NoAnswer
        if isinstance(entry, type) and issubclass(entry, BaseException):
            raise entry()
        if isinstance(entry, BaseException):
            raise entry
        return entry

    resolver.resolve = AsyncMock(side_effect=_resolve)
    return resolver


# === Tests ====================================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsARecord:
    """Test 1: Happy path A record resolution."""

    async def test_a_record_emits_observation(self) -> None:
        answers = {"A": _make_a_answer(["93.184.216.34"])}
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations: list[Observation] = [
            obs async for obs in collector.expand(seed)
        ]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.collector_id == "active-dns-resolve"
        assert obs.observation_type == ObservationType.DNS_RESOLUTION
        assert obs.subject.identifier_type == ExtendedIdentifierType.DOMAIN
        assert obs.subject.identifier_value == "example.com"
        assert obs.structured_payload["record_type"] == "A"
        assert obs.structured_payload["values"] == ["93.184.216.34"]
        assert obs.structured_payload["ttl"] == 300
        assert obs.tenant_id == TENANT_ID


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsMultipleTypes:
    """Test 2: Multiple record types resolved in one expansion."""

    async def test_aaaa_mx_ns_resolved(self) -> None:
        answers = {
            "AAAA": _make_a_answer(["2001:db8::1"], ttl=600),
            "MX": _make_mx_answer([(10, "mail.example.com."), (20, "mail2.example.com.")]),
            "NS": _make_ns_answer(["ns1.example.com.", "ns2.example.com."]),
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        # One per record type that returned data.
        assert len(observations) == 3

        by_type = {
            obs.structured_payload["record_type"]: obs for obs in observations
        }

        # AAAA
        aaaa = by_type["AAAA"]
        assert aaaa.structured_payload["values"] == ["2001:db8::1"]
        assert aaaa.structured_payload["ttl"] == 600

        # MX
        mx = by_type["MX"]
        exchanges = mx.structured_payload["exchanges"]
        assert len(exchanges) == 2
        assert exchanges[0]["priority"] == 10
        assert exchanges[0]["exchange"] == "mail.example.com"

        # NS
        ns = by_type["NS"]
        assert "ns1.example.com" in ns.structured_payload["nameservers"]
        assert "ns2.example.com" in ns.structured_payload["nameservers"]


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsTxtSanitization:
    """Test 3: TXT records are sanitized via SanitizationFieldKind.DNS_TXT_RECORD."""

    async def test_txt_record_sanitized(self) -> None:
        # Include a control character that sanitization should strip.
        raw_txt = "v=spf1 include:_spf.google.com ~all\x00"
        answers = {"TXT": _make_txt_answer([raw_txt])}
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["record_type"] == "TXT"
        values = obs.structured_payload["values"]
        assert len(values) == 1
        # Control char should be stripped by sanitize_field.
        assert "\x00" not in values[0]
        assert "v=spf1" in values[0]


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsNxdomain:
    """Test 4: NXDOMAIN produces no observations and no error."""

    async def test_nxdomain_emits_nothing(self) -> None:
        collector = ActiveDnsCollector(_config())
        # Make every resolve call raise NXDOMAIN.
        resolver = MagicMock()
        resolver.lifetime = 30.0
        resolver.resolve = AsyncMock(side_effect=_dns_ar.NXDOMAIN)
        collector._resolver = resolver

        seed = Seed(seed_type=SeedType.DOMAIN, value="nonexistent.invalid")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsTimeout:
    """Test 5: Timeout raises CollectorSourceUnreachableError."""

    async def test_timeout_raises_source_unreachable(self) -> None:
        collector = ActiveDnsCollector(_config())
        resolver = MagicMock()
        resolver.lifetime = 30.0
        resolver.resolve = AsyncMock(side_effect=_dns_resolver.LifetimeTimeout)
        collector._resolver = resolver

        seed = Seed(seed_type=SeedType.DOMAIN, value="slow.example.com")
        with pytest.raises(CollectorSourceUnreachableError):
            _ = [obs async for obs in collector.expand(seed)]


class TestActiveDnsNonDomainSeed:
    """Test 6: Non-domain seeds are silently skipped."""

    async def test_ip_seed_skipped(self) -> None:
        collector = ActiveDnsCollector(_config())

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []

    async def test_organization_seed_skipped(self) -> None:
        collector = ActiveDnsCollector(_config())

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="ACME Corp")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []


class TestActiveDnsMissingDnspython:
    """Test 7: CollectorError when dnspython is not available."""

    async def test_expand_raises_collector_error(self) -> None:
        with patch(
            "expose.collectors.builtin.active_dns.HAS_DNSPYTHON", False
        ):
            collector = ActiveDnsCollector(_config())
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            with pytest.raises(CollectorError, match="dnspython not installed"):
                _ = [obs async for obs in collector.expand(seed)]


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsHealthCheck:
    """Test 8: Health check success and failure paths."""

    async def test_health_check_success(self) -> None:
        collector = ActiveDnsCollector(_config())
        # Mock the resolver to return a valid A-record answer.
        collector._resolver = _mock_resolver_factory(
            {"A": _make_a_answer(["8.8.8.8"])}
        )

        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "active-dns-resolve"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    async def test_health_check_failure(self) -> None:
        collector = ActiveDnsCollector(_config())
        resolver = MagicMock()
        resolver.lifetime = 30.0
        resolver.resolve = AsyncMock(side_effect=_dns_resolver.LifetimeTimeout)
        collector._resolver = resolver

        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    async def test_health_check_without_dnspython(self) -> None:
        with patch(
            "expose.collectors.builtin.active_dns.HAS_DNSPYTHON", False
        ):
            collector = ActiveDnsCollector(_config())
            result = await collector.health_check()

            assert result.status == CollectorStatus.FAILURE
            assert "dnspython not installed" in (result.error_message or "")


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsCname:
    """Test 9: CNAME resolution emits correct observation."""

    async def test_cname_emits_observation(self) -> None:
        answers = {"CNAME": _make_cname_answer("www.example.com.")}
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="alias.example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["record_type"] == "CNAME"
        assert obs.structured_payload["target"] == "www.example.com"


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsSoa:
    """Test 10: SOA record resolution emits correct observation."""

    async def test_soa_emits_observation(self) -> None:
        answers = {
            "SOA": _make_soa_answer(
                mname="ns1.example.com.",
                rname="admin.example.com.",
                serial=2026051001,
                refresh=3600,
                retry=900,
                expire=604800,
                minimum=86400,
            ),
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        payload = obs.structured_payload
        assert payload["record_type"] == "SOA"
        assert payload["mname"] == "ns1.example.com"
        assert payload["rname"] == "admin.example.com"
        assert payload["serial"] == 2026051001
        assert payload["refresh"] == 3600
        assert payload["retry"] == 900
        assert payload["expire"] == 604800
        assert payload["minimum"] == 86400


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsNoAnswer:
    """Test 11: NoAnswer for a record type is skipped without failing."""

    async def test_partial_answers_skip_noanswer(self) -> None:
        """Only record types with actual answers produce observations."""
        answers = {
            "A": _make_a_answer(["93.184.216.34"]),
            # All other types will raise NoAnswer (default in mock factory).
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        assert observations[0].structured_payload["record_type"] == "A"


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsRegistration:
    """Verify the collector registers correctly in the default registry."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("active-dns-resolve")
        cls = DEFAULT_REGISTRY.get("active-dns-resolve")
        assert cls is ActiveDnsCollector

    def test_metadata_correct(self) -> None:
        assert ActiveDnsCollector.collector_id == "active-dns-resolve"
        assert ActiveDnsCollector.collector_version == "0.1.0"
        assert ActiveDnsCollector.tier == CollectorTier.TIER_3
        assert ActiveDnsCollector.requires_credentials is False


# === Egress profile integration ===============================================


def _config_with_egress(**extra: Any) -> CollectorConfig:
    """Build a CollectorConfig with extra fields for egress tests."""
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        extra=dict(extra),  # type: ignore[arg-type]
    )


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsEgressProfile:
    """Egress profile integration tests for the DNS collector."""

    async def test_works_without_egress_profile(self) -> None:
        """Backward compatibility: collector works with no egress_profile."""
        answers = {"A": _make_a_answer(["93.184.216.34"])}
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        assert observations[0].structured_payload["values"] == ["93.184.216.34"]

    async def test_direct_egress_profile_works(self) -> None:
        """DirectEgressProfile passes through without altering resolver."""
        cfg = _config_with_egress(egress_profile=DirectEgressProfile())
        collector = ActiveDnsCollector(cfg)

        # DirectEgressProfile returns {} from configure_dns_resolver,
        # so the resolver's nameservers should remain unchanged (system default).
        answers = {"A": _make_a_answer(["93.184.216.34"])}
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        assert observations[0].structured_payload["record_type"] == "A"

    async def test_egress_profile_configure_dns_resolver_called(self) -> None:
        """A mock egress profile's configure_dns_resolver is invoked."""
        mock_profile = MagicMock(spec=EgressProfile)
        mock_profile.profile_type = EgressProfileType.DIRECT
        mock_profile.configure_dns_resolver.return_value = {
            "nameservers": ["10.0.0.53"],
        }

        cfg = _config_with_egress(egress_profile=mock_profile)
        collector = ActiveDnsCollector(cfg)

        mock_profile.configure_dns_resolver.assert_called_once()
        # The resolver's nameservers should have been set.
        assert collector._resolver.nameservers == ["10.0.0.53"]

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
   12. _collector_id tagging on all observation payloads
   13. Wildcard DNS detection (positive and negative)
   14. DNSSEC validation check (enabled and disabled)
   15. Zone transfer (AXFR) attempt detection (allowed and denied)
   16. Egress profile port and source kwargs
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
    *,
    domain_answers: dict[tuple[str, str], Any] | None = None,
) -> MagicMock:
    """Create a mock Resolver whose ``resolve`` returns preconfigured answers.

    ``answers`` maps record-type strings ("A", "AAAA", ...) to either a
    mock answer object or an exception class to raise. Used as a fallback
    when no domain-specific match is found.

    ``domain_answers`` maps ``(domain, rdtype)`` tuples to answers or
    exceptions, enabling tests for domain-specific queries like wildcard
    detection (``*.example.com``, ``A``) or DNSSEC (``example.com``,
    ``DNSKEY``).
    """
    resolver = MagicMock()
    resolver.lifetime = 30.0

    async def _resolve(
        domain: str,
        rdtype: str,
        **kwargs: Any,
    ) -> Any:
        # Check domain-specific answers first.
        if domain_answers is not None:
            key = (domain, rdtype)
            if key in domain_answers:
                entry = domain_answers[key]
                if isinstance(entry, type) and issubclass(entry, BaseException):
                    raise entry()
                if isinstance(entry, BaseException):
                    raise entry
                return entry

        # Fall back to type-only answers.
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

        # Filter to only A-record observations (supplementary checks
        # may add DNSSEC observations).
        a_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "A"
        ]
        assert len(a_obs) == 1
        obs = a_obs[0]
        assert obs.collector_id == "active-dns-resolve"
        assert obs.observation_type == ObservationType.DNS_RESOLUTION
        assert obs.subject.identifier_type == ExtendedIdentifierType.DOMAIN
        assert obs.subject.identifier_value == "example.com"
        assert obs.structured_payload["record_type"] == "A"
        assert obs.structured_payload["values"] == ["93.184.216.34"]
        assert obs.structured_payload["ttl"] == 300
        assert obs.structured_payload["_collector_id"] == "active-dns-resolve"
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

        by_type = {
            obs.structured_payload["record_type"]: obs for obs in observations
        }

        # At least the three standard record types must be present.
        assert "AAAA" in by_type
        assert "MX" in by_type
        assert "NS" in by_type

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

        txt_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "TXT"
        ]
        assert len(txt_obs) == 1
        obs = txt_obs[0]
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

        cname_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "CNAME"
        ]
        assert len(cname_obs) == 1
        obs = cname_obs[0]
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

        soa_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "SOA"
        ]
        assert len(soa_obs) == 1
        obs = soa_obs[0]
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
        """Only record types with actual answers produce observations.

        The supplementary checks (DNSSEC, wildcard) may also emit
        observations; we only verify the A record is present and no
        other standard record types leaked through.
        """
        answers = {
            "A": _make_a_answer(["93.184.216.34"]),
            # All other types will raise NoAnswer (default in mock factory).
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        standard_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") in (
                "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"
            )
        ]
        assert len(standard_obs) == 1
        assert standard_obs[0].structured_payload["record_type"] == "A"


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsCollectorIdTagging:
    """Test 12: Every observation payload contains _collector_id."""

    async def test_collector_id_on_a_record(self) -> None:
        answers = {"A": _make_a_answer(["93.184.216.34"])}
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        # Every single observation must carry _collector_id.
        for obs in observations:
            assert "_collector_id" in obs.structured_payload
            assert obs.structured_payload["_collector_id"] == "active-dns-resolve"

    async def test_collector_id_on_all_record_types(self) -> None:
        """All standard record types plus supplementary checks carry the tag."""
        answers = {
            "A": _make_a_answer(["93.184.216.34"]),
            "AAAA": _make_a_answer(["2001:db8::1"]),
            "CNAME": _make_cname_answer("www.example.com."),
            "MX": _make_mx_answer([(10, "mail.example.com.")]),
            "NS": _make_ns_answer(["ns1.example.com."]),
            "TXT": _make_txt_answer(["v=spf1 ~all"]),
            "SOA": _make_soa_answer(),
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) >= 7  # 7 standard + supplementary checks
        for obs in observations:
            assert obs.structured_payload["_collector_id"] == "active-dns-resolve"

    async def test_collector_id_matches_collector_id_attr(self) -> None:
        """The _collector_id in payload must match the collector_id attribute."""
        answers = {"A": _make_a_answer(["1.2.3.4"])}
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        for obs in observations:
            assert obs.structured_payload["_collector_id"] == obs.collector_id


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsWildcard:
    """Test 13: Wildcard DNS detection."""

    async def test_wildcard_detected(self) -> None:
        """When *.domain resolves, emit a WILDCARD observation."""
        answers = {"A": _make_a_answer(["93.184.216.34"])}
        domain_answers = {
            ("*.example.com", "A"): _make_a_answer(["10.0.0.1"]),
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(
            answers, domain_answers=domain_answers
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        wildcard_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "WILDCARD"
        ]
        assert len(wildcard_obs) == 1
        obs = wildcard_obs[0]
        assert obs.structured_payload["wildcard_detected"] is True
        assert obs.structured_payload["wildcard_values"] == ["10.0.0.1"]
        assert obs.structured_payload["severity"] == "warning"
        assert obs.structured_payload["_collector_id"] == "active-dns-resolve"

    async def test_no_wildcard(self) -> None:
        """When *.domain returns NXDOMAIN, no wildcard observation is emitted."""
        answers = {"A": _make_a_answer(["93.184.216.34"])}
        domain_answers = {
            ("*.example.com", "A"): _dns_resolver.NXDOMAIN,
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(
            answers, domain_answers=domain_answers
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        wildcard_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "WILDCARD"
        ]
        assert wildcard_obs == []

    async def test_wildcard_noanswer_no_observation(self) -> None:
        """NoAnswer for wildcard query produces no observation."""
        answers = {"A": _make_a_answer(["93.184.216.34"])}
        domain_answers = {
            ("*.example.com", "A"): _dns_resolver.NoAnswer,
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(
            answers, domain_answers=domain_answers
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        wildcard_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "WILDCARD"
        ]
        assert wildcard_obs == []

    async def test_wildcard_timeout_no_observation(self) -> None:
        """Timeout on wildcard check is swallowed (non-fatal)."""
        answers = {"A": _make_a_answer(["93.184.216.34"])}
        domain_answers = {
            ("*.example.com", "A"): _dns_resolver.LifetimeTimeout,
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(
            answers, domain_answers=domain_answers
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        wildcard_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "WILDCARD"
        ]
        assert wildcard_obs == []

    async def test_wildcard_unexpected_error_swallowed(self) -> None:
        """Unexpected errors on wildcard check are swallowed."""
        answers = {"A": _make_a_answer(["93.184.216.34"])}
        domain_answers = {
            ("*.example.com", "A"): RuntimeError("mock failure"),
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(
            answers, domain_answers=domain_answers
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        # Should not raise.
        observations = [obs async for obs in collector.expand(seed)]

        wildcard_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "WILDCARD"
        ]
        assert wildcard_obs == []


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsDnssec:
    """Test 14: DNSSEC validation check."""

    async def test_dnssec_enabled(self) -> None:
        """DNSKEY records present -> dnssec_enabled=True."""
        # Mock a DNSKEY answer with 2 keys.
        dnskey_answer = MagicMock()
        dnskey_answer.__iter__ = lambda self: iter([MagicMock(), MagicMock()])

        answers = {"A": _make_a_answer(["93.184.216.34"])}
        domain_answers = {
            ("example.com", "DNSKEY"): dnskey_answer,
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(
            answers, domain_answers=domain_answers
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        dnssec_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "DNSSEC"
        ]
        assert len(dnssec_obs) == 1
        obs = dnssec_obs[0]
        assert obs.structured_payload["dnssec_enabled"] is True
        assert obs.structured_payload["dnskey_count"] == 2
        assert obs.structured_payload["severity"] == "info"
        assert obs.structured_payload["_collector_id"] == "active-dns-resolve"

    async def test_dnssec_disabled(self) -> None:
        """No DNSKEY records -> dnssec_enabled=False."""
        answers = {"A": _make_a_answer(["93.184.216.34"])}
        domain_answers = {
            ("example.com", "DNSKEY"): _dns_resolver.NoAnswer,
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(
            answers, domain_answers=domain_answers
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        dnssec_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "DNSSEC"
        ]
        assert len(dnssec_obs) == 1
        obs = dnssec_obs[0]
        assert obs.structured_payload["dnssec_enabled"] is False
        assert obs.structured_payload["dnskey_count"] == 0

    async def test_dnssec_nxdomain_means_disabled(self) -> None:
        """NXDOMAIN on DNSKEY -> dnssec_enabled=False."""
        answers = {"A": _make_a_answer(["93.184.216.34"])}
        domain_answers = {
            ("example.com", "DNSKEY"): _dns_resolver.NXDOMAIN,
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(
            answers, domain_answers=domain_answers
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        dnssec_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "DNSSEC"
        ]
        assert len(dnssec_obs) == 1
        assert dnssec_obs[0].structured_payload["dnssec_enabled"] is False

    async def test_dnssec_timeout_no_observation(self) -> None:
        """Timeout on DNSSEC check returns None (no observation)."""
        answers = {"A": _make_a_answer(["93.184.216.34"])}
        domain_answers = {
            ("example.com", "DNSKEY"): _dns_resolver.LifetimeTimeout,
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(
            answers, domain_answers=domain_answers
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        dnssec_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "DNSSEC"
        ]
        assert dnssec_obs == []


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsZoneTransfer:
    """Test 15: Zone transfer (AXFR) attempt detection."""

    async def test_axfr_denied(self) -> None:
        """AXFR refused -> axfr_allowed=False observation."""
        import dns.exception as _dns_exc

        answers = {
            "A": _make_a_answer(["93.184.216.34"]),
            "NS": _make_ns_answer(["ns1.example.com."]),
        }
        # NS hostname resolves to an IP.
        domain_answers = {
            ("ns1.example.com", "A"): _make_a_answer(["10.0.0.53"]),
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(
            answers, domain_answers=domain_answers
        )

        # Mock the AXFR to raise FormError (refused).
        with patch(
            "expose.collectors.builtin.active_dns._dns_zone.from_xfr",
            side_effect=_dns_exc.FormError,
        ), patch(
            "expose.collectors.builtin.active_dns._dns_query.xfr",
            return_value=MagicMock(),
        ):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        axfr_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "AXFR"
        ]
        assert len(axfr_obs) == 1
        obs = axfr_obs[0]
        assert obs.structured_payload["axfr_allowed"] is False
        assert obs.structured_payload["nameserver"] == "ns1.example.com"
        assert obs.structured_payload["severity"] == "info"
        assert obs.structured_payload["_collector_id"] == "active-dns-resolve"

    async def test_axfr_allowed(self) -> None:
        """AXFR succeeds -> axfr_allowed=True critical observation."""
        answers = {
            "A": _make_a_answer(["93.184.216.34"]),
            "NS": _make_ns_answer(["ns1.example.com."]),
        }
        domain_answers = {
            ("ns1.example.com", "A"): _make_a_answer(["10.0.0.53"]),
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(
            answers, domain_answers=domain_answers
        )

        # Mock the AXFR to succeed (from_xfr returns a zone object).
        mock_zone = MagicMock()
        with patch(
            "expose.collectors.builtin.active_dns._dns_zone.from_xfr",
            return_value=mock_zone,
        ), patch(
            "expose.collectors.builtin.active_dns._dns_query.xfr",
            return_value=MagicMock(),
        ):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        axfr_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "AXFR"
        ]
        assert len(axfr_obs) == 1
        obs = axfr_obs[0]
        assert obs.structured_payload["axfr_allowed"] is True
        assert obs.structured_payload["severity"] == "critical"
        assert "dns-zone-transfer" in obs.structured_payload["note"]

    async def test_axfr_no_nameservers_no_observation(self) -> None:
        """Without NS records, no AXFR attempt is made."""
        answers = {"A": _make_a_answer(["93.184.216.34"])}
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        axfr_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "AXFR"
        ]
        assert axfr_obs == []

    async def test_axfr_ns_resolve_failure_no_observation(self) -> None:
        """If NS hostname cannot be resolved, no AXFR observation is emitted."""
        answers = {
            "A": _make_a_answer(["93.184.216.34"]),
            "NS": _make_ns_answer(["ns1.example.com."]),
        }
        domain_answers = {
            ("ns1.example.com", "A"): _dns_resolver.NXDOMAIN,
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(
            answers, domain_answers=domain_answers
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        axfr_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "AXFR"
        ]
        assert axfr_obs == []

    async def test_axfr_timeout_no_observation(self) -> None:
        """AXFR timeout is swallowed (non-fatal) — no observation."""
        answers = {
            "A": _make_a_answer(["93.184.216.34"]),
            "NS": _make_ns_answer(["ns1.example.com."]),
        }
        domain_answers = {
            ("ns1.example.com", "A"): _make_a_answer(["10.0.0.53"]),
        }
        collector = ActiveDnsCollector(_config())
        collector._resolver = _mock_resolver_factory(
            answers, domain_answers=domain_answers
        )

        # Mock AXFR to raise a timeout.
        with patch(
            "expose.collectors.builtin.active_dns._dns_zone.from_xfr",
            side_effect=TimeoutError("mock timeout"),
        ), patch(
            "expose.collectors.builtin.active_dns._dns_query.xfr",
            return_value=MagicMock(),
        ):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        axfr_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "AXFR"
        ]
        assert axfr_obs == []


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestActiveDnsRegistration:
    """Verify the collector registers correctly in the default registry."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("active-dns-resolve")
        cls = DEFAULT_REGISTRY.get("active-dns-resolve")
        assert cls is ActiveDnsCollector

    def test_metadata_correct(self) -> None:
        assert ActiveDnsCollector.collector_id == "active-dns-resolve"
        assert ActiveDnsCollector.collector_version == "0.2.0"
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

        a_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "A"
        ]
        assert len(a_obs) == 1
        assert a_obs[0].structured_payload["values"] == ["93.184.216.34"]

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

        a_obs = [
            o for o in observations
            if o.structured_payload.get("record_type") == "A"
        ]
        assert len(a_obs) == 1
        assert a_obs[0].structured_payload["record_type"] == "A"

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

    async def test_egress_profile_port_and_source(self) -> None:
        """Egress profile that returns port and source kwargs."""
        mock_profile = MagicMock(spec=EgressProfile)
        mock_profile.profile_type = EgressProfileType.SOCKS5
        mock_profile.configure_dns_resolver.return_value = {
            "nameservers": ["10.0.0.53"],
            "port": 5353,
            "source": "10.0.0.1",
        }

        cfg = _config_with_egress(egress_profile=mock_profile)
        collector = ActiveDnsCollector(cfg)

        assert collector._resolver.nameservers == ["10.0.0.53"]
        assert collector._resolver.port == 5353
        assert collector._resolver.source == "10.0.0.1"

    async def test_egress_profile_empty_nameservers_dns_through_proxy(self) -> None:
        """SOCKS5h/Tor profiles return empty nameservers list (dns-through-proxy)."""
        mock_profile = MagicMock(spec=EgressProfile)
        mock_profile.profile_type = EgressProfileType.SOCKS5
        mock_profile.configure_dns_resolver.return_value = {
            "nameservers": [],
        }

        cfg = _config_with_egress(egress_profile=mock_profile)
        collector = ActiveDnsCollector(cfg)

        assert collector._resolver.nameservers == []

    async def test_egress_profile_empty_dict_passthrough(self) -> None:
        """Profiles like WireGuard that return {} leave resolver untouched."""
        mock_profile = MagicMock(spec=EgressProfile)
        mock_profile.profile_type = EgressProfileType.WIREGUARD
        mock_profile.configure_dns_resolver.return_value = {}

        cfg = _config_with_egress(egress_profile=mock_profile)
        collector = ActiveDnsCollector(cfg)

        # nameservers should remain whatever the real Resolver default is
        # (not overridden). We just verify configure_dns_resolver was called.
        mock_profile.configure_dns_resolver.assert_called_once()

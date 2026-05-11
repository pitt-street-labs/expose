"""Tests for the sip-discovery collector.

Exercises all code paths with a fully mocked DNS resolver -- no live DNS
queries are ever issued. The mock strategy replaces the ``_resolver``
attribute after construction so that ``SipDiscoveryCollector`` uses our
mock instead of a real resolver.

Coverage:
    1.  Domain with SIP SRV records -> observations emitted
    2.  Domain with no SIP records -> no observations, no errors
    3.  Domain with NAPTR records containing SIP URIs
    4.  Multiple SRV record types found
    5.  DNS query failure -> graceful degradation
    6.  Health check success and failure paths
    7.  Non-domain seed is skipped
    8.  dnspython not available -> CollectorError
    9.  Collector metadata and registration
   10.  NAPTR with non-SIP service -> skipped
   11.  Health check without dnspython
   12.  SRV query timeout -> graceful skip
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import dns.asyncresolver as _dns_ar
import dns.name as _dns_name
import dns.resolver as _dns_resolver
import pytest

from expose.collectors.base import (
    CollectorConfig,
    CollectorError,
    CollectorHealthCheck,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.sip_discovery import (
    HAS_DNSPYTHON,
    SipDiscoveryCollector,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

# Suppress DeprecationWarnings from dnspython internals if present.
pytestmark = [
    pytest.mark.filterwarnings("default::DeprecationWarning"),
]

# Synthetic IDs reused across tests (matches project conventions).
TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000F001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000F002")


def _config() -> CollectorConfig:
    """Build a minimal CollectorConfig for test use."""
    return CollectorConfig(tenant_id=TENANT_ID, run_id=RUN_ID)


# === Mock helpers =============================================================


def _make_srv_answer(
    records: list[tuple[str, int, int, int]],
) -> MagicMock:
    """Build a mock DNS answer for SRV records.

    Each tuple is (target, port, priority, weight).
    """
    rrs = []
    for target, port, priority, weight in records:
        rr = MagicMock()
        rr.target = MagicMock()
        rr.target.__str__ = lambda self, _t=target: _t
        rr.port = port
        rr.priority = priority
        rr.weight = weight
        rrs.append(rr)
    answer = MagicMock()
    answer.__iter__ = lambda self: iter(rrs)
    return answer


def _make_naptr_answer(
    records: list[dict[str, Any]],
) -> MagicMock:
    """Build a mock DNS answer for NAPTR records.

    Each dict should have keys: service, flags, replacement, regexp,
    order, preference.
    """
    rrs = []
    for rec in records:
        rr = MagicMock()
        rr.service = rec.get("service", "")
        rr.flags = rec.get("flags", "")
        rr.replacement = MagicMock()
        rr.replacement.__str__ = lambda self, _r=rec.get("replacement", "."): _r
        rr.regexp = rec.get("regexp", "")
        rr.order = rec.get("order", 100)
        rr.preference = rec.get("preference", 10)
        rrs.append(rr)
    answer = MagicMock()
    answer.__iter__ = lambda self: iter(rrs)
    return answer


def _mock_resolver_factory(
    answers: dict[str, Any] | None = None,
) -> MagicMock:
    """Create a mock Resolver whose ``resolve`` returns preconfigured answers.

    ``answers`` maps query names (e.g., ``_sip._tcp.example.com`` or
    ``example.com``) plus record-type to either a mock answer object or
    an exception to raise. The key format is ``{qname}:{rdtype}``
    (e.g., ``_sip._tcp.example.com:SRV``).
    """
    resolver = MagicMock()
    resolver.lifetime = 30.0

    async def _resolve(
        qname: str,
        rdtype: str,
        **kwargs: Any,
    ) -> Any:
        if answers is None:
            raise _dns_resolver.NoAnswer
        key = f"{qname}:{rdtype}"
        entry = answers.get(key)
        if entry is None:
            raise _dns_resolver.NoAnswer
        if isinstance(entry, type) and issubclass(entry, BaseException):
            raise entry()
        if isinstance(entry, BaseException):
            raise entry
        return entry

    resolver.resolve = AsyncMock(side_effect=_resolve)
    return resolver


# === Tests ====================================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestSipSrvDiscovery:
    """Test 1: Domain with SIP SRV records emits observations."""

    async def test_sip_tcp_srv_emits_observation(self) -> None:
        answers = {
            "_sip._tcp.example.com:SRV": _make_srv_answer(
                [("sip-server.example.com.", 5060, 10, 100)]
            ),
        }
        collector = SipDiscoveryCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations: list[Observation] = [
            obs async for obs in collector.expand(seed)
        ]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.collector_id == "sip-discovery"
        assert obs.observation_type == ObservationType.DNS_RECORD
        assert obs.subject.identifier_type == ExtendedIdentifierType.DOMAIN
        assert obs.subject.identifier_value == "sip-server.example.com"
        payload = obs.structured_payload
        assert payload["source"] == "dns_srv"
        assert payload["service"] == "_sip._tcp"
        assert payload["target"] == "sip-server.example.com"
        assert payload["port"] == 5060
        assert payload["priority"] == 10
        assert payload["weight"] == 100
        assert payload["protocol"] == "sip"
        assert payload["seed_domain"] == "example.com"
        assert obs.tenant_id == TENANT_ID


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestSipNoRecords:
    """Test 2: Domain with no SIP records -> no observations, no errors."""

    async def test_no_records_emits_nothing(self) -> None:
        # Empty answers dict -> all queries raise NoAnswer.
        collector = SipDiscoveryCollector(_config())
        collector._resolver = _mock_resolver_factory({})

        seed = Seed(seed_type=SeedType.DOMAIN, value="nosip.example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestSipNaptrRecords:
    """Test 3: Domain with NAPTR records containing SIP URIs."""

    async def test_naptr_sip_service_emits_observation(self) -> None:
        answers = {
            "example.com:NAPTR": _make_naptr_answer([
                {
                    "service": "SIP+D2T",
                    "flags": "s",
                    "replacement": "sip-proxy.example.com.",
                    "regexp": "",
                    "order": 100,
                    "preference": 10,
                },
            ]),
        }
        collector = SipDiscoveryCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.observation_type == ObservationType.DNS_RECORD
        assert obs.subject.identifier_value == "sip-proxy.example.com"
        payload = obs.structured_payload
        assert payload["source"] == "dns_naptr"
        assert payload["extracted_domain"] == "sip-proxy.example.com"
        assert payload["seed_domain"] == "example.com"

    async def test_naptr_regexp_sip_uri_extracted(self) -> None:
        """NAPTR regexp field containing a SIP URI -> domain extracted."""
        answers = {
            "example.com:NAPTR": _make_naptr_answer([
                {
                    "service": "E2U+sip",
                    "flags": "u",
                    "replacement": ".",
                    "regexp": "!^.*$!sip:info@voip.example.com!",
                    "order": 100,
                    "preference": 10,
                },
            ]),
        }
        collector = SipDiscoveryCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.subject.identifier_value == "voip.example.com"
        assert obs.structured_payload["extracted_domain"] == "voip.example.com"


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestSipMultipleSrvTypes:
    """Test 4: Multiple SRV record types found."""

    async def test_multiple_srv_types_emitted(self) -> None:
        answers = {
            "_sip._tcp.cyberark.com:SRV": _make_srv_answer(
                [("sip-server.cyberark.com.", 5060, 10, 100)]
            ),
            "_sips._tcp.cyberark.com:SRV": _make_srv_answer(
                [("sips-server.cyberark.com.", 5061, 10, 100)]
            ),
            "_sip._udp.cyberark.com:SRV": _make_srv_answer(
                [("sip-udp.cyberark.com.", 5060, 20, 50)]
            ),
            "_stun._udp.cyberark.com:SRV": _make_srv_answer(
                [("stun.cyberark.com.", 3478, 10, 100)]
            ),
        }
        collector = SipDiscoveryCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="cyberark.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 4
        services = {obs.structured_payload["service"] for obs in observations}
        assert services == {"_sip._tcp", "_sips._tcp", "_sip._udp", "_stun._udp"}

        protocols = {obs.structured_payload["protocol"] for obs in observations}
        assert protocols == {"sip", "sips", "stun"}

        targets = {obs.subject.identifier_value for obs in observations}
        assert "sip-server.cyberark.com" in targets
        assert "sips-server.cyberark.com" in targets
        assert "sip-udp.cyberark.com" in targets
        assert "stun.cyberark.com" in targets

    async def test_multiple_records_per_srv(self) -> None:
        """A single SRV query returning multiple records."""
        answers = {
            "_sip._tcp.example.com:SRV": _make_srv_answer([
                ("primary.sip.example.com.", 5060, 10, 100),
                ("backup.sip.example.com.", 5060, 20, 50),
            ]),
        }
        collector = SipDiscoveryCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 2
        targets = {obs.subject.identifier_value for obs in observations}
        assert targets == {"primary.sip.example.com", "backup.sip.example.com"}

        # Verify priority ordering is captured.
        by_target = {
            obs.subject.identifier_value: obs for obs in observations
        }
        assert by_target["primary.sip.example.com"].structured_payload["priority"] == 10
        assert by_target["backup.sip.example.com"].structured_payload["priority"] == 20


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestSipDnsFailure:
    """Test 5: DNS query failure -> graceful degradation."""

    async def test_nxdomain_emits_nothing(self) -> None:
        """NXDOMAIN on all queries produces no observations."""
        resolver = MagicMock()
        resolver.lifetime = 30.0
        resolver.resolve = AsyncMock(side_effect=_dns_resolver.NXDOMAIN)

        collector = SipDiscoveryCollector(_config())
        collector._resolver = resolver

        seed = Seed(seed_type=SeedType.DOMAIN, value="nonexistent.invalid")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []

    async def test_unexpected_exception_skipped(self) -> None:
        """Unexpected exception on a SRV query is logged and skipped."""
        resolver = MagicMock()
        resolver.lifetime = 30.0
        resolver.resolve = AsyncMock(
            side_effect=OSError("network unreachable")
        )

        collector = SipDiscoveryCollector(_config())
        collector._resolver = resolver

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        # All queries fail gracefully, no exceptions raised.
        assert observations == []

    async def test_partial_failure_emits_successful_queries(self) -> None:
        """If some SRV queries succeed and others fail, successful ones emit."""
        answers = {
            "_sip._tcp.example.com:SRV": _make_srv_answer(
                [("sip.example.com.", 5060, 10, 100)]
            ),
            # _sips._tcp will get NoAnswer (not in dict).
            # _sip._udp will get NoAnswer (not in dict).
            # etc.
        }
        collector = SipDiscoveryCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        assert observations[0].subject.identifier_value == "sip.example.com"


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestSipHealthCheck:
    """Test 6: Health check success and failure paths."""

    async def test_health_check_success_with_nxdomain(self) -> None:
        """NXDOMAIN on SRV health-check query means resolver is working."""
        resolver = MagicMock()
        resolver.lifetime = 30.0
        resolver.resolve = AsyncMock(side_effect=_dns_resolver.NXDOMAIN)

        collector = SipDiscoveryCollector(_config())
        collector._resolver = resolver

        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "sip-discovery"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    async def test_health_check_success_with_noanswer(self) -> None:
        """NoAnswer on SRV health-check query means resolver is working."""
        resolver = MagicMock()
        resolver.lifetime = 30.0
        resolver.resolve = AsyncMock(side_effect=_dns_resolver.NoAnswer)

        collector = SipDiscoveryCollector(_config())
        collector._resolver = resolver

        result = await collector.health_check()

        assert result.status == CollectorStatus.SUCCESS

    async def test_health_check_success_with_nonameservers(self) -> None:
        """NoNameservers on SRV health-check query means resolver is working."""
        resolver = MagicMock()
        resolver.lifetime = 30.0
        resolver.resolve = AsyncMock(side_effect=_dns_resolver.NoNameservers)

        collector = SipDiscoveryCollector(_config())
        collector._resolver = resolver

        result = await collector.health_check()

        assert result.status == CollectorStatus.SUCCESS

    async def test_health_check_failure_on_timeout(self) -> None:
        """Timeout on health-check query means resolver is broken."""
        resolver = MagicMock()
        resolver.lifetime = 30.0
        resolver.resolve = AsyncMock(
            side_effect=_dns_resolver.LifetimeTimeout
        )

        collector = SipDiscoveryCollector(_config())
        collector._resolver = resolver

        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    async def test_health_check_failure_on_network_error(self) -> None:
        """Network error on health-check query means resolver is broken."""
        resolver = MagicMock()
        resolver.lifetime = 30.0
        resolver.resolve = AsyncMock(
            side_effect=OSError("network unreachable")
        )

        collector = SipDiscoveryCollector(_config())
        collector._resolver = resolver

        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert "network unreachable" in (result.error_message or "")


class TestSipNonDomainSeed:
    """Test 7: Non-domain seeds are silently skipped."""

    async def test_ip_seed_skipped(self) -> None:
        collector = SipDiscoveryCollector(_config())

        seed = Seed(seed_type=SeedType.IP, value="10.0.0.1")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []

    async def test_organization_seed_skipped(self) -> None:
        collector = SipDiscoveryCollector(_config())

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="ACME Corp")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []

    async def test_asn_seed_skipped(self) -> None:
        collector = SipDiscoveryCollector(_config())

        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []


class TestSipMissingDnspython:
    """Test 8: CollectorError when dnspython is not available."""

    async def test_expand_raises_collector_error(self) -> None:
        with patch(
            "expose.collectors.builtin.sip_discovery.HAS_DNSPYTHON", False
        ):
            collector = SipDiscoveryCollector(_config())
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            with pytest.raises(CollectorError, match="dnspython not installed"):
                _ = [obs async for obs in collector.expand(seed)]


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestSipMetadataAndRegistration:
    """Test 9: Collector metadata and registration in default registry."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("sip-discovery")
        cls = DEFAULT_REGISTRY.get("sip-discovery")
        assert cls is SipDiscoveryCollector

    def test_metadata_correct(self) -> None:
        assert SipDiscoveryCollector.collector_id == "sip-discovery"
        assert SipDiscoveryCollector.collector_version == "0.1.0"
        assert SipDiscoveryCollector.tier == CollectorTier.TIER_1
        assert SipDiscoveryCollector.requires_credentials is False


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestSipNaptrNonSipSkipped:
    """Test 10: NAPTR with non-SIP service -> skipped."""

    async def test_non_sip_naptr_skipped(self) -> None:
        """NAPTR records for non-SIP services (e.g., http) are ignored."""
        answers = {
            "example.com:NAPTR": _make_naptr_answer([
                {
                    "service": "http+I2L+I2C+I2R",
                    "flags": "u",
                    "replacement": "www.example.com.",
                    "regexp": "!^.*$!http://www.example.com!",
                    "order": 100,
                    "preference": 10,
                },
            ]),
        }
        collector = SipDiscoveryCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []


class TestSipHealthCheckWithoutDnspython:
    """Test 11: Health check without dnspython returns FAILURE."""

    async def test_health_check_without_dnspython(self) -> None:
        with patch(
            "expose.collectors.builtin.sip_discovery.HAS_DNSPYTHON", False
        ):
            collector = SipDiscoveryCollector(_config())
            result = await collector.health_check()

            assert result.status == CollectorStatus.FAILURE
            assert "dnspython not installed" in (result.error_message or "")


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestSipSrvTimeout:
    """Test 12: SRV query timeout -> graceful skip."""

    async def test_timeout_skips_gracefully(self) -> None:
        """LifetimeTimeout on SRV query is logged and skipped."""
        resolver = MagicMock()
        resolver.lifetime = 30.0
        resolver.resolve = AsyncMock(
            side_effect=_dns_resolver.LifetimeTimeout
        )

        collector = SipDiscoveryCollector(_config())
        collector._resolver = resolver

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        # Should not raise -- timeouts are handled gracefully.
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestSipSrvAndNaptrCombined:
    """Combined SRV + NAPTR results in a single expansion."""

    async def test_srv_and_naptr_both_emitted(self) -> None:
        """Both SRV and NAPTR observations appear in a single expansion."""
        answers = {
            "_sip._tcp.example.com:SRV": _make_srv_answer(
                [("sip-server.example.com.", 5060, 10, 100)]
            ),
            "example.com:NAPTR": _make_naptr_answer([
                {
                    "service": "SIP+D2U",
                    "flags": "s",
                    "replacement": "sip-proxy.example.com.",
                    "regexp": "",
                    "order": 100,
                    "preference": 10,
                },
            ]),
        }
        collector = SipDiscoveryCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 2
        sources = {obs.structured_payload["source"] for obs in observations}
        assert sources == {"dns_srv", "dns_naptr"}

        targets = {obs.subject.identifier_value for obs in observations}
        assert "sip-server.example.com" in targets
        assert "sip-proxy.example.com" in targets


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestSipH323AndTurn:
    """H.323 and TURN SRV record discovery."""

    async def test_h323_srv_emits_observation(self) -> None:
        answers = {
            "_h323cs._tcp.example.com:SRV": _make_srv_answer(
                [("h323-gw.example.com.", 1720, 10, 100)]
            ),
        }
        collector = SipDiscoveryCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["protocol"] == "h323"
        assert obs.structured_payload["port"] == 1720
        assert obs.subject.identifier_value == "h323-gw.example.com"

    async def test_turn_srv_emits_observation(self) -> None:
        answers = {
            "_turn._udp.example.com:SRV": _make_srv_answer(
                [("turn.example.com.", 3478, 10, 100)]
            ),
        }
        collector = SipDiscoveryCollector(_config())
        collector._resolver = _mock_resolver_factory(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["protocol"] == "turn"
        assert obs.structured_payload["port"] == 3478
        assert obs.subject.identifier_value == "turn.example.com"

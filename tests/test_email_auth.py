"""Tests for the spf-dkim-dmarc email authentication policy collector.

Exercises all code paths with a fully mocked DNS resolver -- no live DNS
queries are ever issued.

Coverage:
    1. Happy path -- domain with SPF + DKIM + DMARC records
    2. Domain with no email auth records -- has_spf/dkim/dmarc = False
    3. SPF includes extraction -- verify third-party SaaS detection
    4. DKIM selector discovery -- only found selectors reported
    5. DMARC policy parsing -- reject/quarantine/none
    6. Non-domain seed skipped
    7. DNS resolution failure -- CollectorSourceUnreachableError for timeout,
       skips NXDOMAIN
    8. Health check success and failure
    9. dnspython not installed -- CollectorError raised
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
from expose.collectors.builtin.email_auth import (
    HAS_DNSPYTHON,
    EmailAuthCollector,
    _parse_dmarc,
    _parse_spf,
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


def _make_txt_answer(values: list[str]) -> MagicMock:
    """Build a mock DNS answer for TXT records.

    Each string in ``values`` becomes one RR with a single chunk in
    ``rr.strings``. The answer supports both iteration (for SPF scanning)
    and ``answer[0]`` access (for single-record queries like DKIM/DMARC).
    """
    records = []
    for v in values:
        rr = MagicMock()
        rr.strings = [v.encode("utf-8")]
        records.append(rr)
    answer = MagicMock()
    answer.__iter__ = lambda self: iter(records)
    answer.__getitem__ = lambda self, idx: records[idx]
    return answer


def _make_a_answer(ips: list[str], ttl: int = 300) -> MagicMock:
    """Build a mock DNS answer for A records (used in health check)."""
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


class _MockResolver:
    """Configurable mock resolver for email auth tests.

    Supports per-query-name answer configuration so we can independently
    control SPF (domain TXT), DKIM ({selector}._domainkey.{domain} TXT),
    and DMARC (_dmarc.{domain} TXT) responses.
    """

    def __init__(
        self,
        answers: dict[str, Any] | None = None,
    ) -> None:
        self.lifetime = 30.0
        self._answers = answers or {}

    async def resolve(
        self,
        name: str,
        rdtype: str,
        **kwargs: Any,
    ) -> Any:
        entry = self._answers.get(name)
        if entry is None:
            raise _dns_ar.NoAnswer
        if isinstance(entry, type) and issubclass(entry, BaseException):
            raise entry()
        if isinstance(entry, BaseException):
            raise entry
        return entry


# === Tests ====================================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestEmailAuthHappyPath:
    """Test 1: Happy path -- domain with SPF + DKIM + DMARC records."""

    async def test_full_email_auth_observation(self) -> None:
        spf_txt = "v=spf1 include:_spf.google.com include:sendgrid.net ~all"
        dkim_google_txt = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3..."
        dmarc_txt = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"

        answers = {
            "example.com": _make_txt_answer([spf_txt]),
            "google._domainkey.example.com": _make_txt_answer(
                [dkim_google_txt]
            ),
            "_dmarc.example.com": _make_txt_answer([dmarc_txt]),
        }

        collector = EmailAuthCollector(_config())
        collector._resolver = _MockResolver(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations: list[Observation] = [
            obs async for obs in collector.expand(seed)
        ]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.collector_id == "spf-dkim-dmarc"
        assert obs.observation_type == ObservationType.DNS_RECORD
        assert obs.subject.identifier_type == ExtendedIdentifierType.DOMAIN
        assert obs.subject.identifier_value == "example.com"
        assert obs.tenant_id == TENANT_ID

        p = obs.structured_payload
        assert p["record_type"] == "email_auth_policy"
        assert p["has_spf"] is True
        assert p["has_dkim"] is True
        assert p["has_dmarc"] is True
        assert "v=spf1" in p["spf_record"]
        assert "_spf.google.com" in p["spf_includes"]
        assert "sendgrid.net" in p["spf_includes"]
        assert "google" in p["dkim_selectors_found"]
        assert "google" in p["dkim_records"]
        assert p["dmarc_policy"] == "reject"
        assert p["dmarc_rua"] == "dmarc@example.com"


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestEmailAuthNoRecords:
    """Test 2: Domain with no email auth records."""

    async def test_no_records_yields_false_flags(self) -> None:
        # Empty answers dict -- every query raises NoAnswer.
        collector = EmailAuthCollector(_config())
        collector._resolver = _MockResolver({})

        seed = Seed(seed_type=SeedType.DOMAIN, value="noemail.example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        p = observations[0].structured_payload
        assert p["has_spf"] is False
        assert p["has_dkim"] is False
        assert p["has_dmarc"] is False
        assert "spf_record" not in p
        assert p["dkim_selectors_found"] == []
        assert p["dkim_records"] == {}


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestEmailAuthSpfIncludes:
    """Test 3: SPF includes extraction -- third-party SaaS detection."""

    async def test_spf_includes_detected(self) -> None:
        spf_txt = (
            "v=spf1 include:_spf.google.com "
            "include:spf.protection.outlook.com "
            "include:servers.mcsv.net "
            "include:sendgrid.net ~all"
        )
        answers = {
            "corp.example.com": _make_txt_answer([spf_txt]),
        }

        collector = EmailAuthCollector(_config())
        collector._resolver = _MockResolver(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="corp.example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        p = observations[0].structured_payload
        assert p["has_spf"] is True
        includes = p["spf_includes"]
        assert "_spf.google.com" in includes
        assert "spf.protection.outlook.com" in includes
        assert "servers.mcsv.net" in includes
        assert "sendgrid.net" in includes
        # Mechanisms include everything after v=spf1
        mechs = p["spf_mechanisms"]
        assert "~all" in mechs
        assert "include:_spf.google.com" in mechs

    async def test_spf_no_includes(self) -> None:
        """SPF record with no includes still parses correctly."""
        spf_txt = "v=spf1 ip4:192.0.2.0/24 -all"
        answers = {
            "bare.example.com": _make_txt_answer([spf_txt]),
        }

        collector = EmailAuthCollector(_config())
        collector._resolver = _MockResolver(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="bare.example.com")
        observations = [obs async for obs in collector.expand(seed)]

        p = observations[0].structured_payload
        assert p["has_spf"] is True
        assert p["spf_includes"] == []
        assert "ip4:192.0.2.0/24" in p["spf_mechanisms"]
        assert "-all" in p["spf_mechanisms"]


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestEmailAuthDkimDiscovery:
    """Test 4: DKIM selector discovery -- only found selectors reported."""

    async def test_multiple_dkim_selectors_found(self) -> None:
        dkim_google = "v=DKIM1; k=rsa; p=MIGfGoogleKey..."
        dkim_s1 = "v=DKIM1; k=rsa; p=MIGfS1Key..."

        answers = {
            "multi.example.com": _make_txt_answer(
                ["v=spf1 -all"]
            ),
            "google._domainkey.multi.example.com": _make_txt_answer(
                [dkim_google]
            ),
            "s1._domainkey.multi.example.com": _make_txt_answer([dkim_s1]),
            # Other selectors are not configured, will raise NoAnswer.
        }

        collector = EmailAuthCollector(_config())
        collector._resolver = _MockResolver(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="multi.example.com")
        observations = [obs async for obs in collector.expand(seed)]

        p = observations[0].structured_payload
        assert p["has_dkim"] is True
        assert sorted(p["dkim_selectors_found"]) == ["google", "s1"]
        assert "google" in p["dkim_records"]
        assert "s1" in p["dkim_records"]
        # Selectors that were not found should not appear.
        assert "selector1" not in p["dkim_selectors_found"]
        assert "default" not in p["dkim_selectors_found"]

    async def test_no_dkim_selectors_found(self) -> None:
        """When no selectors return DKIM records, has_dkim is False."""
        answers = {
            "nodkim.example.com": _make_txt_answer(["v=spf1 -all"]),
        }

        collector = EmailAuthCollector(_config())
        collector._resolver = _MockResolver(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="nodkim.example.com")
        observations = [obs async for obs in collector.expand(seed)]

        p = observations[0].structured_payload
        assert p["has_dkim"] is False
        assert p["dkim_selectors_found"] == []
        assert p["dkim_records"] == {}

    async def test_txt_without_dkim1_marker_is_ignored(self) -> None:
        """A TXT record at a selector that does NOT contain DKIM1 is skipped."""
        answers = {
            "marker.example.com": _make_txt_answer(["v=spf1 -all"]),
            "google._domainkey.marker.example.com": _make_txt_answer(
                ["some random txt record"]
            ),
        }

        collector = EmailAuthCollector(_config())
        collector._resolver = _MockResolver(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="marker.example.com")
        observations = [obs async for obs in collector.expand(seed)]

        p = observations[0].structured_payload
        assert p["has_dkim"] is False
        assert p["dkim_selectors_found"] == []


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestEmailAuthDmarcParsing:
    """Test 5: DMARC policy parsing -- reject/quarantine/none."""

    @pytest.mark.parametrize(
        "policy_value",
        ["reject", "quarantine", "none"],
    )
    async def test_dmarc_policies(self, policy_value: str) -> None:
        dmarc_txt = f"v=DMARC1; p={policy_value}; rua=mailto:reports@example.com"
        answers = {
            "policy.example.com": _make_txt_answer(["v=spf1 -all"]),
            "_dmarc.policy.example.com": _make_txt_answer([dmarc_txt]),
        }

        collector = EmailAuthCollector(_config())
        collector._resolver = _MockResolver(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="policy.example.com")
        observations = [obs async for obs in collector.expand(seed)]

        p = observations[0].structured_payload
        assert p["has_dmarc"] is True
        assert p["dmarc_policy"] == policy_value
        assert p["dmarc_rua"] == "reports@example.com"

    async def test_dmarc_without_rua(self) -> None:
        """DMARC record without rua tag still parses policy."""
        dmarc_txt = "v=DMARC1; p=none"
        answers = {
            "norua.example.com": _make_txt_answer(["v=spf1 -all"]),
            "_dmarc.norua.example.com": _make_txt_answer([dmarc_txt]),
        }

        collector = EmailAuthCollector(_config())
        collector._resolver = _MockResolver(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="norua.example.com")
        observations = [obs async for obs in collector.expand(seed)]

        p = observations[0].structured_payload
        assert p["has_dmarc"] is True
        assert p["dmarc_policy"] == "none"
        assert p["dmarc_rua"] is None


class TestEmailAuthNonDomainSeed:
    """Test 6: Non-domain seeds are silently skipped."""

    async def test_ip_seed_skipped(self) -> None:
        collector = EmailAuthCollector(_config())

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_organization_seed_skipped(self) -> None:
        collector = EmailAuthCollector(_config())

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="ACME Corp")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_cidr_seed_skipped(self) -> None:
        collector = EmailAuthCollector(_config())

        seed = Seed(seed_type=SeedType.CIDR, value="192.0.2.0/24")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestEmailAuthDnsFailure:
    """Test 7: DNS resolution failure handling."""

    async def test_timeout_raises_source_unreachable(self) -> None:
        """LifetimeTimeout on the SPF TXT query raises the error."""
        collector = EmailAuthCollector(_config())
        resolver = MagicMock()
        resolver.lifetime = 30.0
        resolver.resolve = AsyncMock(
            side_effect=_dns_resolver.LifetimeTimeout
        )
        collector._resolver = resolver

        seed = Seed(seed_type=SeedType.DOMAIN, value="slow.example.com")
        with pytest.raises(CollectorSourceUnreachableError):
            _ = [obs async for obs in collector.expand(seed)]

    async def test_nxdomain_on_spf_yields_observation(self) -> None:
        """NXDOMAIN on the domain TXT query does not raise -- just no SPF."""
        answers = {
            "gone.example.com": _dns_resolver.NXDOMAIN(),
        }

        collector = EmailAuthCollector(_config())
        collector._resolver = _MockResolver(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="gone.example.com")
        observations = [obs async for obs in collector.expand(seed)]

        # Should still emit an observation with has_spf=False.
        assert len(observations) == 1
        p = observations[0].structured_payload
        assert p["has_spf"] is False

    async def test_timeout_on_dkim_raises(self) -> None:
        """LifetimeTimeout on a DKIM selector query raises the error."""
        answers: dict[str, Any] = {
            "timeout.example.com": _make_txt_answer(["v=spf1 -all"]),
            "default._domainkey.timeout.example.com": _dns_resolver.LifetimeTimeout(),
        }

        collector = EmailAuthCollector(_config())
        collector._resolver = _MockResolver(answers)

        seed = Seed(seed_type=SeedType.DOMAIN, value="timeout.example.com")
        with pytest.raises(CollectorSourceUnreachableError):
            _ = [obs async for obs in collector.expand(seed)]


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestEmailAuthHealthCheck:
    """Test 8: Health check success and failure."""

    async def test_health_check_success(self) -> None:
        collector = EmailAuthCollector(_config())
        collector._resolver = _MockResolver(
            {"dns.google": _make_a_answer(["8.8.8.8"])}
        )

        result = await collector.health_check()
        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "spf-dkim-dmarc"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    async def test_health_check_failure(self) -> None:
        collector = EmailAuthCollector(_config())
        resolver = MagicMock()
        resolver.lifetime = 30.0
        resolver.resolve = AsyncMock(
            side_effect=_dns_resolver.LifetimeTimeout
        )
        collector._resolver = resolver

        result = await collector.health_check()
        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    async def test_health_check_without_dnspython(self) -> None:
        with patch(
            "expose.collectors.builtin.email_auth.HAS_DNSPYTHON", False
        ):
            collector = EmailAuthCollector(_config())
            result = await collector.health_check()
            assert result.status == CollectorStatus.FAILURE
            assert "dnspython not installed" in (result.error_message or "")


class TestEmailAuthMissingDnspython:
    """Test 9: CollectorError when dnspython is not available."""

    async def test_expand_raises_collector_error(self) -> None:
        with patch(
            "expose.collectors.builtin.email_auth.HAS_DNSPYTHON", False
        ):
            collector = EmailAuthCollector(_config())
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            with pytest.raises(CollectorError, match="dnspython not installed"):
                _ = [obs async for obs in collector.expand(seed)]


# === Registration tests ======================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestEmailAuthRegistration:
    """Verify the collector registers correctly in the default registry."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("spf-dkim-dmarc")
        cls = DEFAULT_REGISTRY.get("spf-dkim-dmarc")
        assert cls is EmailAuthCollector

    def test_metadata_correct(self) -> None:
        assert EmailAuthCollector.collector_id == "spf-dkim-dmarc"
        assert EmailAuthCollector.collector_version == "0.1.0"
        assert EmailAuthCollector.tier == CollectorTier.TIER_1
        assert EmailAuthCollector.requires_credentials is False


# === Unit tests for parsing helpers ==========================================


class TestParseSpf:
    """Unit tests for the _parse_spf helper."""

    def test_basic_spf(self) -> None:
        result = _parse_spf(
            "v=spf1 include:_spf.google.com include:sendgrid.net ~all"
        )
        assert result["includes"] == ["_spf.google.com", "sendgrid.net"]
        assert result["mechanisms"] == [
            "include:_spf.google.com",
            "include:sendgrid.net",
            "~all",
        ]

    def test_spf_no_includes(self) -> None:
        result = _parse_spf("v=spf1 ip4:192.0.2.0/24 -all")
        assert result["includes"] == []
        assert "ip4:192.0.2.0/24" in result["mechanisms"]

    def test_spf_with_redirect(self) -> None:
        result = _parse_spf("v=spf1 redirect=_spf.example.com")
        assert result["includes"] == []
        assert "redirect=_spf.example.com" in result["mechanisms"]


class TestParseDmarc:
    """Unit tests for the _parse_dmarc helper."""

    def test_full_dmarc(self) -> None:
        result = _parse_dmarc(
            "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
        )
        assert result["policy"] == "reject"
        assert result["rua"] == "dmarc@example.com"

    def test_dmarc_quarantine(self) -> None:
        result = _parse_dmarc("v=DMARC1; p=quarantine")
        assert result["policy"] == "quarantine"
        assert result["rua"] is None

    def test_dmarc_none(self) -> None:
        result = _parse_dmarc("v=DMARC1; p=none; rua=mailto:rua@test.com")
        assert result["policy"] == "none"
        assert result["rua"] == "rua@test.com"

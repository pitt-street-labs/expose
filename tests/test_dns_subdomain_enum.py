"""Tests for the dns-subdomain-enum collector.

Exercises all code paths with a fully mocked DNS resolver -- no live DNS
queries are ever issued. The mock strategy patches the resolver instance
directly on the collector so that ``SubdomainEnumCollector`` uses our
controlled responses.

Coverage:
    1.  Collector ID and tier correct
    2.  Only expands DOMAIN seeds
    3.  Mock DNS resolution produces observations with resolved IPs
    4.  Wildcard detection filters false positives
    5.  CNAME chain following
    6.  DNS timeout is skipped (not error)
    7.  NXDOMAIN is skipped
    8.  Rate limiting (semaphore respects max concurrent)
    9.  Empty wordlist produces no observations
   10.  Wordlist loading skips comments and blank lines
   11.  Wildcard detection failure (probe itself times out) proceeds normally
   12.  Mixed A + AAAA resolution
   13.  CNAME-only record (no A) still emits observation
   14.  Health check success and failure paths
   15.  Health check without dnspython
   16.  dnspython not available: CollectorError raised
   17.  Collector registration in default registry
   18.  Duplicate wordlist entries are deduplicated
   19.  Wildcard partial match is NOT filtered (only exact subset)
   20.  Custom wordlist path via config.extra
"""

from __future__ import annotations

import asyncio
import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

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
from expose.collectors.builtin.dns_subdomain_enum import (
    HAS_DNSPYTHON,
    SubdomainEnumCollector,
    load_wordlist,
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


def _config(**extra: Any) -> CollectorConfig:
    """Build a minimal CollectorConfig for test use."""
    return CollectorConfig(tenant_id=TENANT_ID, run_id=RUN_ID, extra=dict(extra))


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
    answer.rrset = MagicMock()
    answer.rrset.ttl = 300
    return answer


def _build_resolver_for_subdomains(
    responses: dict[str, dict[str, Any]],
    wildcard_response: Any = None,
) -> MagicMock:
    """Create a mock Resolver for subdomain enumeration tests.

    ``responses`` maps FQDN -> {rdtype -> answer_or_exception}.
    ``wildcard_response`` controls the wildcard probe response.
    If None, the wildcard probe raises NXDOMAIN.
    """
    resolver = MagicMock()
    resolver.lifetime = 30.0

    async def _resolve(domain: str, rdtype: str, **kwargs: Any) -> Any:
        # Wildcard probe detection (contains our probe prefix).
        if "expose-wildcard-probe" in domain:
            if wildcard_response is None:
                raise _dns_resolver.NXDOMAIN()
            if isinstance(wildcard_response, type) and issubclass(wildcard_response, BaseException):
                raise wildcard_response()
            if isinstance(wildcard_response, BaseException):
                raise wildcard_response
            return wildcard_response

        fqdn_responses = responses.get(domain, {})
        entry = fqdn_responses.get(rdtype)
        if entry is None:
            raise _dns_resolver.NXDOMAIN()
        if isinstance(entry, type) and issubclass(entry, BaseException):
            raise entry()
        if isinstance(entry, BaseException):
            raise entry
        return entry

    resolver.resolve = AsyncMock(side_effect=_resolve)
    return resolver


def _write_wordlist(tmp_path: Path, words: list[str]) -> Path:
    """Write a wordlist file and return its path."""
    wl = tmp_path / "test-wordlist.txt"
    wl.write_text("\n".join(words) + "\n", encoding="utf-8")
    return wl


# === Tests ====================================================================


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestCollectorMetadata:
    """Test 1: Collector ID and tier correct."""

    def test_collector_id(self) -> None:
        assert SubdomainEnumCollector.collector_id == "dns-subdomain-enum"

    def test_collector_version(self) -> None:
        assert SubdomainEnumCollector.collector_version == "0.1.0"

    def test_tier(self) -> None:
        assert SubdomainEnumCollector.tier == CollectorTier.TIER_3

    def test_requires_credentials(self) -> None:
        assert SubdomainEnumCollector.requires_credentials is False


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestNonDomainSeeds:
    """Test 2: Only expands DOMAIN seeds."""

    async def test_ip_seed_skipped(self, tmp_path: Path) -> None:
        wl = _write_wordlist(tmp_path, ["www", "mail"])
        collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_organization_seed_skipped(self, tmp_path: Path) -> None:
        wl = _write_wordlist(tmp_path, ["www", "mail"])
        collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="ACME Corp")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_asn_seed_skipped(self, tmp_path: Path) -> None:
        wl = _write_wordlist(tmp_path, ["www", "mail"])
        collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))

        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_cidr_seed_skipped(self, tmp_path: Path) -> None:
        wl = _write_wordlist(tmp_path, ["www", "mail"])
        collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))

        seed = Seed(seed_type=SeedType.CIDR, value="10.0.0.0/8")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestBasicResolution:
    """Test 3: Mock DNS resolution produces observations with resolved IPs."""

    async def test_single_subdomain_resolved(self, tmp_path: Path) -> None:
        wl = _write_wordlist(tmp_path, ["www"])
        responses = {
            "www.example.com": {
                "A": _make_a_answer(["93.184.216.34"], ttl=300),
            },
        }
        collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))
        collector._resolver = _build_resolver_for_subdomains(responses)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.collector_id == "dns-subdomain-enum"
        assert obs.observation_type == ObservationType.DNS_RESOLUTION
        assert obs.subject.identifier_type == ExtendedIdentifierType.DOMAIN
        assert obs.subject.identifier_value == "www.example.com"
        assert obs.structured_payload["subdomain"] == "www.example.com"
        assert obs.structured_payload["resolved_ips"] == ["93.184.216.34"]
        assert obs.structured_payload["ttl"] == 300
        assert obs.tenant_id == TENANT_ID

    async def test_multiple_subdomains_resolved(self, tmp_path: Path) -> None:
        wl = _write_wordlist(tmp_path, ["www", "mail", "api"])
        responses = {
            "www.example.com": {
                "A": _make_a_answer(["93.184.216.34"]),
            },
            "mail.example.com": {
                "A": _make_a_answer(["93.184.216.35"]),
            },
            # api.example.com does NOT resolve -- should be skipped.
        }
        collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))
        collector._resolver = _build_resolver_for_subdomains(responses)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 2
        subdomains = {obs.structured_payload["subdomain"] for obs in observations}
        assert subdomains == {"www.example.com", "mail.example.com"}


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestWildcardDetection:
    """Test 4: Wildcard detection filters false positives."""

    async def test_wildcard_filters_matching_ips(self, tmp_path: Path) -> None:
        wl = _write_wordlist(tmp_path, ["www", "mail", "real"])
        wildcard_ips = _make_a_answer(["10.0.0.1"])
        responses = {
            # www resolves to wildcard IP -- should be filtered.
            "www.example.com": {
                "A": _make_a_answer(["10.0.0.1"]),
            },
            # mail resolves to wildcard IP -- should be filtered.
            "mail.example.com": {
                "A": _make_a_answer(["10.0.0.1"]),
            },
            # real resolves to a different IP -- should NOT be filtered.
            "real.example.com": {
                "A": _make_a_answer(["93.184.216.34"]),
            },
        }
        collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))
        collector._resolver = _build_resolver_for_subdomains(
            responses, wildcard_response=wildcard_ips
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        assert observations[0].structured_payload["subdomain"] == "real.example.com"


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestCnameChain:
    """Test 5: CNAME chain following."""

    async def test_cname_chain_included_in_observation(self, tmp_path: Path) -> None:
        wl = _write_wordlist(tmp_path, ["cdn"])
        responses = {
            "cdn.example.com": {
                "CNAME": _make_cname_answer("cdn.cloudfront.net."),
                "A": _make_a_answer(["54.230.10.1"]),
            },
        }
        collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))
        collector._resolver = _build_resolver_for_subdomains(responses)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["cname_chain"] == ["cdn.cloudfront.net"]
        assert obs.structured_payload["resolved_ips"] == ["54.230.10.1"]


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestDnsTimeout:
    """Test 6: DNS timeout is skipped (not error)."""

    async def test_timeout_skips_subdomain(self, tmp_path: Path) -> None:
        """A subdomain that times out is silently skipped."""
        wl = _write_wordlist(tmp_path, ["slow", "fast"])
        responses = {
            "slow.example.com": {
                "A": _dns_resolver.LifetimeTimeout(),
                "CNAME": _dns_resolver.LifetimeTimeout(),
            },
            "fast.example.com": {
                "A": _make_a_answer(["93.184.216.34"]),
            },
        }
        collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))
        collector._resolver = _build_resolver_for_subdomains(responses)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        assert observations[0].structured_payload["subdomain"] == "fast.example.com"


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestNxdomain:
    """Test 7: NXDOMAIN is skipped."""

    async def test_nxdomain_skips_subdomain(self, tmp_path: Path) -> None:
        wl = _write_wordlist(tmp_path, ["nonexistent", "exists"])
        responses = {
            # nonexistent.example.com raises NXDOMAIN (default).
            "exists.example.com": {
                "A": _make_a_answer(["93.184.216.34"]),
            },
        }
        collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))
        collector._resolver = _build_resolver_for_subdomains(responses)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        assert observations[0].structured_payload["subdomain"] == "exists.example.com"


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestRateLimiting:
    """Test 8: Rate limiting (semaphore respects max concurrent)."""

    async def test_semaphore_limits_concurrency(self, tmp_path: Path) -> None:
        """Verify that at most max_concurrent queries run simultaneously."""
        wl = _write_wordlist(tmp_path, [f"sub{i}" for i in range(20)])
        max_concurrent = 5
        peak_concurrent = 0
        current_concurrent = 0
        lock = asyncio.Lock()

        # Build a resolver that tracks concurrency.
        resolver = MagicMock()
        resolver.lifetime = 30.0

        async def _tracking_resolve(domain: str, rdtype: str, **kwargs: Any) -> Any:
            nonlocal peak_concurrent, current_concurrent

            if "expose-wildcard-probe" in domain:
                raise _dns_resolver.NXDOMAIN()

            async with lock:
                current_concurrent += 1
                peak_concurrent = max(peak_concurrent, current_concurrent)

            # Simulate network latency.
            await asyncio.sleep(0.01)

            async with lock:
                current_concurrent -= 1

            if rdtype == "A":
                return _make_a_answer(["10.0.0.1"])
            raise _dns_resolver.NXDOMAIN()

        resolver.resolve = AsyncMock(side_effect=_tracking_resolve)

        collector = SubdomainEnumCollector(
            _config(wordlist_path=str(wl), max_concurrent=max_concurrent)
        )
        collector._resolver = resolver

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        _ = [obs async for obs in collector.expand(seed)]

        # Peak concurrency should not exceed max_concurrent.
        assert peak_concurrent <= max_concurrent


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestEmptyWordlist:
    """Test 9: Empty wordlist produces no observations."""

    async def test_empty_wordlist_no_observations(self, tmp_path: Path) -> None:
        wl = _write_wordlist(tmp_path, [])
        collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []

    async def test_missing_wordlist_no_observations(self, tmp_path: Path) -> None:
        """A nonexistent wordlist path produces no observations."""
        missing = tmp_path / "does-not-exist.txt"
        collector = SubdomainEnumCollector(_config(wordlist_path=str(missing)))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []


class TestWordlistLoading:
    """Test 10: Wordlist loading skips comments and blank lines."""

    def test_comments_and_blanks_skipped(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            # This is a comment
            www

            # Another comment
            mail

            api
        """)
        wl = tmp_path / "wl.txt"
        wl.write_text(content, encoding="utf-8")

        words = load_wordlist(wl)
        assert words == ["www", "mail", "api"]

    def test_whitespace_stripped(self, tmp_path: Path) -> None:
        content = "  www  \n  mail  \n  api  \n"
        wl = tmp_path / "wl.txt"
        wl.write_text(content, encoding="utf-8")

        words = load_wordlist(wl)
        assert words == ["www", "mail", "api"]


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestWildcardProbeFailure:
    """Test 11: Wildcard detection failure proceeds normally."""

    async def test_wildcard_probe_timeout_still_enumerates(self, tmp_path: Path) -> None:
        """If the wildcard probe itself times out, enumeration proceeds."""
        wl = _write_wordlist(tmp_path, ["www"])
        responses = {
            "www.example.com": {
                "A": _make_a_answer(["93.184.216.34"]),
            },
        }
        # Wildcard probe raises LifetimeTimeout.
        collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))
        collector._resolver = _build_resolver_for_subdomains(
            responses, wildcard_response=_dns_resolver.LifetimeTimeout()
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        assert observations[0].structured_payload["subdomain"] == "www.example.com"


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestMixedAddressResolution:
    """Test 12: Mixed A + AAAA resolution."""

    async def test_both_a_and_aaaa_collected(self, tmp_path: Path) -> None:
        wl = _write_wordlist(tmp_path, ["dual"])
        responses = {
            "dual.example.com": {
                "A": _make_a_answer(["93.184.216.34"]),
                "AAAA": _make_a_answer(["2001:db8::1"]),
            },
        }
        collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))
        collector._resolver = _build_resolver_for_subdomains(responses)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        ips = observations[0].structured_payload["resolved_ips"]
        assert "93.184.216.34" in ips
        assert "2001:db8::1" in ips


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestCnameOnly:
    """Test 13: CNAME-only record (no A) still emits observation."""

    async def test_cname_only_emits_observation(self, tmp_path: Path) -> None:
        wl = _write_wordlist(tmp_path, ["alias"])
        responses = {
            "alias.example.com": {
                "CNAME": _make_cname_answer("target.cdn.net."),
                # A raises NXDOMAIN (default in resolver mock).
            },
        }
        collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))
        collector._resolver = _build_resolver_for_subdomains(responses)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["cname_chain"] == ["target.cdn.net"]
        assert obs.structured_payload["resolved_ips"] == []


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestHealthCheck:
    """Test 14: Health check success and failure paths."""

    async def test_health_check_success(self) -> None:
        collector = SubdomainEnumCollector(_config())
        resolver = MagicMock()
        resolver.lifetime = 30.0
        resolver.resolve = AsyncMock(return_value=_make_a_answer(["8.8.8.8"]))
        collector._resolver = resolver

        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "dns-subdomain-enum"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    async def test_health_check_failure(self) -> None:
        collector = SubdomainEnumCollector(_config())
        resolver = MagicMock()
        resolver.lifetime = 30.0
        resolver.resolve = AsyncMock(side_effect=_dns_resolver.LifetimeTimeout)
        collector._resolver = resolver

        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None


class TestHealthCheckWithoutDnspython:
    """Test 15: Health check without dnspython."""

    async def test_health_check_without_dnspython(self) -> None:
        with patch("expose.collectors.builtin.dns_subdomain_enum.HAS_DNSPYTHON", False):
            collector = SubdomainEnumCollector(_config())
            result = await collector.health_check()

            assert result.status == CollectorStatus.FAILURE
            assert "dnspython not installed" in (result.error_message or "")


class TestMissingDnspython:
    """Test 16: CollectorError when dnspython is not available."""

    async def test_expand_raises_collector_error(self, tmp_path: Path) -> None:
        wl = _write_wordlist(tmp_path, ["www"])
        with patch("expose.collectors.builtin.dns_subdomain_enum.HAS_DNSPYTHON", False):
            collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            with pytest.raises(CollectorError, match="dnspython not installed"):
                _ = [obs async for obs in collector.expand(seed)]


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestRegistration:
    """Test 17: Collector registration in default registry."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("dns-subdomain-enum")
        cls = DEFAULT_REGISTRY.get("dns-subdomain-enum")
        assert cls is SubdomainEnumCollector


class TestWordlistDeduplication:
    """Test 18: Duplicate wordlist entries are deduplicated."""

    def test_duplicates_removed(self, tmp_path: Path) -> None:
        wl = _write_wordlist(tmp_path, ["www", "www", "mail", "WWW", "Mail"])
        words = load_wordlist(wl)
        assert words == ["www", "mail"]


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestWildcardPartialMatch:
    """Test 19: Wildcard partial match is NOT filtered."""

    async def test_superset_of_wildcard_not_filtered(self, tmp_path: Path) -> None:
        """A subdomain whose IPs are a superset of wildcard IPs passes through."""
        wl = _write_wordlist(tmp_path, ["multi"])
        wildcard_ips = _make_a_answer(["10.0.0.1"])
        responses = {
            # multi resolves to wildcard IP + an extra IP.
            "multi.example.com": {
                "A": _make_a_answer(["10.0.0.1", "93.184.216.34"]),
            },
        }
        collector = SubdomainEnumCollector(_config(wordlist_path=str(wl)))
        collector._resolver = _build_resolver_for_subdomains(
            responses, wildcard_response=wildcard_ips
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        # Should NOT be filtered because the resolved IPs are a superset
        # of the wildcard IPs, not a subset.
        assert len(observations) == 1
        assert observations[0].structured_payload["subdomain"] == "multi.example.com"


@pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
class TestCustomWordlistPath:
    """Test 20: Custom wordlist path via config.extra."""

    async def test_custom_wordlist_used(self, tmp_path: Path) -> None:
        custom_wl = tmp_path / "custom.txt"
        custom_wl.write_text("custom-sub\n", encoding="utf-8")

        responses = {
            "custom-sub.example.com": {
                "A": _make_a_answer(["10.0.0.42"]),
            },
        }
        collector = SubdomainEnumCollector(_config(wordlist_path=str(custom_wl)))
        collector._resolver = _build_resolver_for_subdomains(responses)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        assert observations[0].structured_payload["subdomain"] == "custom-sub.example.com"
        assert observations[0].structured_payload["resolved_ips"] == ["10.0.0.42"]

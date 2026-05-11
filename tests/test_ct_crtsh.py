"""Tests for the ct-crtsh Certificate Transparency collector.

Uses respx to mock all HTTP interactions — NO live network calls.
Fixtures in tests/fixtures/collectors/ct_crtsh/ provide canned crt.sh
JSON responses.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch
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
from expose.collectors.builtin.ct_crtsh import (
    CrtShCollector,
    _CACHE_TTL_SECONDS,
    _domain_cache,
    _org_cache,
    clear_crt_sh_cache,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000ca01")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000ca02")

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "collectors" / "ct_crtsh"


@pytest.fixture(autouse=True)
def _clear_crtsh_cache() -> None:
    """Clear crt.sh response cache before each test to prevent leakage."""
    clear_crt_sh_cache()


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


def _make_seed(domain: str = "example.com") -> Seed:
    return Seed(seed_type=SeedType.DOMAIN, value=domain)


async def _collect_all(collector: CrtShCollector, seed: Seed) -> list[Observation]:
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


class TestCrtShCollectorMetadata:
    """Verify class-level metadata attributes."""

    def test_collector_id(self) -> None:
        assert CrtShCollector.collector_id == "ct-crtsh"

    def test_collector_version(self) -> None:
        assert CrtShCollector.collector_version == "0.1.0"

    def test_tier(self) -> None:
        assert CrtShCollector.tier == CollectorTier.TIER_1

    def test_requires_credentials(self) -> None:
        assert CrtShCollector.requires_credentials is False


class TestCrtShExpandHappyPath:
    """Test 1: domain seed returns CT entries, observations emitted correctly."""

    @respx.mock
    async def test_happy_path_yields_observations(self) -> None:
        fixture = _load_fixture("happy_path.json")
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        assert len(results) == 2

    @respx.mock
    async def test_observation_fields(self) -> None:
        fixture = _load_fixture("happy_path.json")
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        obs = results[0]
        assert obs.collector_id == "ct-crtsh"
        assert obs.collector_version == "0.1.0"
        assert obs.tenant_id == TENANT_ID
        assert obs.observation_type == ObservationType.CT_LOG_ENTRY
        assert obs.subject.identifier_type == ExtendedIdentifierType.CERTIFICATE_FINGERPRINT
        assert obs.subject.identifier_value == "03a1b2c3d4e5f60718293a4b5c6d7e8f"

    @respx.mock
    async def test_structured_payload_keys(self) -> None:
        fixture = _load_fixture("happy_path.json")
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        payload = results[0].structured_payload
        expected_keys = {"issuer_name", "common_name", "sans", "not_before", "not_after",
                         "serial_number"}
        assert set(payload.keys()) == expected_keys

    @respx.mock
    async def test_sans_parsed_from_newlines(self) -> None:
        fixture = _load_fixture("happy_path.json")
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        first_sans = results[0].structured_payload["sans"]
        assert len(first_sans) == 2
        assert "example.com" in first_sans
        assert "www.example.com" in first_sans

        second_sans = results[1].structured_payload["sans"]
        assert len(second_sans) == 1
        assert "api.example.com" in second_sans


class TestCrtShExpandEmptyResult:
    """Test 2: domain with no certs returns no observations."""

    @respx.mock
    async def test_empty_json_array(self) -> None:
        fixture = _load_fixture("empty_result.json")
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        results = await _collect_all(collector, _make_seed("no-certs.example.com"))

        assert results == []


class TestCrtShExpandNonDomainSeed:
    """Test 3: unsupported seed types are skipped."""

    @respx.mock
    async def test_ip_seed_yields_nothing(self) -> None:
        collector = CrtShCollector(_make_config())
        seed = Seed(seed_type=SeedType.IP, value="192.0.2.1")
        results = await _collect_all(collector, seed)
        assert results == []

    @respx.mock
    async def test_asn_seed_yields_nothing(self) -> None:
        collector = CrtShCollector(_make_config())
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        results = await _collect_all(collector, seed)
        assert results == []


class TestCrtShExpandNetworkError:
    """Test 4: network errors raise CollectorSourceUnreachableError."""

    @respx.mock
    async def test_connection_error_raises(self) -> None:
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        collector = CrtShCollector(_make_config())
        with pytest.raises(CollectorSourceUnreachableError, match="unreachable"):
            await _collect_all(collector, _make_seed())

    @respx.mock
    async def test_timeout_raises(self) -> None:
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            side_effect=httpx.ReadTimeout("read timed out"),
        )

        collector = CrtShCollector(_make_config())
        with pytest.raises(CollectorSourceUnreachableError, match="unreachable"):
            await _collect_all(collector, _make_seed())

    @respx.mock
    async def test_http_500_raises(self) -> None:
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(500, text="Internal Server Error"),
        )

        collector = CrtShCollector(_make_config())
        with pytest.raises(CollectorSourceUnreachableError, match="500"):
            await _collect_all(collector, _make_seed())

    @respx.mock
    async def test_http_429_raises(self) -> None:
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(429, text="Too Many Requests"),
        )

        collector = CrtShCollector(_make_config())
        with pytest.raises(CollectorSourceUnreachableError, match="429"):
            await _collect_all(collector, _make_seed())


class TestCrtShExpandMalformedResponse:
    """Test 5: malformed JSON raises CollectorSourceUnreachableError."""

    @respx.mock
    async def test_not_json_raises(self) -> None:
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text="<html>not json</html>"),
        )

        collector = CrtShCollector(_make_config())
        with pytest.raises(CollectorSourceUnreachableError, match="malformed JSON"):
            await _collect_all(collector, _make_seed())

    @respx.mock
    async def test_json_object_instead_of_array_raises(self) -> None:
        fixture = _load_fixture("malformed.json")
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        with pytest.raises(CollectorSourceUnreachableError, match="instead of JSON array"):
            await _collect_all(collector, _make_seed())


class TestCrtShExpandDeduplication:
    """Test 6: duplicate serial numbers are deduplicated."""

    @respx.mock
    async def test_dedup_by_serial(self) -> None:
        fixture = _load_fixture("duplicates.json")
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        assert len(results) == 2

        serials = [r.subject.identifier_value for r in results]
        assert len(set(serials)) == 2
        assert "aabbccdd00112233aabbccdd00112233" in serials
        assert "11223344556677889900aabbccddeeff" in serials


class TestCrtShExpandSanitization:
    """Test 7: long/malicious SANs are sanitized and capped."""

    @respx.mock
    async def test_long_san_is_capped(self) -> None:
        fixture = _load_fixture("long_sans.json")
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        assert len(results) == 1
        sans = results[0].structured_payload["sans"]
        for san in sans:
            assert len(san.encode("utf-8")) <= 255

    @respx.mock
    async def test_html_in_san_is_preserved_but_flagged(self) -> None:
        entry_data = [
            {
                "issuer_ca_id": 16418,
                "issuer_name": "C=US, O=Test CA",
                "common_name": "test.example.com",
                "name_value": "<script>alert(1)</script>.example.com",
                "id": 7777777777,
                "entry_timestamp": "2025-05-01T00:00:00.000",
                "not_before": "2025-05-01T00:00:00",
                "not_after": "2025-08-01T00:00:00",
                "serial_number": "cafe0000cafe0000cafe0000cafe0000",
            }
        ]
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=json.dumps(entry_data)),
        )

        collector = CrtShCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        assert len(results) == 1
        assert results[0].warnings


class TestCrtShHealthCheck:
    """Test 8: health check returns appropriate status."""

    @respx.mock
    async def test_healthy_returns_success(self) -> None:
        respx.head("https://crt.sh/").mock(
            return_value=httpx.Response(200),
        )

        collector = CrtShCollector(_make_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "ct-crtsh"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    async def test_unhealthy_returns_failure(self) -> None:
        respx.head("https://crt.sh/").mock(
            return_value=httpx.Response(503, text="Service Unavailable"),
        )

        collector = CrtShCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "503" in result.error_message

    @respx.mock
    async def test_network_error_returns_failure(self) -> None:
        respx.head("https://crt.sh/").mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        collector = CrtShCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "unreachable" in result.error_message


class TestCrtShExpandOrganization:
    """Test 9: organization seed queries crt.sh by org name."""

    @respx.mock
    async def test_org_search_yields_domain_observations(self) -> None:
        """Org-name search extracts unique domains from cert SANs/CNs."""
        fixture = _load_fixture("org_search.json")
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        results = await _collect_all(collector, seed)

        # Should extract: acmecorp.com, mail.acmecorp.com,
        # vpn.acme-legacy.net, remote.acme-legacy.net
        # (wildcard *.internal.acmecorp.com is excluded)
        assert len(results) >= 4
        domains = {r.subject.identifier_value for r in results}
        assert "mail.acmecorp.com" in domains
        assert "acmecorp.com" in domains
        assert "vpn.acme-legacy.net" in domains
        assert "remote.acme-legacy.net" in domains

    @respx.mock
    async def test_org_search_excludes_wildcards(self) -> None:
        """Wildcard SANs (*.domain.com) are excluded from org search results."""
        fixture = _load_fixture("org_search.json")
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        results = await _collect_all(collector, seed)

        domains = {r.subject.identifier_value for r in results}
        for domain in domains:
            assert not domain.startswith("*"), f"Wildcard domain found: {domain}"

    @respx.mock
    async def test_org_search_observation_type(self) -> None:
        """Org search observations are CT_LOG_ENTRY type."""
        fixture = _load_fixture("org_search.json")
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        results = await _collect_all(collector, seed)

        for obs in results:
            assert obs.observation_type == ObservationType.CT_LOG_ENTRY

    @respx.mock
    async def test_org_search_payload_fields(self) -> None:
        """Org search observations have discovery_method and organization."""
        fixture = _load_fixture("org_search.json")
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        results = await _collect_all(collector, seed)

        assert len(results) > 0
        payload = results[0].structured_payload
        assert payload["discovery_method"] == "ct_org_search"
        assert payload["organization"] == "Acme Corp"
        assert "domain" in payload
        assert "source_entry_count" in payload

    @respx.mock
    async def test_org_search_empty_name_skipped(self) -> None:
        """Empty organization name returns nothing (no API call)."""
        collector = CrtShCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="  ")
        results = await _collect_all(collector, seed)
        assert results == []

    @respx.mock
    async def test_org_search_empty_result(self) -> None:
        """crt.sh returns empty array for org -> no observations."""
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text="[]"),
        )

        collector = CrtShCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Nonexistent Corp")
        results = await _collect_all(collector, seed)
        assert results == []

    @respx.mock
    async def test_org_search_404_returns_empty(self) -> None:
        """crt.sh 404 for org search -> valid empty result."""
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(404),
        )

        collector = CrtShCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Unknown Org")
        results = await _collect_all(collector, seed)
        assert results == []

    @respx.mock
    async def test_org_search_500_raises(self) -> None:
        """crt.sh 500 for org search -> CollectorSourceUnreachableError."""
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(500, text="Internal Server Error"),
        )

        collector = CrtShCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        with pytest.raises(CollectorSourceUnreachableError, match="500"):
            await _collect_all(collector, seed)

    @respx.mock
    async def test_org_search_connection_error_raises(self) -> None:
        """Connection error on org search -> CollectorSourceUnreachableError."""
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        collector = CrtShCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        with pytest.raises(CollectorSourceUnreachableError, match="unreachable"):
            await _collect_all(collector, seed)


class TestCrtShResponseCache:
    """Test 10: in-memory TTL cache for crt.sh responses."""

    @respx.mock
    async def test_domain_cache_hit_skips_network(self) -> None:
        """Second call for same domain returns cached data, no HTTP request."""
        fixture = _load_fixture("happy_path.json")
        route = respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        seed = _make_seed("cached-example.com")

        # First call — hits the network.
        results1 = await _collect_all(collector, seed)
        assert len(results1) == 2
        assert route.call_count == 1

        # Second call — should serve from cache without network.
        results2 = await _collect_all(collector, seed)
        assert len(results2) == 2
        assert route.call_count == 1  # No additional HTTP call.

    @respx.mock
    async def test_domain_cache_different_domains_not_shared(self) -> None:
        """Cache is keyed per domain — different domains make separate calls."""
        fixture = _load_fixture("happy_path.json")
        route = respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())

        await _collect_all(collector, _make_seed("domain-a.com"))
        await _collect_all(collector, _make_seed("domain-b.com"))
        assert route.call_count == 2

    @respx.mock
    async def test_domain_cache_expired_refetches(self) -> None:
        """Expired cache entries cause a fresh network fetch."""
        fixture = _load_fixture("happy_path.json")
        route = respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        seed = _make_seed("expiry-test.com")

        # First call populates cache.
        await _collect_all(collector, seed)
        assert route.call_count == 1

        # Simulate time passing beyond TTL by manipulating the cache timestamp.
        domain = "expiry-test.com"
        if domain in _domain_cache:
            _, data = _domain_cache[domain]
            _domain_cache[domain] = (time.monotonic() - _CACHE_TTL_SECONDS - 1, data)

        # Second call — cache expired, should refetch.
        await _collect_all(collector, seed)
        assert route.call_count == 2

    @respx.mock
    async def test_org_cache_hit_skips_network(self) -> None:
        """Organization search also caches responses."""
        fixture = _load_fixture("org_search.json")
        route = respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Cache Test Corp")

        results1 = await _collect_all(collector, seed)
        assert len(results1) > 0
        assert route.call_count == 1

        results2 = await _collect_all(collector, seed)
        assert len(results2) == len(results1)
        assert route.call_count == 1  # No second call.

    @respx.mock
    async def test_error_responses_not_cached(self) -> None:
        """Failed requests should not populate the cache."""
        route = respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(500, text="Internal Server Error"),
        )

        collector = CrtShCollector(_make_config())
        seed = _make_seed("error-test.com")

        with pytest.raises(CollectorSourceUnreachableError):
            await _collect_all(collector, seed)

        # Cache should be empty — errors are not cached.
        assert "error-test.com" not in _domain_cache

    def test_clear_cache_function(self) -> None:
        """clear_crt_sh_cache empties both domain and org caches."""
        _domain_cache["test.com"] = (time.monotonic(), [])
        _org_cache["Test Corp"] = (time.monotonic(), [])

        clear_crt_sh_cache()

        assert len(_domain_cache) == 0
        assert len(_org_cache) == 0

    @respx.mock
    async def test_cached_results_match_fresh_results(self) -> None:
        """Cached results produce identical observations to fresh results."""
        fixture = _load_fixture("happy_path.json")
        respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
            return_value=httpx.Response(200, text=fixture),
        )

        collector = CrtShCollector(_make_config())
        seed = _make_seed("match-test.com")

        results1 = await _collect_all(collector, seed)
        results2 = await _collect_all(collector, seed)

        assert len(results1) == len(results2)
        for r1, r2 in zip(results1, results2):
            assert r1.subject.identifier_value == r2.subject.identifier_value
            assert r1.structured_payload["serial_number"] == r2.structured_payload["serial_number"]
            assert r1.structured_payload["sans"] == r2.structured_payload["sans"]


class TestCrtShRegistration:
    """Verify the collector is registered in the default registry."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("ct-crtsh")
        cls = DEFAULT_REGISTRY.get("ct-crtsh")
        assert cls is CrtShCollector

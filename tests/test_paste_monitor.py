"""Tests for the paste-monitor collector (Tier 2, issue #79).

Exercises GitHub code search and entity extraction via ``respx`` mocks --
no live network calls. Coverage:

1.  Collector metadata: ID, tier, version, rate limit, requires_credentials
2.  Only expands DOMAIN and ORGANIZATION seeds (others return [])
3.  Happy path: domain seed -> code search -> IPs and domains extracted
4.  Happy path: organization seed works similarly
5.  Empty/whitespace seed value skipped
6.  No results: empty observations
7.  HTTP errors: graceful degradation
8.  Rate limit (403) raises CollectorRateLimitError
9.  Malformed JSON handled gracefully
10. Multiple leak queries issued (extension:env, extension:conf, etc.)
11. IP extraction from text_matches fragments
12. Domain/hostname extraction from text_matches fragments
13. Ignored IPs filtered (127.0.0.1, 0.0.0.0)
14. Health check: success and failure paths
15. API key usage in headers
"""

from __future__ import annotations

from uuid import UUID

import httpx
import pytest
import respx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorCredential,
    CollectorHealthCheck,
    CollectorRateLimitError,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.paste_monitor import (
    PasteMonitorCollector,
    _extract_entities_from_fragments,
)
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-0000000c0d01")
RUN_ID = UUID("018f1f00-0000-7000-8000-0000000c0d02")

_GITHUB_SEARCH_CODE = "https://api.github.com/search/code"
_GITHUB_ZEN = "https://api.github.com/zen"


def _config(api_key: str | None = None) -> CollectorConfig:
    creds: dict[str, CollectorCredential] = {}
    if api_key:
        creds["api_key"] = CollectorCredential(
            name="api_key", secret_value=api_key
        )
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=5.0,
        credentials=creds,
    )


async def _collect(
    seed: Seed, api_key: str | None = None
) -> list[Observation]:
    cfg = _config(api_key=api_key)
    collector = PasteMonitorCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# === Canned GitHub API responses =============================================

_CODE_SEARCH_WITH_MATCHES = {
    "total_count": 2,
    "items": [
        {
            "repository": {"full_name": "someone/leaked-configs"},
            "path": ".env",
            "html_url": "https://github.com/someone/leaked-configs/blob/main/.env",
            "text_matches": [
                {
                    "fragment": "DB_HOST=10.0.1.50\nAPI_URL=https://api.acme.com/v1\n",
                },
            ],
        },
        {
            "repository": {"full_name": "another/project"},
            "path": "config.yml",
            "html_url": "https://github.com/another/project/blob/main/config.yml",
            "text_matches": [
                {
                    "fragment": "server: staging.acme.com\nbackup: 192.168.1.100\n",
                },
            ],
        },
    ],
}

_CODE_SEARCH_EMPTY = {"total_count": 0, "items": []}

_CODE_SEARCH_IGNORED_IPS = {
    "total_count": 1,
    "items": [
        {
            "repository": {"full_name": "test/repo"},
            "path": ".env",
            "html_url": "https://github.com/test/repo/blob/main/.env",
            "text_matches": [
                {
                    "fragment": "HOST=127.0.0.1\nLISTEN=0.0.0.0\n",
                },
            ],
        },
    ],
}

_CODE_SEARCH_NO_TEXT_MATCHES = {
    "total_count": 1,
    "items": [
        {
            "repository": {"full_name": "test/repo"},
            "path": ".env",
            "html_url": "https://github.com/test/repo/blob/main/.env",
        },
    ],
}


# ======================================================================
# 1. Collector metadata
# ======================================================================
class TestCollectorMetadata:
    def test_collector_id(self) -> None:
        assert PasteMonitorCollector.collector_id == "paste-monitor"

    def test_collector_version(self) -> None:
        assert PasteMonitorCollector.collector_version == "0.1.0"

    def test_tier_is_tier_2(self) -> None:
        assert PasteMonitorCollector.tier == CollectorTier.TIER_2

    def test_no_credentials_required(self) -> None:
        assert PasteMonitorCollector.requires_credentials is False

    def test_rate_limit(self) -> None:
        assert PasteMonitorCollector.rate_limit_per_minute == 10

    def test_is_subclass_of_collector(self) -> None:
        assert issubclass(PasteMonitorCollector, Collector)


# ======================================================================
# 2. Seed type filtering
# ======================================================================
class TestSeedTypeFiltering:
    @pytest.mark.asyncio
    async def test_ip_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.IP, value="192.0.2.1")
        observations = await _collect(seed)
        assert observations == []

    @pytest.mark.asyncio
    async def test_cidr_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.CIDR, value="192.0.2.0/24")
        observations = await _collect(seed)
        assert observations == []

    @pytest.mark.asyncio
    async def test_asn_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        observations = await _collect(seed)
        assert observations == []

    @pytest.mark.asyncio
    async def test_empty_domain_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.DOMAIN, value="  ")
        observations = await _collect(seed)
        assert observations == []

    @pytest.mark.asyncio
    async def test_empty_org_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="  ")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 3. Happy path — DOMAIN seed
# ======================================================================
class TestDomainHappyPath:
    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_seed_extracts_ips_and_domains(self) -> None:
        """DOMAIN seed -> code search -> IPs and subdomains extracted."""
        respx.get(_GITHUB_SEARCH_CODE).mock(
            return_value=httpx.Response(200, json=_CODE_SEARCH_WITH_MATCHES)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)

        ip_obs = [
            o for o in observations if o.subject.identifier_type == IdentifierType.IP
        ]
        domain_obs = [
            o
            for o in observations
            if o.subject.identifier_type == IdentifierType.DOMAIN
        ]

        ip_values = {o.subject.identifier_value for o in ip_obs}
        domain_values = {o.subject.identifier_value for o in domain_obs}

        # 10.0.1.50 and 192.168.1.100 from fragments.
        assert "10.0.1.50" in ip_values
        assert "192.168.1.100" in ip_values

        # api.acme.com and staging.acme.com from fragments.
        assert "api.acme.com" in domain_values
        assert "staging.acme.com" in domain_values

    @respx.mock
    @pytest.mark.asyncio
    async def test_observation_types(self) -> None:
        """IP observations are SCANNER_HOST, domain observations are PASSIVE_DNS."""
        respx.get(_GITHUB_SEARCH_CODE).mock(
            return_value=httpx.Response(200, json=_CODE_SEARCH_WITH_MATCHES)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)

        for obs in observations:
            if obs.subject.identifier_type == IdentifierType.IP:
                assert obs.observation_type == ObservationType.SCANNER_HOST
            elif obs.subject.identifier_type == IdentifierType.DOMAIN:
                assert obs.observation_type == ObservationType.PASSIVE_DNS

    @respx.mock
    @pytest.mark.asyncio
    async def test_structured_payload_shape(self) -> None:
        """Structured payload has expected keys."""
        respx.get(_GITHUB_SEARCH_CODE).mock(
            return_value=httpx.Response(200, json=_CODE_SEARCH_WITH_MATCHES)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)

        for obs in observations:
            payload = obs.structured_payload
            assert payload["source"] == "github_code_leak"
            assert "search_value" in payload
            assert "entity_type" in payload
            assert "source_repos" in payload


# ======================================================================
# 4. Happy path — ORGANIZATION seed
# ======================================================================
class TestOrgSeed:
    @respx.mock
    @pytest.mark.asyncio
    async def test_org_seed_works(self) -> None:
        """ORGANIZATION seed triggers code search too."""
        respx.get(_GITHUB_SEARCH_CODE).mock(
            return_value=httpx.Response(200, json=_CODE_SEARCH_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="AcmeCorp")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 5. No results
# ======================================================================
class TestNoResults:
    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_search_returns_empty(self) -> None:
        """No code matches -> no observations."""
        respx.get(_GITHUB_SEARCH_CODE).mock(
            return_value=httpx.Response(200, json=_CODE_SEARCH_EMPTY)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="nonexistent.example")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_text_matches_returns_empty(self) -> None:
        """Code results without text_matches -> no entities extracted."""
        respx.get(_GITHUB_SEARCH_CODE).mock(
            return_value=httpx.Response(200, json=_CODE_SEARCH_NO_TEXT_MATCHES)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 6. HTTP errors
# ======================================================================
class TestHTTPErrors:
    @respx.mock
    @pytest.mark.asyncio
    async def test_500_returns_empty(self) -> None:
        """Server error degrades gracefully (empty list)."""
        respx.get(_GITHUB_SEARCH_CODE).mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_connection_error_returns_empty(self) -> None:
        """Connection error returns empty."""
        respx.get(_GITHUB_SEARCH_CODE).mock(
            side_effect=httpx.ConnectError("DNS resolution failed")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_403_raises_rate_limit_error(self) -> None:
        """403 raises CollectorRateLimitError."""
        respx.get(_GITHUB_SEARCH_CODE).mock(
            return_value=httpx.Response(403, json={"message": "rate limit"})
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        with pytest.raises(CollectorRateLimitError):
            await _collect(seed)

    @respx.mock
    @pytest.mark.asyncio
    async def test_malformed_json_returns_empty(self) -> None:
        """Malformed JSON returns empty."""
        respx.get(_GITHUB_SEARCH_CODE).mock(
            return_value=httpx.Response(200, text="not json")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 7. Entity extraction unit tests
# ======================================================================
class TestEntityExtraction:
    def test_extract_ips_from_fragments(self) -> None:
        """IPv4 addresses are extracted from text fragments."""
        fragments = ["DB_HOST=10.0.1.50\nBACKUP=172.16.0.1"]
        result = _extract_entities_from_fragments(fragments)
        assert "10.0.1.50" in result["ips"]
        assert "172.16.0.1" in result["ips"]

    def test_ignored_ips_filtered(self) -> None:
        """127.0.0.1 and 0.0.0.0 are filtered out."""
        fragments = ["LISTEN=0.0.0.0\nLOCAL=127.0.0.1\nDB=10.0.1.50"]
        result = _extract_entities_from_fragments(fragments)
        assert "127.0.0.1" not in result["ips"]
        assert "0.0.0.0" not in result["ips"]
        assert "10.0.1.50" in result["ips"]

    def test_extract_domains_with_seed(self) -> None:
        """Hostnames matching the seed domain are extracted."""
        fragments = ["API_URL=https://api.acme.com/v1\nhost: staging.acme.com"]
        result = _extract_entities_from_fragments(fragments, seed_domain="acme.com")
        assert "api.acme.com" in result["domains"]
        assert "staging.acme.com" in result["domains"]

    def test_no_domains_without_seed(self) -> None:
        """Without a seed domain, no hostnames are extracted."""
        fragments = ["host: staging.acme.com"]
        result = _extract_entities_from_fragments(fragments, seed_domain=None)
        assert len(result["domains"]) == 0

    def test_empty_fragments(self) -> None:
        """Empty fragments yield nothing."""
        result = _extract_entities_from_fragments([], seed_domain="acme.com")
        assert len(result["ips"]) == 0
        assert len(result["domains"]) == 0


# ======================================================================
# 8. Ignored IPs in full pipeline
# ======================================================================
class TestIgnoredIPs:
    @respx.mock
    @pytest.mark.asyncio
    async def test_loopback_ips_not_emitted(self) -> None:
        """127.0.0.1 and 0.0.0.0 should not appear in observations."""
        respx.get(_GITHUB_SEARCH_CODE).mock(
            return_value=httpx.Response(200, json=_CODE_SEARCH_IGNORED_IPS)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)

        ip_values = {
            o.subject.identifier_value
            for o in observations
            if o.subject.identifier_type == IdentifierType.IP
        }
        assert "127.0.0.1" not in ip_values
        assert "0.0.0.0" not in ip_values


# ======================================================================
# 9. Health check
# ======================================================================
class TestHealthCheck:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Successful /zen response returns SUCCESS."""
        respx.get(_GITHUB_ZEN).mock(
            return_value=httpx.Response(
                200, text="Responsive is better than fast."
            )
        )

        collector = PasteMonitorCollector(_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "paste-monitor"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_error(self) -> None:
        """Connection error returns FAILURE."""
        respx.get(_GITHUB_ZEN).mock(
            side_effect=httpx.ConnectError("DNS resolution failed")
        )

        collector = PasteMonitorCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_5xx(self) -> None:
        """500 means FAILURE."""
        respx.get(_GITHUB_ZEN).mock(return_value=httpx.Response(500))

        collector = PasteMonitorCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE


# ======================================================================
# 10. API key usage
# ======================================================================
class TestAPIKeyUsage:
    @respx.mock
    @pytest.mark.asyncio
    async def test_api_key_sent_in_header(self) -> None:
        """API key appears in Authorization header."""
        route = respx.get(_GITHUB_SEARCH_CODE).mock(
            return_value=httpx.Response(200, json=_CODE_SEARCH_EMPTY)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        await _collect(seed, api_key="ghp_mykey123")

        assert route.called
        request = route.calls[0].request
        assert request.headers.get("authorization") == "Bearer ghp_mykey123"

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_api_key_no_auth_header(self) -> None:
        """Without API key, no Authorization header."""
        route = respx.get(_GITHUB_SEARCH_CODE).mock(
            return_value=httpx.Response(200, json=_CODE_SEARCH_EMPTY)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        await _collect(seed, api_key=None)

        assert route.called
        request = route.calls[0].request
        assert "authorization" not in request.headers


# ======================================================================
# 11. Multiple queries issued
# ======================================================================
class TestMultipleQueries:
    @respx.mock
    @pytest.mark.asyncio
    async def test_multiple_extension_queries(self) -> None:
        """The collector issues queries for multiple file extensions."""
        route = respx.get(_GITHUB_SEARCH_CODE).mock(
            return_value=httpx.Response(200, json=_CODE_SEARCH_EMPTY)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        await _collect(seed)

        # Should have made 4 requests (env, conf, yml, filename:.env).
        assert route.call_count == 4

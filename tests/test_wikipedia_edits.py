"""Tests for the wikipedia-edits collector (Tier 1, issue #78).

Exercises Wikipedia search and edit-history logic via ``respx`` mocks --
no live network calls. Coverage:

1.  Collector metadata: ID, tier, version, rate limit
2.  Only expands ORGANIZATION and DOMAIN seeds (others return [])
3.  Happy path: org search -> article found -> anonymous IPs extracted
4.  Happy path: domain seed works the same way
5.  No anonymous edits found: empty result
6.  Article not found: empty result
7.  HTTP errors: graceful degradation (empty list, not exception)
8.  Multiple anonymous IPs aggregated correctly (count + last_edit)
9.  Registered (non-IP) editors filtered out
10. IPv6 anonymous editors detected
11. Health check: success and failure paths
12. User-Agent header set correctly
13. Empty seed value skipped
14. Observation fields and structured_payload shape
"""

from __future__ import annotations

from uuid import UUID

import httpx
import pytest
import respx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorHealthCheck,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.wikipedia_edits import WikipediaEditsCollector
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-0000000c0d01")
RUN_ID = UUID("018f1f00-0000-7000-8000-0000000c0d02")

_WIKIPEDIA_API = "https://en.wikipedia.org/w/api.php"


def _config() -> CollectorConfig:
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=5.0,
    )


async def _collect(seed: Seed) -> list[Observation]:
    cfg = _config()
    collector = WikipediaEditsCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# === Canned Wikipedia API responses ==========================================

_SEARCH_RESPONSE = {
    "query": {
        "search": [
            {"title": "Acme Corporation", "snippet": "Acme Corporation is a company..."},
        ]
    }
}

_SEARCH_EMPTY = {"query": {"search": []}}

_REVISIONS_RESPONSE = {
    "query": {
        "pages": {
            "12345": {
                "pageid": 12345,
                "title": "Acme Corporation",
                "revisions": [
                    {
                        "user": "192.0.2.10",
                        "timestamp": "2025-03-15T10:00:00Z",
                        "comment": "Updated revenue figures",
                    },
                    {
                        "user": "192.0.2.10",
                        "timestamp": "2025-06-20T14:30:00Z",
                        "comment": "Fixed typo",
                    },
                    {
                        "user": "198.51.100.42",
                        "timestamp": "2025-01-05T08:00:00Z",
                        "comment": "Added history section",
                    },
                    {
                        "user": "EditorJane",
                        "timestamp": "2025-07-01T12:00:00Z",
                        "comment": "Improved formatting",
                    },
                    {
                        "user": "BotUser123",
                        "timestamp": "2025-04-10T09:00:00Z",
                        "comment": "Automated cleanup",
                    },
                ],
            }
        }
    }
}

_REVISIONS_IPV6 = {
    "query": {
        "pages": {
            "12345": {
                "pageid": 12345,
                "title": "Acme Corporation",
                "revisions": [
                    {
                        "user": "2001:db8::1",
                        "timestamp": "2025-05-10T16:00:00Z",
                        "comment": "IPv6 edit",
                    },
                ],
            }
        }
    }
}

_REVISIONS_NO_ANON = {
    "query": {
        "pages": {
            "12345": {
                "pageid": 12345,
                "title": "Acme Corporation",
                "revisions": [
                    {
                        "user": "EditorJane",
                        "timestamp": "2025-07-01T12:00:00Z",
                        "comment": "Improved formatting",
                    },
                    {
                        "user": "BotUser123",
                        "timestamp": "2025-04-10T09:00:00Z",
                        "comment": "Automated cleanup",
                    },
                ],
            }
        }
    }
}

_REVISIONS_EMPTY = {"query": {"pages": {"12345": {"pageid": 12345, "title": "Acme Corporation"}}}}


# ======================================================================
# 1. Collector metadata
# ======================================================================
class TestCollectorMetadata:
    def test_collector_id(self) -> None:
        assert WikipediaEditsCollector.collector_id == "wikipedia-edits"

    def test_collector_version(self) -> None:
        assert WikipediaEditsCollector.collector_version == "0.1.0"

    def test_tier_is_tier_1(self) -> None:
        assert WikipediaEditsCollector.tier == CollectorTier.TIER_1

    def test_no_credentials_required(self) -> None:
        assert WikipediaEditsCollector.requires_credentials is False

    def test_rate_limit(self) -> None:
        assert WikipediaEditsCollector.rate_limit_per_minute == 30

    def test_is_subclass_of_collector(self) -> None:
        assert issubclass(WikipediaEditsCollector, Collector)


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
    async def test_empty_org_name_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="  ")
        observations = await _collect(seed)
        assert observations == []

    @pytest.mark.asyncio
    async def test_empty_domain_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.DOMAIN, value="  ")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 3. Happy path — ORGANIZATION seed
# ======================================================================
class TestOrgHappyPath:
    @respx.mock
    @pytest.mark.asyncio
    async def test_org_seed_finds_anonymous_ips(self) -> None:
        """ORGANIZATION seed -> search -> revisions -> 2 unique anonymous IPs."""
        # First call: search; second call: revisions.
        route = respx.get(_WIKIPEDIA_API)
        route.side_effect = [
            httpx.Response(200, json=_SEARCH_RESPONSE),
            httpx.Response(200, json=_REVISIONS_RESPONSE),
        ]

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corporation")
        observations = await _collect(seed)

        assert len(observations) == 2
        ips = {obs.subject.identifier_value for obs in observations}
        assert ips == {"192.0.2.10", "198.51.100.42"}

    @respx.mock
    @pytest.mark.asyncio
    async def test_observation_fields(self) -> None:
        """Each observation has correct collector metadata and type."""
        route = respx.get(_WIKIPEDIA_API)
        route.side_effect = [
            httpx.Response(200, json=_SEARCH_RESPONSE),
            httpx.Response(200, json=_REVISIONS_RESPONSE),
        ]

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corporation")
        observations = await _collect(seed)

        obs = observations[0]
        assert obs.collector_id == "wikipedia-edits"
        assert obs.collector_version == "0.1.0"
        assert obs.tenant_id == TENANT_ID
        assert obs.observation_type == ObservationType.SCANNER_HOST
        assert obs.subject.identifier_type == IdentifierType.IP

    @respx.mock
    @pytest.mark.asyncio
    async def test_structured_payload_shape(self) -> None:
        """Structured payload has all expected keys."""
        route = respx.get(_WIKIPEDIA_API)
        route.side_effect = [
            httpx.Response(200, json=_SEARCH_RESPONSE),
            httpx.Response(200, json=_REVISIONS_RESPONSE),
        ]

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corporation")
        observations = await _collect(seed)

        for obs in observations:
            payload = obs.structured_payload
            assert payload["source"] == "wikipedia_edit"
            assert payload["article_title"] == "Acme Corporation"
            assert "edit_count" in payload
            assert "last_edit" in payload
            assert payload["organization"] == "Acme Corporation"

    @respx.mock
    @pytest.mark.asyncio
    async def test_edit_count_aggregated(self) -> None:
        """IP 192.0.2.10 appears twice -> edit_count == 2."""
        route = respx.get(_WIKIPEDIA_API)
        route.side_effect = [
            httpx.Response(200, json=_SEARCH_RESPONSE),
            httpx.Response(200, json=_REVISIONS_RESPONSE),
        ]

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corporation")
        observations = await _collect(seed)

        ip10_obs = [o for o in observations if o.subject.identifier_value == "192.0.2.10"]
        assert len(ip10_obs) == 1
        assert ip10_obs[0].structured_payload["edit_count"] == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_last_edit_is_most_recent(self) -> None:
        """last_edit for 192.0.2.10 is the later of the two timestamps."""
        route = respx.get(_WIKIPEDIA_API)
        route.side_effect = [
            httpx.Response(200, json=_SEARCH_RESPONSE),
            httpx.Response(200, json=_REVISIONS_RESPONSE),
        ]

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corporation")
        observations = await _collect(seed)

        ip10_obs = [o for o in observations if o.subject.identifier_value == "192.0.2.10"]
        assert ip10_obs[0].structured_payload["last_edit"] == "2025-06-20T14:30:00Z"


# ======================================================================
# 4. Happy path — DOMAIN seed
# ======================================================================
class TestDomainSeed:
    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_seed_works(self) -> None:
        """DOMAIN seed also triggers search and revision fetch."""
        route = respx.get(_WIKIPEDIA_API)
        route.side_effect = [
            httpx.Response(200, json=_SEARCH_RESPONSE),
            httpx.Response(200, json=_REVISIONS_RESPONSE),
        ]

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)

        assert len(observations) == 2


# ======================================================================
# 5. No anonymous edits found
# ======================================================================
class TestNoAnonymousEdits:
    @respx.mock
    @pytest.mark.asyncio
    async def test_only_registered_editors_returns_empty(self) -> None:
        """All edits from registered editors -> no observations."""
        route = respx.get(_WIKIPEDIA_API)
        route.side_effect = [
            httpx.Response(200, json=_SEARCH_RESPONSE),
            httpx.Response(200, json=_REVISIONS_NO_ANON),
        ]

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corporation")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_revisions_key_returns_empty(self) -> None:
        """Article exists but has no revisions key -> empty."""
        route = respx.get(_WIKIPEDIA_API)
        route.side_effect = [
            httpx.Response(200, json=_SEARCH_RESPONSE),
            httpx.Response(200, json=_REVISIONS_EMPTY),
        ]

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corporation")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 6. Article not found
# ======================================================================
class TestArticleNotFound:
    @respx.mock
    @pytest.mark.asyncio
    async def test_search_returns_no_results(self) -> None:
        """Wikipedia search yields no articles -> no observations."""
        respx.get(_WIKIPEDIA_API).mock(
            return_value=httpx.Response(200, json=_SEARCH_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="TotallyObscureCorp12345")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 7. HTTP errors — graceful degradation
# ======================================================================
class TestGracefulDegradation:
    @respx.mock
    @pytest.mark.asyncio
    async def test_search_500_returns_empty(self) -> None:
        """Wikipedia search 500 -> empty, no exception."""
        respx.get(_WIKIPEDIA_API).mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corporation")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_search_connection_error_returns_empty(self) -> None:
        """Connection error on search -> empty, not exception."""
        respx.get(_WIKIPEDIA_API).mock(
            side_effect=httpx.ConnectError("DNS resolution failed")
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corporation")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_revisions_500_returns_empty(self) -> None:
        """Search succeeds but revisions 500 -> empty."""
        route = respx.get(_WIKIPEDIA_API)
        route.side_effect = [
            httpx.Response(200, json=_SEARCH_RESPONSE),
            httpx.Response(500, text="Internal Server Error"),
        ]

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corporation")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_revisions_connection_error_returns_empty(self) -> None:
        """Search succeeds but revisions connection fails -> empty."""
        route = respx.get(_WIKIPEDIA_API)
        route.side_effect = [
            httpx.Response(200, json=_SEARCH_RESPONSE),
            httpx.ConnectError("Connection refused"),
        ]

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corporation")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_search_malformed_json_returns_empty(self) -> None:
        """Search returns non-JSON -> empty."""
        respx.get(_WIKIPEDIA_API).mock(
            return_value=httpx.Response(200, text="not json at all")
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corporation")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 8. IPv6 anonymous editors
# ======================================================================
class TestIPv6Editors:
    @respx.mock
    @pytest.mark.asyncio
    async def test_ipv6_anonymous_editor_detected(self) -> None:
        """IPv6 addresses in the user field are recognized as anonymous."""
        route = respx.get(_WIKIPEDIA_API)
        route.side_effect = [
            httpx.Response(200, json=_SEARCH_RESPONSE),
            httpx.Response(200, json=_REVISIONS_IPV6),
        ]

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corporation")
        observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].subject.identifier_value == "2001:db8::1"


# ======================================================================
# 9. Health check
# ======================================================================
class TestHealthCheck:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Successful siteinfo response returns SUCCESS."""
        respx.get(_WIKIPEDIA_API).mock(
            return_value=httpx.Response(200, json={"query": {"general": {"sitename": "Wikipedia"}}})
        )

        collector = WikipediaEditsCollector(_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "wikipedia-edits"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_error(self) -> None:
        """Connection error returns FAILURE with error message."""
        respx.get(_WIKIPEDIA_API).mock(
            side_effect=httpx.ConnectError("DNS resolution failed")
        )

        collector = WikipediaEditsCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_5xx(self) -> None:
        """A 500 response means FAILURE."""
        respx.get(_WIKIPEDIA_API).mock(
            return_value=httpx.Response(500)
        )

        collector = WikipediaEditsCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE


# ======================================================================
# 10. User-Agent header
# ======================================================================
class TestUserAgent:
    @respx.mock
    @pytest.mark.asyncio
    async def test_user_agent_set_on_search_request(self) -> None:
        """Wikipedia search request includes polite User-Agent header."""
        route = respx.get(_WIKIPEDIA_API)
        route.side_effect = [
            httpx.Response(200, json=_SEARCH_EMPTY),
        ]

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corporation")
        await _collect(seed)

        assert route.called
        request = route.calls[0].request
        assert "EXPOSE" in request.headers.get("user-agent", "")

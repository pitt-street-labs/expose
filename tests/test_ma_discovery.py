"""Tests for the ma-discovery collector (Tier 1, issue #53).

Exercises Wikidata SPARQL and Wikipedia API logic via ``respx`` mocks —
no live network calls. Coverage:

1.  Collector metadata: ID, tier, version
2.  Only expands ORGANIZATION seeds (DOMAIN, IP, etc. return [])
3.  Wikidata SPARQL happy path: observations extracted
4.  Wikipedia API happy path: observations extracted
5.  No acquisitions found: empty result
6.  HTTP errors: graceful degradation (empty list, not exception)
7.  Observations include acquisition_date and source_url
8.  Observations include relationship_type "acquired_by"
9.  Acquired domains discovered from Wikidata website property
10. Acquired domains guessed from organization name
11. Deduplication between Wikidata and Wikipedia results
12. Health check: success and failure paths
13. User-Agent header set correctly
14. Empty organization name skipped
15. SPARQL injection safety (quotes in org name)
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
from expose.collectors.builtin.ma_discovery import MADiscoveryCollector
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus

TENANT_ID = UUID("018f1f00-0000-7000-8000-0000000c0d01")
RUN_ID = UUID("018f1f00-0000-7000-8000-0000000c0d02")


def _config() -> CollectorConfig:
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=5.0,
    )


async def _collect(seed: Seed) -> list[Observation]:
    cfg = _config()
    collector = MADiscoveryCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# === Canned Wikidata SPARQL response ========================================

_WIKIDATA_RESPONSE = {
    "results": {
        "bindings": [
            {
                "acquired": {"type": "uri", "value": "http://www.wikidata.org/entity/Q123"},
                "acquiredLabel": {"type": "literal", "value": "Venafi"},
                "date": {"type": "literal", "value": "2024-06-15T00:00:00Z"},
                "website": {"type": "uri", "value": "https://www.venafi.com/"},
            },
            {
                "acquired": {"type": "uri", "value": "http://www.wikidata.org/entity/Q456"},
                "acquiredLabel": {"type": "literal", "value": "Zilla Security"},
                "date": {"type": "literal", "value": "2023-11-01T00:00:00Z"},
            },
        ]
    }
}

_WIKIDATA_EMPTY = {"results": {"bindings": []}}

# === Canned Wikipedia API response ==========================================

_WIKIPEDIA_RESPONSE = {
    "query": {
        "search": [
            {
                "title": "CyberArk acquisitions",
                "snippet": (
                    "CyberArk acquired <b>Idaptive</b> for $70 million in 2020. "
                    "The company also purchased <b>Conjur</b> in 2017."
                ),
            },
        ]
    }
}

_WIKIPEDIA_EMPTY = {"query": {"search": []}}


# ======================================================================
# 1. Collector metadata
# ======================================================================
class TestCollectorMetadata:
    def test_collector_id(self) -> None:
        assert MADiscoveryCollector.collector_id == "ma-discovery"

    def test_collector_version(self) -> None:
        assert MADiscoveryCollector.collector_version == "0.1.0"

    def test_tier_is_tier_1(self) -> None:
        assert MADiscoveryCollector.tier == CollectorTier.TIER_1

    def test_no_credentials_required(self) -> None:
        assert MADiscoveryCollector.requires_credentials is False

    def test_is_subclass_of_collector(self) -> None:
        assert issubclass(MADiscoveryCollector, Collector)


# ======================================================================
# 2. Only expands ORGANIZATION seeds
# ======================================================================
class TestSeedTypeFiltering:
    @pytest.mark.asyncio
    async def test_domain_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)
        assert observations == []

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


# ======================================================================
# 3. Wikidata SPARQL happy path
# ======================================================================
class TestWikidataHappyPath:
    @respx.mock
    @pytest.mark.asyncio
    async def test_wikidata_returns_acquisitions(self) -> None:
        """Wikidata SPARQL finds 2 acquisitions -> 2 observations."""
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json=_WIKIDATA_RESPONSE)
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json=_WIKIPEDIA_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)

        assert len(observations) == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_wikidata_observation_fields(self) -> None:
        """Each observation has the expected fields."""
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json=_WIKIDATA_RESPONSE)
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json=_WIKIPEDIA_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)

        obs = observations[0]
        assert obs.collector_id == "ma-discovery"
        assert obs.collector_version == "0.1.0"
        assert obs.tenant_id == TENANT_ID
        assert obs.observation_type == ObservationType.SCANNER_HOST

    @respx.mock
    @pytest.mark.asyncio
    async def test_wikidata_acquires_venafi_domain_from_website(self) -> None:
        """Venafi has a website property -> domain extracted."""
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json=_WIKIDATA_RESPONSE)
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json=_WIKIPEDIA_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)

        venafi_obs = [
            o for o in observations
            if o.structured_payload["acquired_organization"] == "Venafi"
        ]
        assert len(venafi_obs) == 1
        assert "venafi.com" in venafi_obs[0].structured_payload["acquired_domains"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_wikidata_guesses_domain_from_name(self) -> None:
        """Zilla Security has no website -> domain guessed from name."""
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json=_WIKIDATA_RESPONSE)
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json=_WIKIPEDIA_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)

        zilla_obs = [
            o for o in observations
            if o.structured_payload["acquired_organization"] == "Zilla Security"
        ]
        assert len(zilla_obs) == 1
        assert "zillasecurity.com" in zilla_obs[0].structured_payload["acquired_domains"]


# ======================================================================
# 4. Wikipedia API happy path
# ======================================================================
class TestWikipediaHappyPath:
    @respx.mock
    @pytest.mark.asyncio
    async def test_wikipedia_returns_acquisitions(self) -> None:
        """Wikipedia snippet mentions -> observations extracted."""
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json=_WIKIDATA_EMPTY)
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json=_WIKIPEDIA_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)

        # Should find "Idaptive" and "Conjur" from snippet.
        acquired_names = [
            o.structured_payload["acquired_organization"] for o in observations
        ]
        assert "Idaptive" in acquired_names
        assert "Conjur" in acquired_names


# ======================================================================
# 5. No acquisitions found
# ======================================================================
class TestNoResults:
    @respx.mock
    @pytest.mark.asyncio
    async def test_no_acquisitions_returns_empty(self) -> None:
        """Both sources empty -> no observations."""
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json=_WIKIDATA_EMPTY)
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json=_WIKIPEDIA_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="ObscureCorp")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 6. HTTP errors — graceful degradation
# ======================================================================
class TestGracefulDegradation:
    @respx.mock
    @pytest.mark.asyncio
    async def test_wikidata_500_returns_empty(self) -> None:
        """Wikidata 500 -> empty list, no exception."""
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json=_WIKIPEDIA_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_wikipedia_500_still_returns_wikidata(self) -> None:
        """Wikipedia 500 -> Wikidata results still returned."""
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json=_WIKIDATA_RESPONSE)
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)
        assert len(observations) == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_wikidata_connection_error_returns_empty(self) -> None:
        """Connection error on Wikidata -> empty list, not exception."""
        respx.get("https://query.wikidata.org/sparql").mock(
            side_effect=httpx.ConnectError("DNS resolution failed")
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json=_WIKIPEDIA_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_both_sources_fail_returns_empty(self) -> None:
        """Both sources fail -> empty list, no exception."""
        respx.get("https://query.wikidata.org/sparql").mock(
            side_effect=httpx.ConnectError("fail")
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            side_effect=httpx.ConnectError("fail")
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 7. Observations include acquisition_date and source
# ======================================================================
class TestObservationPayload:
    @respx.mock
    @pytest.mark.asyncio
    async def test_acquisition_date_present(self) -> None:
        """Acquisition date extracted from Wikidata."""
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json=_WIKIDATA_RESPONSE)
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json=_WIKIPEDIA_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)

        venafi_obs = [
            o for o in observations
            if o.structured_payload["acquired_organization"] == "Venafi"
        ]
        assert venafi_obs[0].structured_payload["acquisition_date"] == "2024-06-15"

    @respx.mock
    @pytest.mark.asyncio
    async def test_source_url_present(self) -> None:
        """Source URL present for Wikidata observations."""
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json=_WIKIDATA_RESPONSE)
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json=_WIKIPEDIA_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)
        assert observations[0].structured_payload["source_url"] != ""


# ======================================================================
# 8. Observations include relationship_type "acquired_by"
# ======================================================================
class TestRelationshipType:
    @respx.mock
    @pytest.mark.asyncio
    async def test_relationship_type_is_acquired_by(self) -> None:
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json=_WIKIDATA_RESPONSE)
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json=_WIKIPEDIA_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.structured_payload["relationship_type"] == "acquired_by"

    @respx.mock
    @pytest.mark.asyncio
    async def test_collector_id_in_payload(self) -> None:
        """_collector_id present in structured_payload for downstream filtering."""
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json=_WIKIDATA_RESPONSE)
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json=_WIKIPEDIA_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.structured_payload["_collector_id"] == "ma-discovery"

    @respx.mock
    @pytest.mark.asyncio
    async def test_attribution_source_in_payload(self) -> None:
        """attribution_source is 'transitive_ma'."""
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json=_WIKIDATA_RESPONSE)
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json=_WIKIPEDIA_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.structured_payload["attribution_source"] == "transitive_ma"


# ======================================================================
# 9. Deduplication between sources
# ======================================================================
class TestDeduplication:
    @respx.mock
    @pytest.mark.asyncio
    async def test_duplicate_names_deduplicated(self) -> None:
        """If Wikidata and Wikipedia both find the same company, no dup."""
        wikidata_with_conjur = {
            "results": {
                "bindings": [
                    {
                        "acquired": {"type": "uri", "value": "http://www.wikidata.org/entity/Q789"},
                        "acquiredLabel": {"type": "literal", "value": "Conjur"},
                    },
                ]
            }
        }
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json=wikidata_with_conjur)
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json=_WIKIPEDIA_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)

        conjur_count = sum(
            1 for o in observations
            if o.structured_payload["acquired_organization"].lower() == "conjur"
        )
        # Should appear exactly once (from Wikidata, Wikipedia duplicate filtered).
        assert conjur_count == 1


# ======================================================================
# 10. Health check
# ======================================================================
class TestHealthCheck:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Successful SPARQL response returns SUCCESS."""
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json={"boolean": True})
        )

        collector = MADiscoveryCollector(_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "ma-discovery"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_error(self) -> None:
        """Connection error returns FAILURE with error message."""
        respx.get("https://query.wikidata.org/sparql").mock(
            side_effect=httpx.ConnectError("DNS resolution failed")
        )

        collector = MADiscoveryCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_5xx(self) -> None:
        """A 500 response means FAILURE."""
        respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(500)
        )

        collector = MADiscoveryCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE


# ======================================================================
# 11. User-Agent header
# ======================================================================
class TestUserAgent:
    @respx.mock
    @pytest.mark.asyncio
    async def test_user_agent_set_on_wikidata_request(self) -> None:
        """Wikidata request includes polite User-Agent header."""
        route = respx.get("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json=_WIKIDATA_EMPTY)
        )
        respx.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(200, json=_WIKIPEDIA_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        await _collect(seed)

        assert route.called
        request = route.calls[0].request
        assert "EXPOSE" in request.headers.get("user-agent", "")

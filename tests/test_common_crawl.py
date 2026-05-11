"""Tests for the common-crawl Index passive URL/endpoint discovery collector.

Uses respx to mock all HTTP interactions -- NO live network calls.
"""

from __future__ import annotations

import json
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
from expose.collectors.builtin.common_crawl import (
    CommonCrawlCollector,
    parse_ndjson_response,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-000000000cc1")
RUN_ID = UUID("018f1f00-0000-7000-8000-000000000cc2")

_COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"


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


def _make_seed(
    value: str = "example.com",
    seed_type: SeedType = SeedType.DOMAIN,
) -> Seed:
    return Seed(seed_type=seed_type, value=value)


async def _collect_all(collector: CommonCrawlCollector, seed: Seed) -> list[Observation]:
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


def _ndjson_record(
    url: str = "https://example.com/page",
    timestamp: str = "20240301120000",
    status: str = "200",
    mime: str = "text/html",
    filename: str = "crawl-data/CC-MAIN-2024-10/segments/xyz/warc/part-00000.warc.gz",
    length: str = "12345",
) -> dict[str, str]:
    return {
        "url": url,
        "timestamp": timestamp,
        "status": status,
        "mime": mime,
        "filename": filename,
        "length": length,
    }


def _ndjson_lines(*records: dict[str, str]) -> str:
    """Build an NDJSON response from record dicts."""
    return "\n".join(json.dumps(r) for r in records)


_COLLINFO_RESPONSE = json.dumps([
    {"id": "CC-MAIN-2024-18", "name": "May 2024 Index"},
    {"id": "CC-MAIN-2024-10", "name": "March 2024 Index"},
])


def _mock_collinfo(
    respx_mock: respx.MockRouter | None = None,
    *,
    data: str = _COLLINFO_RESPONSE,
    status: int = 200,
) -> None:
    """Register a collinfo.json mock."""
    target = respx_mock if respx_mock is not None else respx
    target.get(_COLLINFO_URL).mock(
        return_value=httpx.Response(status, text=data),
    )


# ===================================================================
# Metadata tests
# ===================================================================
class TestCommonCrawlCollectorMetadata:
    """Verify class-level metadata attributes."""

    def test_collector_id(self) -> None:
        assert CommonCrawlCollector.collector_id == "common-crawl"

    def test_collector_version(self) -> None:
        assert CommonCrawlCollector.collector_version == "0.1.0"

    def test_tier(self) -> None:
        assert CommonCrawlCollector.tier == CollectorTier.TIER_1

    def test_requires_credentials(self) -> None:
        assert CommonCrawlCollector.requires_credentials is False

    def test_rate_limit_per_minute(self) -> None:
        assert CommonCrawlCollector.rate_limit_per_minute == 30

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("common-crawl")
        cls = DEFAULT_REGISTRY.get("common-crawl")
        assert cls is CommonCrawlCollector


# ===================================================================
# NDJSON parsing tests
# ===================================================================
class TestNdjsonParsing:
    """Test NDJSON response parsing."""

    def test_parse_single_record(self) -> None:
        text = json.dumps({"url": "https://example.com/", "status": "200"})
        result = parse_ndjson_response(text)
        assert len(result) == 1
        assert result[0]["url"] == "https://example.com/"

    def test_parse_multiple_records(self) -> None:
        text = _ndjson_lines(
            _ndjson_record(url="https://example.com/a"),
            _ndjson_record(url="https://example.com/b"),
        )
        result = parse_ndjson_response(text)
        assert len(result) == 2

    def test_parse_empty_string(self) -> None:
        assert parse_ndjson_response("") == []

    def test_parse_blank_lines_skipped(self) -> None:
        text = "\n" + json.dumps({"url": "https://example.com/"}) + "\n\n"
        result = parse_ndjson_response(text)
        assert len(result) == 1

    def test_parse_malformed_lines_skipped(self) -> None:
        text = "not json\n" + json.dumps({"url": "https://example.com/"})
        result = parse_ndjson_response(text)
        assert len(result) == 1
        assert result[0]["url"] == "https://example.com/"

    def test_parse_non_dict_lines_skipped(self) -> None:
        text = json.dumps([1, 2, 3]) + "\n" + json.dumps({"url": "ok"})
        result = parse_ndjson_response(text)
        assert len(result) == 1
        assert result[0]["url"] == "ok"


# ===================================================================
# Seed type filtering
# ===================================================================
class TestCommonCrawlSeedTypes:
    """Verify accepted and rejected seed types."""

    @respx.mock
    async def test_domain_seed_accepted(self) -> None:
        _mock_collinfo()
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(
                200,
                text=_ndjson_lines(
                    _ndjson_record(url="https://sub.example.com/admin/config"),
                ),
            ),
        )

        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com", SeedType.DOMAIN))
        assert len(results) >= 1

    @respx.mock
    async def test_ip_seed_skipped(self) -> None:
        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("192.0.2.1", SeedType.IP))
        assert results == []

    @respx.mock
    async def test_asn_seed_skipped(self) -> None:
        collector = CommonCrawlCollector(_make_config())
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        results = await _collect_all(collector, seed)
        assert results == []

    @respx.mock
    async def test_organization_seed_skipped(self) -> None:
        collector = CommonCrawlCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        results = await _collect_all(collector, seed)
        assert results == []


# ===================================================================
# Crawl index resolution
# ===================================================================
class TestCrawlIndexResolution:
    """Test that the collector resolves the latest crawl index."""

    @respx.mock
    async def test_uses_latest_index_from_collinfo(self) -> None:
        _mock_collinfo()

        captured_urls: list[str] = []

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_urls.append(str(request.url))
            return httpx.Response(200, text="")

        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            side_effect=_capture,
        )

        collector = CommonCrawlCollector(_make_config())
        await _collect_all(collector, _make_seed("example.com"))

        # Should have queried the latest index (CC-MAIN-2024-18).
        assert len(captured_urls) == 1
        assert "CC-MAIN-2024-18-index" in captured_urls[0]

    @respx.mock
    async def test_falls_back_to_hardcoded_on_collinfo_failure(self) -> None:
        respx.get(_COLLINFO_URL).mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        captured_urls: list[str] = []

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_urls.append(str(request.url))
            return httpx.Response(200, text="")

        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-10-index").mock(
            side_effect=_capture,
        )

        collector = CommonCrawlCollector(_make_config())
        await _collect_all(collector, _make_seed("example.com"))

        # Should fall back to hardcoded CC-MAIN-2024-10.
        assert len(captured_urls) == 1
        assert "CC-MAIN-2024-10-index" in captured_urls[0]

    @respx.mock
    async def test_caches_crawl_index(self) -> None:
        """The crawl index is resolved once and cached for subsequent calls."""
        collinfo_call_count = 0

        def _count_collinfo(request: httpx.Request) -> httpx.Response:
            nonlocal collinfo_call_count
            collinfo_call_count += 1
            return httpx.Response(200, text=_COLLINFO_RESPONSE)

        respx.get(_COLLINFO_URL).mock(side_effect=_count_collinfo)
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(200, text=""),
        )

        collector = CommonCrawlCollector(_make_config())
        await _collect_all(collector, _make_seed("example.com"))
        await _collect_all(collector, _make_seed("example.org"))

        # collinfo.json should be fetched only once.
        assert collinfo_call_count == 1


# ===================================================================
# Expand — subdomain discovery
# ===================================================================
class TestCommonCrawlSubdomainDiscovery:
    """Test subdomain extraction from crawled URLs."""

    @respx.mock
    async def test_discovers_subdomains(self) -> None:
        _mock_collinfo()
        records = _ndjson_lines(
            _ndjson_record(url="https://api.example.com/v1/users"),
            _ndjson_record(url="https://admin.example.com/dashboard"),
            _ndjson_record(url="https://example.com/about"),
        )
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(200, text=records),
        )

        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        # Filter for subdomain observations (DNS_RESOLUTION type).
        sub_obs = [r for r in results if r.observation_type == ObservationType.DNS_RESOLUTION]
        discovered = {r.structured_payload["discovered_subdomain"] for r in sub_obs}
        assert "api.example.com" in discovered
        assert "admin.example.com" in discovered
        # The apex domain itself should NOT appear as a subdomain.
        assert "example.com" not in discovered

    @respx.mock
    async def test_deduplicates_subdomains(self) -> None:
        _mock_collinfo()
        records = _ndjson_lines(
            _ndjson_record(url="https://api.example.com/v1"),
            _ndjson_record(url="https://api.example.com/v2"),
            _ndjson_record(url="https://api.example.com/v3"),
        )
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(200, text=records),
        )

        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        sub_obs = [r for r in results if r.observation_type == ObservationType.DNS_RESOLUTION]
        # Only one observation for api.example.com, not three.
        assert len(sub_obs) == 1
        assert sub_obs[0].structured_payload["discovered_subdomain"] == "api.example.com"

    @respx.mock
    async def test_subdomain_observation_structure(self) -> None:
        _mock_collinfo()
        records = _ndjson_lines(
            _ndjson_record(url="https://blog.example.com/post/1"),
        )
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(200, text=records),
        )

        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        sub_obs = [r for r in results if r.observation_type == ObservationType.DNS_RESOLUTION]
        assert len(sub_obs) == 1

        obs = sub_obs[0]
        assert obs.collector_id == "common-crawl"
        assert obs.tenant_id == TENANT_ID
        assert obs.subject.identifier_type == IdentifierType.DOMAIN
        assert obs.subject.identifier_value == "example.com"
        payload = obs.structured_payload
        assert payload["source"] == "common_crawl"
        assert payload["crawl_index"] == "CC-MAIN-2024-18"
        assert payload["discovered_subdomain"] == "blog.example.com"


# ===================================================================
# Expand — interesting endpoint discovery
# ===================================================================
class TestCommonCrawlEndpointDiscovery:
    """Test interesting endpoint pattern detection."""

    @respx.mock
    async def test_discovers_interesting_endpoints(self) -> None:
        _mock_collinfo()
        records = _ndjson_lines(
            _ndjson_record(url="https://example.com/admin/users", status="200", mime="text/html"),
            _ndjson_record(url="https://example.com/api/v1/data", status="200", mime="application/json"),
            _ndjson_record(url="https://example.com/login", status="200", mime="text/html"),
            _ndjson_record(url="https://example.com/about", status="200", mime="text/html"),
            _ndjson_record(url="https://example.com/contact", status="200", mime="text/html"),
        )
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(200, text=records),
        )

        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        http_obs = [r for r in results if r.observation_type == ObservationType.HTTP_RESPONSE]
        urls = {r.structured_payload["url"] for r in http_obs}
        # /admin, /api, /login are interesting; /about and /contact are not.
        assert "https://example.com/admin/users" in urls
        assert "https://example.com/api/v1/data" in urls
        assert "https://example.com/login" in urls
        assert "https://example.com/about" not in urls
        assert "https://example.com/contact" not in urls

    @respx.mock
    async def test_endpoint_observation_structure(self) -> None:
        _mock_collinfo()
        records = _ndjson_lines(
            _ndjson_record(
                url="https://example.com/admin/settings",
                status="403",
                mime="text/html",
                timestamp="20240301120000",
            ),
        )
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(200, text=records),
        )

        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        http_obs = [r for r in results if r.observation_type == ObservationType.HTTP_RESPONSE]
        assert len(http_obs) == 1

        obs = http_obs[0]
        assert obs.collector_id == "common-crawl"
        assert obs.tenant_id == TENANT_ID
        assert obs.subject.identifier_type == IdentifierType.DOMAIN
        payload = obs.structured_payload
        assert payload["source"] == "common_crawl"
        assert payload["crawl_index"] == "CC-MAIN-2024-18"
        assert payload["url"] == "https://example.com/admin/settings"
        assert payload["status"] == 403
        assert payload["mime"] == "text/html"
        assert payload["timestamp"] == "20240301120000"

    @respx.mock
    async def test_deduplicates_urls(self) -> None:
        _mock_collinfo()
        records = _ndjson_lines(
            _ndjson_record(url="https://example.com/admin"),
            _ndjson_record(url="https://example.com/admin"),
        )
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(200, text=records),
        )

        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        http_obs = [r for r in results if r.observation_type == ObservationType.HTTP_RESPONSE]
        assert len(http_obs) == 1

    @respx.mock
    async def test_env_file_detected(self) -> None:
        _mock_collinfo()
        records = _ndjson_lines(
            _ndjson_record(url="https://example.com/.env"),
        )
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(200, text=records),
        )

        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        http_obs = [r for r in results if r.observation_type == ObservationType.HTTP_RESPONSE]
        assert len(http_obs) == 1
        assert http_obs[0].structured_payload["url"] == "https://example.com/.env"

    @respx.mock
    async def test_git_exposure_detected(self) -> None:
        _mock_collinfo()
        records = _ndjson_lines(
            _ndjson_record(url="https://example.com/.git/config"),
        )
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(200, text=records),
        )

        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        http_obs = [r for r in results if r.observation_type == ObservationType.HTTP_RESPONSE]
        assert len(http_obs) == 1


# ===================================================================
# Expand — combined subdomain + endpoint
# ===================================================================
class TestCommonCrawlCombined:
    """Test scenarios that produce both subdomain and endpoint observations."""

    @respx.mock
    async def test_subdomain_with_interesting_path(self) -> None:
        """A URL on a subdomain with an interesting path should emit both."""
        _mock_collinfo()
        records = _ndjson_lines(
            _ndjson_record(url="https://api.example.com/admin/config"),
        )
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(200, text=records),
        )

        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        sub_obs = [r for r in results if r.observation_type == ObservationType.DNS_RESOLUTION]
        http_obs = [r for r in results if r.observation_type == ObservationType.HTTP_RESPONSE]

        assert len(sub_obs) == 1
        assert sub_obs[0].structured_payload["discovered_subdomain"] == "api.example.com"
        assert len(http_obs) == 1
        assert http_obs[0].structured_payload["url"] == "https://api.example.com/admin/config"


# ===================================================================
# Expand — edge cases and errors
# ===================================================================
class TestCommonCrawlExpandEdgeCases:
    """Edge cases in the expand flow."""

    @respx.mock
    async def test_empty_response_no_observations(self) -> None:
        _mock_collinfo()
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(200, text=""),
        )

        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("no-data.example.com"))
        assert results == []

    @respx.mock
    async def test_404_returns_empty(self) -> None:
        _mock_collinfo()
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(404),
        )

        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("notfound.example.com"))
        assert results == []

    @respx.mock
    async def test_http_500_raises(self) -> None:
        _mock_collinfo()
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(500, text="Internal Server Error"),
        )

        collector = CommonCrawlCollector(_make_config())
        with pytest.raises(CollectorSourceUnreachableError, match="500"):
            await _collect_all(collector, _make_seed("error.example.com"))

    @respx.mock
    async def test_connection_error_raises(self) -> None:
        _mock_collinfo()
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        collector = CommonCrawlCollector(_make_config())
        with pytest.raises(CollectorSourceUnreachableError, match="unreachable"):
            await _collect_all(collector, _make_seed("unreachable.example.com"))

    @respx.mock
    async def test_no_interesting_paths_no_http_obs(self) -> None:
        """URLs without interesting path patterns should not emit HTTP obs."""
        _mock_collinfo()
        records = _ndjson_lines(
            _ndjson_record(url="https://example.com/about"),
            _ndjson_record(url="https://example.com/contact"),
            _ndjson_record(url="https://example.com/products/widget"),
        )
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(200, text=records),
        )

        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        http_obs = [r for r in results if r.observation_type == ObservationType.HTTP_RESPONSE]
        assert http_obs == []

    @respx.mock
    async def test_status_parsed_as_int(self) -> None:
        _mock_collinfo()
        records = _ndjson_lines(
            _ndjson_record(url="https://example.com/admin", status="403"),
        )
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(200, text=records),
        )

        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        http_obs = [r for r in results if r.observation_type == ObservationType.HTTP_RESPONSE]
        assert len(http_obs) == 1
        assert http_obs[0].structured_payload["status"] == 403
        assert isinstance(http_obs[0].structured_payload["status"], int)

    @respx.mock
    async def test_non_numeric_status_preserved(self) -> None:
        _mock_collinfo()
        records = _ndjson_lines(
            _ndjson_record(url="https://example.com/api/v1", status="-"),
        )
        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            return_value=httpx.Response(200, text=records),
        )

        collector = CommonCrawlCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        http_obs = [r for r in results if r.observation_type == ObservationType.HTTP_RESPONSE]
        assert len(http_obs) == 1
        assert http_obs[0].structured_payload["status"] == "-"


# ===================================================================
# URL construction
# ===================================================================
class TestCommonCrawlUrlConstruction:
    """Verify query URL parameters."""

    @respx.mock
    async def test_query_uses_wildcard_domain(self) -> None:
        _mock_collinfo()

        captured_params: list[dict[str, str]] = []

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_params.append(dict(request.url.params))
            return httpx.Response(200, text="")

        respx.get("https://index.commoncrawl.org/CC-MAIN-2024-18-index").mock(
            side_effect=_capture,
        )

        collector = CommonCrawlCollector(_make_config())
        await _collect_all(collector, _make_seed("example.com"))

        assert len(captured_params) == 1
        assert captured_params[0]["url"] == "*.example.com"
        assert captured_params[0]["output"] == "json"
        assert captured_params[0]["limit"] == "500"


# ===================================================================
# Health check
# ===================================================================
class TestCommonCrawlHealthCheck:
    """Health check tests."""

    @respx.mock
    async def test_healthy_returns_success(self) -> None:
        respx.get(_COLLINFO_URL).mock(
            return_value=httpx.Response(200, text=_COLLINFO_RESPONSE),
        )

        collector = CommonCrawlCollector(_make_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "common-crawl"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    async def test_unhealthy_returns_failure(self) -> None:
        respx.get(_COLLINFO_URL).mock(
            return_value=httpx.Response(503, text="Service Unavailable"),
        )

        collector = CommonCrawlCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "503" in result.error_message

    @respx.mock
    async def test_network_error_returns_failure(self) -> None:
        respx.get(_COLLINFO_URL).mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        collector = CommonCrawlCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "unreachable" in result.error_message

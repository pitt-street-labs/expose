"""Tests for the wayback-machine historical search collector.

Uses respx to mock all HTTP interactions — NO live network calls.
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
from expose.collectors.builtin.wayback_machine import (
    WaybackMachineCollector,
    build_archive_url,
    format_timestamp,
    is_interesting_content_type,
    parse_cdx_response,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-000000000ba1")
RUN_ID = UUID("018f1f00-0000-7000-8000-000000000ba2")

_CDX_BASE_URL = "https://web.archive.org/cdx/search/cdx"


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


async def _collect_all(collector: WaybackMachineCollector, seed: Seed) -> list[Observation]:
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


def _cdx_response(
    rows: list[list[str]] | None = None,
) -> str:
    """Build a CDX JSON response string."""
    header = ["timestamp", "original", "mimetype", "statuscode", "digest"]
    data = [header]
    if rows:
        data.extend(rows)
    return json.dumps(data)


def _cdx_row(
    timestamp: str = "20230615120000",
    url: str = "https://example.com/page",
    mimetype: str = "text/html",
    statuscode: str = "200",
    digest: str = "ABCDEF1234567890",
) -> list[str]:
    return [timestamp, url, mimetype, statuscode, digest]


# ===================================================================
# Metadata tests
# ===================================================================
class TestWaybackMachineCollectorMetadata:
    """Verify class-level metadata attributes."""

    def test_collector_id(self) -> None:
        assert WaybackMachineCollector.collector_id == "wayback-machine"

    def test_collector_version(self) -> None:
        assert WaybackMachineCollector.collector_version == "0.1.0"

    def test_tier(self) -> None:
        assert WaybackMachineCollector.tier == CollectorTier.TIER_1

    def test_requires_credentials(self) -> None:
        assert WaybackMachineCollector.requires_credentials is False

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("wayback-machine")
        cls = DEFAULT_REGISTRY.get("wayback-machine")
        assert cls is WaybackMachineCollector


# ===================================================================
# Pure function tests
# ===================================================================
class TestCdxParsing:
    """Test CDX response parsing helpers."""

    def test_parse_cdx_response_happy(self) -> None:
        data = [
            ["timestamp", "original", "mimetype", "statuscode", "digest"],
            [
                "20230615120000",
                "https://example.com/",
                "text/html",
                "200",
                "ABC123",
            ],
        ]
        result = parse_cdx_response(data)
        assert len(result) == 1
        assert result[0]["timestamp"] == "20230615120000"
        assert result[0]["original"] == "https://example.com/"
        assert result[0]["mimetype"] == "text/html"
        assert result[0]["statuscode"] == "200"
        assert result[0]["digest"] == "ABC123"

    def test_parse_cdx_response_empty(self) -> None:
        # Only header row, no data.
        data = [
            ["timestamp", "original", "mimetype", "statuscode", "digest"],
        ]
        result = parse_cdx_response(data)
        assert result == []

    def test_parse_cdx_response_completely_empty(self) -> None:
        result = parse_cdx_response([])
        assert result == []

    def test_parse_cdx_response_skips_malformed_rows(self) -> None:
        data = [
            ["timestamp", "original", "mimetype", "statuscode", "digest"],
            ["20230615120000", "https://example.com/"],  # Too few fields.
            [
                "20230615120000",
                "https://example.com/good",
                "text/html",
                "200",
                "ABC",
            ],
        ]
        result = parse_cdx_response(data)
        assert len(result) == 1

    def test_build_archive_url(self) -> None:
        url = build_archive_url("20230615120000", "https://example.com/page")
        assert url == ("https://web.archive.org/web/20230615120000/https://example.com/page")

    def test_format_timestamp_valid(self) -> None:
        result = format_timestamp("20230615120000")
        assert result == "2023-06-15T12:00:00+00:00"

    def test_format_timestamp_short(self) -> None:
        result = format_timestamp("2023")
        assert result == "2023"

    def test_format_timestamp_invalid(self) -> None:
        result = format_timestamp("99999999999999")
        # Should return raw string on parse error.
        assert result == "99999999999999"


class TestContentTypeFiltering:
    """Test MIME type interest filtering."""

    def test_html_interesting(self) -> None:
        assert is_interesting_content_type("text/html") is True

    def test_json_interesting(self) -> None:
        assert is_interesting_content_type("application/json") is True

    def test_plain_text_interesting(self) -> None:
        assert is_interesting_content_type("text/plain") is True

    def test_xml_interesting(self) -> None:
        assert is_interesting_content_type("application/xml") is True

    def test_image_not_interesting(self) -> None:
        assert is_interesting_content_type("image/png") is False

    def test_charset_suffix_stripped(self) -> None:
        assert is_interesting_content_type("text/html; charset=utf-8") is True


# ===================================================================
# Seed type filtering
# ===================================================================
class TestWaybackSeedTypes:
    """Verify accepted and rejected seed types."""

    @respx.mock
    async def test_domain_seed_accepted(self) -> None:
        respx.get(_CDX_BASE_URL).mock(
            return_value=httpx.Response(
                200,
                text=_cdx_response([_cdx_row()]),
            ),
        )

        collector = WaybackMachineCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com", SeedType.DOMAIN))
        assert len(results) >= 1

    @respx.mock
    async def test_ip_seed_accepted(self) -> None:
        respx.get(_CDX_BASE_URL).mock(
            return_value=httpx.Response(
                200,
                text=_cdx_response([_cdx_row(url="http://192.0.2.1/page")]),
            ),
        )

        collector = WaybackMachineCollector(_make_config())
        results = await _collect_all(collector, _make_seed("192.0.2.1", SeedType.IP))
        assert len(results) >= 1
        # Subject should use IP identifier type.
        for obs in results:
            assert obs.subject.identifier_type == IdentifierType.IP

    @respx.mock
    async def test_asn_seed_skipped(self) -> None:
        collector = WaybackMachineCollector(_make_config())
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        results = await _collect_all(collector, seed)
        assert results == []

    @respx.mock
    async def test_organization_seed_skipped(self) -> None:
        collector = WaybackMachineCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        results = await _collect_all(collector, seed)
        assert results == []


# ===================================================================
# Expand — happy path
# ===================================================================
class TestWaybackExpandHappyPath:
    """Test full expand flow with mocked CDX API."""

    @respx.mock
    async def test_domain_query_yields_observations(self) -> None:
        rows = [
            _cdx_row(
                timestamp="20230101000000",
                url="https://example.com/",
                mimetype="text/html",
            ),
            _cdx_row(
                timestamp="20230201000000",
                url="https://example.com/about",
                mimetype="text/html",
            ),
        ]
        # General query + robots.txt query.
        respx.get(_CDX_BASE_URL).mock(
            return_value=httpx.Response(200, text=_cdx_response(rows)),
        )

        collector = WaybackMachineCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com", SeedType.DOMAIN))

        # Should get observations from both general and robots queries.
        assert len(results) >= 2

    @respx.mock
    async def test_observation_payload_structure(self) -> None:
        rows = [
            _cdx_row(
                timestamp="20230615120000",
                url="https://example.com/page",
                mimetype="text/html",
                statuscode="200",
                digest="ABC123",
            ),
        ]
        respx.get(_CDX_BASE_URL).mock(
            return_value=httpx.Response(200, text=_cdx_response(rows)),
        )

        collector = WaybackMachineCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com", SeedType.DOMAIN))

        # Find the general URL observation (not robots.txt).
        general_obs = [
            r for r in results if r.structured_payload.get("query_type") != "historical_robots_txt"
        ]
        assert len(general_obs) >= 1

        obs = general_obs[0]
        payload = obs.structured_payload
        assert payload["source"] == "wayback_machine"
        assert payload["original_url"] == "https://example.com/page"
        assert payload["content_type"] == "text/html"
        assert payload["status_code"] == "200"
        assert payload["digest"] == "ABC123"
        assert payload["archive_url"] == (
            "https://web.archive.org/web/20230615120000/https://example.com/page"
        )
        assert payload["archive_timestamp"] == "2023-06-15T12:00:00+00:00"

    @respx.mock
    async def test_observation_subject_is_domain(self) -> None:
        rows = [_cdx_row()]
        respx.get(_CDX_BASE_URL).mock(
            return_value=httpx.Response(200, text=_cdx_response(rows)),
        )

        collector = WaybackMachineCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com", SeedType.DOMAIN))

        for obs in results:
            assert obs.subject.identifier_type == IdentifierType.DOMAIN
            assert obs.observation_type == ObservationType.HTTP_RESPONSE
            assert obs.tenant_id == TENANT_ID

    @respx.mock
    async def test_filters_uninteresting_content_types(self) -> None:
        rows = [
            _cdx_row(mimetype="text/html"),
            _cdx_row(
                url="https://example.com/logo.png",
                mimetype="image/png",
            ),
            _cdx_row(
                url="https://example.com/style.css",
                mimetype="text/css",
            ),
        ]
        respx.get(_CDX_BASE_URL).mock(
            return_value=httpx.Response(200, text=_cdx_response(rows)),
        )

        collector = WaybackMachineCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com", SeedType.DOMAIN))

        # Only text/html should pass the general query filter.
        # (robots.txt query may also return results.)
        general_obs = [
            r for r in results if r.structured_payload.get("query_type") != "historical_robots_txt"
        ]
        for obs in general_obs:
            ct = obs.structured_payload["content_type"]
            assert is_interesting_content_type(ct)

    @respx.mock
    async def test_historical_robots_txt_observation(self) -> None:
        general_rows = [_cdx_row()]
        robots_rows = [
            _cdx_row(
                timestamp="20220101000000",
                url="https://example.com/robots.txt",
                mimetype="text/plain",
            ),
        ]

        # Use side_effect to return different responses for different params.
        call_count = 0

        def _side_effect(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            params = dict(request.url.params)
            if "robots.txt" in params.get("url", ""):
                return httpx.Response(200, text=_cdx_response(robots_rows))
            return httpx.Response(200, text=_cdx_response(general_rows))

        respx.get(_CDX_BASE_URL).mock(side_effect=_side_effect)

        collector = WaybackMachineCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com", SeedType.DOMAIN))

        robots_obs = [
            r for r in results if r.structured_payload.get("query_type") == "historical_robots_txt"
        ]
        assert len(robots_obs) == 1
        assert "robots.txt" in robots_obs[0].structured_payload["original_url"]


# ===================================================================
# Expand — edge cases and errors
# ===================================================================
class TestWaybackExpandEdgeCases:
    """Edge cases in the expand flow."""

    @respx.mock
    async def test_empty_cdx_response_no_observations(self) -> None:
        # Header only, no data rows.
        respx.get(_CDX_BASE_URL).mock(
            return_value=httpx.Response(200, text=_cdx_response()),
        )

        collector = WaybackMachineCollector(_make_config())
        results = await _collect_all(collector, _make_seed("no-history.example.com"))
        assert results == []

    @respx.mock
    async def test_empty_body_no_observations(self) -> None:
        respx.get(_CDX_BASE_URL).mock(
            return_value=httpx.Response(200, text=""),
        )

        collector = WaybackMachineCollector(_make_config())
        results = await _collect_all(collector, _make_seed("empty.example.com"))
        assert results == []

    @respx.mock
    async def test_http_500_raises(self) -> None:
        respx.get(_CDX_BASE_URL).mock(
            return_value=httpx.Response(500, text="Internal Server Error"),
        )

        collector = WaybackMachineCollector(_make_config())
        with pytest.raises(CollectorSourceUnreachableError, match="500"):
            await _collect_all(collector, _make_seed("error.example.com"))

    @respx.mock
    async def test_connection_error_raises(self) -> None:
        respx.get(_CDX_BASE_URL).mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        collector = WaybackMachineCollector(_make_config())
        with pytest.raises(CollectorSourceUnreachableError, match="unreachable"):
            await _collect_all(collector, _make_seed("unreachable.example.com"))

    @respx.mock
    async def test_404_returns_empty(self) -> None:
        respx.get(_CDX_BASE_URL).mock(
            return_value=httpx.Response(404),
        )

        collector = WaybackMachineCollector(_make_config())
        results = await _collect_all(collector, _make_seed("notfound.example.com"))
        assert results == []

    @respx.mock
    async def test_non_json_response_returns_empty(self) -> None:
        respx.get(_CDX_BASE_URL).mock(
            return_value=httpx.Response(200, text="<html>not json</html>"),
        )

        collector = WaybackMachineCollector(_make_config())
        results = await _collect_all(collector, _make_seed("badjson.example.com"))
        assert results == []


# ===================================================================
# URL construction
# ===================================================================
class TestWaybackUrlConstruction:
    """Verify CDX query URL parameters."""

    @respx.mock
    async def test_domain_query_includes_wildcard(self) -> None:
        captured_params: list[dict[str, str]] = []

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_params.append(dict(request.url.params))
            return httpx.Response(200, text=_cdx_response())

        respx.get(_CDX_BASE_URL).mock(side_effect=_capture)

        collector = WaybackMachineCollector(_make_config())
        await _collect_all(collector, _make_seed("example.com", SeedType.DOMAIN))

        # Should have made 2 requests: general + robots.txt.
        assert len(captured_params) == 2
        # General query should include wildcard suffix.
        assert captured_params[0]["url"] == "example.com/*"

    @respx.mock
    async def test_ip_query_uses_ip(self) -> None:
        captured_urls: list[str] = []

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_urls.append(str(request.url))
            return httpx.Response(200, text=_cdx_response())

        respx.get(_CDX_BASE_URL).mock(side_effect=_capture)

        collector = WaybackMachineCollector(_make_config())
        await _collect_all(collector, _make_seed("192.0.2.1", SeedType.IP))

        assert len(captured_urls) == 2
        assert "192.0.2.1" in captured_urls[0]

    @respx.mock
    async def test_collapse_urlkey_in_general_query(self) -> None:
        captured_params: list[dict[str, str]] = []

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_params.append(dict(request.url.params))
            return httpx.Response(200, text=_cdx_response())

        respx.get(_CDX_BASE_URL).mock(side_effect=_capture)

        collector = WaybackMachineCollector(_make_config())
        await _collect_all(collector, _make_seed("example.com", SeedType.DOMAIN))

        # First call (general) should have collapse=urlkey.
        assert captured_params[0].get("collapse") == "urlkey"
        # Second call (robots.txt) should NOT have collapse.
        assert "collapse" not in captured_params[1]


# ===================================================================
# Health check
# ===================================================================
class TestWaybackHealthCheck:
    """Health check tests."""

    @respx.mock
    async def test_healthy_returns_success(self) -> None:
        respx.head("https://web.archive.org").mock(
            return_value=httpx.Response(200),
        )

        collector = WaybackMachineCollector(_make_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "wayback-machine"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    async def test_unhealthy_returns_failure(self) -> None:
        respx.head("https://web.archive.org").mock(
            return_value=httpx.Response(503, text="Service Unavailable"),
        )

        collector = WaybackMachineCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "503" in result.error_message

    @respx.mock
    async def test_network_error_returns_failure(self) -> None:
        respx.head("https://web.archive.org").mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        collector = WaybackMachineCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "unreachable" in result.error_message

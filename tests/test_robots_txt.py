"""Tests for the robots-txt endpoint discovery collector.

Uses respx to mock all HTTP interactions — NO live network calls.
"""

from __future__ import annotations

from uuid import UUID

import httpx
import respx

from expose.collectors.base import (
    CollectorConfig,
    CollectorHealthCheck,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.robots_txt import (
    RobotsTxtCollector,
    classify_path,
    parse_robots_txt,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-0000000000b1")
RUN_ID = UUID("018f1f00-0000-7000-8000-0000000000b2")


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


async def _collect_all(collector: RobotsTxtCollector, seed: Seed) -> list[Observation]:
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# ===================================================================
# Metadata tests
# ===================================================================
class TestRobotsTxtCollectorMetadata:
    """Verify class-level metadata attributes."""

    def test_collector_id(self) -> None:
        assert RobotsTxtCollector.collector_id == "robots-txt"

    def test_collector_version(self) -> None:
        assert RobotsTxtCollector.collector_version == "0.1.0"

    def test_tier(self) -> None:
        assert RobotsTxtCollector.tier == CollectorTier.TIER_2

    def test_requires_credentials(self) -> None:
        assert RobotsTxtCollector.requires_credentials is False

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("robots-txt")
        cls = DEFAULT_REGISTRY.get("robots-txt")
        assert cls is RobotsTxtCollector


# ===================================================================
# Seed type filtering
# ===================================================================
class TestRobotsTxtSeedTypes:
    """Only DOMAIN seeds should be accepted."""

    @respx.mock
    async def test_domain_seed_accepted(self) -> None:
        body = "User-agent: *\nDisallow: /admin/\n"
        respx.get("https://example.com/robots.txt").mock(
            return_value=httpx.Response(200, text=body)
        )
        respx.get("http://example.com/robots.txt").mock(return_value=httpx.Response(404))

        collector = RobotsTxtCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))
        # Should get at least the /admin/ observation + summary
        assert len(results) >= 1

    @respx.mock
    async def test_ip_seed_skipped(self) -> None:
        collector = RobotsTxtCollector(_make_config())
        seed = Seed(seed_type=SeedType.IP, value="192.0.2.1")
        results = await _collect_all(collector, seed)
        assert results == []

    @respx.mock
    async def test_asn_seed_skipped(self) -> None:
        collector = RobotsTxtCollector(_make_config())
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        results = await _collect_all(collector, seed)
        assert results == []

    @respx.mock
    async def test_organization_seed_skipped(self) -> None:
        collector = RobotsTxtCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        results = await _collect_all(collector, seed)
        assert results == []


# ===================================================================
# Parsing tests
# ===================================================================
class TestParseRobotsTxt:
    """Test robots.txt body parsing."""

    def test_parse_disallow_directives(self) -> None:
        body = "User-agent: *\nDisallow: /admin/\nDisallow: /private/\n"
        result = parse_robots_txt(body)
        assert result["disallow"] == ["/admin/", "/private/"]

    def test_parse_allow_directives(self) -> None:
        body = "User-agent: *\nAllow: /api/public\nDisallow: /api/\n"
        result = parse_robots_txt(body)
        assert result["allow"] == ["/api/public"]
        assert result["disallow"] == ["/api/"]

    def test_parse_sitemap_directives(self) -> None:
        body = "Sitemap: https://example.com/sitemap.xml\n"
        result = parse_robots_txt(body)
        assert result["sitemap"] == ["https://example.com/sitemap.xml"]

    def test_empty_body(self) -> None:
        result = parse_robots_txt("")
        assert result["disallow"] == []
        assert result["allow"] == []
        assert result["sitemap"] == []

    def test_comments_ignored(self) -> None:
        body = (
            "# This is a comment\n"
            "User-agent: * # another comment\n"
            "Disallow: /secret/ # hidden area\n"
        )
        result = parse_robots_txt(body)
        assert result["disallow"] == ["/secret/"]

    def test_empty_value_directives_skipped(self) -> None:
        body = "User-agent: *\nDisallow:\nDisallow: /real/\n"
        result = parse_robots_txt(body)
        assert result["disallow"] == ["/real/"]

    def test_multiple_user_agent_sections(self) -> None:
        body = (
            "User-agent: Googlebot\nDisallow: /no-google/\n\nUser-agent: *\nDisallow: /private/\n"
        )
        result = parse_robots_txt(body)
        # Both sections' directives collected.
        assert "/no-google/" in result["disallow"]
        assert "/private/" in result["disallow"]

    def test_case_insensitive_directives(self) -> None:
        body = "DISALLOW: /upper/\ndisallow: /lower/\nDisallow: /mixed/\n"
        result = parse_robots_txt(body)
        assert len(result["disallow"]) == 3


# ===================================================================
# Path classification tests
# ===================================================================
class TestPathClassification:
    """Test path classification logic."""

    def test_git_exposure_critical(self) -> None:
        classification, interest = classify_path("/.git/")
        assert classification == "git_exposure"
        assert interest == "critical"

    def test_env_file_critical(self) -> None:
        classification, interest = classify_path("/.env")
        assert classification == "env_file"
        assert interest == "critical"

    def test_svn_exposure_critical(self) -> None:
        classification, interest = classify_path("/.svn/")
        assert classification == "svn_exposure"
        assert interest == "critical"

    def test_debug_endpoint_critical(self) -> None:
        classification, interest = classify_path("/phpinfo.php")
        assert classification == "debug_endpoint"
        assert interest == "critical"

    def test_admin_panel_high(self) -> None:
        classification, interest = classify_path("/admin/")
        assert classification == "admin_panel"
        assert interest == "high"

    def test_wp_admin_high(self) -> None:
        classification, interest = classify_path("/wp-admin/")
        assert classification == "admin_panel"
        assert interest == "high"

    def test_api_endpoint_high(self) -> None:
        classification, interest = classify_path("/api/v1/users")
        assert classification == "api_endpoint"
        assert interest == "high"

    def test_graphql_high(self) -> None:
        classification, interest = classify_path("/graphql")
        assert classification == "api_endpoint"
        assert interest == "high"

    def test_staging_medium(self) -> None:
        classification, interest = classify_path("/staging/")
        assert classification == "non_production"
        assert interest == "medium"

    def test_dev_medium(self) -> None:
        classification, interest = classify_path("/dev/")
        assert classification == "non_production"
        assert interest == "medium"

    def test_test_medium(self) -> None:
        classification, interest = classify_path("/test/")
        assert classification == "non_production"
        assert interest == "medium"

    def test_standard_asset_low(self) -> None:
        classification, interest = classify_path("/images/logo.png")
        assert classification == "standard_asset"
        assert interest == "low"

    def test_css_low(self) -> None:
        classification, interest = classify_path("/css/style.css")
        assert classification == "standard_asset"
        assert interest == "low"

    def test_unknown_path_low(self) -> None:
        classification, interest = classify_path("/some/random/path")
        assert classification == "other"
        assert interest == "low"

    def test_backup_high(self) -> None:
        classification, interest = classify_path("/backup/")
        assert classification == "backup_directory"
        assert interest == "high"

    def test_config_high(self) -> None:
        classification, interest = classify_path("/config/")
        assert classification == "configuration"
        assert interest == "high"


# ===================================================================
# Expand — happy path
# ===================================================================
class TestRobotsTxtExpandHappyPath:
    """Test full expand flow with mocked HTTP."""

    @respx.mock
    async def test_disallow_yields_observations(self) -> None:
        body = (
            "User-agent: *\n"
            "Disallow: /admin/\n"
            "Disallow: /.git/\n"
            "Disallow: /images/\n"  # low interest, should be skipped
        )
        respx.get("https://example.com/robots.txt").mock(
            return_value=httpx.Response(200, text=body)
        )
        respx.get("http://example.com/robots.txt").mock(return_value=httpx.Response(404))

        collector = RobotsTxtCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        # 2 interesting paths + 1 summary observation
        endpoint_obs = [
            r for r in results if r.structured_payload.get("directive") in ("disallow", "allow")
        ]
        assert len(endpoint_obs) == 2

        paths = [o.structured_payload["path"] for o in endpoint_obs]
        assert "/admin/" in paths
        assert "/.git/" in paths
        # /images/ should NOT be included (low interest)
        assert "/images/" not in paths

    @respx.mock
    async def test_allow_yields_observations(self) -> None:
        body = "User-agent: *\nDisallow: /api/\nAllow: /api/public/\n"
        respx.get("https://example.com/robots.txt").mock(
            return_value=httpx.Response(200, text=body)
        )
        respx.get("http://example.com/robots.txt").mock(return_value=httpx.Response(404))

        collector = RobotsTxtCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        endpoint_obs = [
            r for r in results if r.structured_payload.get("directive") in ("disallow", "allow")
        ]
        # Both /api/ (disallow) and /api/public/ (allow) are high interest
        assert len(endpoint_obs) == 2

    @respx.mock
    async def test_sitemap_yields_observation(self) -> None:
        body = "Sitemap: https://example.com/sitemap.xml\n"
        respx.get("https://example.com/robots.txt").mock(
            return_value=httpx.Response(200, text=body)
        )
        respx.get("http://example.com/robots.txt").mock(return_value=httpx.Response(404))

        collector = RobotsTxtCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        sitemap_obs = [r for r in results if r.structured_payload.get("directive") == "sitemap"]
        assert len(sitemap_obs) == 1
        assert sitemap_obs[0].structured_payload["path"] == ("https://example.com/sitemap.xml")

    @respx.mock
    async def test_summary_observation_emitted(self) -> None:
        body = (
            "User-agent: *\n"
            "Disallow: /admin/\n"
            "Allow: /api/public\n"
            "Sitemap: https://example.com/sitemap.xml\n"
        )
        respx.get("https://example.com/robots.txt").mock(
            return_value=httpx.Response(200, text=body)
        )
        respx.get("http://example.com/robots.txt").mock(return_value=httpx.Response(404))

        collector = RobotsTxtCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        summary_obs = [
            r
            for r in results
            if r.structured_payload.get("source") == "robots.txt"
            and "disallow_count" in r.structured_payload
        ]
        assert len(summary_obs) == 1
        assert summary_obs[0].structured_payload["disallow_count"] == 1
        assert summary_obs[0].structured_payload["allow_count"] == 1
        assert summary_obs[0].structured_payload["sitemap_count"] == 1
        assert summary_obs[0].evidence_blob is not None

    @respx.mock
    async def test_observation_subject_is_domain(self) -> None:
        body = "User-agent: *\nDisallow: /admin/\n"
        respx.get("https://example.com/robots.txt").mock(
            return_value=httpx.Response(200, text=body)
        )
        respx.get("http://example.com/robots.txt").mock(return_value=httpx.Response(404))

        collector = RobotsTxtCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        for obs in results:
            assert obs.subject.identifier_type == IdentifierType.DOMAIN
            assert obs.observation_type == ObservationType.HTTP_RESPONSE
            assert obs.tenant_id == TENANT_ID


# ===================================================================
# Expand — edge cases
# ===================================================================
class TestRobotsTxtExpandEdgeCases:
    """Edge cases in the expand flow."""

    @respx.mock
    async def test_404_response_no_observations(self) -> None:
        respx.get("https://example.com/robots.txt").mock(return_value=httpx.Response(404))
        respx.get("http://example.com/robots.txt").mock(return_value=httpx.Response(404))

        collector = RobotsTxtCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))
        assert results == []

    @respx.mock
    async def test_empty_robots_txt_yields_summary_only(self) -> None:
        respx.get("https://example.com/robots.txt").mock(return_value=httpx.Response(200, text=""))
        respx.get("http://example.com/robots.txt").mock(return_value=httpx.Response(404))

        collector = RobotsTxtCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))
        # Only the summary observation (no interesting directives).
        assert len(results) == 1
        assert "disallow_count" in results[0].structured_payload
        assert results[0].structured_payload["disallow_count"] == 0

    @respx.mock
    async def test_https_fails_http_succeeds(self) -> None:
        body = "User-agent: *\nDisallow: /admin/\n"
        respx.get("https://example.com/robots.txt").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        respx.get("http://example.com/robots.txt").mock(return_value=httpx.Response(200, text=body))

        collector = RobotsTxtCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))
        # Should still get results from HTTP fallback.
        assert len(results) >= 1

    @respx.mock
    async def test_both_fail_no_observations(self) -> None:
        respx.get("https://example.com/robots.txt").mock(side_effect=httpx.ConnectError("refused"))
        respx.get("http://example.com/robots.txt").mock(side_effect=httpx.ConnectError("refused"))

        collector = RobotsTxtCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))
        assert results == []


# ===================================================================
# Health check
# ===================================================================
class TestRobotsTxtHealthCheck:
    """Health check tests."""

    @respx.mock
    async def test_healthy_returns_success(self) -> None:
        respx.head("https://www.google.com/robots.txt").mock(return_value=httpx.Response(200))

        collector = RobotsTxtCollector(_make_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "robots-txt"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    async def test_unhealthy_returns_failure(self) -> None:
        respx.head("https://www.google.com/robots.txt").mock(return_value=httpx.Response(503))

        collector = RobotsTxtCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE

    @respx.mock
    async def test_network_error_returns_failure(self) -> None:
        respx.head("https://www.google.com/robots.txt").mock(
            side_effect=httpx.ConnectError("connection refused")
        )

        collector = RobotsTxtCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

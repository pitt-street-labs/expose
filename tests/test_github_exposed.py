"""Tests for the github-exposed collector (Tier 1, Sprint 4).

Exercises GitHub search API logic via ``respx`` mocks — no live network
calls.  Coverage:

1.  Happy path: org repos found
2.  Code search finds domain references
3.  No results: yields observation with empty lists
4.  Rate limited (403): raises CollectorRateLimitError
5.  Health check: success and failure paths
6.  Non-matching seed type skipped
7.  Optional API key passed via credentials
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
from expose.collectors.builtin.github_exposed import GitHubExposedCollector
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus

TENANT_ID = UUID("018f1f00-0000-7000-8000-0000000a0b01")
RUN_ID = UUID("018f1f00-0000-7000-8000-0000000a0b02")


def _config(
    api_key: str | None = None,
    **extra: object,
) -> CollectorConfig:
    creds: dict[str, CollectorCredential] = {}
    if api_key:
        creds["api_key"] = CollectorCredential(name="api_key", secret_value=api_key)
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=5.0,
        credentials=creds,
        extra=dict(extra),  # type: ignore[arg-type]
    )


async def _collect(
    seed: Seed, config: CollectorConfig | None = None
) -> list[Observation]:
    cfg = config or _config()
    collector = GitHubExposedCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# Canned GitHub API responses.
_REPO_SEARCH_RESPONSE = {
    "total_count": 2,
    "incomplete_results": False,
    "items": [
        {
            "full_name": "acme/infra-config",
            "description": "Infrastructure configuration",
            "html_url": "https://github.com/acme/infra-config",
            "stargazers_count": 5,
            "updated_at": "2026-01-15T10:00:00Z",
        },
        {
            "full_name": "acme/webapp",
            "description": "Main web application",
            "html_url": "https://github.com/acme/webapp",
            "stargazers_count": 12,
            "updated_at": "2026-03-20T14:30:00Z",
        },
    ],
}

_CODE_SEARCH_RESPONSE = {
    "total_count": 1,
    "incomplete_results": False,
    "items": [
        {
            "path": "config/production.yml",
            "html_url": "https://github.com/acme/webapp/blob/main/config/production.yml",
            "repository": {
                "full_name": "acme/webapp",
            },
        },
    ],
}

_EMPTY_SEARCH_RESPONSE = {
    "total_count": 0,
    "incomplete_results": False,
    "items": [],
}


# ======================================================================
# 1. Happy path — org repos found
# ======================================================================
class TestHappyPathOrgRepos:
    @respx.mock
    @pytest.mark.asyncio
    async def test_org_seed_yields_observation_with_repos(self) -> None:
        """Organization seed finds repos and returns observation."""
        respx.get(
            "https://api.github.com/search/repositories",
            params__contains={"q": "org:acme"},
        ).mock(
            return_value=httpx.Response(
                200, json=_REPO_SEARCH_RESPONSE
            )
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="acme")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.observation_type == ObservationType.SCANNER_HOST
        assert obs.collector_id == "github-exposed"
        assert obs.collector_version == "0.1.0"
        assert obs.tenant_id == TENANT_ID

    @respx.mock
    @pytest.mark.asyncio
    async def test_org_payload_contains_repos(self) -> None:
        """Payload contains repository list with expected fields."""
        respx.get(
            "https://api.github.com/search/repositories",
            params__contains={"q": "org:acme"},
        ).mock(
            return_value=httpx.Response(
                200, json=_REPO_SEARCH_RESPONSE
            )
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="acme")
        observations = await _collect(seed)

        payload = observations[0].structured_payload
        assert payload["source"] == "github"
        assert payload["search_type"] == "repository"
        assert payload["total_results"] == 2
        assert len(payload["repositories"]) == 2
        assert payload["repositories"][0]["full_name"] == "acme/infra-config"
        assert payload["repositories"][1]["stars"] == 12


# ======================================================================
# 2. Code search finds domain references
# ======================================================================
class TestCodeSearch:
    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_seed_searches_code(self) -> None:
        """Domain seed triggers both repo and code search."""
        respx.get(
            "https://api.github.com/search/repositories",
        ).mock(
            return_value=httpx.Response(
                200, json=_REPO_SEARCH_RESPONSE
            )
        )
        respx.get(
            "https://api.github.com/search/code",
        ).mock(
            return_value=httpx.Response(
                200, json=_CODE_SEARCH_RESPONSE
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert payload["search_type"] == "code"
        assert payload["total_results"] == 3  # 2 repo + 1 code
        assert len(payload["code_matches"]) == 1
        assert payload["code_matches"][0]["repository"] == "acme/webapp"
        assert payload["code_matches"][0]["path"] == "config/production.yml"


# ======================================================================
# 3. No results — yields observation with empty lists
# ======================================================================
class TestNoResults:
    @respx.mock
    @pytest.mark.asyncio
    async def test_no_results_still_yields_observation(self) -> None:
        """Even with zero results, an observation is emitted."""
        respx.get("https://api.github.com/search/repositories").mock(
            return_value=httpx.Response(
                200, json=_EMPTY_SEARCH_RESPONSE
            )
        )
        respx.get("https://api.github.com/search/code").mock(
            return_value=httpx.Response(
                200, json=_EMPTY_SEARCH_RESPONSE
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="obscure-domain.example")
        observations = await _collect(seed)

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert payload["total_results"] == 0
        assert payload["repositories"] == []
        assert payload["code_matches"] == []


# ======================================================================
# 4. Rate limited (403) — raises CollectorRateLimitError
# ======================================================================
class TestRateLimit:
    @respx.mock
    @pytest.mark.asyncio
    async def test_403_raises_rate_limit_error(self) -> None:
        """GitHub 403 response raises CollectorRateLimitError."""
        respx.get("https://api.github.com/search/repositories").mock(
            return_value=httpx.Response(
                403,
                json={"message": "API rate limit exceeded"},
            )
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="acme")
        with pytest.raises(CollectorRateLimitError, match="rate limited"):
            await _collect(seed)

    @respx.mock
    @pytest.mark.asyncio
    async def test_code_search_403_raises_rate_limit(self) -> None:
        """Code search 403 also raises CollectorRateLimitError."""
        respx.get("https://api.github.com/search/repositories").mock(
            return_value=httpx.Response(
                200, json=_REPO_SEARCH_RESPONSE
            )
        )
        respx.get("https://api.github.com/search/code").mock(
            return_value=httpx.Response(
                403,
                json={"message": "API rate limit exceeded"},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        with pytest.raises(CollectorRateLimitError):
            await _collect(seed)


# ======================================================================
# 5. Health check
# ======================================================================
class TestHealthCheck:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Successful /zen response returns SUCCESS status."""
        respx.get("https://api.github.com/zen").mock(
            return_value=httpx.Response(200, text="Responsive is better than fast.")
        )

        collector = GitHubExposedCollector(_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "github-exposed"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_error(self) -> None:
        """Connection error returns FAILURE status with error message."""
        respx.get("https://api.github.com/zen").mock(
            side_effect=httpx.ConnectError("DNS resolution failed")
        )

        collector = GitHubExposedCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_5xx(self) -> None:
        """A 500 response means FAILURE."""
        respx.get("https://api.github.com/zen").mock(
            return_value=httpx.Response(500)
        )

        collector = GitHubExposedCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE


# ======================================================================
# 6. Non-matching seed type skipped
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


# ======================================================================
# 7. Optional API key via credentials
# ======================================================================
class TestApiKeyCredential:
    @respx.mock
    @pytest.mark.asyncio
    async def test_api_key_passed_in_authorization_header(self) -> None:
        """When api_key credential is provided, Authorization header is set."""
        route = respx.get("https://api.github.com/search/repositories").mock(
            return_value=httpx.Response(
                200, json=_REPO_SEARCH_RESPONSE
            )
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="acme")
        cfg = _config(api_key="ghp_test1234567890")
        await _collect(seed, cfg)

        # Verify the Authorization header was sent.
        assert route.called
        request = route.calls[0].request
        assert "Authorization" in request.headers
        assert request.headers["Authorization"] == "Bearer ghp_test1234567890"


# ======================================================================
# Collector metadata
# ======================================================================
class TestCollectorMetadata:
    def test_collector_class_attributes(self) -> None:
        assert GitHubExposedCollector.collector_id == "github-exposed"
        assert GitHubExposedCollector.collector_version == "0.1.0"
        assert GitHubExposedCollector.tier == CollectorTier.TIER_1
        assert GitHubExposedCollector.requires_credentials is False

    def test_collector_is_subclass_of_collector_abc(self) -> None:
        assert issubclass(GitHubExposedCollector, Collector)


# ======================================================================
# Registry
# ======================================================================
class TestRegistration:
    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("github-exposed")
        cls = DEFAULT_REGISTRY.get("github-exposed")
        assert cls is GitHubExposedCollector

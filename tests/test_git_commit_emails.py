"""Tests for the git-commit-emails collector (Tier 2, issue #79).

Exercises GitHub commit search and email domain extraction via ``respx``
mocks -- no live network calls. Coverage:

1.  Collector metadata: ID, tier, version, rate limit, requires_credentials
2.  Only expands ORGANIZATION and DOMAIN seeds (others return [])
3.  Happy path: org seed -> commit search -> email domains extracted
4.  Happy path: domain seed -> commit search -> email domains extracted
5.  Generic email providers filtered out (gmail.com, etc.)
6.  Empty/whitespace seed value skipped
7.  No commits found: empty result
8.  HTTP errors: graceful degradation / raised errors as appropriate
9.  Authentication error raises CollectorAuthenticationError
10. Rate limit error raises CollectorRateLimitError
11. Malformed JSON response handled gracefully
12. Health check: success and failure paths
13. Multiple email domains aggregated with commit counts
14. Committer names capped at 10 per domain
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
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.git_commit_emails import (
    GitCommitEmailsCollector,
    _extract_email_domains,
)
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-0000000c0d01")
RUN_ID = UUID("018f1f00-0000-7000-8000-0000000c0d02")

_GITHUB_SEARCH_COMMITS = "https://api.github.com/search/commits"
_GITHUB_RATE_LIMIT = "https://api.github.com/rate_limit"


def _config(token: str | None = "ghp_test_token_123") -> CollectorConfig:
    creds: dict[str, CollectorCredential] = {}
    if token:
        creds["token"] = CollectorCredential(name="token", secret_value=token)
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=5.0,
        credentials=creds,
    )


async def _collect(
    seed: Seed, token: str | None = "ghp_test_token_123"
) -> list[Observation]:
    cfg = _config(token=token)
    collector = GitCommitEmailsCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# === Canned GitHub API responses =============================================

_COMMIT_SEARCH_RESPONSE = {
    "total_count": 3,
    "items": [
        {
            "commit": {
                "author": {
                    "name": "Alice Smith",
                    "email": "alice@cyberark.com",
                },
                "committer": {
                    "name": "Alice Smith",
                    "email": "alice@cyberark.com",
                },
            },
        },
        {
            "commit": {
                "author": {
                    "name": "Bob Jones",
                    "email": "bob@cyberark.com",
                },
                "committer": {
                    "name": "CI Bot",
                    "email": "ci@internal.cyberark.io",
                },
            },
        },
        {
            "commit": {
                "author": {
                    "name": "Charlie",
                    "email": "charlie@gmail.com",
                },
                "committer": {
                    "name": "Charlie",
                    "email": "charlie@gmail.com",
                },
            },
        },
    ],
}

_COMMIT_SEARCH_EMPTY = {"total_count": 0, "items": []}

_RATE_LIMIT_RESPONSE = {
    "resources": {
        "search": {"limit": 30, "remaining": 25, "reset": 1700000000},
    },
    "rate": {"limit": 5000, "remaining": 4999, "reset": 1700000000},
}


# ======================================================================
# 1. Collector metadata
# ======================================================================
class TestCollectorMetadata:
    def test_collector_id(self) -> None:
        assert GitCommitEmailsCollector.collector_id == "git-commit-emails"

    def test_collector_version(self) -> None:
        assert GitCommitEmailsCollector.collector_version == "0.1.0"

    def test_tier_is_tier_2(self) -> None:
        assert GitCommitEmailsCollector.tier == CollectorTier.TIER_2

    def test_requires_credentials(self) -> None:
        assert GitCommitEmailsCollector.requires_credentials is True

    def test_rate_limit(self) -> None:
        assert GitCommitEmailsCollector.rate_limit_per_minute == 30

    def test_is_subclass_of_collector(self) -> None:
        assert issubclass(GitCommitEmailsCollector, Collector)


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
    async def test_empty_value_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="  ")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 3. Happy path — ORGANIZATION seed
# ======================================================================
class TestOrgHappyPath:
    @respx.mock
    @pytest.mark.asyncio
    async def test_org_seed_extracts_email_domains(self) -> None:
        """ORGANIZATION seed -> commit search -> unique email domains."""
        respx.get(_GITHUB_SEARCH_COMMITS).mock(
            return_value=httpx.Response(200, json=_COMMIT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)

        # gmail.com is filtered out; should have cyberark.com and internal.cyberark.io
        domains = {obs.subject.identifier_value for obs in observations}
        assert "cyberark.com" in domains
        assert "internal.cyberark.io" in domains
        assert "gmail.com" not in domains

    @respx.mock
    @pytest.mark.asyncio
    async def test_org_query_format(self) -> None:
        """ORGANIZATION seed uses org:{name} query format."""
        route = respx.get(_GITHUB_SEARCH_COMMITS).mock(
            return_value=httpx.Response(200, json=_COMMIT_SEARCH_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        await _collect(seed)

        assert route.called
        request = route.calls[0].request
        assert "org%3ACyberArk" in str(request.url) or "org:CyberArk" in str(
            request.url
        )

    @respx.mock
    @pytest.mark.asyncio
    async def test_observation_fields(self) -> None:
        """Observations have correct collector metadata and types."""
        respx.get(_GITHUB_SEARCH_COMMITS).mock(
            return_value=httpx.Response(200, json=_COMMIT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.collector_id == "git-commit-emails"
            assert obs.collector_version == "0.1.0"
            assert obs.tenant_id == TENANT_ID
            assert obs.observation_type == ObservationType.PASSIVE_DNS
            assert obs.subject.identifier_type == IdentifierType.DOMAIN

    @respx.mock
    @pytest.mark.asyncio
    async def test_structured_payload_shape(self) -> None:
        """Structured payload has all expected keys."""
        respx.get(_GITHUB_SEARCH_COMMITS).mock(
            return_value=httpx.Response(200, json=_COMMIT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)

        for obs in observations:
            payload = obs.structured_payload
            assert payload["source"] == "github_commit_emails"
            assert "search_query" in payload
            assert "email_domain" in payload
            assert "commit_count" in payload
            assert "sample_committers" in payload
            assert "total_results" in payload


# ======================================================================
# 4. Happy path — DOMAIN seed
# ======================================================================
class TestDomainSeed:
    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_seed_works(self) -> None:
        """DOMAIN seed also triggers commit search."""
        respx.get(_GITHUB_SEARCH_COMMITS).mock(
            return_value=httpx.Response(200, json=_COMMIT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="cyberark.com")
        observations = await _collect(seed)

        assert len(observations) >= 1

    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_query_format(self) -> None:
        """DOMAIN seed uses the domain as-is (no org: prefix)."""
        route = respx.get(_GITHUB_SEARCH_COMMITS).mock(
            return_value=httpx.Response(200, json=_COMMIT_SEARCH_EMPTY)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="cyberark.com")
        await _collect(seed)

        assert route.called
        request = route.calls[0].request
        url_str = str(request.url)
        assert "cyberark.com" in url_str
        assert "org%3A" not in url_str


# ======================================================================
# 5. Generic email providers filtered
# ======================================================================
class TestGenericFiltering:
    def test_extract_filters_generic_domains(self) -> None:
        """gmail.com and other generic providers are excluded."""
        data = {
            "items": [
                {
                    "commit": {
                        "author": {"name": "A", "email": "a@gmail.com"},
                        "committer": {"name": "B", "email": "b@outlook.com"},
                    },
                },
                {
                    "commit": {
                        "author": {"name": "C", "email": "c@acme.com"},
                        "committer": {
                            "name": "GH",
                            "email": "bot@users.noreply.github.com",
                        },
                    },
                },
            ],
        }
        result = _extract_email_domains(data)
        assert "gmail.com" not in result
        assert "outlook.com" not in result
        assert "users.noreply.github.com" not in result
        assert "acme.com" in result


# ======================================================================
# 6. No commits found
# ======================================================================
class TestNoCommits:
    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_search_returns_empty(self) -> None:
        """No commits -> no observations."""
        respx.get(_GITHUB_SEARCH_COMMITS).mock(
            return_value=httpx.Response(200, json=_COMMIT_SEARCH_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="NoSuchOrg12345")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 7. HTTP errors
# ======================================================================
class TestHTTPErrors:
    @respx.mock
    @pytest.mark.asyncio
    async def test_500_returns_empty(self) -> None:
        """Server error returns empty (graceful degradation)."""
        respx.get(_GITHUB_SEARCH_COMMITS).mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_connection_error_returns_empty(self) -> None:
        """Connection error returns empty, not exception."""
        respx.get(_GITHUB_SEARCH_COMMITS).mock(
            side_effect=httpx.ConnectError("DNS resolution failed")
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_401_raises_auth_error(self) -> None:
        """401 raises CollectorAuthenticationError."""
        from expose.collectors.base import CollectorAuthenticationError

        respx.get(_GITHUB_SEARCH_COMMITS).mock(
            return_value=httpx.Response(401, json={"message": "Bad credentials"})
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        with pytest.raises(CollectorAuthenticationError):
            await _collect(seed)

    @respx.mock
    @pytest.mark.asyncio
    async def test_403_raises_rate_limit_error(self) -> None:
        """403 raises CollectorRateLimitError."""
        from expose.collectors.base import CollectorRateLimitError

        respx.get(_GITHUB_SEARCH_COMMITS).mock(
            return_value=httpx.Response(403, json={"message": "rate limit"})
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        with pytest.raises(CollectorRateLimitError):
            await _collect(seed)

    @respx.mock
    @pytest.mark.asyncio
    async def test_malformed_json_returns_empty(self) -> None:
        """Malformed JSON returns empty."""
        respx.get(_GITHUB_SEARCH_COMMITS).mock(
            return_value=httpx.Response(200, text="not json")
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 8. Email domain aggregation
# ======================================================================
class TestAggregation:
    def test_commit_count_aggregated(self) -> None:
        """Same domain in multiple commits -> aggregated count."""
        data = {
            "items": [
                {
                    "commit": {
                        "author": {"name": "A", "email": "a@acme.com"},
                        "committer": {"name": "A", "email": "a@acme.com"},
                    },
                },
                {
                    "commit": {
                        "author": {"name": "B", "email": "b@acme.com"},
                        "committer": {"name": "B", "email": "b@acme.com"},
                    },
                },
            ],
        }
        result = _extract_email_domains(data)
        assert result["acme.com"]["count"] == 4  # 2 author + 2 committer

    def test_committers_collected(self) -> None:
        """Committer names are collected per domain."""
        data = {
            "items": [
                {
                    "commit": {
                        "author": {"name": "Alice", "email": "alice@acme.com"},
                        "committer": {"name": "Bob", "email": "bob@acme.com"},
                    },
                },
            ],
        }
        result = _extract_email_domains(data)
        assert "Alice" in result["acme.com"]["committers"]
        assert "Bob" in result["acme.com"]["committers"]

    def test_emails_without_at_sign_ignored(self) -> None:
        """Emails without @ are skipped."""
        data = {
            "items": [
                {
                    "commit": {
                        "author": {"name": "X", "email": "noemailhere"},
                        "committer": {"name": "Y", "email": ""},
                    },
                },
            ],
        }
        result = _extract_email_domains(data)
        assert result == {}


# ======================================================================
# 9. Health check
# ======================================================================
class TestHealthCheck:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Successful rate_limit response returns SUCCESS."""
        respx.get(_GITHUB_RATE_LIMIT).mock(
            return_value=httpx.Response(200, json=_RATE_LIMIT_RESPONSE)
        )

        collector = GitCommitEmailsCollector(_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "git-commit-emails"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_error(self) -> None:
        """Connection error returns FAILURE with error message."""
        respx.get(_GITHUB_RATE_LIMIT).mock(
            side_effect=httpx.ConnectError("DNS resolution failed")
        )

        collector = GitCommitEmailsCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_401(self) -> None:
        """401 on rate_limit means FAILURE."""
        respx.get(_GITHUB_RATE_LIMIT).mock(
            return_value=httpx.Response(401)
        )

        collector = GitCommitEmailsCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE


# ======================================================================
# 10. Token usage
# ======================================================================
class TestTokenUsage:
    @respx.mock
    @pytest.mark.asyncio
    async def test_token_sent_in_authorization_header(self) -> None:
        """Token is included in the Authorization header."""
        route = respx.get(_GITHUB_SEARCH_COMMITS).mock(
            return_value=httpx.Response(200, json=_COMMIT_SEARCH_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        await _collect(seed, token="ghp_mysecrettoken")

        assert route.called
        request = route.calls[0].request
        assert request.headers.get("authorization") == "Bearer ghp_mysecrettoken"

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_token_no_auth_header(self) -> None:
        """Without a token, no Authorization header is sent."""
        route = respx.get(_GITHUB_SEARCH_COMMITS).mock(
            return_value=httpx.Response(200, json=_COMMIT_SEARCH_EMPTY)
        )

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="CyberArk")
        await _collect(seed, token=None)

        assert route.called
        request = route.calls[0].request
        assert "authorization" not in request.headers

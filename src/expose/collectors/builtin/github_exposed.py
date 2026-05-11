"""GitHub exposed-data collector (Tier 1, passive, broad).

Searches the public GitHub REST API (v3) for repositories and code
belonging to or mentioning the target organization or domain.  Reveals:

- Organization repositories with potential config files, internal
  hostnames, API endpoints.
- Public repositories mentioning the domain in code or configuration.
- Potential leaked credential indicators in commit history (metadata
  only — we flag the repository, we do NOT extract secrets).

No credentials required for basic public search, but an optional
``api_key`` credential slot increases the rate limit from 10 to 30
requests per minute.

Seed types: DOMAIN, ORGANIZATION.  Other seed types are skipped silently.

Rate limiting: GitHub's unauthenticated search API permits 10 requests
per minute.  This collector makes at most 2 requests per expand() call
(one repo search, one code search), well within budget for a single
invocation.  The framework-level rate limiter gates concurrent calls.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, ClassVar

import httpx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorError,
    CollectorHealthCheck,
    CollectorRateLimitError,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import register_collector
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

_GITHUB_API_BASE = "https://api.github.com"
_GITHUB_SEARCH_REPOS = f"{_GITHUB_API_BASE}/search/repositories"
_GITHUB_SEARCH_CODE = f"{_GITHUB_API_BASE}/search/code"

# Health-check endpoint.
_HEALTH_CHECK_URL = f"{_GITHUB_API_BASE}/zen"

# Maximum number of results to include in the observation payload.
_MAX_REPO_RESULTS = 20
_MAX_CODE_RESULTS = 20

# Code search file extensions of interest.
_CODE_EXTENSIONS = ("yml", "yaml", "json", "env", "toml", "ini", "cfg", "conf")


def _build_headers(api_key: str | None = None) -> dict[str, str]:
    """Build request headers for GitHub API calls."""
    headers: dict[str, str] = {
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _extract_repos(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract a summary list of repositories from a search response."""
    items = data.get("items", [])
    repos: list[dict[str, Any]] = []
    for item in items[:_MAX_REPO_RESULTS]:
        repos.append(
            {
                "full_name": item.get("full_name", ""),
                "description": item.get("description"),
                "html_url": item.get("html_url", ""),
                "stars": item.get("stargazers_count", 0),
                "updated_at": item.get("updated_at", ""),
            }
        )
    return repos


def _extract_code_matches(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract a summary list of code matches from a search response."""
    items = data.get("items", [])
    matches: list[dict[str, Any]] = []
    for item in items[:_MAX_CODE_RESULTS]:
        repo = item.get("repository", {})
        matches.append(
            {
                "repository": repo.get("full_name", ""),
                "path": item.get("path", ""),
                "html_url": item.get("html_url", ""),
            }
        )
    return matches


@register_collector
class GitHubExposedCollector(Collector):
    """Tier-1 passive GitHub exposed-data collector.

    Searches the public GitHub API for repositories and code referencing
    the target domain or organization.
    """

    collector_id: str = "github-exposed"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    technique_ids: ClassVar[list[str]] = ["T1593.003"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        # Optional API key for increased rate limits.
        api_key_cred = self.config.credentials.get("api_key")
        self._api_key: str | None = api_key_cred.secret_value if api_key_cred else None

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Search GitHub for the seed and yield an observation with results."""
        if seed.seed_type not in {SeedType.DOMAIN, SeedType.ORGANIZATION}:
            return

        search_value = seed.value.strip()

        headers = _build_headers(self._api_key)
        repos: list[dict[str, Any]] = []
        code_matches: list[dict[str, Any]] = []
        total_results = 0
        warnings_list: list[str] = []

        async with httpx.AsyncClient(
            timeout=self.config.request_timeout_seconds,
            headers={
                "User-Agent": self.config.user_agent,
                **headers,
            },
        ) as client:
            # Repository search.
            repo_query = (
                f"org:{search_value}"
                if seed.seed_type == SeedType.ORGANIZATION
                else search_value
            )
            try:
                repo_data = await self._search(
                    client, _GITHUB_SEARCH_REPOS, repo_query
                )
                repos = _extract_repos(repo_data)
                total_results += repo_data.get("total_count", 0)
            except CollectorRateLimitError:
                raise
            except CollectorError as exc:
                warnings_list.append(f"repo search failed: {exc}")

            # Code search (domain seeds only — org seeds use repo search).
            if seed.seed_type == SeedType.DOMAIN:
                ext_parts = " ".join(
                    f"extension:{ext}" for ext in _CODE_EXTENSIONS
                )
                code_query = f"{search_value} {ext_parts}"
                try:
                    code_data = await self._search(
                        client, _GITHUB_SEARCH_CODE, code_query
                    )
                    code_matches = _extract_code_matches(code_data)
                    total_results += code_data.get("total_count", 0)
                except CollectorRateLimitError:
                    raise
                except CollectorError as exc:
                    warnings_list.append(f"code search failed: {exc}")

        # Determine identifier for the observation subject.
        if seed.seed_type == SeedType.DOMAIN:
            id_type = IdentifierType.DOMAIN
            id_value = search_value.lower()
        else:
            id_type = IdentifierType.DOMAIN
            id_value = search_value

        search_type = (
            "repository"
            if seed.seed_type == SeedType.ORGANIZATION
            else "code"
        )

        yield Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.SCANNER_HOST,
            subject=ObservationSubject(
                identifier_type=id_type,
                identifier_value=id_value,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload={
                "source": "github",
                "search_type": search_type,
                "total_results": total_results,
                "repositories": repos,
                "code_matches": code_matches,
            },
            warnings=warnings_list,
        )

    async def _search(
        self,
        client: httpx.AsyncClient,
        url: str,
        query: str,
    ) -> dict[str, Any]:
        """Execute a GitHub search API call and return parsed JSON."""
        try:
            resp = await client.get(url, params={"q": query, "per_page": 20})
        except httpx.HTTPError as exc:
            msg = f"GitHub API request failed: {exc}"
            raise CollectorError(msg) from exc

        if resp.status_code == 403:  # noqa: PLR2004
            msg = f"GitHub API rate limited (403) for query {query!r}"
            raise CollectorRateLimitError(msg)

        if resp.status_code != 200:  # noqa: PLR2004
            msg = (
                f"GitHub API returned HTTP {resp.status_code} "
                f"for query {query!r}"
            )
            raise CollectorError(msg)

        try:
            data: dict[str, Any] = resp.json()
        except Exception as exc:
            msg = f"GitHub API returned malformed JSON for query {query!r}"
            raise CollectorError(msg) from exc

        return data

    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe using GitHub's /zen endpoint."""
        start = time.monotonic()
        try:
            headers = _build_headers(self._api_key)
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    _HEALTH_CHECK_URL,
                    headers=headers,
                    timeout=self.config.request_timeout_seconds,
                )
            latency = (time.monotonic() - start) * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=(
                    CollectorStatus.SUCCESS
                    if resp.status_code < 400  # noqa: PLR2004
                    else CollectorStatus.FAILURE
                ),
                checked_at=datetime.now(tz=UTC),
                latency_ms=latency,
            )
        except Exception as exc:
            latency = (time.monotonic() - start) * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                latency_ms=latency,
                error_message=str(exc),
            )


__all__ = [
    "GitHubExposedCollector",
]

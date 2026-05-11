"""Git commit email domain discovery collector (Tier 2, passive).

Searches the GitHub Commits Search API for commits associated with a target
organization or domain, then extracts unique committer email domains from
the results.  These domains may reveal:

- Internal email domains used by the organization's developers.
- Contractor or partner domains contributing to org repositories.
- Shadow domains (personal emails, side-project domains) linked to
  the organization's codebase.

Workflow:

1. **Seed resolution** — for ORGANIZATION seeds, search commits via
   ``org:{name}``; for DOMAIN seeds, search for the domain string in
   commit metadata.
2. **Email extraction** — parse ``commit.author.email`` and
   ``commit.committer.email`` from each search result.
3. **Domain aggregation** — extract the domain portion of each email
   (right side of ``@``), deduplicate, and filter generic providers.
4. **Observation emission** — one ``Observation`` per unique email
   domain with commit count, sample committer names, and search context.

Seed types: ORGANIZATION, DOMAIN.  Other seed types are skipped silently.

Requires credentials: ``token`` credential slot for GitHub API authentication
(the Commits Search API requires authentication).

Rate limiting: ``rate_limit_per_minute = 30``.  The GitHub search API is
heavily rate-limited for authenticated users; we stay conservative.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx

from expose.collectors.base import (
    Collector,
    CollectorAuthenticationError,
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
_GITHUB_SEARCH_COMMITS = f"{_GITHUB_API_BASE}/search/commits"
_GITHUB_RATE_LIMIT = f"{_GITHUB_API_BASE}/rate_limit"

# Maximum number of search result items to process per query.
_MAX_RESULTS = 100

# Generic free-email providers whose domains are uninteresting for
# attack-surface discovery.
_GENERIC_EMAIL_DOMAINS: frozenset[str] = frozenset({
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "live.com",
    "icloud.com",
    "protonmail.com",
    "proton.me",
    "aol.com",
    "mail.com",
    "users.noreply.github.com",
    "users.noreply.github.enterprise.com",
})


def _build_headers(token: str | None = None) -> dict[str, str]:
    """Build request headers for GitHub API calls."""
    headers: dict[str, str] = {
        "Accept": "application/vnd.github.cloak-preview+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _extract_email_domains(
    data: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Extract unique email domains from commit search results.

    Returns a dict mapping domain -> {"count": int, "committers": set[str]}.
    """
    items = data.get("items", [])
    domain_info: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "committers": set()}
    )

    for item in items[:_MAX_RESULTS]:
        commit = item.get("commit", {})
        for role in ("author", "committer"):
            person = commit.get(role, {})
            email = person.get("email", "")
            name = person.get("name", "")
            if not email or "@" not in email:
                continue
            domain = email.rsplit("@", 1)[1].lower().strip()
            if not domain or domain in _GENERIC_EMAIL_DOMAINS:
                continue
            domain_info[domain]["count"] += 1
            if name:
                domain_info[domain]["committers"].add(name)

    return dict(domain_info)


@register_collector
class GitCommitEmailsCollector(Collector):
    """Tier-2 passive git commit email domain discovery collector.

    Searches GitHub commits for the target and emits one observation per
    unique email domain found in commit metadata.
    """

    collector_id: str = "git-commit-emails"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_2
    requires_credentials: bool = True
    rate_limit_per_minute: int | None = 30

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        token_cred = self.config.credentials.get("token")
        self._token: str | None = (
            token_cred.secret_value if token_cred else None
        )

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Search GitHub commits and yield domain observations."""
        if seed.seed_type not in (SeedType.ORGANIZATION, SeedType.DOMAIN):
            return

        search_value = seed.value.strip()
        if not search_value:
            return

        warnings_list: list[str] = []

        # Build query based on seed type.
        if seed.seed_type == SeedType.ORGANIZATION:
            query = f"org:{search_value}"
        else:
            query = search_value

        headers = _build_headers(self._token)

        async with httpx.AsyncClient(
            timeout=self.config.request_timeout_seconds,
            headers={
                "User-Agent": self.config.user_agent,
                **headers,
            },
        ) as client:
            try:
                resp = await client.get(
                    _GITHUB_SEARCH_COMMITS,
                    params={"q": query, "per_page": 100},
                )
            except httpx.HTTPError as exc:
                warnings_list.append(f"GitHub commit search failed: {exc}")
                return

            if resp.status_code == 401:  # noqa: PLR2004
                msg = "GitHub API authentication failed"
                raise CollectorAuthenticationError(msg)

            if resp.status_code == 403:  # noqa: PLR2004
                msg = f"GitHub API rate limited (403) for query {query!r}"
                raise CollectorRateLimitError(msg)

            if resp.status_code != 200:  # noqa: PLR2004
                warnings_list.append(
                    f"GitHub commit search returned HTTP {resp.status_code}"
                )
                return

            try:
                data: dict[str, Any] = resp.json()
            except Exception:
                warnings_list.append(
                    "GitHub commit search returned malformed JSON"
                )
                return

        domain_info = _extract_email_domains(data)

        if not domain_info:
            return

        for domain, info in domain_info.items():
            # Cap committer names to avoid oversized payloads.
            committers = sorted(info["committers"])[:10]

            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.PASSIVE_DNS,
                subject=ObservationSubject(
                    identifier_type=IdentifierType.DOMAIN,
                    identifier_value=domain,
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "source": "github_commit_emails",
                    "search_query": query,
                    "email_domain": domain,
                    "commit_count": info["count"],
                    "sample_committers": committers,
                    "total_results": data.get("total_count", 0),
                },
                warnings=warnings_list,
            )

    async def health_check(self) -> CollectorHealthCheck:
        """Check GitHub API reachability and token validity via /rate_limit."""
        start = time.monotonic()
        try:
            headers = _build_headers(self._token)
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    _GITHUB_RATE_LIMIT,
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
    "GitCommitEmailsCollector",
]

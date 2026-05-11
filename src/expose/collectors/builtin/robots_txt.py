"""robots.txt endpoint discovery collector (Tier 2, per SPEC §6.3).

Fetches ``/robots.txt`` from target domains over HTTPS and HTTP, then parses
``Disallow:``, ``Allow:``, and ``Sitemap:`` directives to discover endpoints
and classify them by security interest level.

This is a Tier-2 (passive-targeted) collector.  It queries the target directly
but only requests the publicly-published ``robots.txt`` file — no probing,
fuzzing, or crawling.

Seed types: DOMAIN only.  Other seed types are skipped.

Dependencies
------------
- ``httpx`` (in project deps) for async HTTP.
"""

from __future__ import annotations

import logging
import re
import time
import warnings as _warnings_mod
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorHealthCheck,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import register_collector
from expose.collectors.tiers import CollectorTier
from expose.sanitization.canonicalize import canonicalize_domain
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Path classification rules
# ---------------------------------------------------------------------------
# Each tuple: (compiled regex, classification label, interest level).
# Order matters — first match wins.
SENSITIVE_PATHS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\.git", re.IGNORECASE), "git_exposure", "critical"),
    (re.compile(r"\.env", re.IGNORECASE), "env_file", "critical"),
    (re.compile(r"\.svn", re.IGNORECASE), "svn_exposure", "critical"),
    (
        re.compile(r"debug|trace|phpinfo|server-status", re.IGNORECASE),
        "debug_endpoint",
        "critical",
    ),
    (
        re.compile(r"admin|wp-admin|dashboard|panel|console|manager", re.IGNORECASE),
        "admin_panel",
        "high",
    ),
    (re.compile(r"api|graphql|v[0-9]+", re.IGNORECASE), "api_endpoint", "high"),
    (re.compile(r"backup", re.IGNORECASE), "backup_directory", "high"),
    (
        re.compile(r"internal|private|intranet|corp", re.IGNORECASE),
        "internal_resource",
        "high",
    ),
    (re.compile(r"config|settings|setup", re.IGNORECASE), "configuration", "high"),
    (re.compile(r"upload|uploads|files", re.IGNORECASE), "file_upload", "medium"),
    (
        re.compile(r"staging|dev|test|uat|sandbox|preprod", re.IGNORECASE),
        "non_production",
        "medium",
    ),
    (
        re.compile(r"cgi-bin|servlet|xmlrpc", re.IGNORECASE),
        "legacy_endpoint",
        "medium",
    ),
]

# Standard/low-interest paths — matched paths are tagged LOW and typically
# skipped or merely noted.
_LOW_INTEREST_RE = re.compile(
    r"^/(images|css|js|static|assets|fonts|media|favicon)\b", re.IGNORECASE
)


def classify_path(path: str) -> tuple[str, str]:
    """Classify a robots.txt path by security interest.

    Returns ``(classification, interest_level)`` where interest_level is one
    of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
    """
    for pattern, classification, interest in SENSITIVE_PATHS:
        if pattern.search(path):
            return classification, interest

    if _LOW_INTEREST_RE.search(path):
        return "standard_asset", "low"

    return "other", "low"


# ---------------------------------------------------------------------------
# robots.txt line parser
# ---------------------------------------------------------------------------
def parse_robots_txt(body: str) -> dict[str, list[str]]:
    """Parse a robots.txt body into directive lists.

    Returns a dict with keys ``"disallow"``, ``"allow"``, ``"sitemap"``,
    each containing a list of path/URL strings.
    """
    result: dict[str, list[str]] = {
        "disallow": [],
        "allow": [],
        "sitemap": [],
    }

    for raw_line in body.splitlines():
        # Strip comments.
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        # Split on first colon.
        if ":" not in line:
            continue
        directive, _, value = line.partition(":")
        directive = directive.strip().lower()
        value = value.strip()

        if not value:
            continue

        if directive == "disallow":
            result["disallow"].append(value)
        elif directive == "allow":
            result["allow"].append(value)
        elif directive == "sitemap":
            result["sitemap"].append(value)

    return result


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
@register_collector
class RobotsTxtCollector(Collector):
    """Tier-2 robots.txt endpoint discovery collector.

    Fetches ``/robots.txt`` from target domains and classifies discovered
    paths by security interest level.
    """

    collector_id: str = "robots-txt"
    collector_version: str = "0.1.0"
    display_name: str = "robots.txt Endpoint Discovery"
    tier: CollectorTier = CollectorTier.TIER_2
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)

    # ------------------------------------------------------------------
    # expand
    # ------------------------------------------------------------------
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Fetch robots.txt from the seed domain and yield observations."""
        if seed.seed_type != SeedType.DOMAIN:
            return

        domain = seed.value.strip()
        canonical_domain = canonicalize_domain(domain)

        urls = [
            f"https://{domain}/robots.txt",
            f"http://{domain}/robots.txt",
        ]

        any_success = False

        for url in urls:
            try:
                body = await self._fetch_robots_txt(url)
            except (httpx.HTTPStatusError, httpx.HTTPError) as exc:
                logger.debug("robots-txt: failed to fetch %s: %s", url, exc)
                continue

            if body is None:
                # 404 — no robots.txt at this scheme.
                continue

            any_success = True
            scheme = "https" if url.startswith("https") else "http"

            directives = parse_robots_txt(body)

            # Disallow directives → endpoint observations.
            for path in directives["disallow"]:
                classification, interest = classify_path(path)
                if interest == "low":
                    continue
                yield self._make_observation(
                    domain=canonical_domain,
                    path=path,
                    directive="disallow",
                    classification=classification,
                    interest_level=interest,
                    scheme=scheme,
                    raw_body=body,
                )

            # Allow directives → endpoint observations.
            for path in directives["allow"]:
                classification, interest = classify_path(path)
                if interest == "low":
                    continue
                yield self._make_observation(
                    domain=canonical_domain,
                    path=path,
                    directive="allow",
                    classification=classification,
                    interest_level=interest,
                    scheme=scheme,
                    raw_body=body,
                )

            # Sitemap directives → separate observations.
            for sitemap_url in directives["sitemap"]:
                yield self._make_observation(
                    domain=canonical_domain,
                    path=sitemap_url,
                    directive="sitemap",
                    classification="sitemap",
                    interest_level="medium",
                    scheme=scheme,
                    raw_body=body,
                )

            # Yield one summary observation with the full robots.txt content.
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.HTTP_RESPONSE,
                subject=ObservationSubject(
                    identifier_type=IdentifierType.DOMAIN,
                    identifier_value=canonical_domain,
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "url": url,
                    "source": "robots.txt",
                    "scheme": scheme,
                    "disallow_count": len(directives["disallow"]),
                    "allow_count": len(directives["allow"]),
                    "sitemap_count": len(directives["sitemap"]),
                },
                evidence_blob=body.encode("utf-8"),
                evidence_blob_content_type="text/plain",
            )

            # Only need one successful fetch per domain.
            break

        if not any_success:
            logger.debug("robots-txt: no robots.txt found for domain %s", domain)

    # ------------------------------------------------------------------
    # health_check
    # ------------------------------------------------------------------
    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe — verify we can make outbound HTTP."""
        start = time.monotonic()
        try:
            with _warnings_mod.catch_warnings():
                _warnings_mod.filterwarnings("ignore", category=DeprecationWarning)
                _warnings_mod.filterwarnings("ignore", message="Unverified HTTPS request")
                async with httpx.AsyncClient(verify=False) as client:  # noqa: S501
                    resp = await client.head(
                        "https://www.google.com/robots.txt",
                        timeout=self.config.request_timeout_seconds,
                    )
            latency = (time.monotonic() - start) * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=(
                    CollectorStatus.SUCCESS
                    if resp.status_code < 500  # noqa: PLR2004
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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    async def _fetch_robots_txt(self, url: str) -> str | None:
        """Fetch a robots.txt URL.  Returns body text or None on 404."""
        with _warnings_mod.catch_warnings():
            _warnings_mod.filterwarnings("ignore", category=DeprecationWarning)
            _warnings_mod.filterwarnings("ignore", message="Unverified HTTPS request")
            async with httpx.AsyncClient(
                verify=False,  # noqa: S501
                timeout=self.config.request_timeout_seconds,
                follow_redirects=True,
                max_redirects=3,
            ) as client:
                client.headers["User-Agent"] = self.config.user_agent
                response = await client.get(url)

        if response.status_code == 404:  # noqa: PLR2004
            return None

        response.raise_for_status()
        return response.text

    def _make_observation(
        self,
        *,
        domain: str,
        path: str,
        directive: str,
        classification: str,
        interest_level: str,
        scheme: str,
        raw_body: str,
    ) -> Observation:
        """Build an endpoint-discovery observation."""
        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.HTTP_RESPONSE,
            subject=ObservationSubject(
                identifier_type=IdentifierType.DOMAIN,
                identifier_value=domain,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload={
                "source": "robots.txt",
                "directive": directive,
                "path": path,
                "classification": classification,
                "interest_level": interest_level,
                "scheme": scheme,
            },
        )


__all__ = [
    "RobotsTxtCollector",
    "classify_path",
    "parse_robots_txt",
]

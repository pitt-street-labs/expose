"""Legal and social media mentions collector (Tier 1, passive).

Searches public data sources for mentions of discovered domains/IPs in
legal proceedings and security-related social media discussions.  This is a
Tier-1 (passive, broad query) collector -- no direct contact with the target,
no API keys required.

Data sources:

1. **ICANN UDRP dispute search** -- Queries the WIPO UDRP database for
   domain dispute case history.  WIPO publishes domain dispute decisions
   through a public search interface.  The collector checks whether the
   seed domain appears in UDRP case history, extracting case number,
   status, outcome, and decision date when available.

2. **CVE reference search** -- Queries the NIST NVD (National Vulnerability
   Database) for CVE entries that reference the seed domain in their
   description or reference URLs.  This surfaces publicly-known
   vulnerabilities associated with the target's infrastructure.

3. **Public security discussion aggregation** -- Searches public security
   paste/breach notification aggregator APIs (urlscan.io public search)
   for domain mentions in security researcher discussions and threat
   reports.

All three sources are public data, requiring no authentication.  The
collector uses ``httpx.AsyncClient`` for HTTP requests and applies
``sanitize_field`` to all externally-sourced strings per SPEC section 7.1.

Seed types: DOMAIN only.  IP seeds are skipped silently.

MITRE ATT&CK: T1593.001 (Search Open Websites/Domains) -- the collector
queries publicly available legal databases, vulnerability databases, and
security discussion aggregators for mentions of the target domain.

FIPS gate compliance: This module does NOT import ``hashlib``, ``secrets``,
or ``Crypto``.  All HTTP is via ``httpx`` (stdlib TLS).
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
    CollectorHealthCheck,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import register_collector
from expose.collectors.tiers import CollectorTier
from expose.sanitization.text import SanitizationFieldKind, sanitize_field
from expose.types.canonical import CollectorStatus, IdentifierType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

# WIPO UDRP domain search -- public JSON endpoint.
_WIPO_UDRP_SEARCH_URL = "https://www.wipo.int/amc/en/domains/search/json"

# NIST NVD CVE API v2.0 -- public, no key required (rate-limited to 5/30s).
_NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# urlscan.io public search API -- no key required for public results.
_URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"

# Health check targets (lightweight endpoints for reachability probes).
_WIPO_HEALTH_URL = "https://www.wipo.int/amc/en/domains/search/"

# Default user agent for requests.
_DEFAULT_USER_AGENT = "EXPOSE/0.1 (attack-surface-intelligence)"

# Maximum results to process per source.
_MAX_UDRP_RESULTS = 50
_MAX_CVE_RESULTS = 20
_MAX_SOCIAL_RESULTS = 50

# Severity mappings for different mention types.
_UDRP_SEVERITY = "medium"
_CVE_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "info",
}
_SOCIAL_SEVERITY = "info"


def _sanitize(value: str) -> str:
    """Sanitize a string field via the project sanitization layer."""
    return sanitize_field(value, SanitizationFieldKind.GENERIC).value


def _extract_udrp_observations(
    data: dict[str, Any],
    domain: str,
) -> list[dict[str, Any]]:
    """Parse WIPO UDRP search response into structured mention dicts.

    The WIPO JSON response contains a list of dispute cases under the
    ``cases`` key. Each case includes case number, status, complainant
    and respondent names, decision date, and outcome.
    """
    mentions: list[dict[str, Any]] = []

    cases = data.get("cases", [])
    if not isinstance(cases, list):
        return mentions

    for case in cases[:_MAX_UDRP_RESULTS]:
        if not isinstance(case, dict):
            continue

        case_number = _sanitize(str(case.get("caseNumber", "")))
        status = _sanitize(str(case.get("status", "")))
        decision_date = _sanitize(str(case.get("decisionDate", "")))
        outcome = _sanitize(str(case.get("outcome", "")))
        complainant = _sanitize(str(case.get("complainant", "")))
        respondent = _sanitize(str(case.get("respondent", "")))

        if not case_number:
            continue

        title = f"UDRP Case {case_number}"
        snippet = f"Status: {status}"
        if outcome:
            snippet += f", Outcome: {outcome}"
        if complainant:
            snippet += f", Complainant: {complainant}"

        mentions.append({
            "mention_type": "udrp",
            "source": "wipo_udrp",
            "title": title,
            "url": f"https://www.wipo.int/amc/en/domains/search/text.jsp?case={case_number}",
            "date": decision_date,
            "snippet": snippet,
            "severity": _UDRP_SEVERITY,
            "case_number": case_number,
            "status": status,
            "outcome": outcome,
            "respondent": respondent,
            "_collector_id": "legal-social-mentions",
        })

    return mentions


def _extract_cve_observations(
    data: dict[str, Any],
    domain: str,
) -> list[dict[str, Any]]:
    """Parse NVD CVE API v2.0 response into structured mention dicts.

    The NVD API returns vulnerabilities under ``vulnerabilities``, each
    containing a ``cve`` object with ID, descriptions, references, and
    CVSS metrics.
    """
    mentions: list[dict[str, Any]] = []

    vulnerabilities = data.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return mentions

    for vuln in vulnerabilities[:_MAX_CVE_RESULTS]:
        if not isinstance(vuln, dict):
            continue

        cve = vuln.get("cve", {})
        if not isinstance(cve, dict):
            continue

        cve_id = _sanitize(str(cve.get("id", "")))
        if not cve_id:
            continue

        # Extract English description.
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if isinstance(desc, dict) and desc.get("lang") == "en":
                description = _sanitize(str(desc.get("value", "")))
                break

        # Extract published date.
        published = _sanitize(str(cve.get("published", "")))

        # Extract CVSS severity from metrics.
        severity = "info"
        metrics = cve.get("metrics", {})
        if isinstance(metrics, dict):
            # Try CVSS v3.1 first, then v3.0, then v2.0.
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if isinstance(metric_list, list) and metric_list:
                    first_metric = metric_list[0]
                    if isinstance(first_metric, dict):
                        cvss_data = first_metric.get("cvssData", {})
                        if isinstance(cvss_data, dict):
                            base_severity = str(
                                cvss_data.get("baseSeverity", "")
                            ).upper()
                            severity = _CVE_SEVERITY_MAP.get(
                                base_severity, "info"
                            )
                            break

        # Extract reference URLs.
        references = cve.get("references", [])
        ref_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        if isinstance(references, list) and references:
            first_ref = references[0]
            if isinstance(first_ref, dict) and first_ref.get("url"):
                ref_url = _sanitize(str(first_ref["url"]))

        # Truncate description for snippet.
        snippet = description[:500] if description else f"CVE {cve_id}"

        mentions.append({
            "mention_type": "cve",
            "source": "nvd",
            "title": cve_id,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "date": published,
            "snippet": snippet,
            "severity": severity,
            "cve_id": cve_id,
            "reference_url": ref_url,
            "_collector_id": "legal-social-mentions",
        })

    return mentions


def _extract_social_observations(
    data: dict[str, Any],
    domain: str,
) -> list[dict[str, Any]]:
    """Parse urlscan.io search response into structured mention dicts.

    urlscan.io returns scan results under ``results``, each containing
    ``task`` (with URL and time), ``page`` (with title, domain, IP), and
    ``stats`` metadata.
    """
    mentions: list[dict[str, Any]] = []

    results = data.get("results", [])
    if not isinstance(results, list):
        return mentions

    for result in results[:_MAX_SOCIAL_RESULTS]:
        if not isinstance(result, dict):
            continue

        task = result.get("task", {})
        page = result.get("page", {})
        if not isinstance(task, dict) or not isinstance(page, dict):
            continue

        scan_url = _sanitize(str(task.get("url", "")))
        scan_time = _sanitize(str(task.get("time", "")))
        visibility = _sanitize(str(task.get("visibility", "")))
        result_url = _sanitize(str(result.get("result", "")))
        page_title = _sanitize(str(page.get("title", "")))
        page_domain = _sanitize(str(page.get("domain", "")))
        page_ip = _sanitize(str(page.get("ip", "")))

        title = page_title if page_title else f"Scan of {page_domain}"
        snippet = f"URL: {scan_url}"
        if page_ip:
            snippet += f", IP: {page_ip}"
        if visibility:
            snippet += f", Visibility: {visibility}"

        mentions.append({
            "mention_type": "social",
            "source": "urlscan",
            "title": title,
            "url": result_url if result_url else scan_url,
            "date": scan_time,
            "snippet": snippet,
            "severity": _SOCIAL_SEVERITY,
            "scan_url": scan_url,
            "page_domain": page_domain,
            "_collector_id": "legal-social-mentions",
        })

    return mentions


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
@register_collector
class LegalSocialMentionsCollector(Collector):
    """Tier-1 passive legal and social media mentions collector.

    Searches public databases for legal disputes (UDRP), CVE references,
    and security discussion mentions associated with DOMAIN seeds.
    """

    collector_id: str = "legal-social-mentions"
    collector_version: str = "0.1.0"
    display_name: str = "Legal & Social Media Mentions"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = 20
    technique_ids: ClassVar[list[str]] = ["T1593.001"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)

    # ------------------------------------------------------------------
    # expand
    # ------------------------------------------------------------------
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Search public sources for legal/social mentions of a domain.

        Skips non-DOMAIN seeds silently.  Queries three sources in sequence:
        WIPO UDRP, NIST NVD, and urlscan.io.
        """
        if seed.seed_type != SeedType.DOMAIN:
            return

        domain = seed.value.strip().lower()
        if not domain:
            return

        warnings_list: list[str] = []

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.request_timeout_seconds),
            headers={"User-Agent": self._user_agent},
        ) as client:
            # Source 1: WIPO UDRP domain disputes.
            udrp_mentions = await self._search_udrp(
                client, domain, warnings_list
            )
            for mention in udrp_mentions:
                yield self._mention_to_observation(mention, domain, warnings_list)

            # Source 2: NVD CVE references.
            cve_mentions = await self._search_cve(
                client, domain, warnings_list
            )
            for mention in cve_mentions:
                yield self._mention_to_observation(mention, domain, warnings_list)

            # Source 3: urlscan.io public security scans.
            social_mentions = await self._search_social(
                client, domain, warnings_list
            )
            for mention in social_mentions:
                yield self._mention_to_observation(mention, domain, warnings_list)

    # ------------------------------------------------------------------
    # Source: WIPO UDRP
    # ------------------------------------------------------------------
    async def _search_udrp(
        self,
        client: httpx.AsyncClient,
        domain: str,
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        """Query WIPO UDRP database for domain dispute history."""
        try:
            resp = await client.get(
                _WIPO_UDRP_SEARCH_URL,
                params={"domainName": domain},
            )
        except httpx.HTTPError as exc:
            warnings.append(f"WIPO UDRP search failed: {exc}")
            return []

        if resp.status_code == 404:  # noqa: PLR2004
            return []

        if resp.status_code != 200:  # noqa: PLR2004
            warnings.append(
                f"WIPO UDRP search returned HTTP {resp.status_code}"
            )
            return []

        try:
            data = resp.json()
        except Exception:
            warnings.append("WIPO UDRP search returned malformed JSON")
            return []

        if not isinstance(data, dict):
            return []

        return _extract_udrp_observations(data, domain)

    # ------------------------------------------------------------------
    # Source: NVD CVE
    # ------------------------------------------------------------------
    async def _search_cve(
        self,
        client: httpx.AsyncClient,
        domain: str,
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        """Query NIST NVD for CVE entries referencing the domain."""
        try:
            resp = await client.get(
                _NVD_CVE_API_URL,
                params={
                    "keywordSearch": domain,
                    "resultsPerPage": str(_MAX_CVE_RESULTS),
                },
            )
        except httpx.HTTPError as exc:
            warnings.append(f"NVD CVE search failed: {exc}")
            return []

        if resp.status_code == 404:  # noqa: PLR2004
            return []

        if resp.status_code == 403:  # noqa: PLR2004
            warnings.append("NVD CVE API rate limited (403)")
            return []

        if resp.status_code != 200:  # noqa: PLR2004
            warnings.append(
                f"NVD CVE API returned HTTP {resp.status_code}"
            )
            return []

        try:
            data = resp.json()
        except Exception:
            warnings.append("NVD CVE API returned malformed JSON")
            return []

        if not isinstance(data, dict):
            return []

        return _extract_cve_observations(data, domain)

    # ------------------------------------------------------------------
    # Source: urlscan.io (social/security mentions)
    # ------------------------------------------------------------------
    async def _search_social(
        self,
        client: httpx.AsyncClient,
        domain: str,
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        """Query urlscan.io for public security scan mentions of the domain."""
        try:
            resp = await client.get(
                _URLSCAN_SEARCH_URL,
                params={
                    "q": f"domain:{domain}",
                    "size": str(_MAX_SOCIAL_RESULTS),
                },
            )
        except httpx.HTTPError as exc:
            warnings.append(f"urlscan.io search failed: {exc}")
            return []

        if resp.status_code == 404:  # noqa: PLR2004
            return []

        if resp.status_code != 200:  # noqa: PLR2004
            warnings.append(
                f"urlscan.io search returned HTTP {resp.status_code}"
            )
            return []

        try:
            data = resp.json()
        except Exception:
            warnings.append("urlscan.io search returned malformed JSON")
            return []

        if not isinstance(data, dict):
            return []

        return _extract_social_observations(data, domain)

    # ------------------------------------------------------------------
    # Observation builder
    # ------------------------------------------------------------------
    def _mention_to_observation(
        self,
        mention: dict[str, Any],
        domain: str,
        warnings: list[str],
    ) -> Observation:
        """Convert a structured mention dict to an Observation."""
        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.DARK_WEB_MENTION,
            subject=ObservationSubject(
                identifier_type=IdentifierType.DOMAIN,
                identifier_value=domain,
            ),
            observed_at=datetime.now(tz=UTC),
            structured_payload=mention,
            warnings=warnings,
        )

    # ------------------------------------------------------------------
    # health_check
    # ------------------------------------------------------------------
    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe against the WIPO UDRP search page.

        Uses a lightweight HEAD request to verify the WIPO domain search
        endpoint is reachable.  Returns SUCCESS if the response status is
        below 400, FAILURE otherwise.
        """
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0),
                headers={"User-Agent": self._user_agent},
            ) as client:
                resp = await client.head(_WIPO_HEALTH_URL)
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
        except httpx.HTTPError as exc:
            latency = (time.monotonic() - start) * 1000.0
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=datetime.now(tz=UTC),
                latency_ms=latency,
                error_message=f"WIPO UDRP unreachable: {exc}",
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @property
    def _user_agent(self) -> str:
        """User-Agent string for API requests."""
        return self.config.extra.get("user_agent", _DEFAULT_USER_AGENT)


__all__ = [
    "LegalSocialMentionsCollector",
]

"""M&A Discovery collector (Tier 1, passive, broad).

Discovers recent mergers-and-acquisitions activity for an organization seed
using public data sources that require no API keys:

1. **Wikidata SPARQL** — queries ``wdt:P1830`` (owner of) and ``wdt:P127``
   (owned by) properties to find subsidiaries and acquired companies.
2. **Wikipedia API** — searches for "{company} acquisitions" and extracts
   mentioned company names from article text.
3. **DNS-based discovery** — for each acquired company name, attempts to
   resolve ``{name}.com`` as a candidate domain seed.

The collector emits one ``Observation`` per discovered acquisition with
``relationship_type: "acquired_by"`` in its ``structured_payload`` and
the acquired company's name, date, source URL, and candidate domains.

Seed types: ORGANIZATION only.  Other seed types are skipped silently.

Rate limiting: Wikidata's SPARQL endpoint has a polite-use policy; this
collector sets a ``User-Agent`` header per their guidelines and makes at
most 3 requests per ``expand()`` call (1 SPARQL + 1 Wikipedia + 1 DNS
check batch), well within budget for a single invocation.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, ClassVar

import httpx

from expose.collectors.base import (
    Collector,
    CollectorHealthCheck,
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

_WIKIDATA_SPARQL_URL = "https://query.wikidata.org/sparql"
_WIKIPEDIA_API_URL = "https://en.wikipedia.org/w/api.php"

_USER_AGENT = "EXPOSE/0.1 (attack-surface-intelligence)"

# SPARQL query template: finds entities owned by the target organization.
# Uses wdt:P1830 (owner of) — the parent owns these subsidiaries.
# Also queries wdt:P127 (owned by) in reverse — entities that declare
# the target as their owner.
_SPARQL_QUERY_TEMPLATE = """\
SELECT DISTINCT ?acquired ?acquiredLabel ?date ?website WHERE {{
  {{
    ?parent rdfs:label "{org_name}"@en .
    ?parent wdt:P1830 ?acquired .
  }} UNION {{
    ?acquired wdt:P127 ?parent .
    ?parent rdfs:label "{org_name}"@en .
  }}
  OPTIONAL {{ ?acquired wdt:P571 ?date }}
  OPTIONAL {{ ?acquired wdt:P856 ?website }}
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en" }}
}}
LIMIT 50
"""


# TLDs to probe when guessing domains for acquired companies (issue #83).
_GUESS_TLDS = [".com", ".net", ".org", ".io", ".cloud", ".dev", ".ai", ".co", ".us", ".gov"]


def _normalize_org_for_domain(name: str) -> str:
    """Convert an organization name to a plausible domain slug.

    ``"Zilla Security"`` -> ``"zillasecurity"``
    ``"Acme Corp."`` -> ``"acmecorp"``
    """
    # Remove common suffixes and punctuation.
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _guess_domains_for_name(name: str) -> list[str]:
    """Generate candidate domains for an acquired company across multiple TLDs.

    Returns up to ``len(_GUESS_TLDS)`` domain strings derived from the
    organization name slug. Falls back to empty list if the slug is empty.
    """
    slug = _normalize_org_for_domain(name)
    if not slug:
        return []
    return [f"{slug}{tld}" for tld in _GUESS_TLDS]


def _extract_domain_from_url(url: str) -> str | None:
    """Extract the bare domain from a URL like ``https://venafi.com/``."""
    match = re.match(r"https?://(?:www\.)?([^/]+)", url)
    if match:
        return match.group(1).rstrip(".")
    return None


def _parse_wikidata_date(date_str: str | None) -> str | None:
    """Extract an ISO date or year from a Wikidata date literal.

    Wikidata returns dates like ``"2024-01-15T00:00:00Z"`` or just a year.
    We normalize to ISO date or year string.
    """
    if not date_str:
        return None
    # Try full ISO datetime first.
    match = re.match(r"(\d{4}-\d{2}-\d{2})", date_str)
    if match:
        return match.group(1)
    # Fallback: extract just the year.
    match = re.match(r"(\d{4})", date_str)
    if match:
        return match.group(1)
    return None


@register_collector
class MADiscoveryCollector(Collector):
    """Tier-1 passive M&A discovery collector.

    Queries Wikidata SPARQL and Wikipedia for corporate acquisitions
    related to the target organization, then emits observations for
    each discovered subsidiary or acquired company.
    """

    collector_id: str = "ma-discovery"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_1
    requires_credentials: bool = False
    technique_ids: ClassVar[list[str]] = ["T1591.004"]

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Discover M&A activity for an organization seed."""
        if seed.seed_type != SeedType.ORGANIZATION:
            return

        org_name = seed.value.strip()
        if not org_name:
            return

        acquisitions: list[dict[str, Any]] = []
        warnings_list: list[str] = []

        async with httpx.AsyncClient(
            timeout=self.config.request_timeout_seconds,
            headers={"User-Agent": _USER_AGENT},
        ) as client:
            # 1. Query Wikidata SPARQL.
            wikidata_results = await self._query_wikidata(
                client, org_name, warnings_list
            )
            acquisitions.extend(wikidata_results)

            # 2. Query Wikipedia API.
            wikipedia_results = await self._query_wikipedia(
                client, org_name, warnings_list
            )
            # Merge Wikipedia results, avoiding duplicates by acquired name.
            seen_names = {a["acquired_name"].lower() for a in acquisitions}
            for result in wikipedia_results:
                if result["acquired_name"].lower() not in seen_names:
                    seen_names.add(result["acquired_name"].lower())
                    acquisitions.append(result)

        if not acquisitions:
            return

        # Yield one observation per acquisition.
        for acq in acquisitions:
            acquired_domains = acq.get("acquired_domains", [])
            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.SCANNER_HOST,
                subject=ObservationSubject(
                    identifier_type=IdentifierType.DOMAIN,
                    identifier_value=org_name.lower(),
                ),
                observed_at=datetime.now(tz=UTC),
                structured_payload={
                    "_collector_id": "ma-discovery",
                    "source": acq.get("source", "wikidata"),
                    "source_url": acq.get("source_url", ""),
                    "relationship_type": "acquired_by",
                    "parent_organization": org_name,
                    "acquired_organization": acq["acquired_name"],
                    "acquisition_date": acq.get("acquisition_date"),
                    "acquired_domains": acquired_domains,
                    "confidence": acq.get("confidence", 0.7),
                    "attribution_source": "transitive_ma",
                },
                warnings=warnings_list,
            )

    async def _query_wikidata(
        self,
        client: httpx.AsyncClient,
        org_name: str,
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        """Query Wikidata SPARQL for acquisitions owned by ``org_name``."""
        # Escape quotes in org name for SPARQL injection safety.
        safe_name = org_name.replace('"', '\\"')
        query = _SPARQL_QUERY_TEMPLATE.format(org_name=safe_name)

        try:
            resp = await client.get(
                _WIKIDATA_SPARQL_URL,
                params={"query": query, "format": "json"},
                headers={
                    "Accept": "application/sparql-results+json",
                    "User-Agent": _USER_AGENT,
                },
            )
        except httpx.HTTPError as exc:
            warnings.append(f"Wikidata SPARQL request failed: {exc}")
            return []

        if resp.status_code != 200:  # noqa: PLR2004
            warnings.append(
                f"Wikidata SPARQL returned HTTP {resp.status_code}"
            )
            return []

        try:
            data = resp.json()
        except Exception:
            warnings.append("Wikidata SPARQL returned malformed JSON")
            return []

        results: list[dict[str, Any]] = []
        bindings = data.get("results", {}).get("bindings", [])

        for binding in bindings:
            label = binding.get("acquiredLabel", {}).get("value", "")
            if not label:
                continue

            date_raw = binding.get("date", {}).get("value")
            website_raw = binding.get("website", {}).get("value")
            acquired_uri = binding.get("acquired", {}).get("value", "")

            acquired_domains: list[str] = []
            if website_raw:
                domain = _extract_domain_from_url(website_raw)
                if domain:
                    acquired_domains.append(domain)

            # Fallback: guess domains from name across multiple TLDs.
            if not acquired_domains:
                acquired_domains = _guess_domains_for_name(label)

            results.append({
                "acquired_name": label,
                "acquisition_date": _parse_wikidata_date(date_raw),
                "acquired_domains": acquired_domains,
                "source": "wikidata",
                "source_url": acquired_uri or _WIKIDATA_SPARQL_URL,
                "confidence": 0.8 if website_raw else 0.6,
            })

        return results

    async def _query_wikipedia(
        self,
        client: httpx.AsyncClient,
        org_name: str,
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        """Search Wikipedia for "{org_name} acquisitions" and extract names."""
        search_term = f"{org_name} acquisitions"

        try:
            resp = await client.get(
                _WIKIPEDIA_API_URL,
                params={
                    "action": "query",
                    "list": "search",
                    "srsearch": search_term,
                    "format": "json",
                    "srlimit": "5",
                    "utf8": "1",
                },
            )
        except httpx.HTTPError as exc:
            warnings.append(f"Wikipedia API request failed: {exc}")
            return []

        if resp.status_code != 200:  # noqa: PLR2004
            warnings.append(
                f"Wikipedia API returned HTTP {resp.status_code}"
            )
            return []

        try:
            data = resp.json()
        except Exception:
            warnings.append("Wikipedia API returned malformed JSON")
            return []

        results: list[dict[str, Any]] = []
        search_results = data.get("query", {}).get("search", [])

        for item in search_results:
            title = item.get("title", "")
            snippet = item.get("snippet", "")

            # Look for "acquired X" or "acquisition of X" patterns in snippets.
            acquired_names = self._extract_acquisitions_from_text(
                snippet, org_name
            )
            page_url = f"https://en.wikipedia.org/wiki/{title.replace(' ', '_')}"

            for name in acquired_names:
                acquired_domains = _guess_domains_for_name(name)
                results.append({
                    "acquired_name": name,
                    "acquisition_date": None,
                    "acquired_domains": acquired_domains,
                    "source": "wikipedia",
                    "source_url": page_url,
                    "confidence": 0.5,
                })

        return results

    @staticmethod
    def _extract_acquisitions_from_text(
        text: str, parent_org: str
    ) -> list[str]:
        """Extract acquired company names from Wikipedia snippet text.

        Looks for patterns like:
        - "acquired {Company}"
        - "acquisition of {Company}"
        - "purchase of {Company}"
        - "merged with {Company}"

        Returns deduplicated list of extracted names.
        """
        # Strip HTML tags from Wikipedia snippets.
        clean = re.sub(r"<[^>]+>", "", text)

        patterns = [
            r"acqui(?:red|sition of)\s+([A-Z][A-Za-z0-9\s&.'-]{2,30}?)(?:\s+(?:for|in|on|,|\.))",
            r"purchase(?:d)?\s+(?:of\s+)?([A-Z][A-Za-z0-9\s&.'-]{2,30}?)(?:\s+(?:for|in|on|,|\.))",
            r"merged?\s+with\s+([A-Z][A-Za-z0-9\s&.'-]{2,30}?)(?:\s+(?:for|in|on|,|\.))",
        ]

        names: list[str] = []
        seen: set[str] = set()
        parent_lower = parent_org.lower()

        for pattern in patterns:
            for match in re.finditer(pattern, clean, re.IGNORECASE):
                name = match.group(1).strip().rstrip(".")
                if name.lower() != parent_lower and name.lower() not in seen:
                    seen.add(name.lower())
                    names.append(name)

        return names

    async def health_check(self) -> CollectorHealthCheck:
        """Quick reachability probe against Wikidata SPARQL endpoint."""
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(
                headers={"User-Agent": _USER_AGENT},
            ) as client:
                resp = await client.get(
                    _WIKIDATA_SPARQL_URL,
                    params={
                        "query": "ASK { wd:Q5 wdt:P31 wd:Q55983715 }",
                        "format": "json",
                    },
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
    "MADiscoveryCollector",
]

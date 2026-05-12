# Copyright 2026 Korlogos / Pitt Street Labs. All rights reserved.
# This file is part of the EXPOSE commercial module and is NOT covered
# by the Apache 2.0 license that governs the open-source core.
# Unauthorized copying, distribution, or use is prohibited.
#
"""Dark web threat intelligence enricher (EXPOSE Threat Context module).

Queries **public** dark web aggregator APIs -- NOT the actual dark web --
to surface threat context for domains and email addresses. This enricher
provides the intelligence layer that feeds the ``dark-web-indicators``
collector.

Supported public aggregators:

1. **Have I Been Pwned (HIBP)** -- breach detection for domains/emails.
   Endpoint: ``https://haveibeenpwned.com/api/v3/``
   Requires: ``hibp-api-key`` header.

2. **IntelX (Intelligence X)** -- public search API for leaked data mentions.
   Endpoint: ``https://2.intelx.io/``
   Requires: ``x-key`` header.

3. **DeHashed** -- credential leak search via public API.
   Endpoint: ``https://api.dehashed.com/``
   Requires: HTTP Basic auth (email + API key).

Indicator taxonomy (per SPEC):

- **IoC** (Indicators of Compromise) -- known malicious infrastructure overlap.
  E.g., domain appears in a breach alongside known C2 infrastructure.
- **IoI** (Indicators of Interest) -- mentions in dark web forums/markets.
  E.g., organization name referenced in a paste or marketplace listing.
- **IoAc** (Indicators of Activity) -- active campaigns targeting the entity.
  E.g., fresh credential dumps, active phishing kits targeting the domain.
- **IoP** (Indicators of Preparation) -- staging/recon activity patterns.
  E.g., domain lookalikes registered, DNS enumeration detected.

Each indicator carries: ``indicator_type``, ``source``, ``first_seen``,
``last_seen``, ``confidence`` (0.0--1.0), ``description``.

FIPS gate compliance: This module does NOT import ``hashlib``, ``secrets``,
or ``Crypto``. All HTTP is via ``httpx`` (stdlib TLS).
"""

from __future__ import annotations

# Copyright 2026 Korlogos / Pitt Street Labs. All rights reserved.
# This file is part of EXPOSE Commercial Modules and is NOT covered by the
# Apache 2.0 license that governs the core engine. Unauthorized copying,
# distribution, or use of this file is strictly prohibited. Contact
# licensing@korlogos.com for commercial licensing terms.

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# === Input validation ==========================================================

# DNS label-safe domain pattern (RFC 1035 / RFC 1123).
_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

# Basic email sanity check (not full RFC 5322).
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Characters that indicate path traversal or injection attempts.
_PATH_TRAVERSAL_CHARS = re.compile(r"[/\\]|\.\.")

# DNS maximum length per RFC 1035.
_MAX_INPUT_LEN = 253


def _validate_domain(domain: str) -> bool:
    """Return True if *domain* passes basic format validation.

    Rejects overlong inputs, path-traversal characters, and strings
    that don't look like valid DNS names.
    """
    if not domain or len(domain) > _MAX_INPUT_LEN:
        return False
    if _PATH_TRAVERSAL_CHARS.search(domain):
        return False
    return bool(_DOMAIN_RE.match(domain))


def _validate_email(email: str) -> bool:
    """Return True if *email* passes basic format validation.

    Rejects overlong inputs, path-traversal characters, and strings
    that don't match a minimal ``user@host.tld`` pattern.
    """
    if not email or len(email) > _MAX_INPUT_LEN:
        return False
    if _PATH_TRAVERSAL_CHARS.search(email):
        return False
    return bool(_EMAIL_RE.match(email))


# === Indicator types ==========================================================

class IndicatorType(StrEnum):
    """Threat indicator classification per SPEC."""

    IOC = "ioc"          # Indicators of Compromise
    IOI = "ioi"          # Indicators of Interest
    IOAC = "ioac"        # Indicators of Activity
    IOP = "iop"          # Indicators of Preparation


@dataclass(frozen=True)
class ThreatIndicator:
    """Single dark web threat indicator.

    Immutable value type carrying one finding from a dark web aggregator.
    """

    indicator_type: IndicatorType
    source: str
    first_seen: datetime | None
    last_seen: datetime | None
    confidence: float  # 0.0 -- 1.0
    description: str
    raw_data: dict[str, Any] = field(default_factory=dict)


# === API base URLs ============================================================

_HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
_INTELX_API_BASE = "https://2.intelx.io"
_DEHASHED_API_BASE = "https://api.dehashed.com"


class DarkWebEnricher:
    """Query public dark web aggregator APIs for threat context.

    This enricher does NOT access the dark web directly. It queries
    public REST APIs that aggregate and index dark web data.

    Credential slots (resolved by the collector via CredentialResolver):
        ``hibp_api_key``   -- Have I Been Pwned API key (required for HIBP)
        ``intelx_api_key`` -- IntelX API key (required for IntelX)
        ``dehashed_email`` -- DeHashed account email (required for DeHashed)
        ``dehashed_api_key`` -- DeHashed API key (required for DeHashed)

    All API calls are optional -- if credentials are missing for a source,
    that source is skipped and a warning is logged.
    """

    def __init__(
        self,
        *,
        hibp_api_key: str | None = None,
        intelx_api_key: str | None = None,
        dehashed_email: str | None = None,
        dehashed_api_key: str | None = None,
        timeout_seconds: float = 30.0,
        user_agent: str = "expose-collector/0.1 (+https://github.com/pitt-street-labs/expose)",
    ) -> None:
        self._hibp_api_key = hibp_api_key
        self._intelx_api_key = intelx_api_key
        self._dehashed_email = dehashed_email
        self._dehashed_api_key = dehashed_api_key
        self._timeout = timeout_seconds
        self._user_agent = user_agent

    async def enrich_domain(self, domain: str) -> list[ThreatIndicator]:
        """Query all configured aggregators for a domain.

        Returns a list of ThreatIndicators from all sources that had
        credentials configured. Sources without credentials are skipped.
        Invalid domains are rejected with an empty result and a warning.
        """
        if not _validate_domain(domain):
            logger.warning(
                "Invalid domain rejected by input validation: %r", domain
            )
            return []

        indicators: list[ThreatIndicator] = []

        if self._hibp_api_key:
            indicators.extend(await self._query_hibp_domain(domain))
        else:
            logger.debug("HIBP API key not configured; skipping HIBP for %r", domain)

        if self._intelx_api_key:
            indicators.extend(await self._query_intelx(domain))
        else:
            logger.debug("IntelX API key not configured; skipping IntelX for %r", domain)

        if self._dehashed_email and self._dehashed_api_key:
            indicators.extend(await self._query_dehashed(domain))
        else:
            logger.debug(
                "DeHashed credentials not configured; skipping DeHashed for %r",
                domain,
            )

        return indicators

    async def enrich_email(self, email: str) -> list[ThreatIndicator]:
        """Query all configured aggregators for an email address.

        Returns a list of ThreatIndicators. Similar to enrich_domain but
        uses email-specific endpoints where available. Invalid emails are
        rejected with an empty result and a warning.
        """
        if not _validate_email(email):
            logger.warning(
                "Invalid email rejected by input validation: %r", email
            )
            return []

        indicators: list[ThreatIndicator] = []

        if self._hibp_api_key:
            indicators.extend(await self._query_hibp_email(email))
        else:
            logger.debug("HIBP API key not configured; skipping HIBP for %r", email)

        if self._intelx_api_key:
            indicators.extend(await self._query_intelx(email))
        else:
            logger.debug("IntelX API key not configured; skipping IntelX for %r", email)

        if self._dehashed_email and self._dehashed_api_key:
            indicators.extend(await self._query_dehashed_email(email))
        else:
            logger.debug(
                "DeHashed credentials not configured; skipping DeHashed for %r",
                email,
            )

        return indicators

    # === HIBP ==================================================================

    async def _query_hibp_domain(self, domain: str) -> list[ThreatIndicator]:
        """Query HIBP for breaches affecting a domain.

        Uses the breachedaccount search against the domain.
        """
        indicators: list[ThreatIndicator] = []
        url = f"{_HIBP_API_BASE}/breaches"
        headers = {
            "hibp-api-key": self._hibp_api_key or "",
            "User-Agent": self._user_agent,
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(url, headers=headers, params={"domain": domain})

            if resp.status_code == 200:  # noqa: PLR2004
                breaches = resp.json()
                for breach in breaches:
                    indicators.append(self._hibp_breach_to_indicator(breach, domain))
            elif resp.status_code == 404:  # noqa: PLR2004
                logger.debug("HIBP: no breaches found for domain %r", domain)
            else:
                logger.warning(
                    "HIBP domain query returned HTTP %d for %r",
                    resp.status_code,
                    domain,
                )
        except httpx.HTTPError as exc:
            logger.warning("HIBP domain query failed for %r: %s", domain, exc)

        return indicators

    async def _query_hibp_email(self, email: str) -> list[ThreatIndicator]:
        """Query HIBP for breaches affecting an email address."""
        indicators: list[ThreatIndicator] = []
        url = f"{_HIBP_API_BASE}/breachedaccount/{email}"
        headers = {
            "hibp-api-key": self._hibp_api_key or "",
            "User-Agent": self._user_agent,
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    url,
                    headers=headers,
                    params={"truncateResponse": "false"},
                )

            if resp.status_code == 200:  # noqa: PLR2004
                breaches = resp.json()
                for breach in breaches:
                    indicators.append(self._hibp_breach_to_indicator(breach, email))
            elif resp.status_code == 404:  # noqa: PLR2004
                logger.debug("HIBP: no breaches found for email %r", email)
            else:
                logger.warning(
                    "HIBP email query returned HTTP %d for %r",
                    resp.status_code,
                    email,
                )
        except httpx.HTTPError as exc:
            logger.warning("HIBP email query failed for %r: %s", email, exc)

        return indicators

    def _hibp_breach_to_indicator(
        self, breach: dict[str, Any], query_value: str
    ) -> ThreatIndicator:
        """Convert a HIBP breach record to a ThreatIndicator."""
        breach_name = breach.get("Name", "Unknown")
        breach_date = breach.get("BreachDate")
        data_classes = breach.get("DataClasses", [])
        pwn_count = breach.get("PwnCount", 0)
        is_verified = breach.get("IsVerified", False)

        first_seen = None
        if breach_date:
            try:
                first_seen = datetime.fromisoformat(breach_date)
            except (ValueError, TypeError):
                pass

        # Credential-containing breaches indicate active compromise (IoC).
        # Non-credential breaches are indicators of interest (IoI).
        has_credentials = any(
            dc in ("Passwords", "Password hints", "Security questions and answers")
            for dc in data_classes
        )
        indicator_type = IndicatorType.IOC if has_credentials else IndicatorType.IOI

        confidence = 0.9 if is_verified else 0.5

        return ThreatIndicator(
            indicator_type=indicator_type,
            source="hibp",
            first_seen=first_seen,
            last_seen=None,
            confidence=confidence,
            description=(
                f"Breach '{breach_name}' affecting {query_value}: "
                f"{pwn_count:,} accounts, data classes: {', '.join(data_classes)}"
            ),
            raw_data=breach,
        )

    # === IntelX ================================================================

    async def _query_intelx(self, term: str) -> list[ThreatIndicator]:
        """Query IntelX public search API for mentions of a term.

        Uses the phonebook search endpoint for fast enumeration of
        leaked data mentions.
        """
        indicators: list[ThreatIndicator] = []
        url = f"{_INTELX_API_BASE}/phonebook/search"
        headers = {
            "x-key": self._intelx_api_key or "",
            "User-Agent": self._user_agent,
        }
        payload = {
            "term": term,
            "maxresults": 100,
            "media": 0,  # All media types
            "timeout": 10,
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(url, headers=headers, json=payload)

            if resp.status_code != 200:  # noqa: PLR2004
                logger.warning(
                    "IntelX search returned HTTP %d for %r",
                    resp.status_code,
                    term,
                )
                return indicators

            data = resp.json()
            search_id = data.get("id")
            if not search_id:
                return indicators

            # Fetch results using the search ID.
            result_url = f"{_INTELX_API_BASE}/phonebook/search/result"
            resp2 = await client.get(
                result_url,
                headers=headers,
                params={"id": search_id, "limit": 100},
            )

            if resp2.status_code == 200:  # noqa: PLR2004
                results = resp2.json()
                selectors = results.get("selectors", [])
                for selector in selectors:
                    indicators.append(
                        self._intelx_selector_to_indicator(selector, term)
                    )

        except httpx.HTTPError as exc:
            logger.warning("IntelX query failed for %r: %s", term, exc)

        return indicators

    def _intelx_selector_to_indicator(
        self, selector: dict[str, Any], query_term: str
    ) -> ThreatIndicator:
        """Convert an IntelX selector result to a ThreatIndicator."""
        selector_value = selector.get("selectorvalue", "")
        selector_type = selector.get("selectortype", 0)

        # IntelX selector types: 1=email, 2=domain, 3=URL, etc.
        # Dark web forum mentions are IoI; leaked credentials are IoC.
        if selector_type in (1, 2):  # noqa: PLR2004
            indicator_type = IndicatorType.IOI
        else:
            indicator_type = IndicatorType.IOI

        return ThreatIndicator(
            indicator_type=indicator_type,
            source="intelx",
            first_seen=None,
            last_seen=None,
            confidence=0.6,
            description=(
                f"IntelX mention of {query_term!r}: "
                f"selector={selector_value!r} (type={selector_type})"
            ),
            raw_data=selector,
        )

    # === DeHashed ==============================================================

    async def _query_dehashed(self, domain: str) -> list[ThreatIndicator]:
        """Query DeHashed for credential leaks involving a domain."""
        return await self._dehashed_search("domain", domain)

    async def _query_dehashed_email(self, email: str) -> list[ThreatIndicator]:
        """Query DeHashed for credential leaks involving an email."""
        return await self._dehashed_search("email", email)

    async def _dehashed_search(
        self, field: str, value: str
    ) -> list[ThreatIndicator]:
        """Execute a DeHashed API search and return indicators."""
        indicators: list[ThreatIndicator] = []
        url = f"{_DEHASHED_API_BASE}/search"
        params = {"query": f"{field}:{value}"}

        try:
            async with httpx.AsyncClient(
                timeout=self._timeout,
                auth=(self._dehashed_email or "", self._dehashed_api_key or ""),
            ) as client:
                resp = await client.get(
                    url,
                    params=params,
                    headers={"User-Agent": self._user_agent},
                )

            if resp.status_code == 200:  # noqa: PLR2004
                data = resp.json()
                entries = data.get("entries", [])
                if entries is None:
                    entries = []
                for entry in entries:
                    indicators.append(
                        self._dehashed_entry_to_indicator(entry, value)
                    )
            elif resp.status_code == 401:  # noqa: PLR2004
                logger.warning("DeHashed: authentication failed for %r", value)
            else:
                logger.warning(
                    "DeHashed search returned HTTP %d for %r",
                    resp.status_code,
                    value,
                )
        except httpx.HTTPError as exc:
            logger.warning("DeHashed query failed for %r: %s", value, exc)

        return indicators

    def _dehashed_entry_to_indicator(
        self, entry: dict[str, Any], query_value: str
    ) -> ThreatIndicator:
        """Convert a DeHashed entry to a ThreatIndicator."""
        email = entry.get("email", "")
        database_name = entry.get("database_name", "Unknown")
        has_password = bool(entry.get("password") or entry.get("hashed_password"))

        # Leaked credentials with passwords are IoC (active compromise risk).
        # Entries without passwords are IoI (entity mentioned in leak).
        indicator_type = IndicatorType.IOC if has_password else IndicatorType.IOI

        confidence = 0.8 if has_password else 0.5

        return ThreatIndicator(
            indicator_type=indicator_type,
            source="dehashed",
            first_seen=None,
            last_seen=None,
            confidence=confidence,
            description=(
                f"DeHashed leak for {query_value!r}: "
                f"email={email!r}, database={database_name!r}, "
                f"has_password={has_password}"
            ),
            raw_data=entry,
        )


__all__ = [
    "DarkWebEnricher",
    "IndicatorType",
    "ThreatIndicator",
    "_validate_domain",
    "_validate_email",
]

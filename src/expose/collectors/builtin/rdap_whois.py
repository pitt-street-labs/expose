"""RDAP/WHOIS collector — Tier 1 passive registration data (per SPEC §6.1).

Queries RDAP (Registration Data Access Protocol, RFC 9083) endpoints via the
``rdap.org`` bootstrap service for domain and IP seed types.  Extracts
registration metadata (registrant org, registrar, dates, nameservers, status)
without harvesting any personally identifiable information.

**PII non-enrichment policy**: This collector deliberately skips personal
names, email addresses, phone numbers, and street addresses.  Only
organization names are extracted from RDAP ``vcardArray`` entities.  If a
registrant entity's ``fn`` field looks like a personal name (no ``org``
field present and no organizational indicators in the ``fn`` value), it is
discarded.

Credential requirements: None (RDAP is a public protocol).

FIPS gate: This module does not import ``hashlib`` or ``secrets``
(per ADR-010).
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorHealthCheck,
    CollectorSourceUnreachableError,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import register_collector
from expose.collectors.tiers import CollectorTier
from expose.sanitization.canonicalize import (
    CanonicalizationError,
    canonicalize_domain,
    canonicalize_ip,
)
from expose.sanitization.text import SanitizationFieldKind, sanitize_field
from expose.types.canonical import CollectorStatus, IdentifierType

# RDAP bootstrap base URL.  rdap.org is the IANA-blessed bootstrap service
# that redirects to the authoritative RIR/registrar RDAP server.
_RDAP_BOOTSTRAP_BASE = "https://rdap.org"

# Heuristic for detecting personal names vs. organization names.
# Organizations typically contain one of these indicators.
_ORG_INDICATORS_RE = re.compile(
    r"""
    (?:
        \b(?:Inc|LLC|Ltd|Corp|Co|GmbH|AG|SA|BV|NV|AB|Oy|AS|SRL|PLC)\.?\b
        | \b(?:Association|Authority|Foundation|Institute|University|Ministry)\b
        | \b(?:Department|Bureau|Agency|Commission|Council|Board)\b
        | \b(?:Group|Holdings|Partners|Services|Solutions|Technologies)\b
        | \b(?:Networks|Communications|Telecom|Systems|Labs?|Laboratories)\b
        | ,\s  # "Acme, Inc." pattern
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# A personal name typically has 2-3 words, all capitalized, no org indicators.
_PERSONAL_NAME_RE = re.compile(
    r"^[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}$",
)


def _looks_like_personal_name(name: str) -> bool:
    """Return True if ``name`` appears to be a personal name, not an org."""
    stripped = name.strip()
    if not stripped:
        return False
    # If it has org indicators, it is an organization name.
    if _ORG_INDICATORS_RE.search(stripped):
        return False
    # If it matches the personal-name pattern, treat as PII.
    return bool(_PERSONAL_NAME_RE.match(stripped))


def _extract_org_from_vcard(
    vcard_array: list[Any],
) -> str | None:
    """Extract organization name from an RFC 6350 jCard ``vcardArray``.

    Per PII non-enrichment policy:
    - If an ``org`` property exists, return it (sanitized downstream).
    - If only ``fn`` exists and it looks like an org name, return it.
    - If ``fn`` looks like a personal name, return None.
    - Never extract ``email``, ``tel``, or ``adr`` properties.
    """
    if not vcard_array or len(vcard_array) < 2:  # noqa: PLR2004
        return None

    properties: list[Any] = vcard_array[1]
    org_value: str | None = None
    fn_value: str | None = None

    for prop in properties:
        if not isinstance(prop, list) or len(prop) < 4:  # noqa: PLR2004
            continue
        prop_name = prop[0]
        prop_val = prop[3]
        if prop_name == "org" and isinstance(prop_val, str) and prop_val.strip():
            org_value = prop_val.strip()
        elif prop_name == "fn" and isinstance(prop_val, str) and prop_val.strip():
            fn_value = prop_val.strip()

    # Prefer explicit org field.
    if org_value is not None:
        return org_value

    # Fall back to fn only if it does not look like a personal name.
    if fn_value is not None and not _looks_like_personal_name(fn_value):
        return fn_value

    return None


def _extract_registrant_and_registrar(
    entities: list[dict[str, Any]],
) -> tuple[str | None, str | None]:
    """Walk RDAP entities to find registrant org and registrar name.

    Returns ``(registrant_org, registrar_name)``.
    """
    registrant_org: str | None = None
    registrar_name: str | None = None

    for entity in entities:
        roles: list[str] = entity.get("roles", [])
        vcard: list[Any] | None = entity.get("vcardArray")
        if "registrant" in roles and vcard is not None:
            registrant_org = _extract_org_from_vcard(vcard)
        elif (
            "registrar" in roles
            and vcard is not None
            and len(vcard) >= 2  # noqa: PLR2004
        ):
            # For registrar, fn is always an org name (registrars are companies).
            for prop in vcard[1]:
                if (
                    isinstance(prop, list)
                    and len(prop) >= 4  # noqa: PLR2004
                    and prop[0] == "fn"
                    and isinstance(prop[3], str)
                    and prop[3].strip()
                ):
                    registrar_name = prop[3].strip()
                    break

    return registrant_org, registrar_name


def _extract_dates(
    events: list[dict[str, Any]],
) -> tuple[str | None, str | None]:
    """Extract registration and expiration dates from RDAP events."""
    registration_date: str | None = None
    expiration_date: str | None = None

    for event in events:
        action = event.get("eventAction", "")
        date_str = event.get("eventDate")
        if not isinstance(date_str, str):
            continue
        if action == "registration":
            registration_date = date_str
        elif action == "expiration":
            expiration_date = date_str

    return registration_date, expiration_date


def _extract_nameservers(
    nameservers: list[dict[str, Any]],
) -> list[str]:
    """Extract nameserver hostnames from RDAP nameserver objects."""
    result: list[str] = []
    for ns in nameservers:
        ldh = ns.get("ldhName")
        if isinstance(ldh, str) and ldh.strip():
            result.append(ldh.strip().lower())
    return result


def _extract_status(status_list: list[Any]) -> list[str]:
    """Extract status strings from RDAP status array."""
    return [str(s) for s in status_list if isinstance(s, str)]


def _sanitize_org_string(value: str | None) -> str | None:
    """Sanitize an organization/registrar string via the text sanitizer."""
    if value is None:
        return None
    result = sanitize_field(value, SanitizationFieldKind.WHOIS_ORGANIZATION)
    return result.value if result.value else None


@register_collector
class RdapWhoisCollector(Collector):
    """RDAP/WHOIS registration data collector (Tier 1, passive).

    Queries the RDAP bootstrap service (``rdap.org``) for domain and IP
    registration information.  Emits ``RDAP_REGISTRATION`` observations
    containing registrant organization, registrar, dates, nameservers,
    and status codes.
    """

    collector_id: str = "rdap-whois"
    collector_version: str = "0.1.0"
    requires_credentials: bool = False
    tier: CollectorTier = CollectorTier.TIER_1

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query RDAP for domain or IP registration data."""
        if seed.seed_type == SeedType.DOMAIN:
            async for obs in self._expand_domain(seed):
                yield obs
        elif seed.seed_type == SeedType.IP:
            async for obs in self._expand_ip(seed):
                yield obs
        # All other seed types are silently skipped per contract.

    async def _expand_domain(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query RDAP for a domain seed."""
        canonical = canonicalize_domain(seed.value)
        url = f"{_RDAP_BOOTSTRAP_BASE}/domain/{canonical}"
        data = await self._fetch_rdap(url)

        observation = self._parse_rdap_response(
            data=data,
            identifier_type=IdentifierType.DOMAIN,
            identifier_value=canonical,
            raw_bytes=json.dumps(data, ensure_ascii=False).encode("utf-8"),
        )
        yield observation

    async def _expand_ip(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query RDAP for an IP seed."""
        canonical = canonicalize_ip(seed.value)
        url = f"{_RDAP_BOOTSTRAP_BASE}/ip/{canonical}"
        data = await self._fetch_rdap(url)

        observation = self._parse_rdap_response(
            data=data,
            identifier_type=IdentifierType.IP,
            identifier_value=canonical,
            raw_bytes=json.dumps(data, ensure_ascii=False).encode("utf-8"),
        )
        yield observation

    async def _fetch_rdap(self, url: str) -> dict[str, Any]:
        """Fetch an RDAP JSON response from the given URL.

        Raises ``CollectorSourceUnreachableError`` on network failures.
        """
        try:
            async with httpx.AsyncClient(
                timeout=self.config.request_timeout_seconds,
                follow_redirects=True,
                headers={
                    "Accept": "application/rdap+json, application/json",
                    "User-Agent": self.config.user_agent,
                },
            ) as client:
                response = await client.get(url)
                response.raise_for_status()
                return response.json()  # type: ignore[no-any-return]
        except (httpx.HTTPError, httpx.StreamError) as exc:
            msg = f"RDAP query failed for {url}: {exc}"
            raise CollectorSourceUnreachableError(msg) from exc

    def _parse_rdap_response(
        self,
        *,
        data: dict[str, Any],
        identifier_type: IdentifierType,
        identifier_value: str,
        raw_bytes: bytes,
    ) -> Observation:
        """Parse an RDAP JSON response into an Observation."""
        warnings: list[str] = []

        # Extract entities.
        entities: list[dict[str, Any]] = data.get("entities", [])
        registrant_org, registrar_name = _extract_registrant_and_registrar(entities)

        # Sanitize org strings.
        registrant_org = _sanitize_org_string(registrant_org)
        registrar_name = _sanitize_org_string(registrar_name)

        # Extract dates.
        events: list[dict[str, Any]] = data.get("events", [])
        registration_date, expiration_date = _extract_dates(events)

        # Extract nameservers — sanitize each through canonicalize_domain.
        ns_objects: list[dict[str, Any]] = data.get("nameservers", [])
        nameservers = _extract_nameservers(ns_objects)
        nameservers = [
            canonicalize_domain(ns) for ns in nameservers
            if ns.strip()
        ]

        # Extract status — sanitize each through generic field sanitizer.
        status_list = [
            sanitize_field(s, SanitizationFieldKind.GENERIC).value
            for s in _extract_status(data.get("status", []))
        ]

        # WHOIS server (port43) — canonicalize as domain.
        port43_raw: str | None = data.get("port43")
        rdap_port43: str | None = None
        if isinstance(port43_raw, str) and port43_raw.strip():
            try:
                rdap_port43 = canonicalize_domain(port43_raw)
            except CanonicalizationError:
                rdap_port43 = sanitize_field(
                    port43_raw, SanitizationFieldKind.GENERIC
                ).value

        # Build structured payload — omit None values for clean output.
        payload: dict[str, Any] = {}
        if registrant_org is not None:
            payload["registrant_org"] = registrant_org
        if registrar_name is not None:
            payload["registrar"] = registrar_name
        if registration_date is not None:
            payload["registration_date"] = registration_date
        if expiration_date is not None:
            payload["expiration_date"] = expiration_date
        if nameservers:
            payload["nameservers"] = nameservers
        if status_list:
            payload["status"] = status_list
        if rdap_port43 is not None:
            payload["rdap_port43"] = rdap_port43

        # Warn if no registrant org could be extracted.
        if registrant_org is None:
            warnings.append(
                "No registrant organization extracted "
                "(privacy-redacted or personal name filtered)"
            )

        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.RDAP_REGISTRATION,
            subject=ObservationSubject(
                identifier_type=identifier_type,
                identifier_value=identifier_value,
            ),
            observed_at=datetime.now(UTC),
            evidence_blob=raw_bytes,
            evidence_blob_content_type="application/rdap+json",
            structured_payload=payload,
            warnings=warnings,
        )

    async def health_check(self) -> CollectorHealthCheck:
        """HEAD request to rdap.org to verify reachability."""
        checked_at = datetime.now(UTC)
        try:
            async with httpx.AsyncClient(
                timeout=self.config.request_timeout_seconds,
                headers={"User-Agent": self.config.user_agent},
            ) as client:
                start = datetime.now(UTC)
                response = await client.head(_RDAP_BOOTSTRAP_BASE + "/")
                elapsed_ms = (
                    datetime.now(UTC) - start
                ).total_seconds() * 1000
                # Accept 2xx and 405 (some servers reject HEAD).
                if response.status_code < 500:  # noqa: PLR2004
                    return CollectorHealthCheck(
                        collector_id=self.collector_id,
                        collector_version=self.collector_version,
                        status=CollectorStatus.SUCCESS,
                        checked_at=checked_at,
                        latency_ms=elapsed_ms,
                    )
                return CollectorHealthCheck(
                    collector_id=self.collector_id,
                    collector_version=self.collector_version,
                    status=CollectorStatus.FAILURE,
                    checked_at=checked_at,
                    latency_ms=elapsed_ms,
                    error_message=f"RDAP bootstrap returned HTTP {response.status_code}",
                )
        except (httpx.HTTPError, httpx.StreamError) as exc:
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=checked_at,
                error_message=f"RDAP bootstrap unreachable: {exc}",
            )


__all__ = [
    "RdapWhoisCollector",
]

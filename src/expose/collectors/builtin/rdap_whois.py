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

import asyncio
import json
import logging
import re
import shutil
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

_log = logging.getLogger(__name__)

# Timeout for the ``whois`` CLI subprocess (seconds).
_WHOIS_CLI_TIMEOUT_SECONDS = 15

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


# --------------------------------------------------------------------------- #
# WHOIS CLI text-parsing helpers                                               #
# --------------------------------------------------------------------------- #

# Regex patterns for extracting fields from ``whois`` CLI text output.
# Each pattern captures the *value* portion of a ``Key: Value`` line.
_WHOIS_REGISTRANT_ORG_RE = re.compile(
    r"^\s*Registrant\s+Org(?:anization)?:\s*(.+)$",
    re.MULTILINE | re.IGNORECASE,
)
_WHOIS_REGISTRAR_RE = re.compile(
    r"^\s*Registrar:\s*(.+)$",
    re.MULTILINE | re.IGNORECASE,
)
_WHOIS_CREATION_DATE_RE = re.compile(
    r"^\s*(?:Creation Date|Created):\s*(.+)$",
    re.MULTILINE | re.IGNORECASE,
)
_WHOIS_EXPIRATION_DATE_RE = re.compile(
    r"^\s*(?:Registry Expiry Date|Expiration Date):\s*(.+)$",
    re.MULTILINE | re.IGNORECASE,
)
_WHOIS_NAMESERVER_RE = re.compile(
    r"^\s*Name\s+Server:\s*(.+)$",
    re.MULTILINE | re.IGNORECASE,
)
_WHOIS_STATUS_RE = re.compile(
    r"^\s*Domain\s+Status:\s*(.+)$",
    re.MULTILINE | re.IGNORECASE,
)


def _parse_whois_text(text: str) -> dict[str, Any] | None:
    """Parse key registration fields from raw ``whois`` CLI output.

    Returns a dict with the parsed fields (matching the RDAP structured
    payload key names) or ``None`` if the output contains no useful data.
    """
    payload: dict[str, Any] = {}

    m = _WHOIS_REGISTRANT_ORG_RE.search(text)
    if m and m.group(1).strip():
        payload["registrant_org"] = m.group(1).strip()

    m = _WHOIS_REGISTRAR_RE.search(text)
    if m and m.group(1).strip():
        payload["registrar"] = m.group(1).strip()

    m = _WHOIS_CREATION_DATE_RE.search(text)
    if m and m.group(1).strip():
        payload["registration_date"] = m.group(1).strip()

    m = _WHOIS_EXPIRATION_DATE_RE.search(text)
    if m and m.group(1).strip():
        payload["expiration_date"] = m.group(1).strip()

    nameservers = _WHOIS_NAMESERVER_RE.findall(text)
    if nameservers:
        payload["nameservers"] = [ns.strip().lower() for ns in nameservers if ns.strip()]

    statuses = _WHOIS_STATUS_RE.findall(text)
    if statuses:
        # WHOIS status lines often include a URL after the status code —
        # e.g. "clientDeleteProhibited https://icann.org/epp#...".
        # Strip the URL and keep only the human-readable code.
        cleaned: list[str] = []
        for s in statuses:
            code = s.strip().split()[0] if s.strip() else ""
            if code:
                cleaned.append(code)
        if cleaned:
            payload["status"] = cleaned

    if not payload:
        return None

    return payload


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

    @staticmethod
    def _to_apex(domain: str) -> str:
        """Strip subdomains to get the registered/apex domain for RDAP queries.

        RDAP only has records for registered domains (e.g. cyberark.com),
        not subdomains (e.g. www.cyberark.com).  Uses a simple heuristic:
        keep the last two labels for standard TLDs.  For known compound
        ccTLDs (co.uk, com.au, etc.) keep the last three.
        """
        _COMPOUND_TLDS = frozenset({
            "co.uk", "org.uk", "ac.uk", "gov.uk",
            "com.au", "net.au", "org.au",
            "co.nz", "net.nz", "org.nz",
            "co.jp", "or.jp", "ne.jp",
            "co.kr", "or.kr",
            "com.br", "org.br", "net.br",
            "co.za", "org.za", "net.za",
            "co.in", "net.in", "org.in",
            "com.cn", "net.cn", "org.cn",
            "co.il", "org.il",
            "com.mx", "org.mx",
            "com.sg", "org.sg",
        })
        parts = domain.lower().split(".")
        if len(parts) <= 2:
            return domain
        suffix2 = ".".join(parts[-2:])
        if suffix2 in _COMPOUND_TLDS and len(parts) >= 3:
            return ".".join(parts[-3:])
        return suffix2

    async def _expand_domain(self, seed: Seed) -> AsyncIterator[Observation]:
        """Query RDAP for a domain seed (stripped to apex).

        Falls back to the ``whois`` CLI tool if the RDAP server is
        unreachable (network error, timeout, HTTP 4xx/5xx).
        """
        canonical = canonicalize_domain(seed.value)
        apex = self._to_apex(canonical)
        url = f"{_RDAP_BOOTSTRAP_BASE}/domain/{apex}"

        try:
            data = await self._fetch_rdap(url)
        except CollectorSourceUnreachableError as rdap_exc:
            # RDAP failed — attempt WHOIS CLI fallback.
            _log.warning(
                "RDAP unreachable for %s, trying whois CLI fallback: %s",
                apex,
                rdap_exc,
            )
            fallback = await self._whois_cli_fallback(apex)
            if fallback is None:
                # Both sources failed; re-raise the original RDAP error.
                raise
            yield fallback
            return

        observation = self._parse_rdap_response(
            data=data,
            identifier_type=IdentifierType.DOMAIN,
            identifier_value=apex,
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

    async def _whois_cli_fallback(self, domain: str) -> Observation | None:
        """Shell out to the ``whois`` CLI tool and parse the text output.

        Returns an ``Observation`` with ``"source": "whois_cli_fallback"``
        in the structured payload, or ``None`` if the whois command fails
        or returns no useful data.

        Uses ``asyncio.create_subprocess_exec`` (not ``shell=True``) so the
        domain argument is passed directly to the ``whois`` binary without
        shell interpolation — no injection risk.
        """
        if shutil.which("whois") is None:
            _log.warning("whois CLI not found on PATH; cannot fall back")
            return None

        try:
            proc = await asyncio.create_subprocess_exec(
                "whois",
                domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=_WHOIS_CLI_TIMEOUT_SECONDS,
            )
        except TimeoutError:
            _log.warning(
                "whois CLI timed out after %ds for %s",
                _WHOIS_CLI_TIMEOUT_SECONDS,
                domain,
            )
            return None
        except OSError as exc:
            _log.warning("whois CLI exec failed for %s: %s", domain, exc)
            return None

        if proc.returncode != 0:
            _log.warning(
                "whois CLI returned exit code %d for %s: %s",
                proc.returncode,
                domain,
                stderr.decode("utf-8", errors="replace").strip()[:200],
            )
            return None

        text = stdout.decode("utf-8", errors="replace")
        parsed = _parse_whois_text(text)
        if parsed is None:
            _log.warning("whois CLI returned no useful data for %s", domain)
            return None

        # Sanitize org strings through the same pipeline as RDAP.
        if "registrant_org" in parsed:
            parsed["registrant_org"] = _sanitize_org_string(
                parsed["registrant_org"],
            )
            if parsed["registrant_org"] is None:
                del parsed["registrant_org"]
        if "registrar" in parsed:
            parsed["registrar"] = _sanitize_org_string(parsed["registrar"])
            if parsed["registrar"] is None:
                del parsed["registrar"]

        # Canonicalize nameservers.
        if "nameservers" in parsed:
            canonical_ns: list[str] = []
            for ns in parsed["nameservers"]:
                try:
                    canonical_ns.append(canonicalize_domain(ns))
                except CanonicalizationError:
                    canonical_ns.append(ns)
            parsed["nameservers"] = canonical_ns

        # Sanitize status values.
        if "status" in parsed:
            parsed["status"] = [
                sanitize_field(s, SanitizationFieldKind.GENERIC).value
                for s in parsed["status"]
            ]

        # Tag the payload so downstream consumers know this came from the
        # CLI fallback rather than RDAP proper.
        parsed["source"] = "whois_cli_fallback"

        warnings: list[str] = [
            "Data sourced from whois CLI fallback (RDAP was unreachable)",
        ]
        if "registrant_org" not in parsed:
            warnings.append(
                "No registrant organization extracted "
                "(privacy-redacted or personal name filtered)",
            )

        return Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.RDAP_REGISTRATION,
            subject=ObservationSubject(
                identifier_type=IdentifierType.DOMAIN,
                identifier_value=domain,
            ),
            observed_at=datetime.now(UTC),
            evidence_blob=text.encode("utf-8"),
            evidence_blob_content_type="text/plain",
            structured_payload=parsed,
            warnings=warnings,
        )

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
        """HEAD request to rdap.org to verify reachability.

        Also checks whether the ``whois`` CLI is available on PATH (used
        as a fallback when RDAP is unreachable).  The result is reported
        in the ``detail`` dict as ``whois_cli_available``.
        """
        checked_at = datetime.now(UTC)
        whois_available = shutil.which("whois") is not None
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
                        detail={"whois_cli_available": whois_available},
                    )
                return CollectorHealthCheck(
                    collector_id=self.collector_id,
                    collector_version=self.collector_version,
                    status=CollectorStatus.FAILURE,
                    checked_at=checked_at,
                    latency_ms=elapsed_ms,
                    error_message=f"RDAP bootstrap returned HTTP {response.status_code}",
                    detail={"whois_cli_available": whois_available},
                )
        except (httpx.HTTPError, httpx.StreamError) as exc:
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=checked_at,
                error_message=f"RDAP bootstrap unreachable: {exc}",
                detail={"whois_cli_available": whois_available},
            )


__all__ = [
    "RdapWhoisCollector",
]

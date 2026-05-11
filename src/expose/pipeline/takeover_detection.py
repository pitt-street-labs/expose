"""Subdomain takeover detection — identify dangling CNAME records (Issue #95).

When a CNAME record points to a third-party service that no longer exists
(e.g., ``staging.cyberark.com CNAME -> cyberark.herokuapp.com`` but the
Heroku app was deleted), an attacker can claim that service and hijack the
subdomain.  This is a critical finding.

Detection algorithm:

1. Find entities with CNAME-related properties (``target``, ``cname_chain``,
   ``cname_target``) from the active-dns and dns_subdomain_enum collectors.
2. Match CNAME targets against ``TAKEOVER_FINGERPRINTS`` — known providers
   whose unclaimed services can be registered by anyone.
3. For each match, perform a quick async DNS resolution on the CNAME target.
4. If the CNAME target returns NXDOMAIN (no DNS records), the service is
   dangling and the subdomain is vulnerable to takeover.
5. Return a list of ``TakeoverRisk`` findings.

The fingerprint database covers the most common takeover-vulnerable services
documented by `can-i-take-over-xyz <https://github.com/EdOverflow/can-i-take-over-xyz>`_.
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import socket
from collections.abc import Sequence
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Takeover-vulnerable service fingerprints
# ---------------------------------------------------------------------------

TAKEOVER_FINGERPRINTS: dict[str, dict[str, str]] = {
    "herokuapp.com": {
        "provider": "heroku",
        "check": "NXDOMAIN on CNAME target",
    },
    "s3.amazonaws.com": {
        "provider": "aws_s3",
        "check": "NoSuchBucket response",
    },
    "*.s3.amazonaws.com": {
        "provider": "aws_s3",
        "check": "NoSuchBucket response",
    },
    "azurewebsites.net": {
        "provider": "azure",
        "check": "NXDOMAIN on CNAME target",
    },
    "cloudapp.net": {
        "provider": "azure",
        "check": "NXDOMAIN",
    },
    "github.io": {
        "provider": "github_pages",
        "check": "404 from GitHub",
    },
    "netlify.app": {
        "provider": "netlify",
        "check": "Not found page",
    },
    "*.wpengine.com": {
        "provider": "wpengine",
        "check": "NXDOMAIN",
    },
    "*.ghost.io": {
        "provider": "ghost",
        "check": "NXDOMAIN",
    },
    "*.firebaseapp.com": {
        "provider": "firebase",
        "check": "NXDOMAIN",
    },
    "*.vercel.app": {
        "provider": "vercel",
        "check": "NXDOMAIN",
    },
    "*.fly.dev": {
        "provider": "fly",
        "check": "NXDOMAIN",
    },
    "*.surge.sh": {
        "provider": "surge",
        "check": "NXDOMAIN",
    },
    "*.bitbucket.io": {
        "provider": "bitbucket",
        "check": "NXDOMAIN",
    },
    "*.zendesk.com": {
        "provider": "zendesk",
        "check": "NXDOMAIN",
    },
    "*.freshdesk.com": {
        "provider": "freshdesk",
        "check": "NXDOMAIN",
    },
    "*.statuspage.io": {
        "provider": "statuspage",
        "check": "NXDOMAIN",
    },
    "unbouncepages.com": {
        "provider": "unbounce",
        "check": "NXDOMAIN",
    },
    "*.shopify.com": {
        "provider": "shopify",
        "check": "NXDOMAIN",
    },
}


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TakeoverRisk:
    """A confirmed subdomain takeover risk.

    Attributes:
        subdomain: The source domain whose CNAME is dangling
            (e.g. ``staging.cyberark.com``).
        cname_target: The CNAME target that no longer resolves
            (e.g. ``cyberark.herokuapp.com``).
        provider: The hosting provider whose service was deleted
            (e.g. ``heroku``).
        risk_level: Severity — ``"critical"`` for confirmed NXDOMAIN,
            ``"high"`` for matched but unverified, ``"medium"`` for edge cases.
        evidence: Human-readable description of the evidence
            (e.g. ``"CNAME target returns NXDOMAIN"``).
    """

    subdomain: str
    cname_target: str
    provider: str
    risk_level: str  # "critical" | "high" | "medium"
    evidence: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _normalize(value: str) -> str:
    """Lowercase and strip trailing dots for consistent matching."""
    return value.lower().rstrip(".")


def _match_fingerprint(cname_target: str) -> dict[str, str] | None:
    """Match a CNAME target against the takeover fingerprint database.

    Returns the fingerprint dict if matched, else ``None``.
    Uses glob-style matching (``fnmatch``) for patterns starting with ``*``.
    """
    normalized = _normalize(cname_target)

    for pattern, fingerprint in TAKEOVER_FINGERPRINTS.items():
        pattern_lower = pattern.lower()
        if pattern_lower.startswith("*."):
            # Glob match: *.herokuapp.com matches foo.herokuapp.com
            if fnmatch.fnmatch(normalized, pattern_lower):
                return fingerprint
        else:
            # Suffix match: herokuapp.com matches foo.herokuapp.com
            if normalized == pattern_lower or normalized.endswith("." + pattern_lower):
                return fingerprint

    return None


def _extract_cname_targets(properties: dict) -> list[str]:
    """Extract CNAME target values from entity properties.

    Checks the same property keys as the supply chain module:
    - ``target`` when ``record_type`` is ``CNAME`` (from active_dns)
    - ``cname_chain`` (from dns_subdomain_enum)
    - ``cname_target`` (from some collectors)
    """
    targets: list[str] = []

    # active_dns CNAME record
    if properties.get("record_type") == "CNAME" and "target" in properties:
        targets.append(str(properties["target"]))

    # dns_subdomain_enum CNAME chain
    for cname in properties.get("cname_chain", []):
        targets.append(str(cname))

    # Standalone cname_target field
    if "cname_target" in properties:
        targets.append(str(properties["cname_target"]))

    return targets


async def _check_nxdomain(hostname: str, timeout: float = 3.0) -> bool:
    """Return True if the hostname returns NXDOMAIN (does not resolve).

    Uses ``socket.getaddrinfo`` in an executor for non-blocking operation.
    Returns ``True`` (dangling) when the lookup fails with ``gaierror``
    or times out, ``False`` when the name resolves to any address.
    """
    try:
        result = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None,
                socket.getaddrinfo,
                hostname,
                None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            ),
            timeout=timeout,
        )
        # If we got results, the service still exists
        return not bool(result)
    except (TimeoutError, socket.gaierror, OSError):
        # NXDOMAIN, timeout, or other resolution failure — dangling
        return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def detect_takeover_risks(
    entities: Sequence,
    *,
    dns_check: bool = True,
) -> list[TakeoverRisk]:
    """Check entity CNAME records against takeover-vulnerable services.

    Scans all entities for CNAME properties, matches targets against
    ``TAKEOVER_FINGERPRINTS``, and (optionally) performs DNS resolution
    to confirm the target is dangling.

    Args:
        entities: Sequence of Entity-like objects with ``canonical_identifier``
            and ``properties`` attributes.
        dns_check: If ``True`` (default), performs async DNS resolution to
            confirm NXDOMAIN. Set to ``False`` in tests to skip network calls.

    Returns:
        A list of ``TakeoverRisk`` objects for each confirmed risk.
    """
    risks: list[TakeoverRisk] = []
    # Collect all (subdomain, cname_target, fingerprint) candidates first
    candidates: list[tuple[str, str, dict[str, str]]] = []

    for entity in entities:
        props = entity.properties or {}
        subdomain = entity.canonical_identifier
        cname_targets = _extract_cname_targets(props)

        for target in cname_targets:
            fingerprint = _match_fingerprint(target)
            if fingerprint is not None:
                candidates.append((subdomain, target, fingerprint))

    if not candidates:
        return risks

    if dns_check:
        # Check all candidates concurrently
        dns_tasks = [_check_nxdomain(target) for _, target, _ in candidates]
        dns_results = await asyncio.gather(*dns_tasks)
    else:
        # Skip DNS checks — treat all matches as high risk (for tests)
        dns_results = [None] * len(candidates)

    for (subdomain, target, fingerprint), is_nxdomain in zip(
        candidates, dns_results, strict=True,
    ):
        if dns_check:
            if is_nxdomain:
                # Confirmed dangling CNAME — critical risk
                risks.append(TakeoverRisk(
                    subdomain=subdomain,
                    cname_target=target,
                    provider=fingerprint["provider"],
                    risk_level="critical",
                    evidence="CNAME target returns NXDOMAIN",
                ))
            else:
                # CNAME target resolves — service still active, no risk
                logger.debug(
                    "Takeover check: %s -> %s resolves (service active)",
                    subdomain,
                    target,
                )
        else:
            # No DNS check — report as high risk (needs verification)
            risks.append(TakeoverRisk(
                subdomain=subdomain,
                cname_target=target,
                provider=fingerprint["provider"],
                risk_level="high",
                evidence=f"CNAME target matches takeover-vulnerable service ({fingerprint['check']})",
            ))

    return risks


__all__ = [
    "TAKEOVER_FINGERPRINTS",
    "TakeoverRisk",
    "detect_takeover_risks",
]

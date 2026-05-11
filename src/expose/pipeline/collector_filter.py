"""AI-guided collector selection via signal-to-action rules.

After Pass 1 builds a ``TargetProfile``, this module applies a rule table to
determine which collectors should be skipped or prioritized for Pass 2+. The
goal is to avoid wasted work (e.g., active port scanning a CDN edge) and to
front-load the highest-value collectors for the target's infrastructure.

Rule evaluation:

1. The target profile is translated into a set of *signal tags* (e.g.,
   ``"cloud_proxied"``, ``"no_voip"``, ``"high_cert_count"``).
2. Each signal tag maps to a ``skip`` list and/or ``prioritize`` list of
   collector IDs.
3. ``filter_collectors`` removes skipped collectors and reorders the remaining
   list so prioritized collectors come first.
4. Filtering decisions are returned alongside the filtered list for logging
   and audit.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from expose.pipeline.target_profile import TargetProfile

logger = logging.getLogger(__name__)


# === Signal-to-action rule table ==============================================

# Each key is a signal tag derived from the target profile.  Values are dicts
# with optional ``skip`` and ``prioritize`` lists of collector IDs.

COLLECTOR_RULES: dict[str, dict[str, list[str]]] = {
    "cloud_proxied": {
        "skip": ["active-port-surface"],  # scanning CDN edge, not target
        "prioritize": ["ct-certspotter", "ct-crtsh"],  # many subdomains behind CDN
    },
    "email_outsourced": {
        "skip": ["mail-headers"],  # no on-prem mail server to probe
    },
    "no_voip": {
        "skip": ["sip-discovery"],  # no SIP infrastructure detected
    },
    "low_cert_count": {
        "skip": ["ct-censys", "common-crawl"],  # won't find more certs
        "prioritize": ["active-dns-resolve", "active-tls-handshake"],
    },
    "high_cert_count": {
        "skip": [
            "active-port-surface",
            "active-http-fingerprint",
        ],  # too many targets for active probing
        "prioritize": ["ct-certspotter", "ct-crtsh", "ct-censys"],
    },
    "whois_privacy": {
        "skip": ["ma-discovery"],  # can't extract org from RDAP
    },
}

# Thresholds for cert count classification.
_LOW_CERT_THRESHOLD = 5
_HIGH_CERT_THRESHOLD = 50


# === Filtering result =========================================================


@dataclass(frozen=True)
class FilterDecision:
    """Record of a single filtering decision for audit/logging."""

    signal: str
    action: str  # "skip" | "prioritize"
    collector_id: str
    reason: str


@dataclass(frozen=True)
class FilterResult:
    """Complete result of collector filtering."""

    filtered_collector_ids: list[str]
    decisions: list[FilterDecision] = field(default_factory=list)
    signals_active: list[str] = field(default_factory=list)


# === Signal derivation ========================================================


def _derive_signals(profile: TargetProfile) -> list[str]:
    """Translate a target profile into a list of active signal tags.

    Returns signal tags in evaluation order. The order matters because
    ``high_cert_count`` and ``low_cert_count`` have contradictory rules
    and only one should fire.
    """
    signals: list[str] = []

    # Infrastructure type signals.
    if profile.infrastructure_type == "cloud_proxied":
        signals.append("cloud_proxied")

    # Email provider signals.
    if profile.email_provider not in ("self_hosted", "unknown"):
        signals.append("email_outsourced")

    # VoIP signals.
    if not profile.has_voip:
        signals.append("no_voip")

    # Certificate count signals (mutually exclusive).
    if profile.cert_count >= _HIGH_CERT_THRESHOLD:
        signals.append("high_cert_count")
    elif profile.cert_count <= _LOW_CERT_THRESHOLD:
        signals.append("low_cert_count")

    # WHOIS privacy signals -- check detected providers and org availability.
    if not profile.org_name_available:
        signals.append("whois_privacy")

    return signals


# === Public API ===============================================================


def filter_collectors(
    profile: TargetProfile,
    collector_ids: list[str],
) -> FilterResult:
    """Apply signal-to-action rules to filter and reorder collectors.

    Parameters
    ----------
    profile:
        Target profile built from Pass 1 entities.
    collector_ids:
        Full list of enabled collector IDs for this run.

    Returns
    -------
    FilterResult
        Contains the filtered/reordered collector ID list, the active signals,
        and the individual decisions made.
    """
    signals = _derive_signals(profile)
    decisions: list[FilterDecision] = []

    skip_set: set[str] = set()
    prioritize_list: list[str] = []  # ordered, deduped
    prioritize_set: set[str] = set()

    for signal in signals:
        rule = COLLECTOR_RULES.get(signal)
        if rule is None:
            continue

        for cid in rule.get("skip", []):
            if cid in {c for c in collector_ids} and cid not in skip_set:
                skip_set.add(cid)
                decisions.append(FilterDecision(
                    signal=signal,
                    action="skip",
                    collector_id=cid,
                    reason=f"Signal '{signal}' skips '{cid}'",
                ))

        for cid in rule.get("prioritize", []):
            if cid in {c for c in collector_ids} and cid not in prioritize_set:
                prioritize_list.append(cid)
                prioritize_set.add(cid)
                decisions.append(FilterDecision(
                    signal=signal,
                    action="prioritize",
                    collector_id=cid,
                    reason=f"Signal '{signal}' prioritizes '{cid}'",
                ))

    # Build the filtered list: prioritized collectors first, then the rest
    # in original order, with skipped collectors removed.
    remaining = [
        cid for cid in collector_ids
        if cid not in skip_set and cid not in prioritize_set
    ]
    # Only include prioritized collectors that are NOT also skipped.
    filtered_prioritized = [
        cid for cid in prioritize_list if cid not in skip_set
    ]
    filtered = filtered_prioritized + remaining

    logger.info(
        "Collector filter: %d signals active, %d skipped, %d prioritized, "
        "%d -> %d collectors",
        len(signals),
        len(skip_set),
        len(filtered_prioritized),
        len(collector_ids),
        len(filtered),
    )
    for decision in decisions:
        logger.debug(
            "Filter decision: %s %s %s (%s)",
            decision.action,
            decision.collector_id,
            decision.signal,
            decision.reason,
        )

    return FilterResult(
        filtered_collector_ids=filtered,
        decisions=decisions,
        signals_active=signals,
    )


__all__ = [
    "COLLECTOR_RULES",
    "FilterDecision",
    "FilterResult",
    "filter_collectors",
]

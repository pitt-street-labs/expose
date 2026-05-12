"""Advanced scoring signals — commercial threat-context IP.

These 14 signals provide the competitive differentiation of EXPOSE Threat
Context over table-stakes EASM tooling.  They are auto-discovered by the
``LeadScoringEngine`` via the ``ADVANCED_SIGNALS`` registry exported here.

Each signal function has the same interface as the engine's built-in
``_check_*`` static methods: it receives the relevant kwargs from
``score_entity()`` and returns a ``list[ScoringSignal]`` (empty if the
signal does not fire).

License: proprietary (EXPOSE Threat Context module, per ADR-009).
"""

from __future__ import annotations

# Copyright 2026 Korlogos / Pitt Street Labs. All rights reserved.
# This file is part of EXPOSE Commercial Modules and is NOT covered by the
# Apache 2.0 license that governs the core engine. Unauthorized copying,
# distribution, or use of this file is strictly prohibited. Contact
# licensing@korlogos.com for commercial licensing terms.

import re
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from expose.pipeline.environment_classifier import EnvironmentClassification
    from expose.pipeline.saas_alignment import SurfaceGap
    from expose.pipeline.trust_degradation import TrustDegradationEvent
    from expose.pipeline.vision import ScreenshotAnalysis

from expose.pipeline.lead_scoring import ScoringSignal

# ---------------------------------------------------------------------------
# Type alias for signal functions used in the registry
# ---------------------------------------------------------------------------

SignalFunc = Callable[..., list[ScoringSignal]]

# ---------------------------------------------------------------------------
# Weak cipher keywords (case-insensitive substring match).
# ---------------------------------------------------------------------------

_WEAK_CIPHER_KEYWORDS: tuple[str, ...] = ("RC4", "DES", "3DES", "NULL", "EXPORT")

# Regex for version numbers in Server header (e.g. "nginx/1.24.0").
_VERSION_RE: re.Pattern[str] = re.compile(r"/\d+[\d.]*")

# CWE classes that indicate RCE-capable weakness patterns.
_RCE_CWE_CLASSES: frozenset[str] = frozenset({
    "CWE-94",   # Code Injection
    "CWE-502",  # Deserialization of Untrusted Data
    "CWE-78",   # OS Command Injection
    "CWE-119",  # Buffer Overflow (Improper Restriction of Operations)
})


# ===================================================================
# Signal functions
# ===================================================================


def _check_waf(
    *,
    waf_detected: bool | None = None,
    **_kwargs: Any,
) -> list[ScoringSignal]:
    """No WAF/CDN detected -> +20 points."""
    if waf_detected is False:
        return [
            ScoringSignal(
                signal_name="no_waf_protection",
                points=20,
                evidence="No CDN/WAF detected — direct exposure",
                source_module="waf_detection",
            )
        ]
    return []


def _check_dnsbl(
    *,
    dnsbl_listings: list[dict[str, Any]] | None = None,
    **_kwargs: Any,
) -> list[ScoringSignal]:
    """DNSBL listings -> +15 (medium) or +25 (critical/xbl)."""
    if not dnsbl_listings:
        return []

    has_critical = any(
        listing.get("listing_type") == "xbl" or listing.get("severity") == "critical"
        for listing in dnsbl_listings
    )
    points = 25 if has_critical else 15

    providers = [
        listing.get("blacklist_name", listing.get("blacklist_zone", "unknown"))
        for listing in dnsbl_listings
    ]
    evidence = f"Listed on {len(dnsbl_listings)} DNSBL(s): {', '.join(providers)}"

    return [
        ScoringSignal(
            signal_name="dnsbl_listed",
            points=points,
            evidence=evidence,
            source_module="dns_blacklist",
        )
    ]


def _check_trust(
    *,
    trust_events: list[TrustDegradationEvent] | None = None,
    **_kwargs: Any,
) -> list[ScoringSignal]:
    """Trust degradation -> +15 (HIGH/CRITICAL severity) or +10 (others)."""
    if not trust_events:
        return []

    from expose.pipeline.trust_degradation import DegradationSeverity

    severity_rank = {
        DegradationSeverity.INFO: 0,
        DegradationSeverity.LOW: 1,
        DegradationSeverity.MEDIUM: 2,
        DegradationSeverity.HIGH: 3,
        DegradationSeverity.CRITICAL: 4,
    }

    worst = max(trust_events, key=lambda e: severity_rank.get(e.severity, 0))
    worst_rank = severity_rank.get(worst.severity, 0)
    points = 15 if worst_rank >= severity_rank[DegradationSeverity.HIGH] else 10

    return [
        ScoringSignal(
            signal_name="trust_degradation",
            points=points,
            evidence=f"{worst.event_type.value} ({worst.severity.value}): {worst.description}",
            source_module="trust_degradation",
        )
    ]


def _check_ma(
    *,
    is_transitive_ma: bool = False,
    **_kwargs: Any,
) -> list[ScoringSignal]:
    """Post-acquisition asset -> +10 points."""
    if is_transitive_ma:
        return [
            ScoringSignal(
                signal_name="post_acquisition_asset",
                points=10,
                evidence="Discovered via M&A search — post-acquisition integration risk",
                source_module="ma_discovery",
            )
        ]
    return []


def _check_saas(
    *,
    saas_gaps: list[SurfaceGap] | None = None,
    **_kwargs: Any,
) -> list[ScoringSignal]:
    """Unexpected SaaS products -> +10 points."""
    if not saas_gaps:
        return []

    unexpected = [g for g in saas_gaps if g.gap_type == "unexpected_product"]
    if not unexpected:
        return []

    names = [g.product_name for g in unexpected]
    return [
        ScoringSignal(
            signal_name="unexpected_saas_product",
            points=10,
            evidence=f"Unexpected product(s): {', '.join(names)}",
            source_module="saas_alignment",
        )
    ]


def _check_vision(
    *,
    vision_analysis: ScreenshotAnalysis | None = None,
    **_kwargs: Any,
) -> list[ScoringSignal]:
    """Vision security indicators -> +10 points."""
    if vision_analysis is None or not vision_analysis.security_indicators:
        return []

    indicator_types = [ind.indicator_type for ind in vision_analysis.security_indicators]
    return [
        ScoringSignal(
            signal_name="security_indicator_found",
            points=10,
            evidence=f"Visual analysis found: {', '.join(indicator_types)}",
            source_module="vision",
        )
    ]


def _check_debug_mode(
    *,
    environment: EnvironmentClassification | None = None,
    **_kwargs: Any,
) -> list[ScoringSignal]:
    """Debug mode or stack traces visible -> +10 points."""
    if environment is None:
        return []

    debug_indicators = {"Debug mode enabled", "Stack traces visible"}
    found = [rf for rf in environment.risk_factors if rf in debug_indicators]
    if not found:
        return []

    return [
        ScoringSignal(
            signal_name="debug_mode_detected",
            points=10,
            evidence=f"Environment classifier detected: {', '.join(found)}",
            source_module="environment_classifier",
        )
    ]


def _check_dns_exposure(
    *,
    observations: list[dict[str, Any]] | None = None,
    **_kwargs: Any,
) -> list[ScoringSignal]:
    """DNS misconfiguration signals -> +5-15 points."""
    obs = observations or []
    signals: list[ScoringSignal] = []

    for ob in obs:
        cid = ob.get("_collector_id") or ob.get("collector_id", "")
        if cid != "active-dns-resolve":
            continue

        payload = ob.get("structured_payload", ob)

        if payload.get("zone_transfer"):
            signals.append(
                ScoringSignal(
                    signal_name="dns_exposure",
                    points=15,
                    evidence="Zone transfer successful — full zone data exposed",
                    source_module="dns_resolve",
                )
            )
            return signals

        if payload.get("wildcard_dns"):
            signals.append(
                ScoringSignal(
                    signal_name="dns_exposure",
                    points=10,
                    evidence="Wildcard DNS detected — attack surface amplifier",
                    source_module="dns_resolve",
                )
            )
            return signals

        if payload.get("dnssec") is False:
            signals.append(
                ScoringSignal(
                    signal_name="dns_exposure",
                    points=5,
                    evidence="No DNSSEC configured",
                    source_module="dns_resolve",
                )
            )
            return signals

    return signals


def _check_http_exposure(
    *,
    observations: list[dict[str, Any]] | None = None,
    **_kwargs: Any,
) -> list[ScoringSignal]:
    """HTTP technology exposure signals -> +5-10 points."""
    obs = observations or []
    signals: list[ScoringSignal] = []

    for ob in obs:
        cid = ob.get("_collector_id") or ob.get("collector_id", "")
        if cid != "active-http-fingerprint":
            continue

        payload = ob.get("structured_payload", ob)

        # Server header version leak.
        server_header: str | None = payload.get("server_header")
        if server_header and _VERSION_RE.search(server_header):
            signals.append(
                ScoringSignal(
                    signal_name="http_technology_exposure",
                    points=5,
                    evidence=f"Server header leaks version: {server_header}",
                    source_module="http_fingerprint",
                )
            )

        # Cookie without Secure/HttpOnly flags.
        cookie_issues: list[dict[str, Any]] = payload.get("cookie_issues", [])
        insecure_cookies: list[str] = []
        for issue in cookie_issues:
            missing = issue.get("missing_flags", [])
            if "secure" in missing or "httponly" in missing:
                insecure_cookies.append(issue.get("name", "unknown"))
        if insecure_cookies:
            signals.append(
                ScoringSignal(
                    signal_name="http_technology_exposure",
                    points=5,
                    evidence=f"Insecure cookies: {', '.join(insecure_cookies)}",
                    source_module="http_fingerprint",
                )
            )

        # CORS wildcard origin.
        cors_misconfig: dict[str, Any] | None = payload.get("cors_misconfig")
        if cors_misconfig and "wildcard_origin" in cors_misconfig.get("issues", []):
            signals.append(
                ScoringSignal(
                    signal_name="http_technology_exposure",
                    points=10,
                    evidence="CORS wildcard origin (*) configured",
                    source_module="http_fingerprint",
                )
            )

        if signals:
            return signals

    return signals


def _check_vendor_cve_density(
    *,
    observations: list[dict[str, Any]] | None = None,
    **_kwargs: Any,
) -> list[ScoringSignal]:
    """Vendor CVE density -> +10 (>50), +15 (>100), +20 (>200) points."""
    obs = observations or []

    for ob in obs:
        cid = ob.get("_collector_id") or ob.get("collector_id", "")
        if cid != "vendor-cve-history":
            continue

        payload = ob.get("structured_payload", ob)
        cve_count = payload.get("cve_count", 0)
        if not isinstance(cve_count, int):
            continue

        if cve_count > 200:  # noqa: PLR2004
            return [
                ScoringSignal(
                    signal_name="vendor_cve_density",
                    points=20,
                    evidence=f"Vendor has {cve_count} historical CVEs (>200)",
                    source_module="vendor_cve_history",
                )
            ]
        if cve_count > 100:  # noqa: PLR2004
            return [
                ScoringSignal(
                    signal_name="vendor_cve_density",
                    points=15,
                    evidence=f"Vendor has {cve_count} historical CVEs (>100)",
                    source_module="vendor_cve_history",
                )
            ]
        if cve_count > 50:  # noqa: PLR2004
            return [
                ScoringSignal(
                    signal_name="vendor_cve_density",
                    points=10,
                    evidence=f"Vendor has {cve_count} historical CVEs (>50)",
                    source_module="vendor_cve_history",
                )
            ]

    return []


def _check_eol_product(
    *,
    observations: list[dict[str, Any]] | None = None,
    **_kwargs: Any,
) -> list[ScoringSignal]:
    """End-of-life product -> +15 (EOL), +25 (EOL with >50 CVEs) points."""
    obs = observations or []

    for ob in obs:
        payload = ob.get("structured_payload", ob)
        eol_status = payload.get("eol_status")

        if eol_status is not True:
            continue

        cve_count = payload.get("cve_count", 0)
        if isinstance(cve_count, int) and cve_count > 50:  # noqa: PLR2004
            return [
                ScoringSignal(
                    signal_name="eol_product",
                    points=25,
                    evidence=f"End-of-life product with {cve_count} CVEs",
                    source_module="vendor_cve_history",
                )
            ]

        return [
            ScoringSignal(
                signal_name="eol_product",
                points=15,
                evidence="End-of-life product — no further security patches",
                source_module="vendor_cve_history",
            )
        ]

    return []


def _check_predicted_rce(
    *,
    observations: list[dict[str, Any]] | None = None,
    **_kwargs: Any,
) -> list[ScoringSignal]:
    """Predicted RCE-class weakness -> +20 points."""
    obs = observations or []

    for ob in obs:
        cid = ob.get("_collector_id") or ob.get("collector_id", "")
        if cid != "vendor-cve-history":
            continue

        payload = ob.get("structured_payload", ob)
        top_cwes: list[dict[str, Any]] = payload.get("top_cwes", [])

        for cwe_entry in top_cwes:
            cwe_id = cwe_entry.get("cwe_id", "")
            frequency = cwe_entry.get("frequency", 0.0)
            if not isinstance(frequency, (int, float)):
                continue
            if cwe_id in _RCE_CWE_CLASSES and frequency > 0.10:  # noqa: PLR2004
                return [
                    ScoringSignal(
                        signal_name="predicted_rce",
                        points=20,
                        evidence=f"{cwe_id} appears in {frequency:.0%} of vendor CVEs",
                        source_module="vendor_cve_history",
                    )
                ]

    return []


def _check_active_exploitation(
    *,
    observations: list[dict[str, Any]] | None = None,
    **_kwargs: Any,
) -> list[ScoringSignal]:
    """Active exploitation confirmed by CISA KEV -> +25 points."""
    obs = observations or []

    for ob in obs:
        cid = ob.get("_collector_id") or ob.get("collector_id", "")
        if cid != "vendor-cve-history":
            continue

        payload = ob.get("structured_payload", ob)
        kev_count = payload.get("kev_count", 0)
        if isinstance(kev_count, int) and kev_count > 0:
            return [
                ScoringSignal(
                    signal_name="active_exploitation",
                    points=25,
                    evidence=f"{kev_count} vendor CVE(s) in CISA KEV catalog",
                    source_module="vendor_cve_history",
                )
            ]

    return []


def _check_slow_patch_velocity(
    *,
    observations: list[dict[str, Any]] | None = None,
    **_kwargs: Any,
) -> list[ScoringSignal]:
    """Slow patch velocity -> +10 points."""
    obs = observations or []

    for ob in obs:
        cid = ob.get("_collector_id") or ob.get("collector_id", "")
        if cid != "vendor-cve-history":
            continue

        payload = ob.get("structured_payload", ob)
        velocity = payload.get("patch_velocity_days")
        if isinstance(velocity, (int, float)) and velocity > 60:  # noqa: PLR2004
            return [
                ScoringSignal(
                    signal_name="slow_patch_velocity",
                    points=10,
                    evidence=f"Average patch time: {velocity:.0f} days (>60 day threshold)",
                    source_module="vendor_cve_history",
                )
            ]

    return []


# ===================================================================
# Signal registry — exported for auto-discovery by the engine
# ===================================================================

ADVANCED_SIGNALS: list[SignalFunc] = [
    _check_waf,
    _check_dnsbl,
    _check_trust,
    _check_ma,
    _check_saas,
    _check_vision,
    _check_debug_mode,
    _check_dns_exposure,
    _check_http_exposure,
    _check_vendor_cve_density,
    _check_eol_product,
    _check_predicted_rce,
    _check_active_exploitation,
    _check_slow_patch_velocity,
]

__all__ = [
    "ADVANCED_SIGNALS",
]

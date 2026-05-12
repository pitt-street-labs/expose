"""Lead scoring engine — aggregate multi-signal analysis into composite priority scores.

Combines signals from environment classification, WAF detection, DNSBL listings,
trust degradation events, SaaS alignment gaps, vision analysis, and observation-level
security indicators into a single 0-100 score per entity.  The score answers
"what should I investigate first?" and is deterministic given the same inputs.

This module is pure — no LLM calls, no external I/O, no side effects.  All
scoring logic is deterministic and operates on structured model instances and
observation dicts.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from expose.pipeline.environment_classifier import EnvironmentClassification
from expose.pipeline.saas_alignment import SurfaceGap
from expose.pipeline.trust_degradation import DegradationSeverity, TrustDegradationEvent
from expose.pipeline.vision import ScreenshotAnalysis

# === Enums ====================================================================


class PriorityTier(StrEnum):
    CRITICAL = "critical"  # 70-100
    HIGH = "high"  # 40-69
    MEDIUM = "medium"  # 20-39
    LOW = "low"  # 0-19


# === Models ===================================================================


class ScoringSignal(BaseModel):
    """A single signal contributing to the composite lead score."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    signal_name: str = Field(min_length=1)
    points: int = Field(ge=0, le=100)
    evidence: str
    source_module: str = Field(min_length=1)


class LeadScore(BaseModel):
    """Aggregated lead score for a single entity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entity_identifier: str = Field(min_length=1)
    score: int = Field(ge=0, le=100)
    priority_tier: PriorityTier
    contributing_signals: list[ScoringSignal]
    justification: str
    scored_at: datetime


# === Tier mapping =============================================================


def _score_to_tier(score: int) -> PriorityTier:
    """Map a numeric score to its priority tier."""
    if score >= 70:  # noqa: PLR2004
        return PriorityTier.CRITICAL
    if score >= 40:  # noqa: PLR2004
        return PriorityTier.HIGH
    if score >= 20:  # noqa: PLR2004
        return PriorityTier.MEDIUM
    return PriorityTier.LOW


# === Justification builder ====================================================

# Human-readable phrases for each signal name.
_SIGNAL_PHRASES: dict[str, str] = {
    "non_production_exposed": "non-production endpoint",
    "no_waf_protection": "no WAF protection",
    "dnsbl_listed": "blacklisted IP",
    "trust_degradation": "recent infrastructure changes",
    "post_acquisition_asset": "post-acquisition asset",
    "unexpected_saas_product": "shadow IT detected",
    "security_indicator_found": "security finding in page analysis",
    "missing_security_headers": "missing security headers",
    "weak_certificate": "weak/self-signed certificate",
    "debug_mode_detected": "debug mode enabled",
    "open_port_risk": "risky open ports",
    "deprecated_tls": "deprecated TLS configuration",
    "dns_exposure": "DNS misconfiguration",
    "http_technology_exposure": "HTTP technology exposure",
    "vendor_cve_density": "high vendor CVE density",
    "eol_product": "end-of-life product",
    "predicted_rce": "predicted RCE-class weakness",
    "active_exploitation": "actively exploited (CISA KEV)",
    "slow_patch_velocity": "slow patch velocity",
}


def _build_justification(
    entity: str,
    signals: list[ScoringSignal],
    score: int,
) -> str:
    """Build a one-line human-readable justification from the top signals."""
    if not signals:
        return f"{entity}: no risk signals detected (score: {score})"

    # Take the top 3 signals by points.
    top = sorted(signals, key=lambda s: s.points, reverse=True)[:3]
    phrases = [_SIGNAL_PHRASES.get(s.signal_name, s.signal_name.replace("_", " ")) for s in top]

    joined = phrases[0] if len(phrases) == 1 else ", ".join(phrases[:-1]) + " and " + phrases[-1]

    return f"{entity}: {joined} (score: {score})"


# === Engine ===================================================================


class LeadScoringEngine:
    """Aggregates multi-signal analysis into composite lead scores."""

    def score_entity(
        self,
        *,
        entity_identifier: str,
        observations: list[dict[str, Any]] | None = None,
        environment: EnvironmentClassification | None = None,
        trust_events: list[TrustDegradationEvent] | None = None,
        waf_detected: bool | None = None,
        dnsbl_listings: list[dict[str, Any]] | None = None,
        saas_gaps: list[SurfaceGap] | None = None,
        vision_analysis: ScreenshotAnalysis | None = None,
        is_transitive_ma: bool = False,
    ) -> LeadScore:
        """Score a single entity based on all available signals.

        Parameters
        ----------
        entity_identifier:
            The canonical identifier of the entity (e.g. ``"staging.example.com"``).
        observations:
            Raw observation dicts from the pipeline run (used for header/cert checks).
        environment:
            Environment classification result from the environment classifier.
        trust_events:
            Trust degradation events detected for this entity.
        waf_detected:
            ``True`` if a WAF/CDN was detected, ``False`` if none was found,
            ``None`` if WAF detection was not run.
        dnsbl_listings:
            DNSBL listing dicts, each with ``listing_type``, ``severity``, etc.
        saas_gaps:
            Surface gaps from SaaS alignment analysis.
        vision_analysis:
            Screenshot/banner analysis result.
        is_transitive_ma:
            Whether the entity was discovered via M&A transitive search.

        Returns
        -------
        LeadScore
            Composite score with contributing signals and justification.
        """
        signals: list[ScoringSignal] = []
        obs = observations or []

        # 1. Environment risk (+30 for non-production)
        signals.extend(self._check_environment(environment))

        # 2. WAF exposure (+20 for no WAF)
        signals.extend(self._check_waf(waf_detected))

        # 3. DNSBL reputation (+15-25)
        signals.extend(self._check_dnsbl(dnsbl_listings))

        # 4. Trust degradation (+10-15)
        signals.extend(self._check_trust(trust_events))

        # 5. M&A transitive (+10)
        signals.extend(self._check_ma(is_transitive_ma))

        # 6. SaaS misalignment (+10)
        signals.extend(self._check_saas(saas_gaps))

        # 7. Vision findings (+10)
        signals.extend(self._check_vision(vision_analysis))

        # 8. Missing security headers (+5)
        signals.extend(self._check_missing_headers(obs))

        # 9. Self-signed/expiring cert (+5-10)
        signals.extend(self._check_weak_cert(obs))

        # 10. Debug mode / stack traces (+10)
        signals.extend(self._check_debug_mode(environment))

        # 11. Open port risk (+5-20)
        signals.extend(self._check_open_ports(obs))

        # 12. Deprecated TLS (+10-15)
        signals.extend(self._check_deprecated_tls(obs))

        # 13. DNS exposure signals (+5-15)
        signals.extend(self._check_dns_exposure(obs))

        # 14. HTTP technology exposure (+5-10)
        signals.extend(self._check_http_exposure(obs))

        # 15. Vendor CVE density (+10-20)
        signals.extend(self._check_vendor_cve_density(obs))

        # 16. End-of-life product (+15-25)
        signals.extend(self._check_eol_product(obs))

        # 17. Predicted RCE-class weakness (+20)
        signals.extend(self._check_predicted_rce(obs))

        # 18. Active exploitation — CISA KEV (+25)
        signals.extend(self._check_active_exploitation(obs))

        # 19. Slow patch velocity (+10)
        signals.extend(self._check_slow_patch_velocity(obs))

        # Aggregate
        raw_score = sum(s.points for s in signals)
        score = min(100, raw_score)
        tier = _score_to_tier(score)
        justification = _build_justification(entity_identifier, signals, score)

        return LeadScore(
            entity_identifier=entity_identifier,
            score=score,
            priority_tier=tier,
            contributing_signals=signals,
            justification=justification,
            scored_at=datetime.now(tz=UTC),
        )

    def score_entities(
        self,
        entities: list[dict[str, Any]],
    ) -> list[LeadScore]:
        """Score multiple entities and return sorted by score descending.

        Each dict in *entities* is passed as keyword arguments to
        ``score_entity``.  At minimum, each must contain
        ``entity_identifier``.
        """
        scores = [self.score_entity(**e) for e in entities]
        return sorted(scores, key=lambda s: s.score, reverse=True)

    # -- Signal extraction methods ---------------------------------------------

    @staticmethod
    def _check_environment(
        environment: EnvironmentClassification | None,
    ) -> list[ScoringSignal]:
        """Non-production environment → +30 points."""
        if environment is not None and environment.is_non_production:
            return [
                ScoringSignal(
                    signal_name="non_production_exposed",
                    points=30,
                    evidence=f"Classified as {environment.predicted_environment.value}",
                    source_module="environment_classifier",
                )
            ]
        return []

    @staticmethod
    def _check_waf(waf_detected: bool | None) -> list[ScoringSignal]:
        """No WAF/CDN detected → +20 points."""
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

    @staticmethod
    def _check_dnsbl(
        dnsbl_listings: list[dict[str, Any]] | None,
    ) -> list[ScoringSignal]:
        """DNSBL listings → +15 (medium) or +25 (critical/xbl)."""
        if not dnsbl_listings:
            return []

        # Determine max severity across all listings.
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

    @staticmethod
    def _check_trust(
        trust_events: list[TrustDegradationEvent] | None,
    ) -> list[ScoringSignal]:
        """Trust degradation → +15 (HIGH/CRITICAL severity) or +10 (others)."""
        if not trust_events:
            return []

        # Severity ordering for comparison.
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

    @staticmethod
    def _check_ma(is_transitive_ma: bool) -> list[ScoringSignal]:
        """Post-acquisition asset → +10 points."""
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

    @staticmethod
    def _check_saas(
        saas_gaps: list[SurfaceGap] | None,
    ) -> list[ScoringSignal]:
        """Unexpected SaaS products → +10 points."""
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

    @staticmethod
    def _check_vision(
        vision_analysis: ScreenshotAnalysis | None,
    ) -> list[ScoringSignal]:
        """Vision security indicators → +10 points."""
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

    @staticmethod
    def _check_missing_headers(
        observations: list[dict[str, Any]],
    ) -> list[ScoringSignal]:
        """Missing HSTS or CSP headers → +5 points."""
        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")
            if cid != "active-http-fingerprint":
                continue

            payload = obs.get("structured_payload", obs)
            headers: dict[str, str] = payload.get("headers", {})

            missing = []
            if "strict-transport-security" not in headers:
                missing.append("HSTS")
            if "content-security-policy" not in headers:
                missing.append("CSP")

            if missing:
                return [
                    ScoringSignal(
                        signal_name="missing_security_headers",
                        points=5,
                        evidence=f"Missing headers: {', '.join(missing)}",
                        source_module="http_fingerprint",
                    )
                ]
        return []

    @staticmethod
    def _check_weak_cert(
        observations: list[dict[str, Any]],
    ) -> list[ScoringSignal]:
        """Self-signed or near-expiry certificate → +5-10 points."""
        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")
            if cid != "active-tls-handshake":
                continue

            payload = obs.get("structured_payload", obs)
            subject_cn = payload.get("cert_subject_cn") or ""
            issuer_cn = payload.get("cert_issuer_cn") or ""

            # Self-signed: subject CN == issuer CN.
            if subject_cn and issuer_cn and subject_cn == issuer_cn:
                return [
                    ScoringSignal(
                        signal_name="weak_certificate",
                        points=10,
                        evidence=f"Self-signed certificate: subject=issuer={subject_cn}",
                        source_module="tls_handshake",
                    )
                ]

            # Near-expiry: less than 30 days remaining.
            not_after = payload.get("cert_not_after")
            if not_after and isinstance(not_after, str):
                try:
                    expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=UTC)
                    days_remaining = (expiry - datetime.now(tz=UTC)).days
                    if days_remaining < 30:  # noqa: PLR2004
                        return [
                            ScoringSignal(
                                signal_name="weak_certificate",
                                points=5,
                                evidence=f"Certificate expires in {days_remaining} days",
                                source_module="tls_handshake",
                            )
                        ]
                except (ValueError, TypeError):
                    pass

        return []

    @staticmethod
    def _check_debug_mode(
        environment: EnvironmentClassification | None,
    ) -> list[ScoringSignal]:
        """Debug mode or stack traces visible → +10 points.

        Uses risk factors from environment classification since the
        environment classifier already detects debug headers and stack traces.
        """
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

    # -- Active-collector signal methods ---------------------------------------

    # Port sets for risk classification.
    _HIGH_RISK_PORTS: frozenset[int] = frozenset({
        3306, 5432, 27017, 6379,  # databases
        22, 3389, 5900,           # management
    })
    _MEDIUM_RISK_PORTS: frozenset[int] = frozenset({
        135, 445,   # RPC / SMB
        1883, 5672, # MQTT / AMQP
    })
    _WEB_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})

    # Weak cipher keywords (case-insensitive substring match).
    _WEAK_CIPHER_KEYWORDS: tuple[str, ...] = ("RC4", "DES", "3DES", "NULL", "EXPORT")

    # Regex for version numbers in Server header (e.g. "nginx/1.24.0").
    _VERSION_RE: re.Pattern[str] = re.compile(r"/\d+[\d.]*")

    @staticmethod
    def _check_open_ports(
        observations: list[dict[str, Any]],
    ) -> list[ScoringSignal]:
        """Open port risk → +5 (web-only), +10 (medium), +20 (high) points.

        Examines ``active-port-surface`` observations for open ports and
        classifies them by risk tier.  Only the highest-risk tier fires —
        a target with both high-risk and web-only ports gets +20, not +25.
        """
        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")
            if cid != "active-port-surface":
                continue

            payload = obs.get("structured_payload", obs)
            open_ports: list[int] = payload.get("open_ports", [])
            if not open_ports:
                continue

            port_set = frozenset(open_ports)

            if port_set & LeadScoringEngine._HIGH_RISK_PORTS:
                hit = sorted(port_set & LeadScoringEngine._HIGH_RISK_PORTS)
                return [
                    ScoringSignal(
                        signal_name="open_port_risk",
                        points=20,
                        evidence=f"High-risk ports open: {', '.join(str(p) for p in hit)}",
                        source_module="port_surface",
                    )
                ]

            if port_set & LeadScoringEngine._MEDIUM_RISK_PORTS:
                hit = sorted(port_set & LeadScoringEngine._MEDIUM_RISK_PORTS)
                return [
                    ScoringSignal(
                        signal_name="open_port_risk",
                        points=10,
                        evidence=f"Medium-risk ports open: {', '.join(str(p) for p in hit)}",
                        source_module="port_surface",
                    )
                ]

            if port_set <= LeadScoringEngine._WEB_PORTS:
                return [
                    ScoringSignal(
                        signal_name="open_port_risk",
                        points=5,
                        evidence="Only web ports open",
                        source_module="port_surface",
                    )
                ]

        return []

    @staticmethod
    def _check_deprecated_tls(
        observations: list[dict[str, Any]],
    ) -> list[ScoringSignal]:
        """Deprecated TLS version or weak ciphers → +10-15 points.

        Examines ``active-tls-handshake`` observations.  Deprecated protocol
        versions (TLSv1.0, TLSv1.1) score +15.  Weak cipher suites (RC4,
        DES, 3DES, NULL, EXPORT) score +10.  Both can fire independently
        but the method returns at most one signal (the higher-scoring one)
        to avoid double-counting with the existing ``_check_weak_cert``.
        """
        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")
            if cid != "active-tls-handshake":
                continue

            payload = obs.get("structured_payload", obs)
            tls_version: str = payload.get("tls_version") or ""
            cipher_suite: str = payload.get("cipher_suite") or ""

            # Deprecated protocol version.
            if tls_version in ("TLSv1", "TLSv1.0", "TLSv1.1"):
                return [
                    ScoringSignal(
                        signal_name="deprecated_tls",
                        points=15,
                        evidence=f"Deprecated TLS version: {tls_version}",
                        source_module="tls_handshake",
                    )
                ]

            # Weak cipher suite.
            cipher_upper = cipher_suite.upper()
            for kw in LeadScoringEngine._WEAK_CIPHER_KEYWORDS:
                if kw in cipher_upper:
                    return [
                        ScoringSignal(
                            signal_name="deprecated_tls",
                            points=10,
                            evidence=f"Weak cipher suite: {cipher_suite}",
                            source_module="tls_handshake",
                        )
                    ]

        return []

    @staticmethod
    def _check_dns_exposure(
        observations: list[dict[str, Any]],
    ) -> list[ScoringSignal]:
        """DNS misconfiguration signals → +5-15 points.

        Examines ``active-dns-resolve`` observations for:
        - Zone transfer success (+15)
        - Wildcard DNS detected (+10)
        - No DNSSEC (+5)

        Multiple signals can fire — e.g., a target with zone transfer AND
        no DNSSEC gets both signals.
        """
        signals: list[ScoringSignal] = []

        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")
            if cid != "active-dns-resolve":
                continue

            payload = obs.get("structured_payload", obs)

            # Zone transfer successful.
            if payload.get("zone_transfer"):
                signals.append(
                    ScoringSignal(
                        signal_name="dns_exposure",
                        points=15,
                        evidence="Zone transfer successful — full zone data exposed",
                        source_module="dns_resolve",
                    )
                )
                return signals  # Major finding — return immediately.

            # Wildcard DNS detected.
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

            # No DNSSEC configured.
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

    @staticmethod
    def _check_http_exposure(
        observations: list[dict[str, Any]],
    ) -> list[ScoringSignal]:
        """HTTP technology exposure signals → +5-10 points.

        Examines ``active-http-fingerprint`` observations for:
        - Server header version leak (+5)
        - Cookie without Secure/HttpOnly flags (+5)
        - CORS wildcard origin (+10)

        Multiple signals can fire independently.
        """
        signals: list[ScoringSignal] = []

        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")
            if cid != "active-http-fingerprint":
                continue

            payload = obs.get("structured_payload", obs)

            # Server header version leak.
            server_header: str | None = payload.get("server_header")
            if server_header and LeadScoringEngine._VERSION_RE.search(server_header):
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

            # Return after first matching HTTP observation (avoid double-counting
            # from multiple HTTP obs for same entity).
            if signals:
                return signals

        return signals

    # -- Vendor vulnerability signal methods -----------------------------------

    # CWE classes that indicate RCE-capable weakness patterns.
    _RCE_CWE_CLASSES: frozenset[str] = frozenset({
        "CWE-94",   # Code Injection
        "CWE-502",  # Deserialization of Untrusted Data
        "CWE-78",   # OS Command Injection
        "CWE-119",  # Buffer Overflow (Improper Restriction of Operations)
    })

    @staticmethod
    def _check_vendor_cve_density(
        observations: list[dict[str, Any]],
    ) -> list[ScoringSignal]:
        """Vendor CVE density → +10 (>50), +15 (>100), +20 (>200) points.

        Examines ``vendor-cve-history`` observations for the total CVE count
        associated with the vendor.  Higher CVE counts indicate a vendor with
        a larger historical vulnerability footprint, which increases the
        probability of unpatched or undiscovered issues in their products.
        """
        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")
            if cid != "vendor-cve-history":
                continue

            payload = obs.get("structured_payload", obs)
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

    @staticmethod
    def _check_eol_product(
        observations: list[dict[str, Any]],
    ) -> list[ScoringSignal]:
        """End-of-life product → +15 (EOL), +25 (EOL with >50 CVEs) points.

        Examines observations for ``eol_status == true``.  End-of-life products
        no longer receive security patches, making every existing vulnerability
        permanent.  If the product also has a high CVE count, the risk compounds.
        """
        for obs in observations:
            payload = obs.get("structured_payload", obs)
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

    @staticmethod
    def _check_predicted_rce(
        observations: list[dict[str, Any]],
    ) -> list[ScoringSignal]:
        """Predicted RCE-class weakness → +20 points.

        Examines ``vendor-cve-history`` observations for the vendor's top CWE
        classes.  If any RCE-capable CWE (Code Injection CWE-94,
        Deserialization CWE-502, OS Command Injection CWE-78, or Buffer
        Overflow CWE-119) appears with frequency >10%, the vendor's products
        are statistically likely to contain RCE-class vulnerabilities.
        """
        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")
            if cid != "vendor-cve-history":
                continue

            payload = obs.get("structured_payload", obs)
            top_cwes: list[dict[str, Any]] = payload.get("top_cwes", [])

            for cwe_entry in top_cwes:
                cwe_id = cwe_entry.get("cwe_id", "")
                frequency = cwe_entry.get("frequency", 0.0)
                if not isinstance(frequency, (int, float)):
                    continue
                if cwe_id in LeadScoringEngine._RCE_CWE_CLASSES and frequency > 0.10:  # noqa: PLR2004
                    return [
                        ScoringSignal(
                            signal_name="predicted_rce",
                            points=20,
                            evidence=f"{cwe_id} appears in {frequency:.0%} of vendor CVEs",
                            source_module="vendor_cve_history",
                        )
                    ]

        return []

    @staticmethod
    def _check_active_exploitation(
        observations: list[dict[str, Any]],
    ) -> list[ScoringSignal]:
        """Active exploitation confirmed by CISA KEV → +25 points.

        Examines ``vendor-cve-history`` observations for ``kev_count > 0``.
        The CISA Known Exploited Vulnerabilities catalog confirms that at
        least one vulnerability from this vendor has been actively exploited
        in the wild — a strong signal for real-world risk.
        """
        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")
            if cid != "vendor-cve-history":
                continue

            payload = obs.get("structured_payload", obs)
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

    @staticmethod
    def _check_slow_patch_velocity(
        observations: list[dict[str, Any]],
    ) -> list[ScoringSignal]:
        """Slow patch velocity → +10 points.

        Examines ``vendor-cve-history`` observations for
        ``patch_velocity_days > 60``.  A vendor that takes more than 60 days
        on average to release patches leaves customers exposed for extended
        periods, increasing the exploitation window.
        """
        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")
            if cid != "vendor-cve-history":
                continue

            payload = obs.get("structured_payload", obs)
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


__all__ = [
    "LeadScore",
    "LeadScoringEngine",
    "PriorityTier",
    "ScoringSignal",
]

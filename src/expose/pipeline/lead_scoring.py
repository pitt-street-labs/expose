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


__all__ = [
    "LeadScore",
    "LeadScoringEngine",
    "PriorityTier",
    "ScoringSignal",
]

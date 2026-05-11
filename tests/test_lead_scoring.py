"""Tests for the lead scoring engine.

Covers individual signal scoring, multi-signal aggregation, score capping,
tier boundaries, justification formatting, model validation (frozen, bounds),
and batch scoring with sort order.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from expose.pipeline.environment_classifier import (
    EnvironmentClassification,
    EnvironmentLabel,
    EnvironmentSignal,
    SignalCategory,
)
from expose.pipeline.lead_scoring import (
    LeadScore,
    LeadScoringEngine,
    PriorityTier,
    ScoringSignal,
    _build_justification,
    _score_to_tier,
)
from expose.pipeline.saas_alignment import SurfaceGap
from expose.pipeline.trust_degradation import (
    DegradationEventType,
    DegradationSeverity,
    TrustDegradationEvent,
)
from expose.pipeline.vision import ScreenshotAnalysis, SecurityIndicator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ENGINE = LeadScoringEngine()


def _make_env(
    *,
    predicted: EnvironmentLabel = EnvironmentLabel.STAGING,
    is_non_prod: bool = True,
    risk_factors: list[str] | None = None,
) -> EnvironmentClassification:
    """Build a minimal EnvironmentClassification."""
    return EnvironmentClassification(
        entity_identifier="test.example.com",
        predicted_environment=predicted,
        confidence=0.8,
        signals=[
            EnvironmentSignal(
                category=SignalCategory.DNS_PATTERN,
                signal_name="subdomain_prefix",
                matched_value="staging",
                suggested_environment=predicted,
                confidence=0.8,
            ),
        ],
        is_non_production=is_non_prod,
        risk_factors=risk_factors or [],
        categories_matched=1,
    )


def _make_trust_event(
    *,
    severity: DegradationSeverity = DegradationSeverity.HIGH,
    event_type: DegradationEventType = DegradationEventType.REGISTRAR_CHANGE,
) -> TrustDegradationEvent:
    """Build a minimal TrustDegradationEvent."""
    return TrustDegradationEvent(
        entity_identifier="example.com",
        event_type=event_type,
        severity=severity,
        description=f"Test {event_type.value} event",
        detected_at=datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
        confidence=0.9,
    )


def _make_surface_gap(
    *,
    gap_type: str = "unexpected_product",
    product_name: str = "ShadowApp",
) -> SurfaceGap:
    """Build a minimal SurfaceGap."""
    return SurfaceGap(
        product_id="shadow-app",
        product_name=product_name,
        gap_type=gap_type,
        description=f"Product '{product_name}' detected unexpectedly",
        severity="medium",
    )


def _make_vision(
    *,
    indicators: list[SecurityIndicator] | None = None,
) -> ScreenshotAnalysis:
    """Build a minimal ScreenshotAnalysis."""
    return ScreenshotAnalysis(
        page_type="login",
        technologies_detected=["nginx"],
        security_indicators=indicators or [],
        visual_confidence=0.9,
        description="Login page detected",
    )


def _http_obs(**payload_fields: object) -> dict[str, object]:
    """Build a minimal HTTP fingerprint observation dict."""
    sp: dict[str, object] = {
        "url": "https://example.com",
        "headers": {},
    }
    sp.update(payload_fields)
    return {"_collector_id": "active-http-fingerprint", "structured_payload": sp}


def _tls_obs(**payload_fields: object) -> dict[str, object]:
    """Build a minimal TLS handshake observation dict."""
    sp: dict[str, object] = {
        "cert_subject_cn": "example.com",
        "cert_issuer_cn": "R3",
        "cert_issuer_org": "Let's Encrypt",
        "cert_not_before": "2026-01-01T00:00:00Z",
        "cert_not_after": "2026-12-01T00:00:00Z",
    }
    sp.update(payload_fields)
    return {"_collector_id": "active-tls-handshake", "structured_payload": sp}


# ===========================================================================
# Individual signal tests
# ===========================================================================


class TestNoSignals:
    """Entity with no signals."""

    def test_no_signals_score_zero(self) -> None:
        result = _ENGINE.score_entity(entity_identifier="clean.example.com")
        assert result.score == 0

    def test_no_signals_tier_low(self) -> None:
        result = _ENGINE.score_entity(entity_identifier="clean.example.com")
        assert result.priority_tier == PriorityTier.LOW

    def test_no_signals_empty_contributing(self) -> None:
        result = _ENGINE.score_entity(entity_identifier="clean.example.com")
        assert result.contributing_signals == []


class TestEnvironmentSignal:
    """Non-production environment → +30 points."""

    def test_non_production_adds_30(self) -> None:
        env = _make_env(is_non_prod=True)
        result = _ENGINE.score_entity(entity_identifier="staging.example.com", environment=env)
        env_signals = [
            s for s in result.contributing_signals if s.signal_name == "non_production_exposed"
        ]
        assert len(env_signals) == 1
        assert env_signals[0].points == 30

    def test_production_no_signal(self) -> None:
        env = _make_env(predicted=EnvironmentLabel.PRODUCTION, is_non_prod=False)
        result = _ENGINE.score_entity(entity_identifier="example.com", environment=env)
        env_signals = [
            s for s in result.contributing_signals if s.signal_name == "non_production_exposed"
        ]
        assert len(env_signals) == 0

    def test_no_environment_no_signal(self) -> None:
        result = _ENGINE.score_entity(entity_identifier="example.com", environment=None)
        env_signals = [
            s for s in result.contributing_signals if s.signal_name == "non_production_exposed"
        ]
        assert len(env_signals) == 0


class TestWafSignal:
    """No WAF detected → +20 points."""

    def test_no_waf_adds_20(self) -> None:
        result = _ENGINE.score_entity(entity_identifier="example.com", waf_detected=False)
        waf_signals = [
            s for s in result.contributing_signals if s.signal_name == "no_waf_protection"
        ]
        assert len(waf_signals) == 1
        assert waf_signals[0].points == 20

    def test_waf_present_no_signal(self) -> None:
        result = _ENGINE.score_entity(entity_identifier="example.com", waf_detected=True)
        waf_signals = [
            s for s in result.contributing_signals if s.signal_name == "no_waf_protection"
        ]
        assert len(waf_signals) == 0

    def test_waf_none_no_signal(self) -> None:
        result = _ENGINE.score_entity(entity_identifier="example.com", waf_detected=None)
        waf_signals = [
            s for s in result.contributing_signals if s.signal_name == "no_waf_protection"
        ]
        assert len(waf_signals) == 0


class TestDnsblSignal:
    """DNSBL listings → +15 or +25 points."""

    def test_critical_listing_adds_25(self) -> None:
        listings = [
            {"blacklist_name": "Spamhaus ZEN", "listing_type": "xbl", "severity": "critical"}
        ]
        result = _ENGINE.score_entity(entity_identifier="1.2.3.4", dnsbl_listings=listings)
        dnsbl = [s for s in result.contributing_signals if s.signal_name == "dnsbl_listed"]
        assert len(dnsbl) == 1
        assert dnsbl[0].points == 25

    def test_critical_severity_without_xbl_adds_25(self) -> None:
        listings = [{"blacklist_name": "Abusix", "listing_type": "listed", "severity": "critical"}]
        result = _ENGINE.score_entity(entity_identifier="1.2.3.4", dnsbl_listings=listings)
        dnsbl = [s for s in result.contributing_signals if s.signal_name == "dnsbl_listed"]
        assert dnsbl[0].points == 25

    def test_medium_listing_adds_15(self) -> None:
        listings = [{"blacklist_name": "SORBS", "listing_type": "listed", "severity": "medium"}]
        result = _ENGINE.score_entity(entity_identifier="1.2.3.4", dnsbl_listings=listings)
        dnsbl = [s for s in result.contributing_signals if s.signal_name == "dnsbl_listed"]
        assert len(dnsbl) == 1
        assert dnsbl[0].points == 15

    def test_no_listings_no_signal(self) -> None:
        result = _ENGINE.score_entity(entity_identifier="1.2.3.4", dnsbl_listings=[])
        dnsbl = [s for s in result.contributing_signals if s.signal_name == "dnsbl_listed"]
        assert len(dnsbl) == 0

    def test_none_listings_no_signal(self) -> None:
        result = _ENGINE.score_entity(entity_identifier="1.2.3.4", dnsbl_listings=None)
        dnsbl = [s for s in result.contributing_signals if s.signal_name == "dnsbl_listed"]
        assert len(dnsbl) == 0


class TestTrustDegradationSignal:
    """Trust degradation events → +10 or +15 points."""

    def test_high_severity_adds_15(self) -> None:
        events = [_make_trust_event(severity=DegradationSeverity.HIGH)]
        result = _ENGINE.score_entity(entity_identifier="example.com", trust_events=events)
        trust = [s for s in result.contributing_signals if s.signal_name == "trust_degradation"]
        assert len(trust) == 1
        assert trust[0].points == 15

    def test_critical_severity_adds_15(self) -> None:
        events = [_make_trust_event(severity=DegradationSeverity.CRITICAL)]
        result = _ENGINE.score_entity(entity_identifier="example.com", trust_events=events)
        trust = [s for s in result.contributing_signals if s.signal_name == "trust_degradation"]
        assert trust[0].points == 15

    def test_medium_severity_adds_10(self) -> None:
        events = [_make_trust_event(severity=DegradationSeverity.MEDIUM)]
        result = _ENGINE.score_entity(entity_identifier="example.com", trust_events=events)
        trust = [s for s in result.contributing_signals if s.signal_name == "trust_degradation"]
        assert trust[0].points == 10

    def test_low_severity_adds_10(self) -> None:
        events = [_make_trust_event(severity=DegradationSeverity.LOW)]
        result = _ENGINE.score_entity(entity_identifier="example.com", trust_events=events)
        trust = [s for s in result.contributing_signals if s.signal_name == "trust_degradation"]
        assert trust[0].points == 10

    def test_empty_events_no_signal(self) -> None:
        result = _ENGINE.score_entity(entity_identifier="example.com", trust_events=[])
        trust = [s for s in result.contributing_signals if s.signal_name == "trust_degradation"]
        assert len(trust) == 0

    def test_worst_severity_wins(self) -> None:
        """When multiple events exist, the worst severity determines points."""
        events = [
            _make_trust_event(severity=DegradationSeverity.LOW),
            _make_trust_event(
                severity=DegradationSeverity.HIGH,
                event_type=DegradationEventType.CERT_AUTHORITY_CHANGE,
            ),
        ]
        result = _ENGINE.score_entity(entity_identifier="example.com", trust_events=events)
        trust = [s for s in result.contributing_signals if s.signal_name == "trust_degradation"]
        assert trust[0].points == 15


class TestMaSignal:
    """M&A transitive → +10 points."""

    def test_ma_adds_10(self) -> None:
        result = _ENGINE.score_entity(
            entity_identifier="acquired.example.com", is_transitive_ma=True
        )
        ma = [s for s in result.contributing_signals if s.signal_name == "post_acquisition_asset"]
        assert len(ma) == 1
        assert ma[0].points == 10

    def test_no_ma_no_signal(self) -> None:
        result = _ENGINE.score_entity(entity_identifier="example.com", is_transitive_ma=False)
        ma = [s for s in result.contributing_signals if s.signal_name == "post_acquisition_asset"]
        assert len(ma) == 0


class TestSaasSignal:
    """SaaS misalignment (unexpected products) → +10 points."""

    def test_unexpected_product_adds_10(self) -> None:
        gaps = [_make_surface_gap(gap_type="unexpected_product")]
        result = _ENGINE.score_entity(entity_identifier="example.com", saas_gaps=gaps)
        saas = [
            s for s in result.contributing_signals if s.signal_name == "unexpected_saas_product"
        ]
        assert len(saas) == 1
        assert saas[0].points == 10

    def test_missing_expected_no_signal(self) -> None:
        gaps = [_make_surface_gap(gap_type="missing_expected")]
        result = _ENGINE.score_entity(entity_identifier="example.com", saas_gaps=gaps)
        saas = [
            s for s in result.contributing_signals if s.signal_name == "unexpected_saas_product"
        ]
        assert len(saas) == 0

    def test_empty_gaps_no_signal(self) -> None:
        result = _ENGINE.score_entity(entity_identifier="example.com", saas_gaps=[])
        saas = [
            s for s in result.contributing_signals if s.signal_name == "unexpected_saas_product"
        ]
        assert len(saas) == 0


class TestVisionSignal:
    """Vision security indicators → +10 points."""

    def test_security_indicators_add_10(self) -> None:
        indicators = [
            SecurityIndicator(
                indicator_type="admin_panel", detail="Admin panel found", severity="high"
            ),
        ]
        vision = _make_vision(indicators=indicators)
        result = _ENGINE.score_entity(entity_identifier="example.com", vision_analysis=vision)
        vis = [
            s for s in result.contributing_signals if s.signal_name == "security_indicator_found"
        ]
        assert len(vis) == 1
        assert vis[0].points == 10

    def test_no_indicators_no_signal(self) -> None:
        vision = _make_vision(indicators=[])
        result = _ENGINE.score_entity(entity_identifier="example.com", vision_analysis=vision)
        vis = [
            s for s in result.contributing_signals if s.signal_name == "security_indicator_found"
        ]
        assert len(vis) == 0

    def test_none_vision_no_signal(self) -> None:
        result = _ENGINE.score_entity(entity_identifier="example.com", vision_analysis=None)
        vis = [
            s for s in result.contributing_signals if s.signal_name == "security_indicator_found"
        ]
        assert len(vis) == 0


class TestMissingHeadersSignal:
    """Missing security headers → +5 points."""

    def test_missing_both_headers_adds_5(self) -> None:
        obs = [_http_obs(headers={})]
        result = _ENGINE.score_entity(entity_identifier="example.com", observations=obs)
        hdr = [
            s for s in result.contributing_signals if s.signal_name == "missing_security_headers"
        ]
        assert len(hdr) == 1
        assert hdr[0].points == 5

    def test_headers_present_no_signal(self) -> None:
        obs = [
            _http_obs(
                headers={
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                }
            )
        ]
        result = _ENGINE.score_entity(entity_identifier="example.com", observations=obs)
        hdr = [
            s for s in result.contributing_signals if s.signal_name == "missing_security_headers"
        ]
        assert len(hdr) == 0

    def test_no_http_observations_no_signal(self) -> None:
        result = _ENGINE.score_entity(entity_identifier="example.com", observations=[])
        hdr = [
            s for s in result.contributing_signals if s.signal_name == "missing_security_headers"
        ]
        assert len(hdr) == 0


class TestWeakCertSignal:
    """Self-signed or near-expiry cert → +5-10 points."""

    def test_self_signed_adds_10(self) -> None:
        obs = [_tls_obs(cert_subject_cn="example.com", cert_issuer_cn="example.com")]
        result = _ENGINE.score_entity(entity_identifier="example.com", observations=obs)
        cert = [s for s in result.contributing_signals if s.signal_name == "weak_certificate"]
        assert len(cert) == 1
        assert cert[0].points == 10

    def test_valid_cert_no_signal(self) -> None:
        obs = [_tls_obs()]
        result = _ENGINE.score_entity(entity_identifier="example.com", observations=obs)
        cert = [s for s in result.contributing_signals if s.signal_name == "weak_certificate"]
        assert len(cert) == 0


class TestDebugModeSignal:
    """Debug mode detected via environment risk factors → +10 points."""

    def test_debug_mode_adds_10(self) -> None:
        env = _make_env(risk_factors=["Debug mode enabled"])
        result = _ENGINE.score_entity(entity_identifier="dev.example.com", environment=env)
        debug = [s for s in result.contributing_signals if s.signal_name == "debug_mode_detected"]
        assert len(debug) == 1
        assert debug[0].points == 10

    def test_stack_traces_adds_10(self) -> None:
        env = _make_env(risk_factors=["Stack traces visible"])
        result = _ENGINE.score_entity(entity_identifier="dev.example.com", environment=env)
        debug = [s for s in result.contributing_signals if s.signal_name == "debug_mode_detected"]
        assert len(debug) == 1
        assert debug[0].points == 10

    def test_no_debug_risk_factors_no_signal(self) -> None:
        env = _make_env(risk_factors=["Missing security headers"])
        result = _ENGINE.score_entity(entity_identifier="dev.example.com", environment=env)
        debug = [s for s in result.contributing_signals if s.signal_name == "debug_mode_detected"]
        assert len(debug) == 0


# ===========================================================================
# Aggregation tests
# ===========================================================================


class TestAggregation:
    """Multi-signal aggregation and score capping."""

    def test_multiple_signals_aggregate(self) -> None:
        """Environment(30) + WAF(20) + MA(10) = 60."""
        env = _make_env(is_non_prod=True)
        result = _ENGINE.score_entity(
            entity_identifier="staging.example.com",
            environment=env,
            waf_detected=False,
            is_transitive_ma=True,
        )
        assert result.score == 60
        assert result.priority_tier == PriorityTier.HIGH

    def test_score_capped_at_100(self) -> None:
        """Many signals push raw above 100 but score is capped."""
        env = _make_env(is_non_prod=True, risk_factors=["Debug mode enabled"])
        listings = [
            {"blacklist_name": "Spamhaus ZEN", "listing_type": "xbl", "severity": "critical"}
        ]
        trust_events = [_make_trust_event(severity=DegradationSeverity.CRITICAL)]
        gaps = [_make_surface_gap(gap_type="unexpected_product")]
        indicators = [
            SecurityIndicator(indicator_type="admin_panel", detail="Admin panel", severity="high"),
        ]
        vision = _make_vision(indicators=indicators)
        # Self-signed cert observation.
        obs = [
            _tls_obs(cert_subject_cn="evil.com", cert_issuer_cn="evil.com"),
            _http_obs(headers={}),
        ]

        result = _ENGINE.score_entity(
            entity_identifier="staging.evil.com",
            observations=obs,
            environment=env,
            trust_events=trust_events,
            waf_detected=False,
            dnsbl_listings=listings,
            saas_gaps=gaps,
            vision_analysis=vision,
            is_transitive_ma=True,
        )
        # Raw: 30+20+25+15+10+10+10+5+10+10 = 145, capped to 100
        assert result.score == 100
        assert result.priority_tier == PriorityTier.CRITICAL


# ===========================================================================
# Tier boundary tests
# ===========================================================================


class TestTierBoundaries:
    """Score-to-tier mapping at exact boundaries."""

    def test_score_0_is_low(self) -> None:
        assert _score_to_tier(0) == PriorityTier.LOW

    def test_score_19_is_low(self) -> None:
        assert _score_to_tier(19) == PriorityTier.LOW

    def test_score_20_is_medium(self) -> None:
        assert _score_to_tier(20) == PriorityTier.MEDIUM

    def test_score_39_is_medium(self) -> None:
        assert _score_to_tier(39) == PriorityTier.MEDIUM

    def test_score_40_is_high(self) -> None:
        assert _score_to_tier(40) == PriorityTier.HIGH

    def test_score_69_is_high(self) -> None:
        assert _score_to_tier(69) == PriorityTier.HIGH

    def test_score_70_is_critical(self) -> None:
        assert _score_to_tier(70) == PriorityTier.CRITICAL

    def test_score_100_is_critical(self) -> None:
        assert _score_to_tier(100) == PriorityTier.CRITICAL


# ===========================================================================
# Justification tests
# ===========================================================================


class TestJustification:
    """Justification string formatting."""

    def test_no_signals_justification(self) -> None:
        text = _build_justification("example.com", [], 0)
        assert text == "example.com: no risk signals detected (score: 0)"

    def test_single_signal_justification(self) -> None:
        signals = [
            ScoringSignal(
                signal_name="no_waf_protection",
                points=20,
                evidence="test",
                source_module="waf_detection",
            ),
        ]
        text = _build_justification("example.com", signals, 20)
        assert text == "example.com: no WAF protection (score: 20)"

    def test_multiple_signals_top_3(self) -> None:
        signals = [
            ScoringSignal(
                signal_name="non_production_exposed", points=30, evidence="e1", source_module="m1"
            ),
            ScoringSignal(
                signal_name="no_waf_protection", points=20, evidence="e2", source_module="m2"
            ),
            ScoringSignal(signal_name="dnsbl_listed", points=15, evidence="e3", source_module="m3"),
            ScoringSignal(
                signal_name="post_acquisition_asset", points=10, evidence="e4", source_module="m4"
            ),
        ]
        text = _build_justification("staging.example.com", signals, 75)
        # Top 3 by points: non_production_exposed(30), no_waf_protection(20), dnsbl_listed(15)
        assert "non-production endpoint" in text
        assert "no WAF protection" in text
        assert "blacklisted IP" in text
        # 4th signal (post_acquisition_asset) should not appear.
        assert "post-acquisition asset" not in text
        assert "(score: 75)" in text

    def test_two_signals_uses_and(self) -> None:
        signals = [
            ScoringSignal(
                signal_name="non_production_exposed", points=30, evidence="e1", source_module="m1"
            ),
            ScoringSignal(
                signal_name="no_waf_protection", points=20, evidence="e2", source_module="m2"
            ),
        ]
        text = _build_justification("example.com", signals, 50)
        assert "non-production endpoint and no WAF protection" in text

    def test_unknown_signal_name_falls_back(self) -> None:
        """Unknown signal names use underscore-to-space fallback."""
        signals = [
            ScoringSignal(
                signal_name="custom_new_signal", points=10, evidence="e1", source_module="m1"
            ),
        ]
        text = _build_justification("example.com", signals, 10)
        assert "custom new signal" in text


# ===========================================================================
# Model validation tests
# ===========================================================================


class TestModelValidation:
    """Pydantic model constraints — frozen, bounds, required fields."""

    def test_lead_score_frozen(self) -> None:
        score = LeadScore(
            entity_identifier="example.com",
            score=50,
            priority_tier=PriorityTier.HIGH,
            contributing_signals=[],
            justification="test",
            scored_at=datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
        )
        with pytest.raises(ValidationError):
            score.score = 99  # type: ignore[misc]

    def test_scoring_signal_frozen(self) -> None:
        signal = ScoringSignal(
            signal_name="test",
            points=10,
            evidence="test evidence",
            source_module="test_module",
        )
        with pytest.raises(ValidationError):
            signal.points = 99  # type: ignore[misc]

    def test_lead_score_bounds(self) -> None:
        with pytest.raises(ValidationError):
            LeadScore(
                entity_identifier="example.com",
                score=101,
                priority_tier=PriorityTier.CRITICAL,
                contributing_signals=[],
                justification="test",
                scored_at=datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
            )

    def test_lead_score_negative_rejected(self) -> None:
        with pytest.raises(ValidationError):
            LeadScore(
                entity_identifier="example.com",
                score=-1,
                priority_tier=PriorityTier.LOW,
                contributing_signals=[],
                justification="test",
                scored_at=datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
            )

    def test_scoring_signal_points_bounds(self) -> None:
        with pytest.raises(ValidationError):
            ScoringSignal(
                signal_name="test",
                points=101,
                evidence="test",
                source_module="test_module",
            )

    def test_scoring_signal_empty_name_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScoringSignal(
                signal_name="",
                points=10,
                evidence="test",
                source_module="test_module",
            )

    def test_scoring_signal_empty_source_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScoringSignal(
                signal_name="test",
                points=10,
                evidence="test",
                source_module="",
            )

    def test_lead_score_empty_identifier_rejected(self) -> None:
        with pytest.raises(ValidationError):
            LeadScore(
                entity_identifier="",
                score=0,
                priority_tier=PriorityTier.LOW,
                contributing_signals=[],
                justification="test",
                scored_at=datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
            )

    def test_priority_tier_enum_values(self) -> None:
        assert PriorityTier.CRITICAL == "critical"
        assert PriorityTier.HIGH == "high"
        assert PriorityTier.MEDIUM == "medium"
        assert PriorityTier.LOW == "low"

    def test_lead_score_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            LeadScore(
                entity_identifier="example.com",
                score=50,
                priority_tier=PriorityTier.HIGH,
                contributing_signals=[],
                justification="test",
                scored_at=datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
                bogus_field="nope",  # type: ignore[call-arg]
            )


# ===========================================================================
# score_entities tests
# ===========================================================================


class TestScoreEntities:
    """Batch scoring with sort order."""

    def test_sorted_by_score_descending(self) -> None:
        entities = [
            {"entity_identifier": "low.example.com"},
            {
                "entity_identifier": "high.example.com",
                "waf_detected": False,
                "is_transitive_ma": True,
            },
            {"entity_identifier": "mid.example.com", "is_transitive_ma": True},
        ]
        results = _ENGINE.score_entities(entities)
        assert len(results) == 3
        # high = 20 (waf) + 10 (ma) = 30; mid = 10 (ma); low = 0
        assert results[0].entity_identifier == "high.example.com"
        assert results[1].entity_identifier == "mid.example.com"
        assert results[2].entity_identifier == "low.example.com"
        assert results[0].score >= results[1].score >= results[2].score

    def test_empty_list_returns_empty(self) -> None:
        results = _ENGINE.score_entities([])
        assert results == []

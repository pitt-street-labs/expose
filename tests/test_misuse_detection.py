"""Tests for misuse-detection heuristics (issue #33).

Coverage:

 1. No alerts when all metrics are normal.
 2. Scope drift detected when >30% out of scope.
 3. No scope drift when under threshold.
 4. Excessive Tier-3 detected when >80%.
 5. High denial rate detected.
 6. Unusual hours detected (3 AM run).
 7. Normal hours pass (2 PM run).
 8. evaluate_run returns multiple alerts simultaneously.
 9. Small runs (< min_dispatches) skip rate checks.
10. Custom thresholds override defaults.
11. MisuseAlert has correct severity levels.
12. Alert evidence dict contains supporting data.
13. Zero-total entities produce no scope-drift alert.
14. Boundary: exactly-at-threshold does not trigger.

All tests are pure unit tests -- no I/O, no mocking required.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from expose.compliance.misuse_detection import (
    MisuseAlert,
    MisuseDetector,
    MisuseIndicator,
    MisuseThresholds,
)

# Synthetic IDs matching the TENANT_A / TENANT_B pattern used elsewhere.
TENANT_A = UUID("018f1f00-0000-7000-8000-00000000A001")
RUN_1 = UUID("00000000-0000-0000-0000-000000000B01")


@pytest.fixture
def detector() -> MisuseDetector:
    """Detector with default thresholds."""
    return MisuseDetector()


# ---------------------------------------------------------------------------
# 1. No alerts when all metrics are normal
# ---------------------------------------------------------------------------


def test_no_alerts_when_normal(detector: MisuseDetector) -> None:
    """All metrics within bounds produces zero alerts."""
    alerts = detector.evaluate_run(
        tenant_id=TENANT_A,
        run_id=RUN_1,
        in_scope=90,
        out_of_scope=10,        # 10% — below 30% threshold
        tier3_dispatches=20,
        total_dispatches=100,   # 20% — below 80% threshold
        denied=10,              # 10% — below 50% threshold
        run_timestamp=datetime(2026, 5, 10, 14, 0, tzinfo=UTC),  # 2 PM — normal
    )
    assert alerts == []


# ---------------------------------------------------------------------------
# 2. Scope drift detected when >30% out of scope
# ---------------------------------------------------------------------------


def test_scope_drift_detected(detector: MisuseDetector) -> None:
    """Scope drift fires when out-of-scope entities exceed threshold."""
    alert = detector.check_scope_drift(
        in_scope_count=50,
        out_of_scope_count=50,  # 50% — above 30%
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert isinstance(alert, MisuseAlert)
    assert alert.indicator == MisuseIndicator.SCOPE_DRIFT
    assert alert.tenant_id == TENANT_A
    assert alert.run_id == RUN_1


# ---------------------------------------------------------------------------
# 3. No scope drift when under threshold
# ---------------------------------------------------------------------------


def test_no_scope_drift_under_threshold(detector: MisuseDetector) -> None:
    """No alert when out-of-scope ratio is within bounds."""
    alert = detector.check_scope_drift(
        in_scope_count=80,
        out_of_scope_count=20,  # 20% — under 30%
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert alert is None


# ---------------------------------------------------------------------------
# 4. Excessive Tier-3 detected when >80%
# ---------------------------------------------------------------------------


def test_excessive_tier3_detected(detector: MisuseDetector) -> None:
    """Excessive Tier-3 fires when active-probe rate exceeds threshold."""
    alert = detector.check_tier3_rate(
        tier3_dispatches=90,
        total_dispatches=100,  # 90% — above 80%
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert alert is not None
    assert alert.indicator == MisuseIndicator.EXCESSIVE_TIER3
    assert alert.evidence["tier3_rate"] == pytest.approx(0.9)


# ---------------------------------------------------------------------------
# 5. High denial rate detected
# ---------------------------------------------------------------------------


def test_high_denial_rate_detected(detector: MisuseDetector) -> None:
    """High denial rate fires when >50% of requests are denied."""
    alert = detector.check_denial_rate(
        denied=70,
        total=100,  # 70% — above 50%
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert alert is not None
    assert alert.indicator == MisuseIndicator.HIGH_DENIAL_RATE
    assert alert.evidence["denial_rate"] == pytest.approx(0.7)


# ---------------------------------------------------------------------------
# 6. Unusual hours detected (3 AM run)
# ---------------------------------------------------------------------------


def test_unusual_hours_detected(detector: MisuseDetector) -> None:
    """Run at 3 AM triggers unusual-hours alert."""
    alert = detector.check_run_timing(
        run_timestamp=datetime(2026, 5, 10, 3, 0, tzinfo=UTC),
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert alert is not None
    assert alert.indicator == MisuseIndicator.UNUSUAL_HOURS
    assert alert.severity == "info"
    assert alert.evidence["run_hour"] == 3


# ---------------------------------------------------------------------------
# 7. Normal hours pass (2 PM run)
# ---------------------------------------------------------------------------


def test_normal_hours_pass(detector: MisuseDetector) -> None:
    """Run at 2 PM produces no timing alert."""
    alert = detector.check_run_timing(
        run_timestamp=datetime(2026, 5, 10, 14, 0, tzinfo=UTC),
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert alert is None


# ---------------------------------------------------------------------------
# 8. evaluate_run returns multiple alerts simultaneously
# ---------------------------------------------------------------------------


def test_evaluate_run_multiple_alerts(detector: MisuseDetector) -> None:
    """evaluate_run can return multiple alerts from a single run."""
    alerts = detector.evaluate_run(
        tenant_id=TENANT_A,
        run_id=RUN_1,
        in_scope=20,
        out_of_scope=80,        # 80% drift — triggers scope_drift
        tier3_dispatches=95,
        total_dispatches=100,   # 95% — triggers excessive_tier3
        denied=60,              # 60% — triggers high_denial_rate
        run_timestamp=datetime(2026, 5, 10, 3, 0, tzinfo=UTC),  # 3 AM — unusual
    )
    indicators = {a.indicator for a in alerts}
    assert MisuseIndicator.SCOPE_DRIFT in indicators
    assert MisuseIndicator.EXCESSIVE_TIER3 in indicators
    assert MisuseIndicator.HIGH_DENIAL_RATE in indicators
    assert MisuseIndicator.UNUSUAL_HOURS in indicators
    assert len(alerts) == 4


# ---------------------------------------------------------------------------
# 9. Small runs (< min_dispatches) skip rate checks
# ---------------------------------------------------------------------------


def test_small_runs_skip_rate_checks(detector: MisuseDetector) -> None:
    """Runs with fewer than min_dispatches_for_check skip rate-based checks."""
    # Default min_dispatches_for_check = 10.  With only 5 dispatches, even
    # extreme rates should not fire.
    tier3_alert = detector.check_tier3_rate(
        tier3_dispatches=5,
        total_dispatches=5,  # 100% but only 5 dispatches
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    denial_alert = detector.check_denial_rate(
        denied=5,
        total=5,  # 100% but only 5 dispatches
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert tier3_alert is None
    assert denial_alert is None


# ---------------------------------------------------------------------------
# 10. Custom thresholds override defaults
# ---------------------------------------------------------------------------


def test_custom_thresholds(detector: MisuseDetector) -> None:
    """Custom thresholds change detection sensitivity."""
    strict = MisuseThresholds(
        scope_drift_pct=0.1,   # 10% instead of 30%
        tier3_rate_pct=0.5,    # 50% instead of 80%
        denial_rate_pct=0.2,   # 20% instead of 50%
        business_hours_start=9,
        business_hours_end=17,
        min_dispatches_for_check=5,
    )
    strict_detector = MisuseDetector(thresholds=strict)

    # 15% drift: under default 30% but above strict 10%.
    alert = strict_detector.check_scope_drift(
        in_scope_count=85,
        out_of_scope_count=15,
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert alert is not None
    assert alert.indicator == MisuseIndicator.SCOPE_DRIFT

    # 7 AM: within default hours (6-22) but outside strict hours (9-17).
    timing_alert = strict_detector.check_run_timing(
        run_timestamp=datetime(2026, 5, 10, 7, 0, tzinfo=UTC),
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert timing_alert is not None
    assert timing_alert.indicator == MisuseIndicator.UNUSUAL_HOURS


# ---------------------------------------------------------------------------
# 11. MisuseAlert has correct severity levels
# ---------------------------------------------------------------------------


def test_severity_levels(detector: MisuseDetector) -> None:
    """Severity escalates with the magnitude of the indicator."""
    # 35% drift -> info (just over 30% threshold, under 50%)
    info_alert = detector.check_scope_drift(
        in_scope_count=65,
        out_of_scope_count=35,
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert info_alert is not None
    assert info_alert.severity == "info"

    # 60% drift -> warning (>= 50%)
    warn_alert = detector.check_scope_drift(
        in_scope_count=40,
        out_of_scope_count=60,
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert warn_alert is not None
    assert warn_alert.severity == "warning"

    # 85% drift -> critical (>= 80%)
    crit_alert = detector.check_scope_drift(
        in_scope_count=15,
        out_of_scope_count=85,
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert crit_alert is not None
    assert crit_alert.severity == "critical"


# ---------------------------------------------------------------------------
# 12. Alert evidence dict contains supporting data
# ---------------------------------------------------------------------------


def test_evidence_contains_supporting_data(detector: MisuseDetector) -> None:
    """Evidence dicts carry the raw metrics that triggered the alert."""
    alert = detector.check_scope_drift(
        in_scope_count=30,
        out_of_scope_count=70,
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert alert is not None
    assert "in_scope_count" in alert.evidence
    assert "out_of_scope_count" in alert.evidence
    assert "drift_pct" in alert.evidence
    assert alert.evidence["in_scope_count"] == 30
    assert alert.evidence["out_of_scope_count"] == 70
    assert alert.evidence["drift_pct"] == pytest.approx(0.7)

    # Tier-3 evidence
    t3_alert = detector.check_tier3_rate(
        tier3_dispatches=85,
        total_dispatches=100,
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert t3_alert is not None
    assert "tier3_dispatches" in t3_alert.evidence
    assert "total_dispatches" in t3_alert.evidence
    assert "tier3_rate" in t3_alert.evidence

    # Denial evidence
    denial_alert = detector.check_denial_rate(
        denied=55,
        total=100,
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert denial_alert is not None
    assert "denied" in denial_alert.evidence
    assert "total" in denial_alert.evidence
    assert "denial_rate" in denial_alert.evidence

    # Timing evidence
    ts = datetime(2026, 5, 10, 2, 30, tzinfo=UTC)
    timing_alert = detector.check_run_timing(
        run_timestamp=ts,
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert timing_alert is not None
    assert "run_hour" in timing_alert.evidence
    assert "business_hours_start" in timing_alert.evidence
    assert "business_hours_end" in timing_alert.evidence
    assert "run_timestamp" in timing_alert.evidence


# ---------------------------------------------------------------------------
# 13. Zero-total entities produce no scope-drift alert
# ---------------------------------------------------------------------------


def test_zero_total_entities_no_alert(detector: MisuseDetector) -> None:
    """Zero in-scope + zero out-of-scope does not divide by zero."""
    alert = detector.check_scope_drift(
        in_scope_count=0,
        out_of_scope_count=0,
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert alert is None


# ---------------------------------------------------------------------------
# 14. Boundary: exactly-at-threshold does not trigger
# ---------------------------------------------------------------------------


def test_exactly_at_threshold_no_trigger(detector: MisuseDetector) -> None:
    """Values exactly at the threshold do not fire (threshold is >not >=)."""
    # Scope drift: exactly 30%
    alert = detector.check_scope_drift(
        in_scope_count=70,
        out_of_scope_count=30,
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert alert is None

    # Tier-3 rate: exactly 80%
    t3_alert = detector.check_tier3_rate(
        tier3_dispatches=80,
        total_dispatches=100,
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert t3_alert is None

    # Denial rate: exactly 50%
    denial_alert = detector.check_denial_rate(
        denied=50,
        total=100,
        tenant_id=TENANT_A,
        run_id=RUN_1,
    )
    assert denial_alert is None

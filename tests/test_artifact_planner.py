"""Tests for the ArtifactPlanner coverage and readiness evaluator.

Coverage:

1.  Fully successful run -> ready=True, high confidence.
2.  All collectors failed -> ready=False, confidence=0.
3.  Partial success -> ready=True, gaps listed.
4.  Zero entities -> ready=False even if dispatches succeeded.
5.  High denial rate -> recommendation about scope.
6.  No attributed entities -> recommendation about rule pack.
7.  Coverage gaps include failed collector details.
8.  Confidence calculation is correct.
9.  Estimated size scales with entity count.
10. Custom min_confidence threshold respected.
11. Recommendations list is non-empty when issues found.
12. Clean run -> empty recommendations.
"""

from __future__ import annotations

from typing import Any

import pytest

from expose.pipeline.artifact_planner import (
    ArtifactPlanner,
    ArtifactReadiness,
    CoverageGap,
)

# === Helpers ==================================================================


def _evaluate_full_success(
    planner: ArtifactPlanner | None = None,
    entity_count: int = 5,
    attributed_count: int = 3,
) -> ArtifactReadiness:
    """Evaluate a fully successful run with sensible defaults."""
    p = planner or ArtifactPlanner()
    return p.evaluate(
        total_seeds=2,
        expanded_seeds=4,
        successful_dispatches=4,
        failed_dispatches=0,
        denied_dispatches=0,
        total_observations=10,
        entity_count=entity_count,
        attributed_count=attributed_count,
        collectors_used=["dns-resolve", "passive-dns"],
        collectors_failed=[],
    )


# === Tests ====================================================================


def test_fully_successful_run_is_ready() -> None:
    """1. All dispatches succeed with entities -> ready=True, high confidence."""
    result = _evaluate_full_success()

    assert result.ready is True
    assert result.confidence == 1.0
    assert result.entity_count == 5
    assert result.attributed_count == 3
    assert result.unattributed_count == 2
    assert result.coverage_gaps == []
    assert result.recommendations == []


def test_all_collectors_failed_not_ready() -> None:
    """2. All collectors failed -> ready=False, confidence=0."""
    planner = ArtifactPlanner()
    result = planner.evaluate(
        total_seeds=2,
        expanded_seeds=4,
        successful_dispatches=0,
        failed_dispatches=4,
        denied_dispatches=0,
        total_observations=0,
        entity_count=0,
        attributed_count=0,
        collectors_used=["dns-resolve", "passive-dns"],
        collectors_failed=["dns-resolve", "passive-dns"],
    )

    assert result.ready is False
    assert result.confidence == 0.0


def test_partial_success_ready_with_gaps() -> None:
    """3. Some succeed, some fail -> ready=True, gaps listed."""
    planner = ArtifactPlanner()
    result = planner.evaluate(
        total_seeds=2,
        expanded_seeds=4,
        successful_dispatches=3,
        failed_dispatches=1,
        denied_dispatches=0,
        total_observations=6,
        entity_count=3,
        attributed_count=2,
        collectors_used=["dns-resolve", "passive-dns"],
        collectors_failed=["passive-dns"],
    )

    assert result.ready is True
    assert result.confidence == 0.75
    assert len(result.coverage_gaps) == 1
    assert result.coverage_gaps[0].collector_id == "passive-dns"
    assert result.coverage_gaps[0].reason == "collector_failed"


def test_zero_entities_not_ready() -> None:
    """4. Zero entities -> ready=False even if dispatches succeeded."""
    planner = ArtifactPlanner()
    result = planner.evaluate(
        total_seeds=2,
        expanded_seeds=4,
        successful_dispatches=4,
        failed_dispatches=0,
        denied_dispatches=0,
        total_observations=0,
        entity_count=0,
        attributed_count=0,
        collectors_used=["dns-resolve"],
        collectors_failed=[],
    )

    assert result.ready is False
    assert result.confidence == 1.0  # dispatches succeeded, but no entities


def test_high_denial_rate_recommendation() -> None:
    """5. >50% denied -> recommendation about authorization scope."""
    planner = ArtifactPlanner()
    result = planner.evaluate(
        total_seeds=2,
        expanded_seeds=4,
        successful_dispatches=1,
        failed_dispatches=0,
        denied_dispatches=3,
        total_observations=2,
        entity_count=1,
        attributed_count=1,
        collectors_used=["dns-resolve", "active-tls", "whois"],
        collectors_failed=[],
    )

    assert any("denial rate" in r for r in result.recommendations)
    assert any("authorization scope" in r for r in result.recommendations)


def test_no_attributed_entities_recommendation() -> None:
    """6. Entities found but none attributed -> recommendation about rule pack."""
    planner = ArtifactPlanner()
    result = planner.evaluate(
        total_seeds=2,
        expanded_seeds=4,
        successful_dispatches=4,
        failed_dispatches=0,
        denied_dispatches=0,
        total_observations=8,
        entity_count=4,
        attributed_count=0,
        collectors_used=["dns-resolve"],
        collectors_failed=[],
    )

    assert any("none attributed" in r for r in result.recommendations)


def test_coverage_gaps_include_failed_collector_details() -> None:
    """7. Coverage gaps capture collector_id, reason, and severity."""
    planner = ArtifactPlanner()
    result = planner.evaluate(
        total_seeds=1,
        expanded_seeds=2,
        successful_dispatches=2,
        failed_dispatches=2,
        denied_dispatches=0,
        total_observations=4,
        entity_count=2,
        attributed_count=1,
        collectors_used=["dns-resolve", "passive-dns"],
        collectors_failed=["passive-dns"],
    )

    failed_gaps = [g for g in result.coverage_gaps if g.reason == "collector_failed"]
    assert len(failed_gaps) == 1
    assert failed_gaps[0].collector_id == "passive-dns"
    assert failed_gaps[0].severity in {"critical", "warning"}


def test_confidence_calculation() -> None:
    """8. Confidence = successful / total dispatches."""
    planner = ArtifactPlanner()
    result = planner.evaluate(
        total_seeds=1,
        expanded_seeds=1,
        successful_dispatches=3,
        failed_dispatches=1,
        denied_dispatches=1,
        total_observations=6,
        entity_count=3,
        attributed_count=2,
        collectors_used=["a", "b", "c", "d", "e"],
        collectors_failed=["d"],
    )

    # 3 / (3 + 1 + 1) = 0.6
    assert result.confidence == pytest.approx(0.6)


def test_estimated_size_scales_with_entities() -> None:
    """9. estimated_artifact_size_kb = entity_count * 2.5 + 10."""
    result_small = _evaluate_full_success(entity_count=1, attributed_count=1)
    result_large = _evaluate_full_success(entity_count=100, attributed_count=50)

    assert result_small.estimated_artifact_size_kb == pytest.approx(12.5)  # 1*2.5 + 10
    assert result_large.estimated_artifact_size_kb == pytest.approx(260.0)  # 100*2.5 + 10
    assert result_large.estimated_artifact_size_kb > result_small.estimated_artifact_size_kb


def test_custom_min_confidence_threshold() -> None:
    """10. Custom min_confidence is respected for the ready decision."""
    strict_planner = ArtifactPlanner(min_confidence=0.9)
    lenient_planner = ArtifactPlanner(min_confidence=0.1)

    kwargs: dict[str, Any] = {
        "total_seeds": 2,
        "expanded_seeds": 4,
        "successful_dispatches": 2,
        "failed_dispatches": 2,
        "denied_dispatches": 0,
        "total_observations": 4,
        "entity_count": 2,
        "attributed_count": 1,
        "collectors_used": ["dns-resolve", "passive-dns"],
        "collectors_failed": ["passive-dns"],
    }

    strict_result = strict_planner.evaluate(**kwargs)
    lenient_result = lenient_planner.evaluate(**kwargs)

    # confidence = 2/4 = 0.5 -> strict (0.9) rejects, lenient (0.1) accepts
    assert strict_result.ready is False
    assert lenient_result.ready is True
    # Both should have the same confidence value
    assert strict_result.confidence == lenient_result.confidence == pytest.approx(0.5)


def test_recommendations_nonempty_when_issues_found() -> None:
    """11. When there are issues, recommendations list is non-empty."""
    planner = ArtifactPlanner()
    # All failed, no entities -> should produce recommendations
    result = planner.evaluate(
        total_seeds=2,
        expanded_seeds=4,
        successful_dispatches=0,
        failed_dispatches=4,
        denied_dispatches=0,
        total_observations=0,
        entity_count=0,
        attributed_count=0,
        collectors_used=["dns-resolve"],
        collectors_failed=["dns-resolve"],
    )

    assert len(result.recommendations) > 0


def test_clean_run_empty_recommendations() -> None:
    """12. Fully clean run -> empty recommendations list."""
    result = _evaluate_full_success()

    assert result.recommendations == []


# === Extra coverage ===========================================================


def test_models_are_frozen() -> None:
    """CoverageGap and ArtifactReadiness are immutable (Pydantic frozen=True)."""
    gap = CoverageGap(
        collector_id="test",
        seed_value="example.com",
        reason="collector_failed",
        severity="critical",
    )
    with pytest.raises(Exception):  # noqa: B017
        gap.collector_id = "mutated"  # type: ignore[misc]

    result = _evaluate_full_success()
    with pytest.raises(Exception):  # noqa: B017
        result.ready = False  # type: ignore[misc]


def test_zero_dispatches_confidence() -> None:
    """Zero total dispatches -> confidence = 0 (not division by zero)."""
    planner = ArtifactPlanner()
    result = planner.evaluate(
        total_seeds=0,
        expanded_seeds=0,
        successful_dispatches=0,
        failed_dispatches=0,
        denied_dispatches=0,
        total_observations=0,
        entity_count=0,
        attributed_count=0,
        collectors_used=[],
        collectors_failed=[],
    )

    assert result.confidence == 0.0
    assert result.ready is False


def test_denied_dispatches_produce_tier3_gap() -> None:
    """Denied dispatches generate a tier3_denied coverage gap."""
    planner = ArtifactPlanner()
    result = planner.evaluate(
        total_seeds=1,
        expanded_seeds=1,
        successful_dispatches=1,
        failed_dispatches=0,
        denied_dispatches=1,
        total_observations=2,
        entity_count=1,
        attributed_count=1,
        collectors_used=["dns-resolve", "active-tls"],
        collectors_failed=[],
    )

    tier3_gaps = [g for g in result.coverage_gaps if g.reason == "tier3_denied"]
    assert len(tier3_gaps) == 1


def test_all_dispatches_fail_recommendation_text() -> None:
    """All passive collectors failed -> specific recommendation text."""
    planner = ArtifactPlanner()
    result = planner.evaluate(
        total_seeds=1,
        expanded_seeds=1,
        successful_dispatches=0,
        failed_dispatches=2,
        denied_dispatches=0,
        total_observations=0,
        entity_count=0,
        attributed_count=0,
        collectors_used=["dns-resolve", "passive-dns"],
        collectors_failed=["dns-resolve", "passive-dns"],
    )

    assert any("network connectivity" in r for r in result.recommendations)

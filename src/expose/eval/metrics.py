"""Scoring metrics for evaluation results.

The primary output is :class:`EvalMetrics`, a frozen Pydantic model that
captures attribution accuracy, confidence calibration error, and false-
positive / false-negative counts for a single dataset run.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from expose.eval.datasets import EvalResult

# Attribution values that mean "this asset belongs to the tenant".
_YOURS_TIERS: frozenset[str] = frozenset({"confirmed", "high", "medium"})


class EvalMetrics(BaseModel):
    """Aggregate scoring metrics for a single dataset evaluation run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dataset_name: str
    total_cases: int = Field(ge=0)
    correct_attributions: int = Field(ge=0)
    attribution_accuracy: float = Field(ge=0.0, le=1.0)
    mean_confidence_error: float = Field(ge=0.0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)


def compute_metrics(results: list[EvalResult], *, dataset_name: str) -> EvalMetrics:
    """Compute aggregate metrics from a list of per-case results.

    *dataset_name* is propagated verbatim into the returned
    :class:`EvalMetrics`.

    An empty *results* list yields zero-valued metrics (accuracy 0.0,
    mean_confidence_error 0.0, no false positives / negatives).
    """
    if not results:
        return EvalMetrics(
            dataset_name=dataset_name,
            total_cases=0,
            correct_attributions=0,
            attribution_accuracy=0.0,
            mean_confidence_error=0.0,
            false_positives=0,
            false_negatives=0,
        )

    total = len(results)
    correct = sum(1 for r in results if r.correct)
    accuracy = correct / total

    # Mean absolute confidence error: distance from the midpoint of the
    # expected confidence range.
    confidence_errors: list[float] = []
    for r in results:
        midpoint = (r.expected_confidence_range[0] + r.expected_confidence_range[1]) / 2.0
        confidence_errors.append(abs(r.actual_confidence - midpoint))
    mean_conf_error = sum(confidence_errors) / total

    # False positives: said "yours" when expected "not_yours".
    false_positives = sum(
        1
        for r in results
        if r.actual_attribution in _YOURS_TIERS and r.expected_attribution == "not_yours"
    )

    # False negatives: said "not_yours" when expected a "yours" tier.
    false_negatives = sum(
        1
        for r in results
        if r.actual_attribution == "not_yours" and r.expected_attribution in _YOURS_TIERS
    )

    return EvalMetrics(
        dataset_name=dataset_name,
        total_cases=total,
        correct_attributions=correct,
        attribution_accuracy=accuracy,
        mean_confidence_error=round(mean_conf_error, 6),
        false_positives=false_positives,
        false_negatives=false_negatives,
    )

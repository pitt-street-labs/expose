"""Evaluation runner -- drives an attribution function over eval datasets.

The runner accepts an injectable *attribution_fn*.  When ``None`` (the
default), a simple rule-based stub is used.  The stub is deliberately naive
-- it exists only to validate the harness plumbing.  When LLM enrichment
lands (Phase 2), callers will inject an LLM-backed attribution function and
compare its :class:`EvalMetrics` against the stub baseline.

A :class:`RuleEvaluator` from ``expose.pipeline.rule_evaluator`` can also
be injected via :meth:`EvalRunner.from_rule_evaluator` -- this wraps the
evaluator in the standard ``AttributionFn`` signature so the harness can
benchmark a real rule-pack-driven attribution function.
"""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from expose.eval.datasets import EvalCase, EvalDataset, EvalResult
from expose.eval.metrics import EvalMetrics, compute_metrics

# Re-export EvalResult so callers importing from runner still work.
__all__ = ["AttributionFn", "ConfusionMatrix", "EvalReport", "EvalResult", "EvalRunner"]

# Type alias for the injectable attribution function.
#
# Signature: (entity_type, canonical_identifier, observations) -> (tier, confidence)
# where tier is one of "confirmed" | "high" | "medium" | "not_yours" and
# confidence is a float in [0.0, 1.0].
AttributionFn = Callable[[str, str, list[dict[str, Any]]], tuple[str, float]]


# Stub thresholds: minimum observation counts for each attribution tier.
_STUB_CONFIRMED_MIN_OBS = 3
_STUB_HIGH_MIN_OBS = 2


def _stub_attribution(
    _entity_type: str,
    _canonical_identifier: str,
    observations: list[dict[str, Any]],
) -> tuple[str, float]:
    """Naive rule-based stub for harness validation.

    Heuristic:
    - 3+ observations with any containing ``"cloud_account_match": true``
      -> confirmed @ 0.98
    - 2+ observations -> high @ 0.80
    - 1 observation -> medium @ 0.55
    - 0 observations -> not_yours @ 0.10
    """
    if not observations:
        return ("not_yours", 0.10)

    cloud_match = any(obs.get("cloud_account_match") is True for obs in observations)
    count = len(observations)

    if count >= _STUB_CONFIRMED_MIN_OBS and cloud_match:
        return ("confirmed", 0.98)
    if count >= _STUB_HIGH_MIN_OBS:
        return ("high", 0.80)
    return ("medium", 0.55)


# =============================================================================
# RuleEvaluator adapter
# =============================================================================


def _rule_evaluator_to_attribution_fn(
    evaluator: Any,  # expose.pipeline.rule_evaluator.RuleEvaluator
) -> AttributionFn:
    """Wrap a ``RuleEvaluator`` as an ``AttributionFn``.

    The adapter builds the entity dict that ``RuleEvaluator.evaluate``
    expects from the ``(entity_type, canonical_identifier, observations)``
    triple that the eval harness passes.
    """

    def _fn(
        entity_type: str,
        canonical_identifier: str,
        observations: list[dict[str, Any]],
    ) -> tuple[str, float]:
        # Build an entity dict compatible with RuleEvaluator.evaluate().
        # Merge all observation dicts into properties so predicates can
        # inspect collector-provided fields.
        properties: dict[str, Any] = {}
        collector_ids: list[str] = []
        for obs in observations:
            for k, v in obs.items():
                if k == "collector_id":
                    collector_ids.append(str(v))
                else:
                    properties[k] = v
        if collector_ids:
            properties["_collector_ids"] = collector_ids

        entity = {
            "entity_type": entity_type,
            "canonical_identifier": canonical_identifier,
            "properties": properties,
            "attribution_confidence": 0.0,
            "attribution_status": "unattributed",
        }

        result = evaluator.evaluate(entity)
        tier = result.attribution_tier
        # Map "unattributed" and "rejected" to "not_yours" for eval purposes.
        if tier in ("unattributed", "rejected"):
            tier = "not_yours"
        return (tier, result.final_confidence)

    return _fn


# =============================================================================
# Confusion matrix
# =============================================================================

# The four tiers used in evaluation.
_EVAL_TIERS = ("confirmed", "high", "medium", "not_yours")


class ConfusionMatrix(BaseModel):
    """Row = expected, Column = actual.  Maps ``(expected, actual) -> count``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    matrix: dict[str, dict[str, int]]

    @classmethod
    def from_results(cls, results: list[EvalResult]) -> ConfusionMatrix:
        """Build a confusion matrix from evaluation results."""
        matrix: dict[str, dict[str, int]] = {}
        for tier in _EVAL_TIERS:
            matrix[tier] = {t: 0 for t in _EVAL_TIERS}

        for r in results:
            expected = r.expected_attribution
            actual = r.actual_attribution
            # Normalise unrecognised tiers to not_yours.
            if expected not in _EVAL_TIERS:
                expected = "not_yours"
            if actual not in _EVAL_TIERS:
                actual = "not_yours"
            matrix[expected][actual] += 1

        return cls(matrix=matrix)

    def display_lines(self) -> list[str]:
        """Render the confusion matrix as formatted text lines."""
        header = f"{'Expected':<14}" + "".join(f"{t:>12}" for t in _EVAL_TIERS)
        sep = "-" * len(header)
        lines = [header, sep]
        for expected in _EVAL_TIERS:
            row = f"{expected:<14}" + "".join(
                f"{self.matrix[expected][actual]:>12}" for actual in _EVAL_TIERS
            )
            lines.append(row)
        return lines


# =============================================================================
# EvalReport — structured output
# =============================================================================


class CategoryReport(BaseModel):
    """Per-category evaluation report with precision, recall, F1."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    category: str
    metrics: EvalMetrics
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    f1: float = Field(ge=0.0, le=1.0)
    total_wall_clock_ms: float = Field(ge=0.0)
    mean_wall_clock_ms: float = Field(ge=0.0)


class EvalReport(BaseModel):
    """Top-level structured evaluation report across all categories."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    categories: dict[str, CategoryReport]
    confusion_matrix: ConfusionMatrix
    overall_accuracy: float = Field(ge=0.0, le=1.0)
    overall_precision: float = Field(ge=0.0, le=1.0)
    overall_recall: float = Field(ge=0.0, le=1.0)
    overall_f1: float = Field(ge=0.0, le=1.0)
    total_cases: int = Field(ge=0)
    total_wall_clock_ms: float = Field(ge=0.0)


def _compute_precision_recall_f1(
    results: list[EvalResult],
) -> tuple[float, float, float]:
    """Compute binary precision, recall, and F1 for a set of results.

    "Positive" = any attribution tier in {confirmed, high, medium}.
    "Negative" = "not_yours".

    This treats the problem as a binary classification: "does this entity
    belong to the target organization?"
    """
    yours_tiers = frozenset({"confirmed", "high", "medium"})
    tp = sum(
        1 for r in results
        if r.actual_attribution in yours_tiers and r.expected_attribution in yours_tiers
    )
    fp = sum(
        1 for r in results
        if r.actual_attribution in yours_tiers and r.expected_attribution not in yours_tiers
    )
    fn = sum(
        1 for r in results
        if r.actual_attribution not in yours_tiers and r.expected_attribution in yours_tiers
    )

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return (precision, recall, f1)


# =============================================================================
# EvalRunner
# =============================================================================


class EvalRunner:
    """Run eval cases against an attribution function and collect results.

    The attribution function is injected via *attribution_fn*.  When omitted
    (or ``None``), the built-in rule-based stub is used.  When LLM enrichment
    lands, pass an LLM-backed callable here and compare with the stub baseline.

    To use a ``RuleEvaluator`` from ``expose.pipeline.rule_evaluator``, call
    :meth:`from_rule_evaluator` instead of the constructor.
    """

    def __init__(self, attribution_fn: AttributionFn | None = None) -> None:
        self._fn: AttributionFn = attribution_fn or _stub_attribution

    @classmethod
    def from_rule_evaluator(
        cls,
        evaluator: Any,  # expose.pipeline.rule_evaluator.RuleEvaluator
    ) -> EvalRunner:
        """Construct an ``EvalRunner`` backed by a ``RuleEvaluator``.

        The evaluator's ``evaluate()`` method is wrapped to match the
        ``AttributionFn`` signature.
        """
        return cls(attribution_fn=_rule_evaluator_to_attribution_fn(evaluator))

    def _run_case(self, case: EvalCase) -> EvalResult:
        """Evaluate a single case synchronously."""
        start = time.monotonic()
        tier, confidence = self._fn(
            case.entity_type,
            case.canonical_identifier,
            case.observations,
        )
        elapsed_ms = (time.monotonic() - start) * 1000.0

        correct = tier == case.expected_attribution
        return EvalResult(
            case_id=case.case_id,
            expected_attribution=case.expected_attribution,
            actual_attribution=tier,
            expected_confidence_range=(
                case.expected_confidence_min,
                case.expected_confidence_max,
            ),
            actual_confidence=confidence,
            correct=correct,
            duration_ms=round(elapsed_ms, 3),
        )

    async def run_dataset(self, dataset: EvalDataset) -> list[EvalResult]:
        """Run all cases in *dataset* and return per-case results.

        The stub attribution function is synchronous, so ``await`` here is
        a no-op on latency.  When an LLM-backed function is injected, the
        runner will switch to ``asyncio.to_thread`` or native async calls.
        """
        return [self._run_case(case) for case in dataset.cases]

    async def run_all(self, datasets: list[EvalDataset]) -> dict[str, EvalMetrics]:
        """Run every dataset and return a mapping of dataset name to metrics."""
        metrics: dict[str, EvalMetrics] = {}
        for ds in datasets:
            results = await self.run_dataset(ds)
            metrics[ds.name] = compute_metrics(results, dataset_name=ds.name)
        return metrics

    async def run_report(self, datasets: list[EvalDataset]) -> EvalReport:
        """Run every dataset and produce a structured :class:`EvalReport`.

        The report includes per-category accuracy/precision/recall/F1,
        a confusion matrix across all results, and wall-clock timing.
        """
        all_results: list[EvalResult] = []
        category_reports: dict[str, CategoryReport] = {}

        overall_start = time.monotonic()

        for ds in datasets:
            ds_start = time.monotonic()
            results = await self.run_dataset(ds)
            ds_elapsed = (time.monotonic() - ds_start) * 1000.0

            all_results.extend(results)
            metrics = compute_metrics(results, dataset_name=ds.name)
            precision, recall, f1 = _compute_precision_recall_f1(results)

            mean_wall = ds_elapsed / len(results) if results else 0.0
            category_reports[ds.name] = CategoryReport(
                category=ds.category,
                metrics=metrics,
                precision=round(precision, 6),
                recall=round(recall, 6),
                f1=round(f1, 6),
                total_wall_clock_ms=round(ds_elapsed, 3),
                mean_wall_clock_ms=round(mean_wall, 3),
            )

        overall_elapsed = (time.monotonic() - overall_start) * 1000.0
        confusion = ConfusionMatrix.from_results(all_results)

        total = len(all_results)
        correct = sum(1 for r in all_results if r.correct)
        overall_accuracy = correct / total if total > 0 else 0.0
        o_precision, o_recall, o_f1 = _compute_precision_recall_f1(all_results)

        return EvalReport(
            categories=category_reports,
            confusion_matrix=confusion,
            overall_accuracy=round(overall_accuracy, 6),
            overall_precision=round(o_precision, 6),
            overall_recall=round(o_recall, 6),
            overall_f1=round(o_f1, 6),
            total_cases=total,
            total_wall_clock_ms=round(overall_elapsed, 3),
        )

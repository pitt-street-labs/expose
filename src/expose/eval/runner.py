"""Evaluation runner -- drives an attribution function over eval datasets.

The runner accepts an injectable *attribution_fn*.  When ``None`` (the
default), a simple rule-based stub is used.  The stub is deliberately naive
-- it exists only to validate the harness plumbing.  When LLM enrichment
lands (Phase 2), callers will inject an LLM-backed attribution function and
compare its :class:`EvalMetrics` against the stub baseline.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from expose.eval.datasets import EvalCase, EvalDataset, EvalResult
from expose.eval.metrics import EvalMetrics, compute_metrics

# Re-export EvalResult so callers importing from runner still work.
__all__ = ["AttributionFn", "EvalResult", "EvalRunner"]

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


class EvalRunner:
    """Run eval cases against an attribution function and collect results.

    The attribution function is injected via *attribution_fn*.  When omitted
    (or ``None``), the built-in rule-based stub is used.  When LLM enrichment
    lands, pass an LLM-backed callable here and compare with the stub baseline.
    """

    def __init__(self, attribution_fn: AttributionFn | None = None) -> None:
        self._fn: AttributionFn = attribution_fn or _stub_attribution

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

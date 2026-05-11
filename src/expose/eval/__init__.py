"""Evaluation harness for measuring LLM enrichment quality (Gitea issue #17).

The eval harness is the Phase 2 entry point for comparing how different LLM
providers perform at attribution decisions.  It decouples the scoring surface
from the pipeline itself so evaluations can run offline against curated
datasets without a live EXPOSE deployment.

Sub-modules:

- ``datasets`` -- :class:`EvalCase` / :class:`EvalDataset` Pydantic models
  and loaders for JSON-serialised evaluation datasets.
- ``metrics`` -- :class:`EvalMetrics` computation from evaluation results.
- ``runner`` -- :class:`EvalRunner` that drives an attribution function
  (injectable; stub by default) over a dataset and produces per-case
  :class:`EvalResult` objects.

Refs #17.
"""

from expose.eval.datasets import (
    EVAL_CATEGORIES,
    EvalCase,
    EvalDataset,
    EvalResult,
    load_all_datasets,
    load_dataset,
    load_dataset_by_category,
    load_datasets_by_categories,
)
from expose.eval.metrics import EvalMetrics, compute_metrics
from expose.eval.runner import EvalReport, EvalRunner

__all__ = [
    "EVAL_CATEGORIES",
    "EvalCase",
    "EvalDataset",
    "EvalMetrics",
    "EvalReport",
    "EvalResult",
    "EvalRunner",
    "compute_metrics",
    "load_all_datasets",
    "load_dataset",
    "load_dataset_by_category",
    "load_datasets_by_categories",
]

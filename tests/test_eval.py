"""Tests for the evaluation harness (Gitea issue #17).

Coverage:

 1. load_dataset parses valid JSON into EvalDataset.
 2. load_all_datasets finds multiple files in a directory.
 3. EvalCase validates correctly (good input accepted).
 4. EvalCase rejects invalid input (extra fields, out-of-range confidence).
 5. EvalRunner with stub attribution runs a single case.
 6. Correct attribution detected by the runner.
 7. Incorrect attribution detected by the runner.
 8. compute_metrics calculates accuracy.
 9. False positive counting.
10. False negative counting.
11. Mean confidence error calculation.
12. Empty results list yields zero-valued metrics.
13. load_dataset raises on missing file.
14. load_all_datasets raises on non-directory path.
15. EvalRunner.run_all returns per-dataset metrics.

Refs #17.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from expose.eval.datasets import EvalCase, EvalDataset, load_all_datasets, load_dataset
from expose.eval.metrics import EvalMetrics, compute_metrics
from expose.eval.runner import EvalResult, EvalRunner

# === Fixtures ================================================================

SAMPLE_CASE_DATA: dict[str, Any] = {
    "case_id": "tc-001",
    "description": "Test case with strong cloud signals",
    "entity_type": "ip",
    "canonical_identifier": "203.0.113.42",
    "observations": [
        {"collector_id": "cloud-range-check", "cloud_account_match": True},
        {"collector_id": "rdap-whois", "matches_tenant": True},
        {"collector_id": "cert-transparency", "subject": "*.example.com"},
    ],
    "expected_attribution": "confirmed",
    "expected_confidence_min": 0.95,
    "expected_confidence_max": 1.0,
}


def _make_dataset_dict(
    name: str = "test_dataset",
    category: str = "confirmed_yours",
    cases: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "category": category,
        "cases": cases if cases is not None else [SAMPLE_CASE_DATA],
    }


@pytest.fixture
def dataset_dir(tmp_path: Path) -> Path:
    """Directory containing two JSON dataset files."""
    d1 = _make_dataset_dict(name="dataset_alpha", category="confirmed_yours")
    d2 = _make_dataset_dict(
        name="dataset_beta",
        category="confirmed_not_yours",
        cases=[
            {
                "case_id": "cn-001",
                "description": "No observations, clearly not ours",
                "entity_type": "ip",
                "canonical_identifier": "192.0.2.99",
                "observations": [],
                "expected_attribution": "not_yours",
                "expected_confidence_min": 0.0,
                "expected_confidence_max": 0.2,
            }
        ],
    )
    (tmp_path / "alpha.json").write_text(json.dumps(d1), encoding="utf-8")
    (tmp_path / "beta.json").write_text(json.dumps(d2), encoding="utf-8")
    # Non-JSON file should be ignored.
    (tmp_path / "README.md").write_text("ignore me", encoding="utf-8")
    return tmp_path


@pytest.fixture
def single_dataset_path(tmp_path: Path) -> Path:
    """Path to a single valid dataset JSON file."""
    data = _make_dataset_dict()
    p = tmp_path / "single.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


# === 1. load_dataset parses valid JSON =======================================


async def test_load_dataset_parses_valid_json(single_dataset_path: Path) -> None:
    """load_dataset returns an EvalDataset from a valid JSON file."""
    ds = load_dataset(single_dataset_path)
    assert isinstance(ds, EvalDataset)
    assert ds.name == "test_dataset"
    assert ds.category == "confirmed_yours"
    assert len(ds.cases) == 1
    assert ds.cases[0].case_id == "tc-001"


# === 2. load_all_datasets finds multiple files ===============================


async def test_load_all_datasets_finds_multiple(dataset_dir: Path) -> None:
    """load_all_datasets loads every JSON file and ignores non-JSON."""
    datasets = load_all_datasets(dataset_dir)
    assert len(datasets) == 2
    names = {ds.name for ds in datasets}
    assert names == {"dataset_alpha", "dataset_beta"}


# === 3. EvalCase validates correctly =========================================


async def test_eval_case_validates_good_input() -> None:
    """EvalCase accepts well-formed input without error."""
    case = EvalCase.model_validate(SAMPLE_CASE_DATA)
    assert case.case_id == "tc-001"
    assert case.entity_type == "ip"
    assert case.expected_confidence_min == 0.95
    assert case.expected_confidence_max == 1.0
    assert len(case.observations) == 3


# === 4. EvalCase rejects invalid input =======================================


async def test_eval_case_rejects_extra_fields() -> None:
    """EvalCase with extra='forbid' rejects unknown fields."""
    bad = {**SAMPLE_CASE_DATA, "rogue_field": "surprise"}
    with pytest.raises(ValidationError):
        EvalCase.model_validate(bad)


async def test_eval_case_rejects_out_of_range_confidence() -> None:
    """Confidence outside [0.0, 1.0] is rejected."""
    bad = {**SAMPLE_CASE_DATA, "expected_confidence_min": -0.1}
    with pytest.raises(ValidationError):
        EvalCase.model_validate(bad)

    bad2 = {**SAMPLE_CASE_DATA, "expected_confidence_max": 1.5}
    with pytest.raises(ValidationError):
        EvalCase.model_validate(bad2)


# === 5. EvalRunner with stub runs a case =====================================


async def test_runner_stub_runs_single_case() -> None:
    """EvalRunner with default stub executes a case and returns EvalResult."""
    ds = EvalDataset.model_validate(_make_dataset_dict())
    runner = EvalRunner()
    results = await runner.run_dataset(ds)
    assert len(results) == 1
    r = results[0]
    assert isinstance(r, EvalResult)
    assert r.case_id == "tc-001"
    assert r.duration_ms >= 0.0


# === 6. Correct attribution detected =========================================


async def test_correct_attribution_detected() -> None:
    """When stub returns the expected tier, result.correct is True."""
    # 3 observations with cloud_account_match -> stub returns "confirmed"
    ds = EvalDataset.model_validate(_make_dataset_dict())
    runner = EvalRunner()
    results = await runner.run_dataset(ds)
    assert results[0].correct is True
    assert results[0].actual_attribution == "confirmed"


# === 7. Incorrect attribution detected =======================================


async def test_incorrect_attribution_detected() -> None:
    """When stub returns a different tier, result.correct is False."""
    # Single observation, no cloud match -> stub returns "medium",
    # but we expect "confirmed" -> mismatch.
    case_data = {
        **SAMPLE_CASE_DATA,
        "case_id": "mismatch-001",
        "observations": [{"collector_id": "rdap-whois", "matches_tenant": True}],
        "expected_attribution": "confirmed",
    }
    ds = EvalDataset.model_validate(_make_dataset_dict(cases=[case_data]))
    runner = EvalRunner()
    results = await runner.run_dataset(ds)
    assert results[0].correct is False
    assert results[0].actual_attribution == "medium"
    assert results[0].expected_attribution == "confirmed"


# === 8. compute_metrics calculates accuracy ==================================


async def test_compute_metrics_accuracy() -> None:
    """Accuracy = correct / total."""
    results = [
        EvalResult(
            case_id="a",
            expected_attribution="confirmed",
            actual_attribution="confirmed",
            expected_confidence_range=(0.9, 1.0),
            actual_confidence=0.98,
            correct=True,
            duration_ms=1.0,
        ),
        EvalResult(
            case_id="b",
            expected_attribution="confirmed",
            actual_attribution="high",
            expected_confidence_range=(0.9, 1.0),
            actual_confidence=0.80,
            correct=False,
            duration_ms=1.0,
        ),
    ]
    m = compute_metrics(results, dataset_name="acc_test")
    assert m.total_cases == 2
    assert m.correct_attributions == 1
    assert m.attribution_accuracy == 0.5


# === 9. False positive counting ==============================================


async def test_false_positive_counting() -> None:
    """False positive: actual is a 'yours' tier but expected is 'not_yours'."""
    results = [
        EvalResult(
            case_id="fp-1",
            expected_attribution="not_yours",
            actual_attribution="confirmed",
            expected_confidence_range=(0.0, 0.2),
            actual_confidence=0.95,
            correct=False,
            duration_ms=1.0,
        ),
        EvalResult(
            case_id="fp-2",
            expected_attribution="not_yours",
            actual_attribution="high",
            expected_confidence_range=(0.0, 0.2),
            actual_confidence=0.80,
            correct=False,
            duration_ms=1.0,
        ),
        EvalResult(
            case_id="tp-1",
            expected_attribution="confirmed",
            actual_attribution="confirmed",
            expected_confidence_range=(0.9, 1.0),
            actual_confidence=0.98,
            correct=True,
            duration_ms=1.0,
        ),
    ]
    m = compute_metrics(results, dataset_name="fp_test")
    assert m.false_positives == 2
    assert m.false_negatives == 0


# === 10. False negative counting =============================================


async def test_false_negative_counting() -> None:
    """False negative: actual is 'not_yours' but expected is a 'yours' tier."""
    results = [
        EvalResult(
            case_id="fn-1",
            expected_attribution="confirmed",
            actual_attribution="not_yours",
            expected_confidence_range=(0.9, 1.0),
            actual_confidence=0.10,
            correct=False,
            duration_ms=1.0,
        ),
        EvalResult(
            case_id="fn-2",
            expected_attribution="high",
            actual_attribution="not_yours",
            expected_confidence_range=(0.7, 0.9),
            actual_confidence=0.10,
            correct=False,
            duration_ms=1.0,
        ),
        EvalResult(
            case_id="tn-1",
            expected_attribution="not_yours",
            actual_attribution="not_yours",
            expected_confidence_range=(0.0, 0.2),
            actual_confidence=0.10,
            correct=True,
            duration_ms=1.0,
        ),
    ]
    m = compute_metrics(results, dataset_name="fn_test")
    assert m.false_negatives == 2
    assert m.false_positives == 0


# === 11. Mean confidence error ===============================================


async def test_mean_confidence_error() -> None:
    """Mean confidence error is the average distance from range midpoint."""
    results = [
        EvalResult(
            case_id="ce-1",
            expected_attribution="confirmed",
            actual_attribution="confirmed",
            expected_confidence_range=(0.9, 1.0),
            # midpoint = 0.95, error = |0.98 - 0.95| = 0.03
            actual_confidence=0.98,
            correct=True,
            duration_ms=1.0,
        ),
        EvalResult(
            case_id="ce-2",
            expected_attribution="confirmed",
            actual_attribution="confirmed",
            expected_confidence_range=(0.9, 1.0),
            # midpoint = 0.95, error = |0.90 - 0.95| = 0.05
            actual_confidence=0.90,
            correct=True,
            duration_ms=1.0,
        ),
    ]
    m = compute_metrics(results, dataset_name="ce_test")
    # mean error = (0.03 + 0.05) / 2 = 0.04
    assert m.mean_confidence_error == pytest.approx(0.04, abs=1e-6)


# === 12. Empty results yield zero-valued metrics =============================


async def test_empty_results_zero_metrics() -> None:
    """An empty results list produces zero-valued metrics (no division by zero)."""
    m = compute_metrics([], dataset_name="empty")
    assert m.total_cases == 0
    assert m.correct_attributions == 0
    assert m.attribution_accuracy == 0.0
    assert m.mean_confidence_error == 0.0
    assert m.false_positives == 0
    assert m.false_negatives == 0


# === 13. load_dataset raises on missing file =================================


async def test_load_dataset_missing_file(tmp_path: Path) -> None:
    """load_dataset raises FileNotFoundError for a nonexistent path."""
    with pytest.raises(FileNotFoundError):
        load_dataset(tmp_path / "does_not_exist.json")


# === 14. load_all_datasets raises on non-directory ===========================


async def test_load_all_datasets_non_directory(tmp_path: Path) -> None:
    """load_all_datasets raises NotADirectoryError for a file path."""
    f = tmp_path / "file.txt"
    f.write_text("not a directory", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        load_all_datasets(f)


# === 15. run_all returns per-dataset metrics =================================


async def test_run_all_returns_per_dataset_metrics(dataset_dir: Path) -> None:
    """run_all processes multiple datasets and keys metrics by name."""
    datasets = load_all_datasets(dataset_dir)
    runner = EvalRunner()
    all_metrics = await runner.run_all(datasets)
    assert len(all_metrics) == 2
    assert "dataset_alpha" in all_metrics
    assert "dataset_beta" in all_metrics
    assert isinstance(all_metrics["dataset_alpha"], EvalMetrics)
    assert isinstance(all_metrics["dataset_beta"], EvalMetrics)


# === 16. Custom attribution function injection ===============================


async def test_custom_attribution_fn() -> None:
    """EvalRunner accepts a custom attribution function."""

    def always_confirmed(
        _entity_type: str,
        _canonical_identifier: str,
        _observations: list[dict[str, Any]],
    ) -> tuple[str, float]:
        return ("confirmed", 0.99)

    ds = EvalDataset.model_validate(_make_dataset_dict())
    runner = EvalRunner(attribution_fn=always_confirmed)
    results = await runner.run_dataset(ds)
    assert results[0].actual_attribution == "confirmed"
    assert results[0].actual_confidence == 0.99


# === 17. Frozen models are immutable =========================================


async def test_eval_result_is_frozen() -> None:
    """EvalResult instances are immutable (frozen=True)."""
    r = EvalResult(
        case_id="frozen-test",
        expected_attribution="confirmed",
        actual_attribution="confirmed",
        expected_confidence_range=(0.9, 1.0),
        actual_confidence=0.98,
        correct=True,
        duration_ms=1.0,
    )
    with pytest.raises(ValidationError):
        r.correct = False  # type: ignore[misc]


# === 18. EvalMetrics is frozen ===============================================


async def test_eval_metrics_is_frozen() -> None:
    """EvalMetrics instances are immutable (frozen=True)."""
    m = EvalMetrics(
        dataset_name="frozen",
        total_cases=1,
        correct_attributions=1,
        attribution_accuracy=1.0,
        mean_confidence_error=0.0,
        false_positives=0,
        false_negatives=0,
    )
    with pytest.raises(ValidationError):
        m.total_cases = 99  # type: ignore[misc]


# === 19. Sample datasets load cleanly from examples/ ========================


async def test_sample_datasets_load(repo_root: Path) -> None:
    """The shipped example datasets in examples/eval-datasets/ parse cleanly."""
    eval_dir = repo_root / "examples" / "eval-datasets"
    if not eval_dir.is_dir():
        pytest.skip("examples/eval-datasets not found")
    datasets = load_all_datasets(eval_dir)
    assert len(datasets) >= 2
    for ds in datasets:
        assert len(ds.cases) >= 1
        for case in ds.cases:
            assert case.expected_confidence_min <= case.expected_confidence_max

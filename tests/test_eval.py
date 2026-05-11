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
16. Custom attribution function injection.
17. Frozen models are immutable.
18. EvalMetrics is frozen.
19. Sample datasets load cleanly from examples/.
20. load_dataset_by_category loads a specific category.
21. load_dataset_by_category rejects unknown categories.
22. load_datasets_by_categories loads all four categories.
23. EvalReport contains per-category precision/recall/F1.
24. EvalReport confusion matrix is well-formed.
25. EvalReport timing fields are populated.
26. RuleEvaluator integration via from_rule_evaluator.
27. CLI eval --all runs without error.
28. CLI eval --dataset runs a single category.
29. CLI exit code 0 when accuracy >= threshold.
30. CLI exit code 1 when accuracy < threshold.
31. CLI --json-output produces valid JSON.
32. CLI rejects --dataset + --all together.
33. CLI requires --dataset or --all.

Refs #17.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from expose.eval.datasets import (
    EVAL_CATEGORIES,
    EvalCase,
    EvalDataset,
    load_all_datasets,
    load_dataset,
    load_dataset_by_category,
    load_datasets_by_categories,
)
from expose.eval.metrics import EvalMetrics, compute_metrics
from expose.eval.runner import ConfusionMatrix, EvalReport, EvalResult, EvalRunner

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


# === 20. load_dataset_by_category loads a specific category =================


async def test_load_dataset_by_category(repo_root: Path) -> None:
    """load_dataset_by_category returns the correct dataset for a known category."""
    eval_dir = repo_root / "examples" / "eval-datasets"
    if not eval_dir.is_dir():
        pytest.skip("examples/eval-datasets not found")
    ds = load_dataset_by_category(eval_dir, "confirmed_yours")
    assert ds.category == "confirmed_yours"
    assert len(ds.cases) >= 1


# === 21. load_dataset_by_category rejects unknown categories ================


async def test_load_dataset_by_category_unknown() -> None:
    """load_dataset_by_category raises ValueError for bogus category."""
    with pytest.raises(ValueError, match="Unknown eval category"):
        load_dataset_by_category(Path("/tmp"), "nonexistent_category")


# === 22. load_datasets_by_categories loads all four =========================


async def test_load_datasets_by_categories_all(repo_root: Path) -> None:
    """load_datasets_by_categories with None loads all four categories."""
    eval_dir = repo_root / "examples" / "eval-datasets"
    if not eval_dir.is_dir():
        pytest.skip("examples/eval-datasets not found")
    datasets = load_datasets_by_categories(eval_dir)
    assert len(datasets) == 4
    categories = {ds.category for ds in datasets}
    assert categories == set(EVAL_CATEGORIES)


# === 23. EvalReport contains per-category precision/recall/F1 ===============


async def test_eval_report_precision_recall_f1() -> None:
    """run_report produces an EvalReport with per-category P/R/F1."""
    # Build two minimal datasets.
    ds_yours = EvalDataset.model_validate(_make_dataset_dict(
        name="cy", category="confirmed_yours",
    ))
    not_yours_case = {
        "case_id": "cn-001",
        "description": "No observations",
        "entity_type": "ip",
        "canonical_identifier": "192.0.2.99",
        "observations": [],
        "expected_attribution": "not_yours",
        "expected_confidence_min": 0.0,
        "expected_confidence_max": 0.2,
    }
    ds_not = EvalDataset.model_validate(_make_dataset_dict(
        name="cn", category="confirmed_not_yours", cases=[not_yours_case],
    ))

    runner = EvalRunner()
    report = await runner.run_report([ds_yours, ds_not])

    assert isinstance(report, EvalReport)
    assert "cy" in report.categories
    assert "cn" in report.categories

    cy_cat = report.categories["cy"]
    assert 0.0 <= cy_cat.precision <= 1.0
    assert 0.0 <= cy_cat.recall <= 1.0
    assert 0.0 <= cy_cat.f1 <= 1.0

    assert 0.0 <= report.overall_precision <= 1.0
    assert 0.0 <= report.overall_recall <= 1.0
    assert 0.0 <= report.overall_f1 <= 1.0


# === 24. Confusion matrix is well-formed ====================================


async def test_confusion_matrix_well_formed() -> None:
    """ConfusionMatrix covers all four tiers and sums to total results."""
    results = [
        EvalResult(
            case_id="a", expected_attribution="confirmed",
            actual_attribution="confirmed",
            expected_confidence_range=(0.9, 1.0),
            actual_confidence=0.98, correct=True, duration_ms=1.0,
        ),
        EvalResult(
            case_id="b", expected_attribution="not_yours",
            actual_attribution="high",
            expected_confidence_range=(0.0, 0.2),
            actual_confidence=0.80, correct=False, duration_ms=1.0,
        ),
    ]
    cm = ConfusionMatrix.from_results(results)
    assert set(cm.matrix.keys()) == {"confirmed", "high", "medium", "not_yours"}
    total = sum(
        cm.matrix[exp][act]
        for exp in cm.matrix
        for act in cm.matrix[exp]
    )
    assert total == 2
    assert cm.matrix["confirmed"]["confirmed"] == 1
    assert cm.matrix["not_yours"]["high"] == 1


# === 25. EvalReport timing fields populated =================================


async def test_eval_report_timing() -> None:
    """run_report populates wall-clock timing fields."""
    ds = EvalDataset.model_validate(_make_dataset_dict())
    runner = EvalRunner()
    report = await runner.run_report([ds])

    assert report.total_wall_clock_ms >= 0.0
    for cat_report in report.categories.values():
        assert cat_report.total_wall_clock_ms >= 0.0
        assert cat_report.mean_wall_clock_ms >= 0.0


# === 26. RuleEvaluator integration via from_rule_evaluator ==================


async def test_from_rule_evaluator() -> None:
    """EvalRunner.from_rule_evaluator wraps a RuleEvaluator correctly."""
    from expose.pipeline.rule_evaluator import RuleEvaluator
    from expose.types.rulepack import (
        Action,
        AttributionRule,
        CategoryThresholds,
        LeadScoreFormula,
        LeadScoreWeights,
        Outcome,
        Predicate,
        PredicateCondition,
        RulePack,
        TierThresholds,
    )

    # Minimal rule pack: any entity with 1+ collector observations -> promote.
    pack = RulePack(
        pack_id="test-pack",
        pack_version="0.1.0",
        description="Minimal test pack",
        attribution_rules=[
            AttributionRule(
                rule_id="always-promote",
                rule_version="1.0.0",
                description="Promote everything observed",
                when=PredicateCondition(
                    predicate=Predicate.TARGET_OBSERVED_BY_COLLECTORS_COUNT_GTE,
                    params={"count": 1},
                ),
                then=Action(outcome=Outcome.PROMOTE, confidence_delta=1.0),
                priority=10,
            ),
        ],
        lead_score_formula=LeadScoreFormula(
            formula_version="0.1.0",
            weights=LeadScoreWeights(),
            modifiers=[],
            category_thresholds=CategoryThresholds(),
        ),
        tier_thresholds=TierThresholds(),
    )
    evaluator = RuleEvaluator(pack)
    runner = EvalRunner.from_rule_evaluator(evaluator)

    ds = EvalDataset.model_validate(_make_dataset_dict())
    results = await runner.run_dataset(ds)
    assert len(results) == 1
    # The case has 3 observations with collector_ids, so rule fires -> confirmed.
    assert results[0].actual_attribution == "confirmed"
    assert results[0].actual_confidence == 1.0


# === 27-33. CLI integration tests ============================================


class TestEvalCLI:
    """CLI integration tests for ``expose eval``."""

    def _invoke(self, args: list[str]) -> Any:
        """Invoke the CLI and return the Click Result."""
        from expose.cli import main as cli_main

        runner = CliRunner()
        return runner.invoke(cli_main, args)

    # --- 27. CLI eval --all runs without error ---

    def test_cli_eval_all(self, repo_root: Path) -> None:
        """expose eval --all runs and produces output."""
        eval_dir = repo_root / "examples" / "eval-datasets"
        if not eval_dir.is_dir():
            pytest.skip("examples/eval-datasets not found")
        result = self._invoke(["eval", "--all", "--dataset-dir", str(eval_dir)])
        # Stub will get some wrong -> could be exit 0 or 1, but not 2.
        assert result.exit_code in (0, 1)
        assert "Accuracy:" in result.output or "overall_accuracy" in result.output

    # --- 28. CLI eval --dataset runs a single category ---

    def test_cli_eval_single_dataset(self, repo_root: Path) -> None:
        """expose eval --dataset confirmed_yours runs only that category."""
        eval_dir = repo_root / "examples" / "eval-datasets"
        if not eval_dir.is_dir():
            pytest.skip("examples/eval-datasets not found")
        result = self._invoke([
            "eval", "--dataset", "confirmed_yours",
            "--dataset-dir", str(eval_dir),
        ])
        assert result.exit_code in (0, 1)
        assert "confirmed_yours" in result.output

    # --- 29. CLI exit code 0 when accuracy >= threshold ---

    def test_cli_exit_code_pass(self, tmp_path: Path) -> None:
        """Exit code 0 when accuracy meets threshold."""
        # Build a dataset the stub will get 100% right.
        ds = _make_dataset_dict(name="confirmed_yours", category="confirmed_yours")
        (tmp_path / "confirmed_yours.json").write_text(json.dumps(ds), encoding="utf-8")

        result = self._invoke([
            "eval", "--dataset", "confirmed_yours",
            "--dataset-dir", str(tmp_path),
            "--threshold", "0.5",
        ])
        assert result.exit_code == 0
        assert "PASS" in result.output

    # --- 30. CLI exit code 1 when accuracy < threshold ---

    def test_cli_exit_code_fail(self, tmp_path: Path) -> None:
        """Exit code 1 when accuracy is below threshold."""
        # Build a dataset the stub will get wrong (expects confirmed but has 0 obs).
        bad_case = {
            "case_id": "force-fail",
            "description": "No observations but expects confirmed",
            "entity_type": "ip",
            "canonical_identifier": "192.0.2.1",
            "observations": [],
            "expected_attribution": "confirmed",
            "expected_confidence_min": 0.95,
            "expected_confidence_max": 1.0,
        }
        ds = _make_dataset_dict(
            name="confirmed_yours", category="confirmed_yours", cases=[bad_case],
        )
        (tmp_path / "confirmed_yours.json").write_text(json.dumps(ds), encoding="utf-8")

        result = self._invoke([
            "eval", "--dataset", "confirmed_yours",
            "--dataset-dir", str(tmp_path),
            "--threshold", "1.0",
        ])
        assert result.exit_code == 1
        assert "FAIL" in result.output

    # --- 31. CLI --json-output produces valid JSON ---

    def test_cli_json_output(self, tmp_path: Path) -> None:
        """--json-output emits a valid EvalReport JSON."""
        ds = _make_dataset_dict(name="confirmed_yours", category="confirmed_yours")
        (tmp_path / "confirmed_yours.json").write_text(json.dumps(ds), encoding="utf-8")

        result = self._invoke([
            "eval", "--dataset", "confirmed_yours",
            "--dataset-dir", str(tmp_path),
            "--json-output",
        ])
        # Extract JSON from output -- skip preamble and trailing PASS/FAIL lines.
        lines = result.output.strip().split("\n")
        json_start = 0
        json_end = len(lines)
        for i, line in enumerate(lines):
            if line.strip().startswith("{"):
                json_start = i
                break
        # Find the closing brace of the JSON object.
        for i in range(len(lines) - 1, json_start - 1, -1):
            if lines[i].strip() == "}":
                json_end = i + 1
                break
        json_text = "\n".join(lines[json_start:json_end])
        parsed = json.loads(json_text)
        assert "categories" in parsed
        assert "confusion_matrix" in parsed
        assert "overall_accuracy" in parsed
        assert "overall_precision" in parsed
        assert "overall_f1" in parsed

    # --- 32. CLI rejects --dataset + --all together ---

    def test_cli_rejects_dataset_plus_all(self) -> None:
        """Specifying both --dataset and --all is an error."""
        result = self._invoke([
            "eval", "--dataset", "confirmed_yours", "--all",
        ])
        assert result.exit_code == 2

    # --- 33. CLI requires --dataset or --all ---

    def test_cli_requires_dataset_or_all(self) -> None:
        """Omitting both --dataset and --all is an error."""
        result = self._invoke(["eval"])
        assert result.exit_code == 2

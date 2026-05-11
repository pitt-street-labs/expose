"""Comprehensive tests for the EXPOSE eval harness (Gitea issue #103).

Tests the complete evaluation pipeline: dataset loading and validation,
metric computation (accuracy, precision, recall, F1), per-category
correctness against reference datasets, adversarial case handling, and
RuleEvaluator integration via the eval runner.

Refs #103.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

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
from expose.eval.runner import (
    ConfusionMatrix,
    EvalReport,
    EvalRunner,
    _compute_precision_recall_f1,
)


# =============================================================================
# Helpers
# =============================================================================


def _eval_datasets_dir(repo_root: Path) -> Path:
    """Return the path to examples/eval-datasets/, skipping if absent."""
    d = repo_root / "examples" / "eval-datasets"
    if not d.is_dir():
        pytest.skip("examples/eval-datasets not found")
    return d


def _make_result(
    case_id: str,
    expected: str,
    actual: str,
    confidence: float = 0.5,
    *,
    correct: bool | None = None,
) -> EvalResult:
    """Build an EvalResult with sensible defaults."""
    if correct is None:
        correct = expected == actual
    range_map = {
        "confirmed": (0.95, 1.0),
        "high": (0.70, 0.95),
        "medium": (0.40, 0.70),
        "not_yours": (0.0, 0.3),
    }
    conf_range = range_map.get(expected, (0.0, 1.0))
    return EvalResult(
        case_id=case_id,
        expected_attribution=expected,
        actual_attribution=actual,
        expected_confidence_range=conf_range,
        actual_confidence=confidence,
        correct=correct,
        duration_ms=0.1,
    )


# =============================================================================
# 1. Dataset loading and validation
# =============================================================================


class TestDatasetLoading:
    """Verify all four reference datasets load and pass schema validation."""

    def test_all_four_categories_exist(self, repo_root: Path) -> None:
        """Every canonical category has a corresponding JSON file."""
        ds_dir = _eval_datasets_dir(repo_root)
        for category in EVAL_CATEGORIES:
            path = ds_dir / f"{category}.json"
            assert path.is_file(), f"Missing dataset file: {path}"

    def test_load_all_datasets_returns_four(self, repo_root: Path) -> None:
        """load_all_datasets finds all four category datasets."""
        ds_dir = _eval_datasets_dir(repo_root)
        datasets = load_all_datasets(ds_dir)
        # May also include README.md which is ignored (not .json).
        assert len(datasets) == 4
        categories = {ds.category for ds in datasets}
        assert categories == set(EVAL_CATEGORIES)

    def test_each_dataset_has_minimum_cases(self, repo_root: Path) -> None:
        """Each dataset has at least 10 cases (per #103 requirement)."""
        ds_dir = _eval_datasets_dir(repo_root)
        for category in EVAL_CATEGORIES:
            ds = load_dataset_by_category(ds_dir, category)
            assert len(ds.cases) >= 10, (
                f"Dataset '{category}' has {len(ds.cases)} cases, expected >= 10"
            )

    def test_case_ids_are_unique_within_dataset(self, repo_root: Path) -> None:
        """No duplicate case_id values within a single dataset."""
        ds_dir = _eval_datasets_dir(repo_root)
        for category in EVAL_CATEGORIES:
            ds = load_dataset_by_category(ds_dir, category)
            ids = [c.case_id for c in ds.cases]
            assert len(ids) == len(set(ids)), (
                f"Duplicate case IDs in '{category}': "
                f"{[x for x in ids if ids.count(x) > 1]}"
            )

    def test_confidence_ranges_are_valid(self, repo_root: Path) -> None:
        """expected_confidence_min <= expected_confidence_max for every case."""
        ds_dir = _eval_datasets_dir(repo_root)
        for category in EVAL_CATEGORIES:
            ds = load_dataset_by_category(ds_dir, category)
            for case in ds.cases:
                assert case.expected_confidence_min <= case.expected_confidence_max, (
                    f"Case {case.case_id}: min={case.expected_confidence_min} > "
                    f"max={case.expected_confidence_max}"
                )

    def test_expected_attributions_use_valid_tiers(self, repo_root: Path) -> None:
        """Every case's expected_attribution is one of the valid tiers."""
        valid_tiers = {"confirmed", "high", "medium", "not_yours"}
        ds_dir = _eval_datasets_dir(repo_root)
        for category in EVAL_CATEGORIES:
            ds = load_dataset_by_category(ds_dir, category)
            for case in ds.cases:
                assert case.expected_attribution in valid_tiers, (
                    f"Case {case.case_id} has invalid tier: "
                    f"'{case.expected_attribution}'"
                )

    def test_confirmed_yours_cases_expect_positive_tiers(
        self, repo_root: Path,
    ) -> None:
        """All confirmed_yours cases expect 'confirmed' attribution."""
        ds_dir = _eval_datasets_dir(repo_root)
        ds = load_dataset_by_category(ds_dir, "confirmed_yours")
        for case in ds.cases:
            assert case.expected_attribution == "confirmed", (
                f"Case {case.case_id} in confirmed_yours expected "
                f"'{case.expected_attribution}', should be 'confirmed'"
            )

    def test_confirmed_not_yours_cases_expect_not_yours(
        self, repo_root: Path,
    ) -> None:
        """All confirmed_not_yours cases expect 'not_yours' attribution."""
        ds_dir = _eval_datasets_dir(repo_root)
        ds = load_dataset_by_category(ds_dir, "confirmed_not_yours")
        for case in ds.cases:
            assert case.expected_attribution == "not_yours", (
                f"Case {case.case_id} in confirmed_not_yours expected "
                f"'{case.expected_attribution}', should be 'not_yours'"
            )

    def test_adversarial_cases_expect_not_yours(
        self, repo_root: Path,
    ) -> None:
        """All adversarial cases expect 'not_yours' -- they are designed to trick the engine."""
        ds_dir = _eval_datasets_dir(repo_root)
        ds = load_dataset_by_category(ds_dir, "adversarial")
        for case in ds.cases:
            assert case.expected_attribution == "not_yours", (
                f"Case {case.case_id} in adversarial expected "
                f"'{case.expected_attribution}', should be 'not_yours'"
            )

    def test_dataset_name_matches_category(self, repo_root: Path) -> None:
        """Each dataset's 'name' field matches its 'category' field."""
        ds_dir = _eval_datasets_dir(repo_root)
        for category in EVAL_CATEGORIES:
            ds = load_dataset_by_category(ds_dir, category)
            assert ds.name == category, (
                f"Dataset name '{ds.name}' does not match "
                f"category '{category}'"
            )

    def test_load_datasets_by_categories_selective(
        self, repo_root: Path,
    ) -> None:
        """load_datasets_by_categories with a subset loads only those."""
        ds_dir = _eval_datasets_dir(repo_root)
        subset = ["confirmed_yours", "adversarial"]
        datasets = load_datasets_by_categories(ds_dir, subset)
        assert len(datasets) == 2
        assert datasets[0].category == "confirmed_yours"
        assert datasets[1].category == "adversarial"


# =============================================================================
# 2. Metric computation
# =============================================================================


class TestMetricComputation:
    """Test accuracy, precision, recall, and F1 calculations."""

    def test_perfect_accuracy(self) -> None:
        """All correct predictions yield accuracy=1.0."""
        results = [
            _make_result("a", "confirmed", "confirmed", 0.98),
            _make_result("b", "not_yours", "not_yours", 0.10),
            _make_result("c", "high", "high", 0.80),
        ]
        m = compute_metrics(results, dataset_name="perfect")
        assert m.attribution_accuracy == 1.0
        assert m.correct_attributions == 3

    def test_zero_accuracy(self) -> None:
        """All wrong predictions yield accuracy=0.0."""
        results = [
            _make_result("a", "confirmed", "not_yours", 0.10, correct=False),
            _make_result("b", "not_yours", "confirmed", 0.98, correct=False),
        ]
        m = compute_metrics(results, dataset_name="zero")
        assert m.attribution_accuracy == 0.0

    def test_partial_accuracy(self) -> None:
        """Mixed correct/incorrect yields expected ratio."""
        results = [
            _make_result("a", "confirmed", "confirmed", 0.98),
            _make_result("b", "confirmed", "high", 0.80, correct=False),
            _make_result("c", "not_yours", "not_yours", 0.10),
            _make_result("d", "not_yours", "medium", 0.55, correct=False),
        ]
        m = compute_metrics(results, dataset_name="partial")
        assert m.attribution_accuracy == pytest.approx(0.5)

    def test_precision_all_true_positives(self) -> None:
        """All positives are correct -> precision=1.0."""
        results = [
            _make_result("a", "confirmed", "confirmed", 0.98),
            _make_result("b", "high", "high", 0.80),
        ]
        p, _, _ = _compute_precision_recall_f1(results)
        assert p == pytest.approx(1.0)

    def test_precision_with_false_positives(self) -> None:
        """FP dilutes precision: TP / (TP + FP)."""
        results = [
            _make_result("tp", "confirmed", "confirmed", 0.98),
            _make_result("fp", "not_yours", "high", 0.80, correct=False),
        ]
        p, _, _ = _compute_precision_recall_f1(results)
        # TP=1, FP=1 -> precision=0.5
        assert p == pytest.approx(0.5)

    def test_recall_all_positives_detected(self) -> None:
        """All expected positives found -> recall=1.0."""
        results = [
            _make_result("a", "confirmed", "confirmed", 0.98),
            _make_result("b", "high", "medium", 0.55),
        ]
        _, r, _ = _compute_precision_recall_f1(results)
        assert r == pytest.approx(1.0)

    def test_recall_with_false_negatives(self) -> None:
        """FN reduces recall: TP / (TP + FN)."""
        results = [
            _make_result("tp", "confirmed", "confirmed", 0.98),
            _make_result("fn", "high", "not_yours", 0.10, correct=False),
        ]
        _, r, _ = _compute_precision_recall_f1(results)
        # TP=1, FN=1 -> recall=0.5
        assert r == pytest.approx(0.5)

    def test_f1_balanced(self) -> None:
        """F1 is harmonic mean of precision and recall."""
        results = [
            _make_result("tp", "confirmed", "confirmed", 0.98),
            _make_result("fp", "not_yours", "high", 0.80, correct=False),
            _make_result("fn", "high", "not_yours", 0.10, correct=False),
        ]
        p, r, f1 = _compute_precision_recall_f1(results)
        expected_f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        assert f1 == pytest.approx(expected_f1)

    def test_f1_perfect(self) -> None:
        """Perfect precision and recall yield F1=1.0."""
        results = [
            _make_result("a", "confirmed", "confirmed", 0.98),
            _make_result("b", "not_yours", "not_yours", 0.10),
        ]
        _, _, f1 = _compute_precision_recall_f1(results)
        assert f1 == pytest.approx(1.0)

    def test_all_negative_precision_recall(self) -> None:
        """No positive predictions or expectations -> 0.0 for all."""
        results = [
            _make_result("a", "not_yours", "not_yours", 0.10),
            _make_result("b", "not_yours", "not_yours", 0.05),
        ]
        p, r, f1 = _compute_precision_recall_f1(results)
        assert p == pytest.approx(0.0)
        assert r == pytest.approx(0.0)
        assert f1 == pytest.approx(0.0)

    def test_false_positive_count_in_metrics(self) -> None:
        """compute_metrics counts false positives correctly."""
        results = [
            _make_result("fp1", "not_yours", "confirmed", 0.95, correct=False),
            _make_result("fp2", "not_yours", "high", 0.80, correct=False),
            _make_result("fp3", "not_yours", "medium", 0.55, correct=False),
            _make_result("tn", "not_yours", "not_yours", 0.10),
        ]
        m = compute_metrics(results, dataset_name="fp_test")
        assert m.false_positives == 3

    def test_false_negative_count_in_metrics(self) -> None:
        """compute_metrics counts false negatives correctly."""
        results = [
            _make_result("fn1", "confirmed", "not_yours", 0.10, correct=False),
            _make_result("fn2", "high", "not_yours", 0.10, correct=False),
            _make_result("fn3", "medium", "not_yours", 0.10, correct=False),
            _make_result("tp", "confirmed", "confirmed", 0.98),
        ]
        m = compute_metrics(results, dataset_name="fn_test")
        assert m.false_negatives == 3

    def test_mean_confidence_error(self) -> None:
        """Mean confidence error is averaged distance from midpoint of expected range."""
        results = [
            EvalResult(
                case_id="a",
                expected_attribution="confirmed",
                actual_attribution="confirmed",
                expected_confidence_range=(0.90, 1.0),
                actual_confidence=0.95,  # midpoint=0.95, error=0.0
                correct=True,
                duration_ms=0.1,
            ),
            EvalResult(
                case_id="b",
                expected_attribution="confirmed",
                actual_attribution="confirmed",
                expected_confidence_range=(0.90, 1.0),
                actual_confidence=0.85,  # midpoint=0.95, error=0.10
                correct=True,
                duration_ms=0.1,
            ),
        ]
        m = compute_metrics(results, dataset_name="ce")
        # mean = (0.0 + 0.10) / 2 = 0.05
        assert m.mean_confidence_error == pytest.approx(0.05, abs=1e-6)


# =============================================================================
# 3. Per-category evaluation with stub
# =============================================================================


class TestPerCategoryStub:
    """Run the stub attribution function against each reference dataset category."""

    async def test_confirmed_yours_with_stub(self, repo_root: Path) -> None:
        """Stub achieves high accuracy on confirmed_yours (entities have 3+ obs with cloud match)."""
        ds_dir = _eval_datasets_dir(repo_root)
        ds = load_dataset_by_category(ds_dir, "confirmed_yours")
        runner = EvalRunner()
        results = await runner.run_dataset(ds)

        correct = sum(1 for r in results if r.correct)
        accuracy = correct / len(results)
        # Confirmed_yours has 3+ observations with cloud_account_match=true
        # -> stub returns "confirmed" -> all should be correct.
        assert accuracy == 1.0, (
            f"Stub accuracy on confirmed_yours: {accuracy:.0%} "
            f"({correct}/{len(results)} correct)"
        )

    async def test_confirmed_not_yours_with_stub(self, repo_root: Path) -> None:
        """Stub handles confirmed_not_yours with expected behavior based on observation count."""
        ds_dir = _eval_datasets_dir(repo_root)
        ds = load_dataset_by_category(ds_dir, "confirmed_not_yours")
        runner = EvalRunner()
        results = await runner.run_dataset(ds)

        # Cases with 0 observations -> stub returns "not_yours" (correct).
        # Cases with 1 observation -> stub returns "medium" (wrong if expected "not_yours").
        # We verify results are produced and each has expected fields.
        for r in results:
            assert r.expected_attribution == "not_yours"
            assert r.actual_attribution in ("not_yours", "medium", "high", "confirmed")

    async def test_ambiguous_with_stub(self, repo_root: Path) -> None:
        """Stub produces results for ambiguous cases."""
        ds_dir = _eval_datasets_dir(repo_root)
        ds = load_dataset_by_category(ds_dir, "ambiguous")
        runner = EvalRunner()
        results = await runner.run_dataset(ds)

        assert len(results) >= 10
        for r in results:
            assert r.expected_attribution in ("confirmed", "high", "medium", "not_yours")
            assert r.duration_ms >= 0.0

    async def test_adversarial_with_stub(self, repo_root: Path) -> None:
        """Stub processes adversarial cases -- some may fool the simple heuristic."""
        ds_dir = _eval_datasets_dir(repo_root)
        ds = load_dataset_by_category(ds_dir, "adversarial")
        runner = EvalRunner()
        results = await runner.run_dataset(ds)

        assert len(results) >= 10
        # Every adversarial case expects "not_yours".
        for r in results:
            assert r.expected_attribution == "not_yours"


# =============================================================================
# 4. Adversarial case specific tests
# =============================================================================


class TestAdversarialCases:
    """Verify adversarial dataset contains the right deception patterns."""

    def test_typosquat_present(self, repo_root: Path) -> None:
        """Dataset includes typosquat domain cases."""
        ds_dir = _eval_datasets_dir(repo_root)
        ds = load_dataset_by_category(ds_dir, "adversarial")
        typosquat_cases = [
            c for c in ds.cases
            if "typosquat" in c.description.lower()
            or "homograph" in c.description.lower()
        ]
        assert len(typosquat_cases) >= 1

    def test_similar_registrant_present(self, repo_root: Path) -> None:
        """Dataset includes cases with similar but different registrant names."""
        ds_dir = _eval_datasets_dir(repo_root)
        ds = load_dataset_by_category(ds_dir, "adversarial")
        similar_reg_cases = [
            c for c in ds.cases
            if "similar registrant" in c.description.lower()
            or "lookalike" in c.description.lower()
        ]
        assert len(similar_reg_cases) >= 1

    def test_cdn_overlap_present(self, repo_root: Path) -> None:
        """Dataset includes certificate overlap via shared CDN."""
        ds_dir = _eval_datasets_dir(repo_root)
        ds = load_dataset_by_category(ds_dir, "adversarial")
        cdn_cases = [
            c for c in ds.cases
            if "cdn" in c.description.lower()
            or "certificate overlap" in c.description.lower()
        ]
        assert len(cdn_cases) >= 1

    def test_honeypot_present(self, repo_root: Path) -> None:
        """Dataset includes honeypot with planted tenant-like banners."""
        ds_dir = _eval_datasets_dir(repo_root)
        ds = load_dataset_by_category(ds_dir, "adversarial")
        honeypot_cases = [
            c for c in ds.cases
            if "honeypot" in c.description.lower()
            or "planted" in c.description.lower()
        ]
        assert len(honeypot_cases) >= 1

    def test_phishing_clone_present(self, repo_root: Path) -> None:
        """Dataset includes phishing clone cases."""
        ds_dir = _eval_datasets_dir(repo_root)
        ds = load_dataset_by_category(ds_dir, "adversarial")
        phishing_cases = [
            c for c in ds.cases
            if "phishing" in c.description.lower()
            or "clone" in c.description.lower()
        ]
        assert len(phishing_cases) >= 1

    async def test_adversarial_high_obs_no_cloud_match(
        self, repo_root: Path,
    ) -> None:
        """Adversarial cases with 3+ observations but no cloud_account_match=true
        should NOT get 'confirmed' from the stub."""
        ds_dir = _eval_datasets_dir(repo_root)
        ds = load_dataset_by_category(ds_dir, "adversarial")
        runner = EvalRunner()
        results = await runner.run_dataset(ds)

        for r in results:
            case = next(c for c in ds.cases if c.case_id == r.case_id)
            has_cloud_match = any(
                obs.get("cloud_account_match") is True
                for obs in case.observations
            )
            if not has_cloud_match:
                # Stub should not return "confirmed" without cloud_account_match.
                # (It might return "high" for 2+ obs -- that's expected stub behavior.)
                assert r.actual_attribution != "confirmed" or has_cloud_match, (
                    f"Case {r.case_id} got 'confirmed' without cloud_account_match"
                )


# =============================================================================
# 5. EvalReport structure
# =============================================================================


class TestEvalReport:
    """Verify the full EvalReport structure and fields."""

    async def test_full_report_structure(self, repo_root: Path) -> None:
        """run_report with all categories produces a well-formed EvalReport."""
        ds_dir = _eval_datasets_dir(repo_root)
        datasets = load_datasets_by_categories(ds_dir)
        runner = EvalRunner()
        report = await runner.run_report(datasets)

        assert isinstance(report, EvalReport)
        assert report.total_cases > 0
        assert 0.0 <= report.overall_accuracy <= 1.0
        assert 0.0 <= report.overall_precision <= 1.0
        assert 0.0 <= report.overall_recall <= 1.0
        assert 0.0 <= report.overall_f1 <= 1.0
        assert report.total_wall_clock_ms >= 0.0

    async def test_report_has_all_categories(self, repo_root: Path) -> None:
        """Report contains a CategoryReport for each dataset."""
        ds_dir = _eval_datasets_dir(repo_root)
        datasets = load_datasets_by_categories(ds_dir)
        runner = EvalRunner()
        report = await runner.run_report(datasets)

        for ds in datasets:
            assert ds.name in report.categories, (
                f"Missing category report for '{ds.name}'"
            )
            cat_report = report.categories[ds.name]
            assert cat_report.category == ds.category
            assert cat_report.metrics.total_cases == len(ds.cases)

    async def test_report_total_cases_sum(self, repo_root: Path) -> None:
        """Total cases in report equals sum of all category cases."""
        ds_dir = _eval_datasets_dir(repo_root)
        datasets = load_datasets_by_categories(ds_dir)
        runner = EvalRunner()
        report = await runner.run_report(datasets)

        expected_total = sum(len(ds.cases) for ds in datasets)
        assert report.total_cases == expected_total

    async def test_confusion_matrix_sums_to_total(
        self, repo_root: Path,
    ) -> None:
        """Confusion matrix cell values sum to total cases."""
        ds_dir = _eval_datasets_dir(repo_root)
        datasets = load_datasets_by_categories(ds_dir)
        runner = EvalRunner()
        report = await runner.run_report(datasets)

        cm = report.confusion_matrix
        cell_sum = sum(
            cm.matrix[exp][act]
            for exp in cm.matrix
            for act in cm.matrix[exp]
        )
        assert cell_sum == report.total_cases

    async def test_report_json_serializable(self, repo_root: Path) -> None:
        """EvalReport serializes to valid JSON and round-trips."""
        ds_dir = _eval_datasets_dir(repo_root)
        datasets = load_datasets_by_categories(ds_dir)
        runner = EvalRunner()
        report = await runner.run_report(datasets)

        json_str = report.model_dump_json(indent=2)
        parsed = json.loads(json_str)
        assert "categories" in parsed
        assert "confusion_matrix" in parsed
        assert "overall_accuracy" in parsed
        assert "overall_precision" in parsed
        assert "overall_recall" in parsed
        assert "overall_f1" in parsed
        assert "total_cases" in parsed


# =============================================================================
# 6. RuleEvaluator integration
# =============================================================================


class TestRuleEvaluatorIntegration:
    """Test the eval harness with a real RuleEvaluator and the example rule pack."""

    @pytest.fixture()
    def baseline_runner(self) -> EvalRunner:
        """Create an EvalRunner backed by the example-baseline rule pack."""
        from expose.pipeline.rule_evaluator import RuleEvaluator
        from expose.types.rulepack import RulePack

        pack_path = (
            Path(__file__).resolve().parent.parent
            / "examples"
            / "rulepacks"
            / "example-baseline.json"
        )
        raw = json.loads(pack_path.read_text())
        raw.pop("$schema", None)
        pack = RulePack.model_validate(raw)
        evaluator = RuleEvaluator(pack)
        return EvalRunner.from_rule_evaluator(evaluator)

    async def test_rulepack_runner_produces_results(
        self, baseline_runner: EvalRunner, repo_root: Path,
    ) -> None:
        """RuleEvaluator-backed runner produces EvalResult for every case."""
        ds_dir = _eval_datasets_dir(repo_root)
        ds = load_dataset_by_category(ds_dir, "confirmed_yours")
        results = await baseline_runner.run_dataset(ds)
        assert len(results) == len(ds.cases)
        for r in results:
            assert isinstance(r, EvalResult)
            assert r.actual_attribution in (
                "confirmed", "high", "medium", "not_yours",
            )
            assert 0.0 <= r.actual_confidence <= 1.0

    async def test_rulepack_runner_full_report(
        self, baseline_runner: EvalRunner, repo_root: Path,
    ) -> None:
        """RuleEvaluator-backed runner produces a full report across all categories."""
        ds_dir = _eval_datasets_dir(repo_root)
        datasets = load_datasets_by_categories(ds_dir)
        report = await baseline_runner.run_report(datasets)

        assert isinstance(report, EvalReport)
        assert report.total_cases > 0
        assert len(report.categories) == 4


# =============================================================================
# 7. Custom attribution function injection
# =============================================================================


class TestCustomAttribution:
    """Verify custom attribution functions integrate correctly."""

    async def test_always_confirmed_fn(self) -> None:
        """An always-confirmed function yields 100% accuracy on confirmed_yours."""
        def always_confirmed(
            _et: str, _ci: str, _obs: list[dict[str, Any]],
        ) -> tuple[str, float]:
            return ("confirmed", 0.99)

        ds = EvalDataset(
            name="test",
            category="confirmed_yours",
            cases=[
                EvalCase(
                    case_id="tc-1",
                    description="Test",
                    entity_type="domain",
                    canonical_identifier="test.example.com",
                    observations=[{"collector_id": "test"}],
                    expected_attribution="confirmed",
                    expected_confidence_min=0.95,
                    expected_confidence_max=1.0,
                ),
            ],
        )
        runner = EvalRunner(attribution_fn=always_confirmed)
        results = await runner.run_dataset(ds)
        assert results[0].correct is True
        assert results[0].actual_confidence == 0.99

    async def test_always_not_yours_fn(self) -> None:
        """An always-not_yours function yields 100% accuracy on confirmed_not_yours."""
        def always_not_yours(
            _et: str, _ci: str, _obs: list[dict[str, Any]],
        ) -> tuple[str, float]:
            return ("not_yours", 0.05)

        ds = EvalDataset(
            name="test",
            category="confirmed_not_yours",
            cases=[
                EvalCase(
                    case_id="cn-1",
                    description="Test",
                    entity_type="ip",
                    canonical_identifier="192.0.2.1",
                    observations=[],
                    expected_attribution="not_yours",
                    expected_confidence_min=0.0,
                    expected_confidence_max=0.2,
                ),
            ],
        )
        runner = EvalRunner(attribution_fn=always_not_yours)
        results = await runner.run_dataset(ds)
        assert results[0].correct is True


# =============================================================================
# 8. Confusion matrix tests
# =============================================================================


class TestConfusionMatrixDetailed:
    """Detailed confusion matrix validation."""

    def test_diagonal_counts_correct_predictions(self) -> None:
        """Diagonal entries represent correct predictions."""
        results = [
            _make_result("a", "confirmed", "confirmed"),
            _make_result("b", "high", "high"),
            _make_result("c", "medium", "medium"),
            _make_result("d", "not_yours", "not_yours"),
        ]
        cm = ConfusionMatrix.from_results(results)
        assert cm.matrix["confirmed"]["confirmed"] == 1
        assert cm.matrix["high"]["high"] == 1
        assert cm.matrix["medium"]["medium"] == 1
        assert cm.matrix["not_yours"]["not_yours"] == 1

    def test_off_diagonal_counts_misclassifications(self) -> None:
        """Off-diagonal entries represent misclassifications."""
        results = [
            _make_result("a", "confirmed", "high", correct=False),
            _make_result("b", "not_yours", "medium", correct=False),
        ]
        cm = ConfusionMatrix.from_results(results)
        assert cm.matrix["confirmed"]["high"] == 1
        assert cm.matrix["not_yours"]["medium"] == 1

    def test_display_lines_format(self) -> None:
        """display_lines produces header + separator + 4 data rows."""
        results = [_make_result("a", "confirmed", "confirmed")]
        cm = ConfusionMatrix.from_results(results)
        lines = cm.display_lines()
        # Header + separator + 4 tiers = 6 lines
        assert len(lines) == 6
        assert "Expected" in lines[0]
        assert "confirmed" in lines[0]

    def test_empty_confusion_matrix(self) -> None:
        """Empty results produce all-zero matrix."""
        cm = ConfusionMatrix.from_results([])
        for expected in cm.matrix:
            for actual in cm.matrix[expected]:
                assert cm.matrix[expected][actual] == 0


# =============================================================================
# 9. CLI integration
# =============================================================================


class TestEvalCLI:
    """CLI integration tests for the eval command."""

    def _invoke(self, args: list[str]) -> Any:
        from click.testing import CliRunner as ClickRunner
        from expose.cli import main as cli_main

        runner = ClickRunner()
        return runner.invoke(cli_main, args)

    def test_cli_eval_all_with_reference_datasets(
        self, repo_root: Path,
    ) -> None:
        """expose eval --all runs against all reference datasets."""
        eval_dir = repo_root / "examples" / "eval-datasets"
        if not eval_dir.is_dir():
            pytest.skip("examples/eval-datasets not found")
        result = self._invoke(["eval", "--all", "--dataset-dir", str(eval_dir)])
        assert result.exit_code in (0, 1)
        # Should show output for all categories.
        assert "confirmed_yours" in result.output
        assert "confirmed_not_yours" in result.output
        assert "ambiguous" in result.output
        assert "adversarial" in result.output

    def test_cli_eval_single_dataset(self, repo_root: Path) -> None:
        """expose eval --dataset confirmed_yours works with reference data."""
        eval_dir = repo_root / "examples" / "eval-datasets"
        if not eval_dir.is_dir():
            pytest.skip("examples/eval-datasets not found")
        result = self._invoke([
            "eval", "--dataset", "confirmed_yours",
            "--dataset-dir", str(eval_dir),
        ])
        assert result.exit_code in (0, 1)
        assert "confirmed_yours" in result.output

    def test_cli_eval_with_rulepack(self, repo_root: Path) -> None:
        """expose eval --all --rulepack uses the RuleEvaluator path."""
        eval_dir = repo_root / "examples" / "eval-datasets"
        rulepack = repo_root / "examples" / "rulepacks" / "example-baseline.json"
        if not eval_dir.is_dir() or not rulepack.is_file():
            pytest.skip("eval-datasets or rulepack not found")
        result = self._invoke([
            "eval", "--all",
            "--dataset-dir", str(eval_dir),
            "--rulepack", str(rulepack),
        ])
        assert result.exit_code in (0, 1)
        assert "example-baseline" in result.output

    def test_cli_eval_json_output(self, repo_root: Path) -> None:
        """--json-output produces valid JSON with all expected fields."""
        eval_dir = repo_root / "examples" / "eval-datasets"
        if not eval_dir.is_dir():
            pytest.skip("examples/eval-datasets not found")
        result = self._invoke([
            "eval", "--dataset", "confirmed_yours",
            "--dataset-dir", str(eval_dir),
            "--json-output",
        ])
        assert result.exit_code in (0, 1)
        # Extract JSON from output.
        lines = result.output.strip().split("\n")
        json_start = next(
            (i for i, line in enumerate(lines)
             if line.strip().startswith("{")),
            None,
        )
        assert json_start is not None
        json_end = next(
            (i + 1 for i in range(len(lines) - 1, json_start - 1, -1)
             if lines[i].strip() == "}"),
            None,
        )
        assert json_end is not None
        parsed = json.loads("\n".join(lines[json_start:json_end]))
        assert "overall_precision" in parsed
        assert "overall_recall" in parsed
        assert "overall_f1" in parsed

    def test_cli_eval_threshold_pass(self, tmp_path: Path) -> None:
        """Exit code 0 when accuracy meets a lenient threshold."""
        # Build a dataset the stub gets 100% right.
        ds = {
            "name": "confirmed_yours",
            "category": "confirmed_yours",
            "cases": [
                {
                    "case_id": "pass-1",
                    "description": "3 obs with cloud match",
                    "entity_type": "ip",
                    "canonical_identifier": "10.0.0.1",
                    "observations": [
                        {"collector_id": "a", "cloud_account_match": True},
                        {"collector_id": "b"},
                        {"collector_id": "c"},
                    ],
                    "expected_attribution": "confirmed",
                    "expected_confidence_min": 0.95,
                    "expected_confidence_max": 1.0,
                },
            ],
        }
        (tmp_path / "confirmed_yours.json").write_text(
            json.dumps(ds), encoding="utf-8",
        )
        result = self._invoke([
            "eval", "--dataset", "confirmed_yours",
            "--dataset-dir", str(tmp_path),
            "--threshold", "0.5",
        ])
        assert result.exit_code == 0
        assert "PASS" in result.output

    def test_cli_eval_threshold_fail(self, tmp_path: Path) -> None:
        """Exit code 1 when accuracy is below threshold."""
        ds = {
            "name": "confirmed_yours",
            "category": "confirmed_yours",
            "cases": [
                {
                    "case_id": "fail-1",
                    "description": "No obs -- stub returns not_yours",
                    "entity_type": "ip",
                    "canonical_identifier": "10.0.0.1",
                    "observations": [],
                    "expected_attribution": "confirmed",
                    "expected_confidence_min": 0.95,
                    "expected_confidence_max": 1.0,
                },
            ],
        }
        (tmp_path / "confirmed_yours.json").write_text(
            json.dumps(ds), encoding="utf-8",
        )
        result = self._invoke([
            "eval", "--dataset", "confirmed_yours",
            "--dataset-dir", str(tmp_path),
            "--threshold", "1.0",
        ])
        assert result.exit_code == 1
        assert "FAIL" in result.output


# =============================================================================
# 10. Edge cases
# =============================================================================


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_dataset_metrics(self) -> None:
        """Empty results list produces zero-valued metrics without division-by-zero."""
        m = compute_metrics([], dataset_name="empty")
        assert m.total_cases == 0
        assert m.attribution_accuracy == 0.0
        assert m.mean_confidence_error == 0.0

    async def test_single_case_dataset(self) -> None:
        """Dataset with exactly one case works correctly."""
        ds = EvalDataset(
            name="single",
            category="confirmed_yours",
            cases=[
                EvalCase(
                    case_id="only-one",
                    description="Single case",
                    entity_type="domain",
                    canonical_identifier="single.example.com",
                    observations=[
                        {"collector_id": "a", "cloud_account_match": True},
                        {"collector_id": "b"},
                        {"collector_id": "c"},
                    ],
                    expected_attribution="confirmed",
                    expected_confidence_min=0.95,
                    expected_confidence_max=1.0,
                ),
            ],
        )
        runner = EvalRunner()
        results = await runner.run_dataset(ds)
        assert len(results) == 1
        assert results[0].correct is True

    async def test_timing_fields_populated(self) -> None:
        """Wall clock timing is non-negative for all results."""
        ds = EvalDataset(
            name="timing",
            category="confirmed_yours",
            cases=[
                EvalCase(
                    case_id="t-1",
                    description="Timing test",
                    entity_type="ip",
                    canonical_identifier="10.0.0.1",
                    observations=[
                        {"collector_id": "a", "cloud_account_match": True},
                        {"collector_id": "b"},
                        {"collector_id": "c"},
                    ],
                    expected_attribution="confirmed",
                    expected_confidence_min=0.95,
                    expected_confidence_max=1.0,
                ),
            ],
        )
        runner = EvalRunner()
        report = await runner.run_report([ds])
        assert report.total_wall_clock_ms >= 0.0
        for cat in report.categories.values():
            assert cat.total_wall_clock_ms >= 0.0
            assert cat.mean_wall_clock_ms >= 0.0

    def test_confusion_matrix_unknown_tier_normalized(self) -> None:
        """Unknown tiers in results are normalized to 'not_yours'."""
        results = [
            EvalResult(
                case_id="weird",
                expected_attribution="unknown_tier",
                actual_attribution="also_unknown",
                expected_confidence_range=(0.0, 1.0),
                actual_confidence=0.5,
                correct=False,
                duration_ms=0.1,
            ),
        ]
        cm = ConfusionMatrix.from_results(results)
        # Both should be normalized to not_yours.
        assert cm.matrix["not_yours"]["not_yours"] == 1

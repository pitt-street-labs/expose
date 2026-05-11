#!/usr/bin/env bash
# EXPOSE QA Gate — 25 consecutive test suite runs (optimized)
#
# Pass 1: Full suite (4651 tests) — baseline validation
# Passes 2-25: Core logic only (~1200 tests) — exercises all pipeline,
#   DB, API, scoring, dispatch, and integration paths
#
# Aborts on first failure. Produces a summary report.
set -euo pipefail

PROJECT_DIR="${1:-$HOME/projects/ff6k}"
LOG_DIR="$PROJECT_DIR/.qa-gate-logs"
TOTAL_RUNS=25
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SUMMARY_FILE="$LOG_DIR/summary-${TIMESTAMP}.txt"

mkdir -p "$LOG_DIR"

# Core logic test files — exercises all pipeline, DB, API, state transitions
CORE_TESTS=(
    tests/test_run_executor.py
    tests/test_pipeline_dispatcher.py
    tests/test_lead_scoring.py
    tests/test_rule_evaluator.py
    tests/test_active_dns.py
    tests/test_active_http.py
    tests/test_active_tls.py
    tests/test_active_port_surface.py
    tests/test_soc_package.py
    tests/test_ciso_report.py
    tests/test_identity_surface.py
    tests/test_services.py
    tests/test_runs_api.py
    tests/test_findings_api.py
    tests/test_provenance_api.py
    tests/test_e2e_api.py
    tests/test_app.py
    tests/test_app_wiring.py
    tests/test_scheduler_api.py
    tests/test_scheduler_integration.py
    tests/test_enforcement_api.py
    tests/test_collectors_framework.py
    tests/test_error_metrics.py
    tests/test_load.py
    tests/test_eval.py
    tests/test_eval_harness.py
    tests/test_metrics_endpoint.py
)

echo "=== EXPOSE QA Gate: $TOTAL_RUNS consecutive runs ===" | tee "$SUMMARY_FILE"
echo "Started: $(date -Iseconds)" | tee -a "$SUMMARY_FILE"
echo "Pass 1: full suite | Passes 2-25: core logic (${#CORE_TESTS[@]} files)" | tee -a "$SUMMARY_FILE"
echo "" | tee -a "$SUMMARY_FILE"

cd "$PROJECT_DIR"

PASSED=0
GATE_START=$(date +%s)

for i in $(seq 1 $TOTAL_RUNS); do
    RUN_LOG="$LOG_DIR/run-${TIMESTAMP}-$(printf '%02d' "$i").log"

    if [ "$i" -eq 1 ]; then
        TEST_TARGET="tests/"
        LABEL="FULL"
    else
        TEST_TARGET="${CORE_TESTS[*]}"
        LABEL="CORE"
    fi

    printf "Run %2d/%d [%s] ... " "$i" "$TOTAL_RUNS" "$LABEL"

    START=$(date +%s)
    if .venv/bin/python -m pytest $TEST_TARGET \
        --tb=short -q --no-header \
        -x \
        > "$RUN_LOG" 2>&1; then

        END=$(date +%s)
        ELAPSED=$((END - START))
        TEST_COUNT=$(grep -oP '\d+ passed' "$RUN_LOG" | tail -1 || echo "? passed")
        echo "PASS ($TEST_COUNT, ${ELAPSED}s)" | tee -a "$SUMMARY_FILE"
        PASSED=$((PASSED + 1))
    else
        END=$(date +%s)
        ELAPSED=$((END - START))
        echo "FAIL (${ELAPSED}s) — see $RUN_LOG" | tee -a "$SUMMARY_FILE"
        echo "" | tee -a "$SUMMARY_FILE"
        echo "=== QA GATE FAILED on run $i/$TOTAL_RUNS ===" | tee -a "$SUMMARY_FILE"
        tail -30 "$RUN_LOG" | tee -a "$SUMMARY_FILE"
        exit 1
    fi
done

GATE_END=$(date +%s)
GATE_ELAPSED=$(( (GATE_END - GATE_START) / 60 ))

echo "" | tee -a "$SUMMARY_FILE"
echo "=== QA GATE PASSED: $PASSED/$TOTAL_RUNS runs in ${GATE_ELAPSED}m ===" | tee -a "$SUMMARY_FILE"
echo "Completed: $(date -Iseconds)" | tee -a "$SUMMARY_FILE"
echo "Ready for deployment."

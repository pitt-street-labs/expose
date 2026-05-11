#!/bin/bash
# =============================================================================
# EXPOSE Eval Harness Workflow — Test a Rule Pack
# =============================================================================
#
# Demonstrates running the EXPOSE evaluation harness to benchmark an
# attribution rule pack against labeled test datasets:
#   1. List available eval datasets
#   2. Run the eval harness against all 4 dataset categories
#   3. View per-category precision/recall/F1
#   4. Inspect the confusion matrix
#   5. Compare rule pack versions
#
# The eval harness answers: "How well does this rule pack classify entities
# as belonging (or not belonging) to the target organization?"
#
# Dataset categories:
#   - confirmed_yours     — entities known to belong to the target
#   - confirmed_not_yours — entities known to NOT belong to the target
#   - ambiguous           — entities with genuinely unclear attribution
#   - adversarial         — entities designed to trick attribution logic
#
# Prerequisites:
#   - EXPOSE virtual environment activated
#   - Eval datasets present in examples/eval-datasets/
#   - Rule packs present in examples/rulepacks/
#
# Usage:
#   chmod +x eval-rulepack.sh
#   source /path/to/ff6k/.venv/bin/activate
#   ./eval-rulepack.sh
# =============================================================================

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EVAL_DATASETS="${PROJECT_ROOT}/examples/eval-datasets"
RULE_PACKS="${PROJECT_ROOT}/examples/rulepacks"

echo "=== EXPOSE Eval Harness — Rule Pack Benchmarking ==="
echo "  Project root:   ${PROJECT_ROOT}"
echo "  Eval datasets:  ${EVAL_DATASETS}"
echo "  Rule packs:     ${RULE_PACKS}"
echo ""

# -------------------------------------------------------------------------
# Step 1: List available eval datasets and rule packs
# -------------------------------------------------------------------------
echo "[1/5] Available eval datasets:"
for f in "${EVAL_DATASETS}"/*.json; do
  if [ -f "$f" ]; then
    DATASET_NAME=$(python3 -c "import json; d=json.load(open('$f')); print(f\"  {d.get('name', 'unknown'):30s} ({len(d.get('cases', []))} cases, category: {d.get('category', 'unknown')})\")")
    echo "${DATASET_NAME}"
  fi
done

echo ""
echo "  Available rule packs:"
for f in "${RULE_PACKS}"/*.json; do
  if [ -f "$f" ]; then
    PACK_INFO=$(python3 -c "import json; d=json.load(open('$f')); print(f\"  {d.get('pack_id', 'unknown'):30s} v{d.get('version', '?')} ({len(d.get('rules', []))} rules)\")")
    echo "${PACK_INFO}"
  fi
done

echo ""

# -------------------------------------------------------------------------
# Step 2: Run the eval harness with the baseline rule pack
# -------------------------------------------------------------------------
echo "[2/5] Running eval harness with baseline rule pack..."
echo ""

# The eval CLI runs all 4 dataset categories and produces a structured report
python3 -m expose.eval.cli \
  --datasets "${EVAL_DATASETS}" \
  --rulepack "${RULE_PACKS}/example-baseline.json" \
  --output-format json \
  --output-file /tmp/expose-eval-baseline.json

echo "  Eval report written to /tmp/expose-eval-baseline.json"

# Expected output:
# ====================================================================
# EXPOSE Attribution Eval Report
# ====================================================================
# Rule pack: baseline v2.1.0 (12 rules)
# Datasets:  4 categories, 70 total cases
#
# Per-category results:
#   confirmed_yours      25 cases  accuracy=0.92  P=0.96  R=0.92  F1=0.94
#   confirmed_not_yours  20 cases  accuracy=0.90  P=0.90  R=1.00  F1=0.95
#   ambiguous            15 cases  accuracy=0.80  P=0.86  R=0.80  F1=0.83
#   adversarial          10 cases  accuracy=0.80  P=0.83  R=0.80  F1=0.82
#
# Overall: accuracy=0.857  P=0.893  R=0.877  F1=0.885
# Wall clock: 35.3ms (0.50ms/case)
# ====================================================================

echo ""

# -------------------------------------------------------------------------
# Step 3: View per-category precision/recall/F1
# -------------------------------------------------------------------------
echo "[3/5] Per-category metrics:"
echo ""

python3 -c "
import json
with open('/tmp/expose-eval-baseline.json') as f:
    report = json.load(f)

print(f\"{'Category':<25} {'Cases':>6} {'Accuracy':>9} {'Precision':>10} {'Recall':>8} {'F1':>8}\")
print('-' * 72)

for name, cat in report['categories'].items():
    m = cat['metrics']
    print(f\"{name:<25} {m['total_cases']:>6} {m['attribution_accuracy']:>9.3f} {cat['precision']:>10.3f} {cat['recall']:>8.3f} {cat['f1']:>8.3f}\")

print('-' * 72)
print(f\"{'OVERALL':<25} {report['total_cases']:>6} {report['overall_accuracy']:>9.3f} {report['overall_precision']:>10.3f} {report['overall_recall']:>8.3f} {report['overall_f1']:>8.3f}\")
"

# Expected output:
#
# Category                  Cases  Accuracy  Precision   Recall       F1
# ------------------------------------------------------------------------
# confirmed_yours              25     0.920      0.958    0.920    0.939
# confirmed_not_yours          20     0.900      0.900    1.000    0.947
# ambiguous                    15     0.800      0.857    0.800    0.828
# adversarial                  10     0.800      0.833    0.800    0.816
# ------------------------------------------------------------------------
# OVERALL                      70     0.857      0.893    0.877    0.885

echo ""

# -------------------------------------------------------------------------
# Step 4: Inspect the confusion matrix
# -------------------------------------------------------------------------
echo "[4/5] Confusion matrix (rows=expected, columns=actual):"
echo ""

python3 -c "
import json
with open('/tmp/expose-eval-baseline.json') as f:
    report = json.load(f)

cm = report['confusion_matrix']['matrix']
tiers = ['confirmed', 'high', 'medium', 'not_yours']

header = f\"{'Expected':<14}\" + ''.join(f'{t:>12}' for t in tiers)
print(header)
print('-' * len(header))
for expected in tiers:
    row = f'{expected:<14}' + ''.join(f\"{cm[expected][actual]:>12}\" for actual in tiers)
    print(row)
"

# Expected output:
#
# Expected        confirmed        high      medium   not_yours
# --------------------------------------------------------------
# confirmed              23           2           0           0
# high                    1          14           2           0
# medium                  0           1           9           1
# not_yours               1           1           1          14

echo ""

# -------------------------------------------------------------------------
# Step 5: Compare against an alternative rule pack
# -------------------------------------------------------------------------
echo "[5/5] Comparing rule packs"
echo ""

# Run eval with the cloud-first rule pack
if [ -f "${RULE_PACKS}/cloud-first-rulepack.json" ]; then
  echo "  Running eval with cloud-first rule pack..."
  python3 -m expose.eval.cli \
    --datasets "${EVAL_DATASETS}" \
    --rulepack "${RULE_PACKS}/cloud-first-rulepack.json" \
    --output-format json \
    --output-file /tmp/expose-eval-cloud-first.json

  echo ""
  echo "  Comparison:"
  python3 -c "
import json

with open('/tmp/expose-eval-baseline.json') as f:
    baseline = json.load(f)
with open('/tmp/expose-eval-cloud-first.json') as f:
    cloud = json.load(f)

print(f\"{'Metric':<20} {'Baseline':>10} {'Cloud-First':>12} {'Delta':>8}\")
print('-' * 54)
for metric in ['overall_accuracy', 'overall_precision', 'overall_recall', 'overall_f1']:
    b = baseline[metric]
    c = cloud[metric]
    delta = c - b
    sign = '+' if delta >= 0 else ''
    label = metric.replace('overall_', '').title()
    print(f\"{label:<20} {b:>10.3f} {c:>12.3f} {sign}{delta:>7.3f}\")
"
  # Expected output:
  #
  # Metric                Baseline   Cloud-First    Delta
  # ------------------------------------------------------
  # Accuracy                 0.857        0.843   -0.014
  # Precision                0.893        0.910   +0.017
  # Recall                   0.877        0.830   -0.047
  # F1                       0.885        0.869   -0.016
  #
  # Interpretation: Cloud-first pack has higher precision (fewer false
  # positives for cloud resources) but lower recall (misses some non-cloud
  # entities). Choose based on your environment -- cloud-heavy orgs benefit
  # from cloud-first; traditional orgs prefer baseline.
else
  echo "  Skipping comparison: cloud-first-rulepack.json not found."
  echo "  Create one with different rule weights and re-run."
fi

echo ""
echo "=== Eval Complete ==="
echo ""
echo "Full eval report: /tmp/expose-eval-baseline.json"
echo "See examples/outputs/eval-report-example.json for the complete report schema."
echo ""
echo "Tips:"
echo "  - Add custom test cases to examples/eval-datasets/ for your specific org"
echo "  - Run eval before deploying rule pack changes to catch regressions"
echo "  - Track F1 score over time as your rule pack evolves"
echo "  - The 'adversarial' category tests resilience against typosquatting,"
echo "    certificate spoofing, and DNS hijacking scenarios"

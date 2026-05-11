#!/usr/bin/env bash
# EXPOSE Core Helm Chart — template validation test
#
# Runs helm template with default and production-like values, then checks
# the rendered output for common errors (missing labels, empty selectors,
# broken YAML, missing required fields).
#
# Usage: ./deploy/helm-chart/test-template.sh
# Exit code 0 = all checks pass; non-zero = failure.

set -euo pipefail

CHART_DIR="$(cd "$(dirname "$0")" && pwd)"
PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS + 1)); TOTAL=$((TOTAL + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1)); echo "  FAIL: $1"; }

# --------------------------------------------------------------------------
# Pre-flight: helm must be installed
# --------------------------------------------------------------------------
if ! command -v helm &>/dev/null; then
  echo "ERROR: helm not found in PATH" >&2
  exit 1
fi

echo "=== EXPOSE Helm Chart Template Tests ==="
echo ""

# --------------------------------------------------------------------------
# Test 1: helm lint passes
# --------------------------------------------------------------------------
echo "[Test 1] helm lint"
if helm lint "$CHART_DIR" >/dev/null 2>&1; then
  pass "helm lint clean"
else
  fail "helm lint reported errors"
fi

# --------------------------------------------------------------------------
# Test 2: helm template renders without errors (default values)
# --------------------------------------------------------------------------
echo "[Test 2] helm template (default values)"
DEFAULT_OUTPUT=$(helm template test-expose "$CHART_DIR" 2>&1) || {
  fail "helm template failed with default values"
  echo "$DEFAULT_OUTPUT"
  exit 1
}
pass "helm template renders cleanly"

# --------------------------------------------------------------------------
# Test 3: All deployments have selector labels
# --------------------------------------------------------------------------
echo "[Test 3] Selector label presence"
EMPTY_SELECTORS=$(echo "$DEFAULT_OUTPUT" | grep -c 'matchLabels: {}' || true)
if [ "$EMPTY_SELECTORS" -eq 0 ]; then
  pass "no empty matchLabels selectors"
else
  fail "found $EMPTY_SELECTORS empty matchLabels selectors"
fi

# --------------------------------------------------------------------------
# Test 4: All resources have standard labels
# --------------------------------------------------------------------------
echo "[Test 4] Standard Kubernetes labels"
for LABEL in "app.kubernetes.io/name" "app.kubernetes.io/instance" "app.kubernetes.io/managed-by"; do
  COUNT=$(echo "$DEFAULT_OUTPUT" | grep -c "$LABEL" || true)
  if [ "$COUNT" -gt 0 ]; then
    pass "label $LABEL present ($COUNT occurrences)"
  else
    fail "label $LABEL missing from rendered output"
  fi
done

# --------------------------------------------------------------------------
# Test 5: Component labels on deployments
# --------------------------------------------------------------------------
echo "[Test 5] Component labels"
for COMPONENT in "control-plane" "scanner-worker" "collector-worker"; do
  COUNT=$(echo "$DEFAULT_OUTPUT" | grep -c "app.kubernetes.io/component: $COMPONENT" || true)
  if [ "$COUNT" -gt 0 ]; then
    pass "component label '$COMPONENT' present"
  else
    fail "component label '$COMPONENT' missing"
  fi
done

# --------------------------------------------------------------------------
# Test 6: Security context enforced
# --------------------------------------------------------------------------
echo "[Test 6] Security context"
if echo "$DEFAULT_OUTPUT" | grep -q "runAsNonRoot: true"; then
  pass "runAsNonRoot: true present"
else
  fail "runAsNonRoot: true missing"
fi

if echo "$DEFAULT_OUTPUT" | grep -q "readOnlyRootFilesystem: true"; then
  pass "readOnlyRootFilesystem: true present"
else
  fail "readOnlyRootFilesystem: true missing"
fi

if echo "$DEFAULT_OUTPUT" | grep -q "allowPrivilegeEscalation: false"; then
  pass "allowPrivilegeEscalation: false present"
else
  fail "allowPrivilegeEscalation: false missing"
fi

DROP_ALL=$(echo "$DEFAULT_OUTPUT" | grep -c -- '- ALL' || true)
if [ "$DROP_ALL" -gt 0 ]; then
  pass "capabilities drop ALL present ($DROP_ALL containers)"
else
  fail "capabilities drop ALL missing"
fi

# --------------------------------------------------------------------------
# Test 7: Prometheus annotations on pods
# --------------------------------------------------------------------------
echo "[Test 7] Prometheus scrape annotations"
SCRAPE_COUNT=$(echo "$DEFAULT_OUTPUT" | grep -c 'prometheus.io/scrape: "true"' || true)
if [ "$SCRAPE_COUNT" -ge 3 ]; then
  pass "prometheus.io/scrape on all deployments ($SCRAPE_COUNT)"
else
  fail "prometheus.io/scrape missing or incomplete ($SCRAPE_COUNT, expected >= 3)"
fi

if echo "$DEFAULT_OUTPUT" | grep -q 'prometheus.io/path: "/metrics"'; then
  pass "prometheus.io/path set to /metrics"
else
  fail "prometheus.io/path missing"
fi

# --------------------------------------------------------------------------
# Test 8: Liveness and readiness probes on control-plane
# --------------------------------------------------------------------------
echo "[Test 8] Health probes"
if echo "$DEFAULT_OUTPUT" | grep -q "livenessProbe:"; then
  pass "livenessProbe present on control-plane"
else
  fail "livenessProbe missing on control-plane"
fi

if echo "$DEFAULT_OUTPUT" | grep -q "readinessProbe:"; then
  pass "readinessProbe present on control-plane"
else
  fail "readinessProbe missing on control-plane"
fi

if echo "$DEFAULT_OUTPUT" | grep -q "/healthz"; then
  pass "/healthz endpoint referenced in probes"
else
  fail "/healthz endpoint missing from probes"
fi

# --------------------------------------------------------------------------
# Test 9: PodDisruptionBudgets exist
# --------------------------------------------------------------------------
echo "[Test 9] PodDisruptionBudgets"
PDB_COUNT=$(echo "$DEFAULT_OUTPUT" | grep -c "kind: PodDisruptionBudget" || true)
if [ "$PDB_COUNT" -eq 3 ]; then
  pass "3 PodDisruptionBudgets present"
else
  fail "expected 3 PDBs, found $PDB_COUNT"
fi

# --------------------------------------------------------------------------
# Test 10: Service targets correct port
# --------------------------------------------------------------------------
echo "[Test 10] Service port"
if echo "$DEFAULT_OUTPUT" | grep -q "port: 8090"; then
  pass "service port 8090 configured"
else
  fail "service port 8090 not found"
fi

# --------------------------------------------------------------------------
# Test 11: tmp volume for readOnlyRootFilesystem
# --------------------------------------------------------------------------
echo "[Test 11] tmp emptyDir volume"
TMP_MOUNTS=$(echo "$DEFAULT_OUTPUT" | grep -c 'mountPath: /tmp' || true)
if [ "$TMP_MOUNTS" -ge 3 ]; then
  pass "tmp volume mounted in all containers ($TMP_MOUNTS)"
else
  fail "tmp volume missing from some containers ($TMP_MOUNTS, expected >= 3)"
fi

# --------------------------------------------------------------------------
# Test 12: helm template with production overrides
# --------------------------------------------------------------------------
echo "[Test 12] helm template (production overrides)"
PROD_OUTPUT=$(helm template test-prod "$CHART_DIR" \
  --set postgres.host=postgres.db.svc \
  --set postgres.existingSecret=expose-pg-secret \
  --set nats.enabled=true \
  --set objectStorage.endpoint=s3.amazonaws.com \
  --set objectStorage.existingSecret=expose-s3-secret \
  --set global.fipsMode=true \
  --set ingress.enabled=true \
  --set 'ingress.hosts[0].host=expose.example.com' \
  --set 'ingress.hosts[0].paths[0].path=/' \
  --set 'ingress.hosts[0].paths[0].pathType=Prefix' \
  2>&1) || {
  fail "helm template failed with production overrides"
  echo "$PROD_OUTPUT"
  exit 1
}
pass "production overrides render cleanly"

# Check FIPS mode env var
if echo "$PROD_OUTPUT" | grep -q 'EXPOSE_FIPS_MODE'; then
  pass "EXPOSE_FIPS_MODE env var present"
else
  fail "EXPOSE_FIPS_MODE env var missing"
fi

# Check NATS URL populated
if echo "$PROD_OUTPUT" | grep -q 'EXPOSE_NATS_URL'; then
  pass "EXPOSE_NATS_URL env var present"
else
  fail "EXPOSE_NATS_URL env var missing"
fi

# Check S3 env vars populated
if echo "$PROD_OUTPUT" | grep -q 'EXPOSE_S3_ENDPOINT'; then
  pass "EXPOSE_S3_ENDPOINT env var present"
else
  fail "EXPOSE_S3_ENDPOINT env var missing"
fi

# Check DB secret refs
if echo "$PROD_OUTPUT" | grep -q 'EXPOSE_DB_USER'; then
  pass "EXPOSE_DB_USER secretKeyRef present"
else
  fail "EXPOSE_DB_USER secretKeyRef missing"
fi

# Check ingress rendered
if echo "$PROD_OUTPUT" | grep -q 'kind: Ingress'; then
  pass "Ingress resource rendered"
else
  fail "Ingress resource not rendered"
fi

# Check NATS StatefulSet rendered
if echo "$PROD_OUTPUT" | grep -q 'kind: StatefulSet'; then
  pass "NATS StatefulSet rendered"
else
  fail "NATS StatefulSet not rendered"
fi

# --------------------------------------------------------------------------
# Test 13: helm template with minimal values (everything disabled)
# --------------------------------------------------------------------------
echo "[Test 13] helm template (minimal — workers disabled)"
MINIMAL_OUTPUT=$(helm template test-minimal "$CHART_DIR" \
  --set collectorWorker.enabled=false \
  --set scannerWorker.enabled=false \
  --set networkPolicy.enabled=false \
  --set observability.prometheus.enabled=false \
  2>&1) || {
  fail "helm template failed with minimal values"
  echo "$MINIMAL_OUTPUT"
  exit 1
}
pass "minimal values render cleanly"

# Should NOT contain worker deployments
if echo "$MINIMAL_OUTPUT" | grep -q "collector-worker"; then
  fail "collector-worker present when disabled"
else
  pass "collector-worker absent when disabled"
fi

if echo "$MINIMAL_OUTPUT" | grep -q "scanner-worker"; then
  fail "scanner-worker present when disabled"
else
  pass "scanner-worker absent when disabled"
fi

# Should NOT contain prometheus annotations
if echo "$MINIMAL_OUTPUT" | grep -q "prometheus.io/scrape"; then
  fail "prometheus annotations present when disabled"
else
  pass "prometheus annotations absent when disabled"
fi

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
echo ""
echo "=== Results: $PASS passed, $FAIL failed (of $TOTAL checks) ==="

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0

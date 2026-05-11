#!/bin/bash
# =============================================================================
# EXPOSE Scheduled Monitoring Workflow
# =============================================================================
#
# Demonstrates setting up recurring scans for continuous attack surface
# monitoring:
#   1. Verify tenant exists
#   2. Create a scan schedule (daily at 02:30 UTC)
#   3. List active schedules
#   4. Verify the schedule fires on next cron tick
#   5. Compare delta between runs
#
# Prerequisites:
#   - EXPOSE API running at localhost:8090
#   - Tenant already created (see basic-scan.sh)
#   - At least one completed run for meaningful deltas
#
# Usage:
#   chmod +x scheduled-monitoring.sh
#   TENANT_ID="f47ac10b-58cc-4372-a567-0e02b2c3d479" ./scheduled-monitoring.sh
# =============================================================================

set -euo pipefail

API="http://localhost:8090"
TENANT_ID="${TENANT_ID:?Set TENANT_ID environment variable (see basic-scan.sh)}"

echo "=== EXPOSE Scheduled Monitoring Setup ==="
echo ""

# -------------------------------------------------------------------------
# Step 1: Verify tenant exists and has at least one completed run
# -------------------------------------------------------------------------
echo "[1/5] Verifying tenant ${TENANT_ID}"

TENANT_INFO=$(curl -s "${API}/v1/tenants/${TENANT_ID}")
TENANT_NAME=$(echo "${TENANT_INFO}" | python3 -c "import sys, json; print(json.load(sys.stdin)['tenant_name'])")
echo "  Tenant: ${TENANT_NAME}"

# Check for existing runs
RUNS=$(curl -s "${API}/v1/tenants/${TENANT_ID}/runs/")
RUN_COUNT=$(echo "${RUNS}" | python3 -c "import sys, json; data=json.load(sys.stdin); print(len(data.get('runs', data)) if isinstance(data, dict) else len(data))")
echo "  Existing runs: ${RUN_COUNT}"

echo ""

# -------------------------------------------------------------------------
# Step 2: Create a daily scan schedule
# -------------------------------------------------------------------------
echo "[2/5] Creating daily scan schedule (02:30 UTC)"

SCHEDULE_RESPONSE=$(curl -s -X POST "${API}/v1/tenants/${TENANT_ID}/schedules/" \
  -H "Content-Type: application/json" \
  -d '{
    "schedule_name": "daily-surface-scan",
    "cron_expression": "30 2 * * *",
    "timezone": "UTC",
    "enabled": true,
    "config_overrides": {
      "rule_pack_version": "baseline-v2.1.0",
      "scope_enforcement_mode": "medium",
      "collectors_enabled": [
        "dns-resolver",
        "ct-log-monitor",
        "http-prober",
        "port-scanner",
        "cloud-ip-ranger",
        "whois-resolver",
        "cloud-scanner"
      ]
    }
  }')

echo "${SCHEDULE_RESPONSE}" | python3 -m json.tool

# Expected output:
# {
#   "schedule_id": "sched-acme-daily-0230",
#   "tenant_id": "f47ac10b-...",
#   "schedule_name": "daily-surface-scan",
#   "cron_expression": "30 2 * * *",
#   "timezone": "UTC",
#   "enabled": true,
#   "next_run_at": "2026-05-12T02:30:00Z",
#   "created_at": "2026-05-11T03:00:00Z"
# }

SCHEDULE_ID=$(echo "${SCHEDULE_RESPONSE}" | python3 -c "import sys, json; print(json.load(sys.stdin).get('schedule_id', 'unknown'))")
echo ""

# -------------------------------------------------------------------------
# Step 3: List all active schedules
# -------------------------------------------------------------------------
echo "[3/5] Listing active schedules for tenant"

curl -s "${API}/v1/tenants/${TENANT_ID}/schedules/" \
  | python3 -m json.tool

# Expected output:
# {
#   "schedules": [
#     {
#       "schedule_id": "sched-acme-daily-0230",
#       "schedule_name": "daily-surface-scan",
#       "cron_expression": "30 2 * * *",
#       "enabled": true,
#       "next_run_at": "2026-05-12T02:30:00Z",
#       "last_run_at": null
#     }
#   ]
# }

echo ""

# -------------------------------------------------------------------------
# Step 4: Trigger an immediate run to simulate the schedule firing
# -------------------------------------------------------------------------
echo "[4/5] Triggering immediate run to simulate schedule execution"

MANUAL_RUN=$(curl -s -X POST "${API}/v1/tenants/${TENANT_ID}/runs/" \
  -H "Content-Type: application/json" \
  -d '{}')

RUN_ID=$(echo "${MANUAL_RUN}" | python3 -c "import sys, json; print(json.load(sys.stdin)['run_id'])")
echo "  Run ID: ${RUN_ID}"

# Poll until complete (abbreviated -- see basic-scan.sh for full polling)
echo "  Waiting for run to complete..."
for i in $(seq 1 30); do
  STATE=$(curl -s "${API}/v1/tenants/${TENANT_ID}/runs/${RUN_ID}" \
    | python3 -c "import sys, json; print(json.load(sys.stdin)['state'])")
  if [ "${STATE}" = "completed" ]; then
    echo "  Run completed."
    break
  elif [ "${STATE}" = "failed" ]; then
    echo "  Run failed. Check logs."
    break
  fi
  sleep 10
done

echo ""

# -------------------------------------------------------------------------
# Step 5: View the delta from the previous run
# -------------------------------------------------------------------------
echo "[5/5] Viewing run history and deltas"

# Get the latest completed run details
echo "  Latest run summary:"
curl -s "${API}/v1/tenants/${TENANT_ID}/runs/${RUN_ID}" \
  | python3 -m json.tool

# Expected output showing delta_from_previous_run:
# {
#   "run_id": "...",
#   "state": "completed",
#   "started_at": "2026-05-12T02:30:00Z",
#   "completed_at": "2026-05-12T02:34:50Z",
#   "targets_discovered": 19,
#   "delta_summary": {
#     "added": 1,       <-- New entity discovered since last scan
#     "removed": 0,
#     "changed": 2      <-- 2 entities had attribution or exposure changes
#   }
# }

echo ""

# View run log for scan history over time
echo "  Recent scan history:"
curl -s "${API}/v1/tenants/${TENANT_ID}/runs/?limit=5" \
  | python3 -m json.tool

# Expected output:
# [
#   { "run_id": "...", "state": "completed", "targets_discovered": 19, "started_at": "2026-05-12T02:30:00Z" },
#   { "run_id": "...", "state": "completed", "targets_discovered": 18, "started_at": "2026-05-11T02:30:00Z" }
# ]

echo ""
echo "=== Schedule Configured ==="
echo ""
echo "The daily scan will run automatically at 02:30 UTC."
echo ""
echo "Monitor scan results:"
echo "  - Findings:  curl ${API}/v1/tenants/${TENANT_ID}/findings/"
echo "  - Run log:   curl ${API}/v1/tenants/${TENANT_ID}/runs/"
echo "  - Events:    curl ${API}/v1/tenants/${TENANT_ID}/events/ (SSE stream)"
echo ""
echo "Manage the schedule:"
echo "  - Disable:   curl -X PATCH ${API}/v1/tenants/${TENANT_ID}/schedules/${SCHEDULE_ID} -d '{\"enabled\": false}'"
echo "  - Delete:    curl -X DELETE ${API}/v1/tenants/${TENANT_ID}/schedules/${SCHEDULE_ID}"

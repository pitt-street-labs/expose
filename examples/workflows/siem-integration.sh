#!/bin/bash
# =============================================================================
# EXPOSE SIEM Integration Workflow (Splunk HEC)
# =============================================================================
#
# Demonstrates configuring EXPOSE to deliver observations and findings
# to Splunk via the HTTP Event Collector (HEC):
#   1. Configure Splunk HEC adapter for the tenant
#   2. Verify HEC connectivity
#   3. Trigger a scan
#   4. Verify events delivered to Splunk
#   5. Query delivered events via Splunk REST API
#
# Supported SIEM adapters:
#   - splunk    (Splunk HTTP Event Collector)
#   - sentinel  (Microsoft Sentinel / Log Analytics)
#   - chronicle (Google Chronicle / SIEM)
#
# Prerequisites:
#   - EXPOSE API running at localhost:8090
#   - Splunk instance with HEC enabled
#   - HEC token created with events allowed to "main" index
#   - Tenant already created (see basic-scan.sh)
#
# Usage:
#   chmod +x siem-integration.sh
#   TENANT_ID="f47ac10b-..." \
#   SPLUNK_HEC_URL="https://splunk.example.com:8088" \
#   SPLUNK_HEC_TOKEN="your-hec-token" \
#   ./siem-integration.sh
# =============================================================================

set -euo pipefail

API="http://localhost:8090"
TENANT_ID="${TENANT_ID:?Set TENANT_ID environment variable}"
SPLUNK_HEC_URL="${SPLUNK_HEC_URL:?Set SPLUNK_HEC_URL (e.g., https://splunk.example.com:8088)}"
SPLUNK_HEC_TOKEN="${SPLUNK_HEC_TOKEN:?Set SPLUNK_HEC_TOKEN}"

echo "=== EXPOSE SIEM Integration (Splunk HEC) ==="
echo ""

# -------------------------------------------------------------------------
# Step 1: Configure the Splunk HEC adapter for the tenant
# -------------------------------------------------------------------------
echo "[1/5] Configuring Splunk HEC adapter"

SIEM_RESPONSE=$(curl -s -X POST "${API}/v1/tenants/${TENANT_ID}/integrations/siem/" \
  -H "Content-Type: application/json" \
  -d "{
    \"adapter_id\": \"splunk\",
    \"enabled\": true,
    \"endpoint\": \"${SPLUNK_HEC_URL}\",
    \"auth_token\": \"${SPLUNK_HEC_TOKEN}\",
    \"batch_size\": 50,
    \"retry_max\": 3,
    \"retry_delay_seconds\": 2,
    \"config\": {
      \"index\": \"main\",
      \"sourcetype_observations\": \"expose:observation\",
      \"sourcetype_findings\": \"expose:finding\"
    }
  }")

echo "${SIEM_RESPONSE}" | python3 -m json.tool

# Expected output:
# {
#   "integration_id": "siem-splunk-acme",
#   "adapter_id": "splunk",
#   "enabled": true,
#   "endpoint": "https://splunk.example.com:8088",
#   "tenant_id": "f47ac10b-...",
#   "status": "configured",
#   "created_at": "2026-05-11T04:00:00Z"
# }

echo ""

# -------------------------------------------------------------------------
# Step 2: Verify HEC connectivity
# -------------------------------------------------------------------------
echo "[2/5] Testing Splunk HEC connectivity"

HEALTH_RESPONSE=$(curl -s -X POST "${API}/v1/tenants/${TENANT_ID}/integrations/siem/health" \
  -H "Content-Type: application/json" \
  -d '{"adapter_id": "splunk"}')

echo "${HEALTH_RESPONSE}" | python3 -m json.tool

# Expected output:
# {
#   "adapter_id": "splunk",
#   "healthy": true,
#   "latency_ms": 45.2,
#   "checked_at": "2026-05-11T04:00:05Z"
# }

# You can also test HEC directly:
echo ""
echo "  Direct HEC health check:"
curl -s -k "${SPLUNK_HEC_URL}/services/collector/health/1.0" \
  -H "Authorization: Splunk ${SPLUNK_HEC_TOKEN}" \
  | python3 -m json.tool || echo "  (Direct check failed -- may require -k for self-signed certs)"

echo ""

# -------------------------------------------------------------------------
# Step 3: Trigger a scan (events will be delivered to Splunk in real-time)
# -------------------------------------------------------------------------
echo "[3/5] Triggering scan with SIEM delivery enabled"

RUN_RESPONSE=$(curl -s -X POST "${API}/v1/tenants/${TENANT_ID}/runs/" \
  -H "Content-Type: application/json" \
  -d '{}')

RUN_ID=$(echo "${RUN_RESPONSE}" | python3 -c "import sys, json; print(json.load(sys.stdin)['run_id'])")
echo "  Run ID: ${RUN_ID}"
echo "  Events are being delivered to Splunk as collectors report observations..."

# Poll for completion
for i in $(seq 1 30); do
  STATE=$(curl -s "${API}/v1/tenants/${TENANT_ID}/runs/${RUN_ID}" \
    | python3 -c "import sys, json; print(json.load(sys.stdin)['state'])")
  if [ "${STATE}" = "completed" ]; then
    echo "  Scan completed."
    break
  elif [ "${STATE}" = "failed" ]; then
    echo "  Scan failed."
    break
  fi
  sleep 10
done

echo ""

# -------------------------------------------------------------------------
# Step 4: Verify SIEM delivery status
# -------------------------------------------------------------------------
echo "[4/5] Checking SIEM delivery status for this run"

DELIVERY_STATUS=$(curl -s "${API}/v1/tenants/${TENANT_ID}/runs/${RUN_ID}/siem-status")

echo "${DELIVERY_STATUS}" | python3 -m json.tool

# Expected output:
# {
#   "run_id": "a1b2c3d4-...",
#   "adapter_id": "splunk",
#   "delivery_summary": {
#     "observations_sent": 88,
#     "observations_failed": 0,
#     "findings_sent": 10,
#     "findings_failed": 0,
#     "total_batches": 2,
#     "total_duration_ms": 342.5
#   },
#   "status": "all_delivered"
# }

echo ""

# -------------------------------------------------------------------------
# Step 5: Query events in Splunk (optional -- requires Splunk REST API)
# -------------------------------------------------------------------------
echo "[5/5] Querying delivered events in Splunk"
echo ""
echo "  Run these Splunk searches to verify event delivery:"
echo ""
echo "  -- All EXPOSE observations for this tenant --"
echo "  index=main sourcetype=expose:observation tenant_id=\"${TENANT_ID}\""
echo ""
echo "  -- Critical findings only --"
echo "  index=main sourcetype=expose:finding tenant_id=\"${TENANT_ID}\" severity=critical"
echo ""
echo "  -- DNS observations mapped to CIM --"
echo "  index=main sourcetype=expose:observation cim_data_model=DNS | table query, query_type, observed_at"
echo ""
echo "  -- Network Traffic observations --"
echo "  index=main sourcetype=expose:observation cim_data_model=Network_Traffic | table src, dest_port, transport"
echo ""
echo "  -- Event count by sourcetype --"
echo "  index=main source=\"expose:tenant:${TENANT_ID}\" | stats count by sourcetype"
echo ""

# Example: HEC event format for reference
# See examples/outputs/siem-splunk-example.json for the full event structure.
#
# CIM Data Model Mappings:
#
# | EXPOSE Entity Type    | Splunk CIM Model       | Key CIM Fields               |
# |-----------------------|------------------------|------------------------------|
# | domain / subdomain    | DNS                    | query, query_type            |
# | ip                    | Network Traffic        | src                          |
# | cidr                  | Network Traffic        | src_range                    |
# | cloud_resource_id     | Cloud Infrastructure   | object_id, vendor_product    |
# | url                   | Web                    | url, http_method             |
#
# Severity Mapping:
#
# | EXPOSE Severity | Splunk CIM Severity |
# |-----------------|---------------------|
# | info            | informational       |
# | low             | low                 |
# | medium          | medium              |
# | high            | high                |
# | critical        | critical            |

echo "=== SIEM Integration Complete ==="
echo ""
echo "EXPOSE will deliver events to Splunk on every scan."
echo "Combine with scheduled-monitoring.sh for continuous SIEM ingestion."

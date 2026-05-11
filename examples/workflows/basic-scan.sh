#!/bin/bash
# =============================================================================
# EXPOSE Basic Scan Workflow
# =============================================================================
#
# Demonstrates the complete lifecycle of an EXPOSE scan:
#   1. Create a tenant
#   2. Configure seed domains
#   3. Trigger a scan
#   4. Poll for completion
#   5. View prioritized findings
#   6. Export the entity graph
#
# Prerequisites:
#   - EXPOSE API running at localhost:8090
#   - PostgreSQL database initialized (alembic upgrade head)
#
# Usage:
#   chmod +x basic-scan.sh
#   ./basic-scan.sh
# =============================================================================

set -euo pipefail

API="http://localhost:8090"
TENANT_NAME="Acme Corp"

echo "=== EXPOSE Basic Scan Workflow ==="
echo ""

# -------------------------------------------------------------------------
# Step 1: Create a tenant
# -------------------------------------------------------------------------
echo "[1/6] Creating tenant: ${TENANT_NAME}"

TENANT_RESPONSE=$(curl -s -X POST "${API}/v1/tenants/" \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_name\": \"${TENANT_NAME}\",
    \"deployment_id\": \"demo\"
  }")

TENANT_ID=$(echo "${TENANT_RESPONSE}" | python3 -c "import sys, json; print(json.load(sys.stdin)['tenant_id'])")
echo "  Tenant ID: ${TENANT_ID}"

# Expected output:
# {
#   "tenant_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
#   "tenant_name": "Acme Corp",
#   "deployment_id": "demo",
#   "created_at": "2026-05-11T02:28:00Z"
# }

echo ""

# -------------------------------------------------------------------------
# Step 2: Configure tenant settings and seed domains
# -------------------------------------------------------------------------
echo "[2/6] Configuring tenant settings and seeds"

# Set the tenant configuration (rule pack, scope, LLM settings)
curl -s -X PUT "${API}/v1/tenants/${TENANT_ID}/config/" \
  -H "Content-Type: application/json" \
  -d '{
    "rule_pack_id": "baseline",
    "rule_pack_version": "v2.1.0",
    "scope_enforcement_mode": "medium",
    "llm_enabled": false,
    "collectors_enabled": [
      "dns-resolver",
      "ct-log-monitor",
      "http-prober",
      "port-scanner",
      "cloud-ip-ranger",
      "whois-resolver"
    ]
  }' | python3 -m json.tool

# Add seed domains
curl -s -X POST "${API}/v1/tenants/${TENANT_ID}/seeds/" \
  -H "Content-Type: application/json" \
  -d '{
    "seeds": [
      {"type": "domain", "value": "acme-corp.com"},
      {"type": "domain", "value": "acme-corp.net"},
      {"type": "ip", "value": "203.0.113.0/24"}
    ]
  }' | python3 -m json.tool

# Expected output:
# {
#   "seeds_added": 3,
#   "tenant_id": "f47ac10b-..."
# }

echo ""

# -------------------------------------------------------------------------
# Step 3: Trigger a scan
# -------------------------------------------------------------------------
echo "[3/6] Triggering scan"

RUN_RESPONSE=$(curl -s -X POST "${API}/v1/tenants/${TENANT_ID}/runs/" \
  -H "Content-Type: application/json" \
  -d '{}')

RUN_ID=$(echo "${RUN_RESPONSE}" | python3 -c "import sys, json; print(json.load(sys.stdin)['run_id'])")
echo "  Run ID: ${RUN_ID}"

# Expected output:
# {
#   "run_id": "a1b2c3d4-5678-4e9f-a012-3456789abcde",
#   "tenant_id": "f47ac10b-...",
#   "state": "pending",
#   "started_at": "2026-05-11T02:30:00Z"
# }

echo ""

# -------------------------------------------------------------------------
# Step 4: Poll for completion
# -------------------------------------------------------------------------
echo "[4/6] Polling for scan completion (max 5 minutes)..."

MAX_POLLS=30
POLL_INTERVAL=10

for i in $(seq 1 ${MAX_POLLS}); do
  STATE=$(curl -s "${API}/v1/tenants/${TENANT_ID}/runs/${RUN_ID}" \
    | python3 -c "import sys, json; print(json.load(sys.stdin)['state'])")

  echo "  Poll ${i}/${MAX_POLLS}: state=${STATE}"

  if [ "${STATE}" = "completed" ]; then
    echo "  Scan completed successfully!"
    break
  elif [ "${STATE}" = "failed" ]; then
    echo "  ERROR: Scan failed. Check server logs."
    exit 1
  fi

  sleep ${POLL_INTERVAL}
done

if [ "${STATE}" != "completed" ]; then
  echo "  WARNING: Scan did not complete within polling window."
  echo "  Continue checking: curl ${API}/v1/tenants/${TENANT_ID}/runs/${RUN_ID}"
  exit 1
fi

# Expected output during polling:
#   Poll 1/30: state=pending
#   Poll 2/30: state=running
#   ...
#   Poll 8/30: state=completed
#   Scan completed successfully!

echo ""

# -------------------------------------------------------------------------
# Step 5: View prioritized findings
# -------------------------------------------------------------------------
echo "[5/6] Fetching top 10 findings (sorted by risk score)"

curl -s "${API}/v1/tenants/${TENANT_ID}/findings/?limit=10&min_score=0" \
  | python3 -m json.tool

# Expected output: see examples/outputs/findings-example.json
# Top findings will include:
#   #1  staging.acme-corp.com   score=92  critical  (no TLS, directory listing)
#   #2  203.0.113.42            score=85  critical  (open SSH/RDP)
#   #3  *.acme-corp.com         score=74  high      (cert expiring)
#   #4  admin.acme-corp.com     score=71  high      (admin portal, no MFA)
#   ...

echo ""

# -------------------------------------------------------------------------
# Step 6: Export the entity graph
# -------------------------------------------------------------------------
echo "[6/6] Exporting entity relationship graph"

curl -s "${API}/v1/tenants/${TENANT_ID}/graph" \
  | python3 -m json.tool

# Expected output: see examples/outputs/graph-example.json
# Graph will contain:
#   - 12+ nodes (domains, IPs, organization)
#   - 15+ edges (resolves_to, certificate_for, belongs_to, ns_for, hosts)

echo ""
echo "=== Scan Complete ==="
echo ""
echo "Next steps:"
echo "  - View provenance for an entity:"
echo "    curl ${API}/v1/tenants/${TENANT_ID}/entities/<entity_id>/provenance"
echo ""
echo "  - Set up scheduled monitoring:"
echo "    See examples/workflows/scheduled-monitoring.sh"
echo ""
echo "  - Configure SIEM integration:"
echo "    See examples/workflows/siem-integration.sh"

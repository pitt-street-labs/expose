#!/usr/bin/env bash
set -euo pipefail

# EXPOSE Demo Script
# Requires: docker compose up -d (or a running EXPOSE API at localhost:8090)

API="http://localhost:8090"
TENANT_NAME="demo-tenant"

echo "=== EXPOSE Demo ==="
echo ""

# 1. Wait for API
echo "[1/5] Waiting for API..."
for i in $(seq 1 30); do
    if curl -sf "$API/healthz" > /dev/null 2>&1; then
        echo "  API is ready."
        break
    fi
    sleep 2
done

# 2. Create tenant
echo "[2/5] Creating tenant..."
TENANT=$(curl -sf -X POST "$API/v1/tenants/" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"$TENANT_NAME\"}" 2>/dev/null || echo '{}')
TENANT_ID=$(echo "$TENANT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id', 'unknown'))" 2>/dev/null || echo "unknown")
echo "  Tenant ID: $TENANT_ID"

# 3. Trigger scan
echo "[3/5] Triggering scan for example.com..."
RUN=$(curl -sf -X POST "$API/v1/tenants/$TENANT_ID/runs" \
    -H "Content-Type: application/json" \
    -d '{"seeds": ["example.com"]}' 2>/dev/null || echo '{}')
RUN_ID=$(echo "$RUN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('run_id', 'unknown'))" 2>/dev/null || echo "unknown")
echo "  Run ID: $RUN_ID"

# 4. Poll for completion
echo "[4/5] Waiting for scan to complete..."
for i in $(seq 1 60); do
    STATE=$(curl -sf "$API/v1/tenants/$TENANT_ID/runs/$RUN_ID" 2>/dev/null | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('state', 'unknown'))" 2>/dev/null || echo "unknown")
    if [ "$STATE" = "completed" ] || [ "$STATE" = "partial" ] || [ "$STATE" = "failed" ]; then
        echo "  Run state: $STATE"
        break
    fi
    echo "  State: $STATE (waiting...)"
    sleep 3
done

# 5. Show results
echo "[5/5] Results:"
ENTITIES=$(curl -sf "$API/v1/tenants/$TENANT_ID/entities" 2>/dev/null || echo '{"entities": []}')
COUNT=$(echo "$ENTITIES" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('entities', d.get('items', []))))" 2>/dev/null || echo "0")
echo "  Discovered entities: $COUNT"
echo ""
echo "  Dashboard: $API/"
echo "  API docs:  $API/docs"
echo ""
echo "=== Demo Complete ==="

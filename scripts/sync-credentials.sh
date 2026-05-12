#!/usr/bin/env bash
# Sync API credentials from dev (z590) to production (Node1).
#
# Usage:
#   ./scripts/sync-credentials.sh [TENANT_ID]
#
# If TENANT_ID is omitted, syncs to the global credential pool only.
# If provided, syncs to both global and the specified tenant.
#
# Prerequisites:
#   - SSH key access to Node1 (jcarlson@172.16.20.10)
#   - EXPOSE API running on Node1:8096
#   - spiderfoot-creds.txt in project root (source of truth)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CREDS_FILE="$PROJECT_DIR/spiderfoot-creds.txt"
NODE1="172.16.20.10"
NODE1_API="http://localhost:8096"
SSH_OPTS="-i $HOME/.ssh/node1-2024 -o ConnectTimeout=10"
TENANT_ID="${1:-}"

if [[ ! -f "$CREDS_FILE" ]]; then
    echo "ERROR: $CREDS_FILE not found" >&2
    exit 1
fi

# Build the credential bundle JSON from spiderfoot-creds.txt
build_bundle() {
    python3 -c "
import json, sys

slot_map = {
    'censys': [('censys_api_id', 0), ('censys_api_secret', 1)],
    'shodan': [('shodan_api_key', 0)],
    'securitytrails': [('securitytrails_api_key', 0)],
    'binaryedge': [('binaryedge_api_key', 0)],
    'greynoise': [('greynoise_api_key', 0)],
    'virus total': [('virustotal_api_key', 0)],
    'passive total': [('passivetotal_username', 0), ('passivetotal_api_key', 1)],
    'intelligencex': [('intelx_api_key', 0)],
}

with open('$CREDS_FILE') as f:
    content = f.read()

bundle = {}
lines = content.strip().split('\n')
current_name = None
values = []

for line in lines:
    stripped = line.strip()
    if not stripped:
        if current_name and values:
            mapping = slot_map.get(current_name.lower(), [])
            for slot, idx in mapping:
                if idx < len(values) and values[idx]:
                    bundle[slot] = values[idx]
        current_name = None
        values = []
        continue
    if not line.startswith(('\t', ' ')):
        if current_name and values:
            mapping = slot_map.get(current_name.lower(), [])
            for slot, idx in mapping:
                if idx < len(values) and values[idx]:
                    bundle[slot] = values[idx]
        current_name = stripped
        values = []
    else:
        val = stripped.split('\t')[0].strip()
        if val and not val.startswith(('key:', 'or', 'api name')):
            values.append(val)

if current_name and values:
    mapping = slot_map.get(current_name.lower(), [])
    for slot, idx in mapping:
        if idx < len(values) and values[idx]:
            bundle[slot] = values[idx]

print(json.dumps({'credentials': bundle}))
"
}

BUNDLE=$(build_bundle)
KEY_COUNT=$(echo "$BUNDLE" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['credentials']))")
echo "Built bundle with $KEY_COUNT credential slots"

# Import to global pool
echo -n "Importing to global pool... "
RESULT=$(SSH_AUTH_SOCK= ssh $SSH_OPTS jcarlson@$NODE1 \
    "curl -sL -X POST '$NODE1_API/v1/credentials/global/import/bundle' \
     -H 'Content-Type: application/json' \
     -d '$BUNDLE'" 2>&1)
IMPORTED=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('imported_count','?'))" 2>/dev/null || echo "ERROR")
echo "$IMPORTED imported"

# Import to tenant if specified
if [[ -n "$TENANT_ID" ]]; then
    echo -n "Importing to tenant $TENANT_ID... "
    RESULT=$(SSH_AUTH_SOCK= ssh $SSH_OPTS jcarlson@$NODE1 \
        "curl -sL -X POST '$NODE1_API/v1/tenants/$TENANT_ID/credentials/import/bundle' \
         -H 'Content-Type: application/json' \
         -d '$BUNDLE'" 2>&1)
    IMPORTED=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('imported_count','?'))" 2>/dev/null || echo "ERROR")
    echo "$IMPORTED imported"
fi

echo "Done."

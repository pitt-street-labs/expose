#!/usr/bin/env bash
set -euo pipefail

# Import SpiderFoot credentials into EXPOSE for a given tenant.
# Reads from spiderfoot-creds.txt (gitignored) and POSTs to the bundle import API.
#
# Usage:
#   ./scripts/import-credentials.sh [TENANT_ID]
#
# Defaults to the well-known default tenant UUID if no argument given.

API="${EXPOSE_API_URL:-http://localhost:8090}"
TENANT_ID="${1:-00000000-0000-0000-0000-000000000000}"
CREDS_FILE="${EXPOSE_CREDS_FILE:-$(dirname "$0")/../spiderfoot-creds.txt}"

if [ ! -f "$CREDS_FILE" ]; then
    echo "ERROR: Credentials file not found: $CREDS_FILE" >&2
    exit 1
fi

for i in $(seq 1 10); do
    if curl -sf "$API/healthz" > /dev/null 2>&1; then
        break
    fi
    if [ "$i" -eq 10 ]; then
        echo "ERROR: API not reachable at $API" >&2
        exit 1
    fi
    sleep 2
done

BUNDLE=$(python3 -c "
import re, json, sys

creds_file = sys.argv[1]
with open(creds_file) as f:
    text = f.read()

mapping = {
    'shodan': {'shodan_api_key': None},
    'censys': {'censys_api_id': None, 'censys_api_secret': None},
    'securitytrails': {'securitytrails_api_key': None},
    'virus total': {'virustotal_api_key': None},
    'binaryedge': {'binaryedge_api_key': None},
    'passive total': {'passivetotal_api_key': None},
    'greynoise': {'greynoise_api_key': None},
}

lines = text.strip().split('\n')
i = 0
result = {}
while i < len(lines):
    line = lines[i].strip().lower()
    for key, slots in mapping.items():
        if line == key:
            values = []
            j = i + 1
            while j < len(lines) and lines[j].strip() and lines[j][0] in ' \t':
                val = lines[j].strip()
                if val and not val.startswith('key:') and not val.startswith('api name'):
                    values.append(val)
                j += 1
            slot_names = list(slots.keys())
            for idx, slot_name in enumerate(slot_names):
                if idx < len(values):
                    result[slot_name] = values[idx]
            break
    i += 1

print(json.dumps({'format_version': '1.0', 'credentials': result}))
" "$CREDS_FILE")

RESP=$(curl -sf -X POST "$API/v1/tenants/$TENANT_ID/credentials/import/bundle" \
    -H "Content-Type: application/json" \
    -d "$BUNDLE")

IMPORTED=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{d[\"imported_count\"]} imported, {d[\"skipped_count\"]} skipped')")
echo "Credentials loaded for tenant $TENANT_ID: $IMPORTED"

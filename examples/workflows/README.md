# EXPOSE Workflow Examples

Shell scripts demonstrating end-to-end EXPOSE workflows using `curl` against
the REST API. Each script is self-contained with inline documentation and
expected output in comments.

## Scripts

| Script | Description | Prerequisites |
|--------|-------------|---------------|
| `basic-scan.sh` | Complete scan lifecycle: create tenant, configure seeds, trigger scan, poll for completion, view findings, export graph | EXPOSE API running |
| `scheduled-monitoring.sh` | Set up recurring scans with cron scheduling, view run history and deltas between scans | Tenant created (via `basic-scan.sh`) |
| `siem-integration.sh` | Configure Splunk HEC adapter, verify connectivity, trigger scan with SIEM delivery, verify event ingestion | Tenant created, Splunk HEC endpoint |
| `eval-rulepack.sh` | Run the eval harness against labeled datasets, view P/R/F1 metrics, inspect confusion matrix, compare rule pack versions | Python venv activated, eval datasets present |

## Quick Start

```bash
# 1. Start EXPOSE (API + PostgreSQL)
docker compose up -d

# 2. Run a basic scan
chmod +x examples/workflows/basic-scan.sh
./examples/workflows/basic-scan.sh

# 3. Set up daily monitoring
TENANT_ID="<tenant-id-from-step-2>" ./examples/workflows/scheduled-monitoring.sh

# 4. Connect to Splunk
TENANT_ID="<tenant-id>" \
SPLUNK_HEC_URL="https://splunk.example.com:8088" \
SPLUNK_HEC_TOKEN="your-token" \
./examples/workflows/siem-integration.sh

# 5. Benchmark a rule pack
source .venv/bin/activate
./examples/workflows/eval-rulepack.sh
```

## API Endpoint Reference

All scripts target `http://localhost:8090` by default. The key endpoints used:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/tenants/` | Create a new tenant |
| `PUT` | `/v1/tenants/{id}/config/` | Configure tenant settings |
| `POST` | `/v1/tenants/{id}/seeds/` | Add seed domains/IPs |
| `POST` | `/v1/tenants/{id}/runs/` | Trigger a scan |
| `GET` | `/v1/tenants/{id}/runs/{run_id}` | Check run status |
| `GET` | `/v1/tenants/{id}/findings/` | Get prioritized findings |
| `GET` | `/v1/tenants/{id}/graph` | Get entity relationship graph |
| `GET` | `/v1/tenants/{id}/entities/{eid}/provenance` | Get entity provenance chain |
| `POST` | `/v1/tenants/{id}/schedules/` | Create a scan schedule |
| `POST` | `/v1/tenants/{id}/integrations/siem/` | Configure SIEM adapter |

## Environment Variables

| Variable | Used By | Description |
|----------|---------|-------------|
| `TENANT_ID` | `scheduled-monitoring.sh`, `siem-integration.sh` | Tenant UUID from tenant creation |
| `SPLUNK_HEC_URL` | `siem-integration.sh` | Splunk HEC endpoint URL |
| `SPLUNK_HEC_TOKEN` | `siem-integration.sh` | Splunk HEC authentication token |

## Example Output Files

See `examples/outputs/` for the JSON structures these workflows produce.
Each output file corresponds to a real API response or pipeline artifact.

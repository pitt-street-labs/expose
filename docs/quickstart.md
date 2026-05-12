# EXPOSE -- Quickstart Guide

**Status:** Advisory
**Status:** Current
**Audience:** Developers and operators evaluating EXPOSE for the first time.

This guide walks through installing EXPOSE, running your first scan, and understanding the output. For the full specification, see `docs/SPEC.md`. For architecture diagrams, see `docs/architecture/`.

---

## 1. Installation

EXPOSE requires Python 3.12 or later.

### Using uv (recommended)

```bash
# Clone the repository
git clone https://github.com/pitt-street-labs/expose.git
cd expose

# Install in development mode with all optional dependencies
uv pip install -e ".[all]"
```

### Using pip

```bash
git clone https://github.com/pitt-street-labs/expose.git
cd expose

# Install base package
pip install -e .

# Install with DNS collectors (dnspython)
pip install -e ".[collectors-dns]"

# Install with all optional dependencies (LLM providers + DNS collectors)
pip install -e ".[all]"
```

### Optional dependency groups

| Extra | What it adds |
|---|---|
| `collectors-dns` | `dnspython` -- required for `active-dns-resolve`, `dns-subdomain-enum`, `dns-zone-transfer`, `dns-reverse-ptr`, `dns-blacklist`, `bgp-team-cymru`, `spf-dkim-dmarc`, and `sip-discovery` collectors |
| `llm-anthropic` | Anthropic SDK for LLM-assisted attribution (Phase 2) |
| `llm-openai` | OpenAI SDK for LLM-assisted attribution (Phase 2) |
| `llm-gemini` | Google GenAI SDK for LLM-assisted attribution (Phase 2) |
| `llm-all` | All LLM provider SDKs |
| `all` | Everything above |

---

## 2. First Scan (CLI)

EXPOSE provides a CLI for quick in-process scans. The `expose run start` command accepts a seed value (domain, IP, or CIDR) and auto-detects the seed type.

### Basic domain scan

```bash
# Scan a domain with all Tier-1 collectors
expose run start example.com --tenant 00000000-0000-0000-0000-000000000001
```

The `--tenant` flag accepts any valid UUID. For local testing, any UUID works as a tenant identifier.

### Scan an IP address

```bash
expose run start 93.184.216.34 --tenant 00000000-0000-0000-0000-000000000001
```

### Scan a CIDR block

```bash
expose run start 93.184.216.0/24 --tenant 00000000-0000-0000-0000-000000000001
```

### Selecting specific collectors

```bash
# Use only specific collectors (repeatable flag)
expose run start example.com \
  --tenant 00000000-0000-0000-0000-000000000001 \
  --collector ct-crtsh \
  --collector security-txt
```

### Seed type auto-detection

The CLI automatically detects the seed type from the input value:

| Input | Detected type |
|---|---|
| `example.com` | Domain |
| `93.184.216.34` | IP |
| `93.184.216.0/24` | CIDR |

You can override detection with `--seed-type`:

```bash
expose run start myorg --seed-type organization --tenant <uuid>
```

### Live mode (against real Postgres)

For runs that persist results to a database rather than printing to stdout:

```bash
expose run start example.com \
  --tenant 00000000-0000-0000-0000-000000000001 \
  --live
```

Live mode requires a running PostgreSQL instance configured via the `EXPOSE_DB_*` environment variables (`EXPOSE_DB_HOST`, `EXPOSE_DB_PASSWORD`, `EXPOSE_DB_DATABASE`).

### Run management

```bash
# Check the status of a run
expose run status <run-id> --tenant <uuid>

# List all runs for a tenant
expose run list --tenant <uuid>
```

---

## 3. CLI Command Reference

| Command | Description |
|---|---|
| `expose run start <seed>` | Start a pipeline run for a domain, IP, or CIDR |
| `expose run status <run-id>` | Check the status of a specific run |
| `expose run list` | List all runs for a tenant |
| `expose serve` | Start the EXPOSE API HTTP server |
| `expose demo` | Run a quick demo: create tenant, scan, show results |
| `expose eval` | Run the attribution eval harness against curated datasets |
| `expose db upgrade` | Apply database migrations forward |
| `expose db downgrade` | Roll database migrations backward |
| `expose db current` | Show the current database migration revision |

### Eval harness

The `expose eval` command tests attribution accuracy against curated datasets:

```bash
# Run against a single dataset category
expose eval --dataset confirmed_yours

# Run against all four categories
expose eval --all --rulepack examples/rulepacks/example-baseline.json

# Output as JSON
expose eval --all --json-output

# Custom pass threshold (default: 0.80)
expose eval --all --threshold 0.90
```

Dataset categories: `confirmed_yours`, `confirmed_not_yours`, `ambiguous`, `adversarial` (in `examples/eval-datasets/`).

---

## 4. Understanding the Output

### Observations

Each collector yields **observations** -- structured evidence records with a consistent schema:

```
collector_id:      ct-crtsh
observation_type:  CT_LOG_ENTRY
subject:           certificate_fingerprint: 3a4b5c6d...
observed_at:       2026-05-10T14:30:00Z
payload:
  issuer_name:     Let's Encrypt Authority X3
  common_name:     example.com
  sans:            [example.com, www.example.com]
  serial_number:   3a4b5c6d7e8f...
  not_before:      2026-04-10T00:00:00
  not_after:       2026-07-09T00:00:00
```

### The canonical artifact

When a run completes, EXPOSE assembles the collected observations into a **canonical artifact** -- a signed, versioned JSON document that is the pipeline's deliverable. The artifact schema is defined in `schemas/canonical-artifact-v1.json` and includes:

- **Metadata** -- run ID, tenant ID, timestamps, engine version.
- **Targets** -- the input seeds and discovered entities, each with an attribution tier.
- **Observations** -- all evidence collected, organized by collector.
- **Collector health** -- per-collector health check results.
- **Manifest** -- cryptographic integrity envelope (SHA-256 content hash).

### Observation types

| Type | Description | Produced by |
|---|---|---|
| `CT_LOG_ENTRY` | Certificate Transparency log entry | ct-crtsh, ct-censys, ct-certspotter, ct-certstream |
| `CLOUD_IP_RANGE` | IP matched to cloud provider range | cloud-ranges, cloud-storage-exposure |
| `RDAP_REGISTRATION` | Domain/IP registration data | rdap-whois |
| `BGP_ASN_LOOKUP` | BGP routing and ASN information | bgp-he-toolkit, bgp-ripestat, bgp-team-cymru |
| `DNS_RECORD` | DNS record data | spf-dkim-dmarc, dns-chaos, dns-zone-transfer, dns-reverse-ptr, dns-blacklist, sip-discovery, dns-passive-history |
| `DNS_RESOLUTION` | Active DNS resolution results | active-dns-resolve, dns-subdomain-enum |
| `TLS_HANDSHAKE` | TLS certificate and session metadata | active-tls-handshake |
| `HTTP_RESPONSE` | HTTP response fingerprint | active-http-fingerprint, favicon-hash, robots-txt, security-txt, waf-detection, screenshot-vision, waf-origin-discovery, wayback-machine, common-crawl, mail-headers |
| `PORT_SCAN_RESULT` | TCP port surface scan | active-port-surface, scan-shodan, scan-censys, scan-binaryedge |
| `SCANNER_HOST` | External data source match | github-exposed, scan-shodan, scan-censys, scan-binaryedge, ma-discovery, wikipedia-edits, paste-monitor, otx-alienvault, mail-headers, dark-web-indicators |
| `PASSIVE_DNS` | Historical DNS resolution | dns-passive-history, otx-alienvault, git-commit-emails |

---

## 5. Running the API Server

EXPOSE includes a FastAPI-based HTTP API with a built-in web UI dashboard:

```bash
# Start the server (default: 0.0.0.0:8090)
expose serve

# With custom host and port
expose serve --host 127.0.0.1 --port 9000

# Development mode with auto-reload
expose serve --reload

# Disable OpenTelemetry console output
expose serve --no-otel
```

### Database setup

Before starting the server, set up the database:

```bash
# Set required environment variables
export EXPOSE_DB_HOST=localhost
export EXPOSE_DB_PASSWORD=expose-dev
export EXPOSE_DB_DATABASE=expose

# Apply migrations
expose db upgrade
```

---

## 6. API Endpoint Catalog

### Tenants

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/tenants/` | Create a tenant |
| `GET` | `/v1/tenants/` | List all tenants |
| `GET` | `/v1/tenants/{tenant_id}` | Get tenant details |
| `PATCH` | `/v1/tenants/{tenant_id}` | Update a tenant |
| `DELETE` | `/v1/tenants/{tenant_id}` | Delete a tenant |

### Tenant Configuration

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/tenants/{tenant_id}/config/` | Get tenant configuration |
| `PUT` | `/v1/tenants/{tenant_id}/config/` | Replace tenant configuration |
| `PATCH` | `/v1/tenants/{tenant_id}/config/` | Patch tenant configuration |

### Runs

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/tenants/{tenant_id}/runs` | Start a new scan run |
| `GET` | `/v1/tenants/{tenant_id}/runs` | List runs for a tenant |
| `GET` | `/v1/tenants/{tenant_id}/runs/{run_id}` | Get run status and results |
| `GET` | `/v1/tenants/{tenant_id}/runs/{run_id}/log` | Get the run event log |
| `GET` | `/v1/tenants/{tenant_id}/runs/{run_id}/events` | Server-sent events stream (SSE) |

### Entities and Graph

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/tenants/{tenant_id}/entities` | List discovered entities |
| `GET` | `/v1/tenants/{tenant_id}/graph` | Get the observation graph (D3 format) |

### Findings

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/tenants/{tenant_id}/findings/` | List findings with filtering and pagination |

### Provenance

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/tenants/{tenant_id}/entities/{entity_id}/provenance` | Get provenance chain for an entity |

### Credentials

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/tenants/{tenant_id}/credentials/` | List credential status (no secret values) |
| `POST` | `/v1/tenants/{tenant_id}/credentials/import/spiderfoot` | Import credentials from SpiderFoot format |
| `POST` | `/v1/tenants/{tenant_id}/credentials/import/bundle` | Import a credential bundle |
| `GET` | `/v1/tenants/{tenant_id}/credentials/export/bundle` | Export credential bundle |
| `POST` | `/v1/tenants/{tenant_id}/credentials/{credential_id}/test` | Test a credential |

### Export

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/tenants/{tenant_id}/export/csv` | Export findings as CSV |

### Scheduler

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/scheduler/schedules` | Create a scan schedule |
| `GET` | `/v1/scheduler/schedules` | List all schedules |
| `GET` | `/v1/scheduler/schedules/{tenant_id}` | Get schedule for a tenant |
| `DELETE` | `/v1/scheduler/schedules/{tenant_id}` | Delete a schedule |

### Webhooks

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/tenants/{tenant_id}/webhooks/` | List webhooks |
| `POST` | `/v1/tenants/{tenant_id}/webhooks/` | Create a webhook |
| `DELETE` | `/v1/tenants/{tenant_id}/webhooks/{webhook_id}` | Delete a webhook |
| `POST` | `/v1/tenants/{tenant_id}/webhooks/{webhook_id}/test` | Test a webhook |

### Admin

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/admin/runs/{run_id}/cancel` | Cancel a running scan |
| `DELETE` | `/v1/admin/runs/{run_id}` | Delete a run record |
| `GET` | `/v1/admin/stats` | Get system statistics |
| `GET` | `/v1/admin/scan-estimate` | Estimate scan duration |
| `GET` | `/v1/admin/org-suggest` | Get organization name suggestions |

### RBAC

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/tenants/{tenant_id}/users/` | List users for a tenant |
| `POST` | `/v1/tenants/{tenant_id}/users/` | Add a user to a tenant |
| `DELETE` | `/v1/tenants/{tenant_id}/users/{user_id}` | Remove a user from a tenant |
| `GET` | `/v1/tenants/{tenant_id}/users/{user_id}/permissions` | Get user permissions |

### Health

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Health check endpoint |

---

## 7. End-to-End Example

This example uses the API to create a tenant, provision credentials, trigger a scan, and inspect results.

### Step 1: Start the server

```bash
# Terminal 1: Start PostgreSQL (via docker-compose or local)
docker compose up -d postgres

# Terminal 2: Apply migrations and start the server
export EXPOSE_DB_HOST=localhost
export EXPOSE_DB_PASSWORD=expose-dev
export EXPOSE_DB_DATABASE=expose
expose db upgrade
expose serve
```

### Step 2: Create a tenant

```bash
curl -s -X POST http://localhost:8090/v1/tenants/ \
  -H "Content-Type: application/json" \
  -d '{"name": "acme-corp"}' | jq .
```

```json
{
  "id": "a1b2c3d4-...",
  "name": "acme-corp",
  "created_at": "2026-05-11T12:00:00Z"
}
```

Save the tenant ID:

```bash
TENANT_ID="a1b2c3d4-..."
```

### Step 3: Provision credentials (optional)

For collectors that require API keys (Shodan, Censys, SecurityTrails, etc.), import credentials:

```bash
# Import from SpiderFoot credential file
curl -s -X POST "http://localhost:8090/v1/tenants/${TENANT_ID}/credentials/import/spiderfoot" \
  -H "Content-Type: application/json" \
  -d '{"credentials_text": "sfp_shodan:api_key=YOUR_KEY_HERE\n..."}' | jq .

# Or import a credential bundle
curl -s -X POST "http://localhost:8090/v1/tenants/${TENANT_ID}/credentials/import/bundle" \
  -H "Content-Type: application/json" \
  -d '{"credentials": [{"collector_id": "scan-shodan", "key": "shodan_api_key", "value": "YOUR_KEY"}]}' | jq .
```

Credentials persist to `~/.expose-credentials.json` and survive server restarts.

### Step 4: Configure the tenant (optional)

Enable LLM-assisted attribution:

```bash
curl -s -X PUT "http://localhost:8090/v1/tenants/${TENANT_ID}/config/" \
  -H "Content-Type: application/json" \
  -d '{
    "llm_enabled": true,
    "llm_provider": "gemini",
    "llm_model": "gemini-2.5-flash",
    "llm_cost_ceiling_per_run": 1.0
  }' | jq .
```

Note: tenant config is in-memory and must be re-applied after server restarts.

### Step 5: Trigger a scan

```bash
curl -s -X POST "http://localhost:8090/v1/tenants/${TENANT_ID}/runs" \
  -H "Content-Type: application/json" \
  -d '{"seeds": ["example.com"]}' | jq .
```

```json
{
  "run_id": "e5f6a7b8-...",
  "state": "pending"
}
```

### Step 6: Monitor progress

```bash
RUN_ID="e5f6a7b8-..."

# Poll run status
curl -s "http://localhost:8090/v1/tenants/${TENANT_ID}/runs/${RUN_ID}" | jq '.state'

# Or use the SSE stream for real-time events
curl -N "http://localhost:8090/v1/tenants/${TENANT_ID}/runs/${RUN_ID}/events"
```

### Step 7: View results

```bash
# List discovered entities
curl -s "http://localhost:8090/v1/tenants/${TENANT_ID}/entities" | jq .

# Get the observation graph (D3 format for visualization)
curl -s "http://localhost:8090/v1/tenants/${TENANT_ID}/graph" | jq .

# List findings with optional filtering
curl -s "http://localhost:8090/v1/tenants/${TENANT_ID}/findings/" | jq .

# Export as CSV
curl -s "http://localhost:8090/v1/tenants/${TENANT_ID}/export/csv" -o findings.csv

# View the run event log
curl -s "http://localhost:8090/v1/tenants/${TENANT_ID}/runs/${RUN_ID}/log" | jq .
```

### Step 8: Open the dashboard

Navigate to `http://localhost:8090/` in a browser to see the interactive web UI with the D3 observation graph, scan log, findings panel, and entity detail views.

### Quick demo (one command)

For a fully automated demo against a running server:

```bash
expose demo --host localhost --port 8090
```

This creates a demo tenant, scans `example.com`, polls until completion, and displays the discovered entity count.

---

## 8. Configuring Collectors

### Collector tiers

Collectors are classified into three tiers based on the sensitivity of the data-collection method:

- **Tier 1 (Passive, Broad):** Query public databases. No target contact. Always safe to run. (24 collectors)
- **Tier 2 (Passive, Targeted):** Query public APIs about specific discovered entities. (9 collectors)
- **Tier 3 (Active, Attribution-Gated):** Send packets to the target. Gated by attribution tier or explicit authorization scope. (8 collectors)

For the full catalog of all 41 built-in collectors with detailed payload documentation, see `docs/collectors.md`.

### Tier-3 authorization gating

Tier-3 collectors will only execute against entities that meet one of two conditions:

1. The entity's attribution tier is `confirmed` or `high`.
2. The entity is explicitly listed in the tenant's authorization scope.

This prevents EXPOSE from probing infrastructure that may not belong to the target organization. The enforcement mode (`medium` or `hard`) is configured per tenant.

### Optional collector dependencies

Some collectors require optional Python packages:

```bash
# DNS-based collectors (8 collectors)
pip install -e ".[collectors-dns]"
```

Collectors that depend on optional packages import cleanly when the package is absent. They raise a clear error message with installation instructions if invoked without the required dependency.

---

## 9. Multi-Tenant Setup

EXPOSE is designed for multi-tenancy from the ground up (per ADR-007). Each tenant has isolated:

- **Seeds and observations** -- all data is scoped by `tenant_id` (UUID).
- **Collector configuration** -- which collectors are enabled, rate limits, timeouts.
- **Authorization scope** -- which domains, IPs, ASNs, and cloud accounts the tenant is authorized to scan.
- **Credentials** -- per-tenant secrets stored in the configured secrets backend.

### Setting up a tenant

For local development, the CLI accepts any UUID as a tenant identifier. In a production deployment:

1. Create the tenant via the API: `POST /v1/tenants/`.
2. Configure the tenant's authorization scope (apex domains, IP ranges, ASN numbers).
3. Store collector credentials via the credentials API or in the secrets backend using the key convention `collector.{collector_id}.{key_name}`.
4. Optionally configure LLM attribution via `PUT /v1/tenants/{tenant_id}/config/`.
5. Optionally set up a scan schedule via `POST /v1/scheduler/schedules`.
6. Optionally configure webhooks for run completion notifications via `POST /v1/tenants/{tenant_id}/webhooks/`.
7. Start runs via the API or CLI.

### Secrets backends

| Backend | Configuration | Best for |
|---|---|---|
| In-Memory | Default for testing | Local development |
| Environment Variables | `EXPOSE_SECRETS_BACKEND=env` | Kubernetes with mounted secrets |
| HashiCorp Vault | `EXPOSE_SECRETS_BACKEND=vault` | Production deployments |

---

## 10. Next Steps

- **Full specification:** `docs/SPEC.md` -- the locked, authoritative system design.
- **Architecture diagrams:** `docs/architecture/` -- nine Mermaid diagrams covering pipeline stages, deployment topology, observation graph, multi-tenancy, egress profiles, and more.
- **ADRs:** `docs/adr/` -- ten architecture decision records covering data model, database, observability, LLM integration, multi-tenancy, authorized use, open-core licensing, and FIPS crypto.
- **Collector catalog:** `docs/collectors.md` -- detailed documentation for all 41 built-in collectors across 10 categories.
- **Strategic positioning:** `docs/positioning.md` -- how EXPOSE fits in the EASM market.
- **Contributing:** `CONTRIBUTING.md` -- development setup, testing, and pull request process.
- **Use cases:** `docs/use-cases.md` -- practical deployment scenarios.
- **Eval datasets:** `examples/eval-datasets/` -- four categories of attribution test cases.
- **Rule packs:** `examples/rulepacks/` -- three example rule pack configurations.

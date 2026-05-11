# EXPOSE User Guide

_Reference guide for operators and security analysts deploying and using EXPOSE._

**Version:** 0.1.0-dev | **Audience:** Security operators, CTEM analysts, red team leads

---

## Getting Started

### Prerequisites

| Requirement | Minimum |
|---|---|
| Python | 3.12+ |
| PostgreSQL | 16+ (required for persistent runs and the API server) |
| Docker + Compose | Optional -- for containerized deployment |
| Kubernetes + Helm | Optional -- for production/multi-tenant deployment |
| cosign | Optional -- for artifact signature verification |

### Installation (pip)

```bash
git clone https://github.com/korlogos/expose.git
cd expose

# Base install
pip install -e .

# With DNS collectors (active-dns-resolve, bgp-team-cymru, spf-dkim-dmarc)
pip install -e ".[collectors-dns]"

# With all optional dependencies (DNS + LLM providers)
pip install -e ".[all]"
```

Optional dependency groups:

| Extra | Adds |
|---|---|
| `collectors-dns` | `dnspython` for DNS-based collectors |
| `llm-anthropic` | Anthropic SDK (Claude) |
| `llm-openai` | OpenAI SDK |
| `llm-gemini` | Google GenAI SDK (Gemini) |
| `llm-all` | All LLM provider SDKs |
| `all` | Everything above |

### Installation (Docker Compose)

The quickest path to a working EXPOSE instance with database persistence:

```bash
git clone https://github.com/korlogos/expose.git
cd expose

# Start Postgres + API server
docker compose up -d

# The API is now available at http://localhost:8090
# The dashboard is at http://localhost:8090/
```

Docker Compose starts two services:

| Service | Purpose | Port |
|---|---|---|
| `postgres` | PostgreSQL 16 (data persistence) | 5432 |
| `api` | EXPOSE API + dashboard (runs migrations on startup) | 8090 |

### Installation (Kubernetes / Helm)

```bash
helm install expose ./deploy/helm-chart \
  --namespace expose --create-namespace \
  --values your-values.yaml
```

Key Helm values to configure:

```yaml
# Container image
image:
  repository: expose
  tag: "0.1.0"

# External Postgres (required for production)
postgres:
  enabled: false
  host: "your-postgres-host"
  port: 5432
  database: "expose"
  existingSecret: "expose-db-credentials"
  sslmode: "require"

# Scanner egress profile
scannerWorker:
  egressProfile:
    type: "direct"  # direct | socks5 | wireguard | http_connect
    config: {}

# LLM enrichment (off by default)
llmWorker:
  enabled: false
  provider: "ollama"
  costCeilingUSD: 5.00

# Run scheduling
runSchedule:
  defaultCron: "0 2 * * *"  # 02:00 UTC daily
```

### First Scan

Run a basic discovery scan from the CLI:

```bash
# Scan a domain with all Tier-1 (passive) collectors
expose run start example.com \
  --tenant 00000000-0000-0000-0000-000000000001

# Scan an IP address
expose run start 93.184.216.34 \
  --tenant 00000000-0000-0000-0000-000000000001

# Scan a CIDR block
expose run start 93.184.216.0/24 \
  --tenant 00000000-0000-0000-0000-000000000001

# Run against a real database (persistent results)
expose run start example.com \
  --tenant 00000000-0000-0000-0000-000000000001 --live
```

Seed type is auto-detected from the input value. Override with `--seed-type domain|ip|cidr` if needed.

To use the API instead of the CLI:

```bash
# Start the server
expose serve --port 8090

# Run the interactive demo (creates tenant, scans example.com, shows results)
expose demo --port 8090
```

---

## Dashboard

### Overview

The EXPOSE dashboard (served at the API root `/`) is a dark-themed single-page interface built with Alpine.js, D3.js, and HTMX. It provides real-time visibility into scans and discovered entities.

### Running a Scan

1. Select a tenant from the dropdown in the top bar.
2. Enter a seed value (domain, IP, or CIDR) in the **Start Scan** form.
3. Click **Scan**. The status bar updates with live progress via Server-Sent Events.

### Entity Table

The right pane displays all discovered entities for the selected tenant. Each row shows:

- Entity identifier (domain, IP, certificate fingerprint)
- Entity type (domain, ip_address, certificate, organization)
- Attribution tier (confirmed, high, medium, requires_review)
- Confidence score

Use the filter input to search by identifier or type. The table auto-refreshes every 5 seconds during active runs.

### Observation Graph

The left pane renders a D3 force-directed graph of discovered entities and their relationships. Node colors indicate attribution status:

| Color | Meaning |
|---|---|
| Seed | Operator-provided input seeds |
| Discovered | Newly found, unattributed |
| Corroborated | Multiple sources confirm existence |
| High | Strong attribution confidence |
| Confirmed | Deterministically attributed to the target |
| Review | Requires operator review |

Toggle between **Force** and **Radial** layouts using the button in the pane header.

### Run Status

The bottom status bar shows:

- **No active run** when idle
- **Streaming live events...** when SSE is connected during a scan
- **Run in progress (polling)** as a fallback if SSE is unavailable

### AI Insights Panel

When an LLM provider is configured, the **Stage 4b AI Insights** panel displays enrichment results:

- **Attribution** -- confidence adjustments with reasoning (original score, adjusted score)
- **Tech stack** -- inferred technologies from HTTP response analysis
- **Noise classification** -- whether an entity is likely a false positive (parked domain, CDN artifact)

This panel only appears when enrichment data exists. See [LLM Enrichment Settings](#llm-enrichment-settings) for configuration.

### Tenant Configuration

Expand the **Tenant Config** panel to view and modify:

- Scope rules (authorization boundary)
- Enabled collectors
- Schedule (cron expression)
- Egress profile
- LLM enrichment settings

### API Key Management

The **API Keys** panel shows all credential slots, their configuration status, and associated collectors. Actions available:

- **Test** -- validate a configured credential against its upstream API
- **Import SpiderFoot** -- paste SpiderFoot-format credential JSON for bulk import
- **Import JSON** -- import an EXPOSE credential bundle
- **Export** -- download masked credentials as JSON

### CSV Export

The **Export** panel appears once entities are discovered. Filter by entity type and attribution tier, then click **Download CSV** to export. CSV columns: `entity_identifier`, `entity_type`, `attribution_tier`, `confidence`, `collectors`, `first_seen`, `last_seen`, `environment`, `risk_summary`.

---

## Collectors

EXPOSE ships 14 built-in collectors across three sensitivity tiers. Tier classification determines when a collector is allowed to run.

### Passive Collectors (Tier 1)

No direct contact with target infrastructure. Safe to run without authorization scope restrictions.

| Collector | ID | Source | Discovers |
|---|---|---|---|
| crt.sh CT Logs | `ct-crtsh` | Certificate Transparency | Subdomains, certificate relationships, issuer chains |
| Certstream CT | `ct-certstream` | crt.sh (recency-filtered) | Recently issued certificates (default: last 24h) |
| RDAP/WHOIS | `rdap-whois` | RDAP bootstrap (RFC 9083) | Registrant org, registrar, nameservers, registration dates |
| Cloud IP Ranges | `cloud-ranges` | AWS/Azure/GCP manifests | Cloud provider, region, and service for IPs |
| BGP (HE Toolkit) | `bgp-he-toolkit` | bgp.he.net | ASN, holder, announced prefixes |
| BGP (RIPEstat) | `bgp-ripestat` | stat.ripe.net API | ASN, holder, announced prefixes |
| BGP (Team Cymru) | `bgp-team-cymru` | Team Cymru DNS | ASN, prefix, country, registry |
| SPF/DKIM/DMARC | `spf-dkim-dmarc` | DNS TXT records | Mail infrastructure, authorized senders, shadow IT |
| GitHub Exposed | `github-exposed` | GitHub Search API | Repos mentioning the target, potential config leaks |

`github-exposed` optionally accepts a GitHub PAT (`api_key` slot) to increase rate limits from 10 to 30 req/min.

### Targeted Collectors (Tier 2)

Query data about specific discovered entities. Still passive (no packets to targets).

| Collector | ID | Source | Discovers |
|---|---|---|---|
| Favicon Hash | `favicon-hash` | Target host HTTP | Favicon SHA-256 hash for cross-host correlation |

### Active Collectors (Tier 3)

Send packets directly to target infrastructure. **Dispatch is attribution-gated:** a Tier-3 collector only runs against entities with `confirmed` or `high` attribution, or entities explicitly listed in the tenant's authorization scope.

| Collector | ID | Source | Discovers |
|---|---|---|---|
| Active DNS | `active-dns-resolve` | System resolver | A/AAAA/CNAME/MX/NS/TXT/SOA records |
| Active TLS | `active-tls-handshake` | TLS handshake (port 443) | Certificate chain, TLS version, cipher suite, JARM stub |
| Active HTTP | `active-http-fingerprint` | HTTP probe (ports 80, 443) | Server header, security headers, redirect chain, page title |
| Active Port Surface | `active-port-surface` | TCP connect (27 ports) | Open ports across common service ports |

Default ports for `active-port-surface`: 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 2222, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 9200, 9443, 27017.

Tier-3 enforcement modes:

| Mode | Behavior |
|---|---|
| `medium` (default) | Denial is advisory; dispatcher logs a warning |
| `hard` | Denial is absolute; dispatcher records a `ScopeRefusalEvent` |

---

## Configuration

### Tenant Configuration

Each tenant has isolated configuration. Retrieve and modify via the API:

```bash
# Get current config
curl http://localhost:8090/v1/tenants/{tenant_id}/config

# Replace entire config
curl -X PUT http://localhost:8090/v1/tenants/{tenant_id}/config \
  -H "Content-Type: application/json" \
  -d '{"scope_rules": [...], "enabled_collectors": ["ct-crtsh", "rdap-whois"]}'

# Patch specific fields
curl -X PATCH http://localhost:8090/v1/tenants/{tenant_id}/config \
  -H "Content-Type: application/json" \
  -d '{"schedule_cron": "0 6 * * 1"}'
```

### Scope Rules (7 Types)

Scope rules define the tenant's authorization boundary. The attribution engine and Tier-3 gating reference these rules.

| Rule Type | Matching Behavior | Example Value |
|---|---|---|
| `apex_domain` | Includes all subdomains and the apex itself | `example.com` |
| `exact_domain` | Exact FQDN match only | `api.internal.example.com` |
| `ip_address` | Single IPv4 or IPv6 address | `93.184.216.34` |
| `cidr` | IP range containment | `93.184.216.0/24` |
| `asn` | ASN string match | `AS13335` |
| `cloud_account` | AWS account ID, Azure subscription, GCP project | `123456789012` |
| `registrant_org` | Case-insensitive substring match on WHOIS registrant | `Example Corp` |

Exclusion rules override inclusions. Set `is_exclusion: true` on a scope rule to explicitly exclude an entity:

```json
{
  "scope_rules": [
    {"rule_type": "apex_domain", "value": "example.com", "is_exclusion": false},
    {"rule_type": "exact_domain", "value": "blog.example.com", "is_exclusion": true}
  ]
}
```

### Collector Selection

Enable specific collectors per tenant:

```json
{
  "enabled_collectors": [
    "ct-crtsh",
    "rdap-whois",
    "cloud-ranges",
    "bgp-ripestat",
    "spf-dkim-dmarc",
    "active-dns-resolve"
  ]
}
```

When no collectors are specified, all Tier-1 collectors are used by default.

### Schedule Configuration (Cron)

Set a cron expression for automatic recurring scans:

```json
{"schedule_cron": "0 2 * * *"}
```

Standard 5-field format: `minute hour day-of-month month day-of-week`. Supports wildcards (`*`), ranges (`1-5`), steps (`*/5`), and comma-separated lists (`1,3,5`).

| Example | Schedule |
|---|---|
| `0 2 * * *` | Daily at 02:00 UTC |
| `0 */6 * * *` | Every 6 hours |
| `0 8 * * 1` | Every Monday at 08:00 UTC |
| `*/30 * * * *` | Every 30 minutes |

Set `null` to disable scheduled runs.

### Egress Profiles

Configure how active collectors route traffic. Four profile types:

| Profile | Use Case |
|---|---|
| `direct` | Default -- connect from the operator's own IP |
| `socks5` | Route through SOCKS5 proxy (Tor, SSH tunnel, microsocks) |
| `wireguard` | Route through WireGuard tunnel to a VPS |
| `http_connect` | Route through HTTP CONNECT proxy (Squid, commercial) |

Configure via tenant config or Helm values. See [Egress Profiles](#egress-profiles-socks5-wireguard-http-connect) for setup details.

### LLM Enrichment Settings

LLM enrichment is off by default and activates only when explicitly configured.

```json
{
  "llm_enabled": true,
  "llm_provider": "ollama",
  "llm_cost_ceiling_per_run": 5.00
}
```

| Provider | Data Residency | Best For |
|---|---|---|
| `anthropic` | Anthropic cloud | Frontier quality (Claude) |
| `openai` | OpenAI cloud | Frontier alternative (GPT) |
| `gemini` | Google cloud | Frontier alternative (Gemini) |
| `ollama` | Operator-local | Air-gapped, data sovereignty, cost control |

Provider credentials are stored via the secrets backend, never in configuration. Cost ceilings are enforced per run -- exceeding the ceiling stops LLM calls for that run without failing the pipeline.

### API Key Management

Collector credentials are managed through the credentials API:

```bash
# List all credential slots and their status
curl http://localhost:8090/v1/tenants/{tenant_id}/credentials/

# Import SpiderFoot credentials
curl -X POST http://localhost:8090/v1/tenants/{tenant_id}/credentials/import/spiderfoot \
  -H "Content-Type: application/json" \
  -d '{"sfp_shodan.api_key": "your-key", "sfp_securitytrails.api_key": "your-key"}'

# Import EXPOSE credential bundle
curl -X POST http://localhost:8090/v1/tenants/{tenant_id}/credentials/import/bundle \
  -H "Content-Type: application/json" \
  -d '{"shodan_api_key": "your-key", "github_token": "ghp_..."}'

# Export (values are masked)
curl http://localhost:8090/v1/tenants/{tenant_id}/credentials/export/bundle

# Test a credential
curl -X POST http://localhost:8090/v1/tenants/{tenant_id}/credentials/{credential_id}/test
```

Secrets backends:

| Backend | Config | Use Case |
|---|---|---|
| In-Memory | Default | Development and testing |
| Environment Variables | `EXPOSE_SECRETS_BACKEND=env` | Kubernetes with mounted secrets |
| HashiCorp Vault | `EXPOSE_SECRETS_BACKEND=vault` | Production deployments |

---

## Analysis Features

### Attribution Engine

EXPOSE uses an 8-rule-type scope matcher to produce confidence tiers with full evidence chains. Every attribution decision links back to the specific observations and rules that justified it.

| Tier | Confidence Range | Meaning |
|---|---|---|
| `confirmed` | >= 0.9 | Deterministically attributed via scope rules |
| `high` | 0.7 -- 0.9 | Strong multi-source corroboration |
| `medium` | 0.4 -- 0.7 | Single-source or partial match |
| `requires_review` | < 0.4 | Insufficient evidence for automated attribution |

Rule packs are declarative JSON files validated against the `rulepack-v1.json` schema. Three example packs ship with EXPOSE: `baseline`, `cloud-first`, and `conservative` (in `examples/rulepacks/`).

### Trust Degradation Detection

Monitors how attribution confidence changes across runs as infrastructure shifts. Entities whose confidence drops between runs are flagged for review -- indicating potential infrastructure changes, domain transfers, or hosting migrations.

### Environment Classification

Classifies discovered entities into environment categories (production, staging, development, internal) based on naming patterns, certificate characteristics, and HTTP response indicators.

### WAF/CDN Detection

Identifies entities behind WAF and CDN layers (Cloudflare, Akamai, AWS CloudFront) using HTTP header analysis, certificate issuer patterns, and response characteristics. Flags cases where the observed asset may differ from the origin server.

### M&A Extended Search

When configured with multiple apex domains or registrant organizations, the attribution engine correlates entities across organizational boundaries -- useful for post-acquisition attack surface consolidation.

### SaaS Product Alignment

SPF/DKIM/DMARC analysis reveals authorized third-party senders (SaaS platforms sending as the organization). The `spf-dkim-dmarc` collector extracts SPF include mechanisms to identify shadow IT.

### DNSBL Reputation Checks

IP addresses are checked against DNS-based blocklists to identify IPs with poor reputation that may indicate compromised infrastructure or shared hosting with malicious neighbors.

---

## API Reference

### Authentication

The API uses bearer token authentication. Include the token in the `Authorization` header:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8090/v1/tenants/
```

The health endpoint (`/healthz`) does not require authentication.

### Tenants

```bash
# Create a tenant
curl -X POST http://localhost:8090/v1/tenants/ \
  -H "Content-Type: application/json" \
  -d '{"name": "acme-corp"}'
# Response: 201 {"id": "<uuid>", "name": "acme-corp", ...}

# List tenants
curl http://localhost:8090/v1/tenants/

# Get a tenant
curl http://localhost:8090/v1/tenants/{tenant_id}

# Update a tenant
curl -X PATCH http://localhost:8090/v1/tenants/{tenant_id} \
  -H "Content-Type: application/json" \
  -d '{"state": "active"}'

# Delete a tenant
curl -X DELETE http://localhost:8090/v1/tenants/{tenant_id}
# Response: 204
```

### Runs

```bash
# Start a scan
curl -X POST http://localhost:8090/v1/tenants/{tenant_id}/runs \
  -H "Content-Type: application/json" \
  -d '{"seeds": ["example.com"]}'
# Response: 202 {"run_id": "<uuid>"}

# List runs
curl http://localhost:8090/v1/tenants/{tenant_id}/runs

# Get run status
curl http://localhost:8090/v1/tenants/{tenant_id}/runs/{run_id}

# List discovered entities
curl http://localhost:8090/v1/tenants/{tenant_id}/entities

# Get a specific entity
curl http://localhost:8090/v1/tenants/{tenant_id}/entities/{entity_id}
```

Run states: `pending` -> `running` -> `completed` | `partial` | `failed`.

### Graph

```bash
# Get the observation graph (D3-compatible nodes and edges)
curl http://localhost:8090/v1/tenants/{tenant_id}/graph
```

Returns `nodes` (entities with attribution status and confidence) and `edges` (relationships with collector IDs and observation types).

### Events (SSE)

```bash
# Stream real-time events for a run
curl -N http://localhost:8090/v1/tenants/{tenant_id}/runs/{run_id}/events
```

Event types: `collector_started`, `collector_completed`, `entity_discovered`, `run_completed`. The stream auto-closes on `run_completed` or client disconnect.

### Export

```bash
# Export entities as CSV (with optional filters)
curl "http://localhost:8090/v1/tenants/{tenant_id}/export/csv?entity_type=domain&attribution_tier=confirmed&limit=1000" \
  -o export.csv
```

Query parameters (all optional):

| Parameter | Values | Default |
|---|---|---|
| `entity_type` | `domain`, `ip_address`, `certificate`, `organization` | All |
| `attribution_tier` | `confirmed`, `high`, `medium`, `requires_review` | All |
| `limit` | 1 -- 10,000 | 10,000 |

### Webhooks

Webhook integration is planned for v0.2. Operators will be able to register HTTP callbacks for run lifecycle events.

### Credentials

See [API Key Management](#api-key-management) for the full credentials API.

---

## Advanced Topics

### Egress Profiles (SOCKS5, WireGuard, HTTP CONNECT)

Active collectors contact target infrastructure directly. Egress profiles control the exit point for this traffic.

**SOCKS5 (Tor gateway example):**

```yaml
# Helm values
scannerWorker:
  egressProfile:
    type: socks5
    config:
      proxyUrl: "socks5://egress-gateway.internal:10899"
      dnsThroughProxy: true
```

DNS leak prevention: EXPOSE rewrites `socks5://` to `socks5h://` by default, ensuring hostname resolution occurs at the proxy, not on the operator's host.

**WireGuard:**

```yaml
scannerWorker:
  egressProfile:
    type: wireguard
    config:
      interfaceName: wg0
      sourceAddress: "10.0.0.2"
```

Health check reads `/sys/class/net/wg0/operstate`. WireGuard interfaces report `unknown` when up (this is normal behavior).

**HTTP CONNECT (commercial proxy):**

```yaml
scannerWorker:
  egressProfile:
    type: http_connect
    config:
      proxyUrl: "http://user:pass@proxy.provider.com:7777"
```

**Choosing the right profile:**

| Need | Profile |
|---|---|
| Lab/internal use, passive only | `direct` |
| Anonymity over fidelity | `socks5` (Tor) |
| Clean IP, moderate cost | `wireguard` (cloud VPS) |
| Best fidelity + anonymity | `http_connect` (residential proxy) |

Note: Tor exit IPs are publicly listed. Targets may block or serve altered content to known Tor exits. For production scanning, prefer WireGuard or commercial proxies.

### Artifact Signing and Verification

EXPOSE produces cryptographically signed artifacts with FIPS SHA-256 content hashing. Verify with cosign:

```bash
# Verify an artifact signature
cosign verify-blob --key cosign.pub \
  --signature canonical.json.gz.sig canonical.json.gz
```

Each artifact includes a manifest with provenance metadata: run ID, tenant ID, timestamps, engine version, collector health, and content hash. SLSA Level 2+ attestations are planned for v0.2.

### Multi-Tenant Deployment

Every resource in EXPOSE is scoped by `tenant_id` (UUID). Tenants are fully isolated:

- Separate seed sets and observation graphs
- Independent collector configurations and rate limits
- Per-tenant authorization scope
- Isolated credential storage in the secrets backend
- Per-tenant quota enforcement and misuse detection

Create tenants via the API, then configure each tenant's scope, collectors, and credentials independently.

### Air-Gapped Deployment

EXPOSE supports fully offline operation:

1. Use only passive collectors with pre-cached data (CT log exports, WHOIS bulk data, cloud IP range manifests).
2. Configure the `direct` egress profile. Disable Tier-3 active collectors.
3. Use the Ollama LLM provider with a locally hosted model for enrichment (or disable LLM entirely).
4. No external API dependencies after initial data import.

For the Ollama provider: lab-validated models include Qwen 2.5 7B and Llama 3.1 8B at Q4_K_M quantization.

### Cost Management (LLM Ceilings)

The `CostTracker` enforces a hard per-run cost ceiling:

- **Default:** $10.00 per run (configurable via `llm_cost_ceiling_per_run`)
- Every LLM call logs `cost_estimate_usd` to the audit trail
- When accumulated cost exceeds the ceiling, `CostCeilingExceededError` stops LLM calls for the remainder of the run (the pipeline continues without enrichment)

Enrichment triggers are bounded by design -- only entities in specific confidence bands are enriched:

| Enrichment Type | Trigger |
|---|---|
| Attribution analysis | Entities with confidence 0.4 -- 0.7 |
| Tech-stack inference | Entities from `active-http-fingerprint` collector |
| Noise classification | Entities with confidence < 0.4 |

---

## Troubleshooting

### Common Issues

**"Cannot connect to Postgres"**

The API server and `--live` CLI mode require a running PostgreSQL instance. Set environment variables:

```bash
export EXPOSE_DB_HOST=localhost
export EXPOSE_DB_PORT=5432
export EXPOSE_DB_DATABASE=expose
export EXPOSE_DB_USER=expose
export EXPOSE_DB_PASSWORD=expose-dev
```

Or use Docker Compose, which configures these automatically.

**"No runs found for tenant"**

The CLI stub mode (without `--live`) stores runs in-memory for the current process only. Use `--live` mode with a database for persistent run records, or use the API server.

**Tier-3 collector dispatches denied**

Active collectors require entities to have `confirmed` or `high` attribution, or be in the tenant's authorization scope. Check:

1. The entity's attribution tier (`GET /v1/tenants/{tenant_id}/entities/{entity_id}`)
2. The tenant's scope rules (`GET /v1/tenants/{tenant_id}/config`)
3. The enforcement mode (`medium` logs warnings, `hard` blocks entirely)

**LLM enrichment not appearing**

- Verify a provider is configured (`llm_enabled: true` in tenant config)
- Check that provider credentials are set in the secrets backend
- Review per-run cost ceiling -- enrichment stops if the ceiling is reached
- Only entities in the trigger confidence bands are enriched (see [Cost Management](#cost-management-llm-ceilings))

**DNS collectors failing with import errors**

Install the optional DNS dependency:

```bash
pip install -e ".[collectors-dns]"
```

### Logs

EXPOSE uses `structlog` for structured JSON logging. Key fields in log entries:

| Field | Description |
|---|---|
| `tenant_id` | Tenant scope for the operation |
| `run_id` | Pipeline run identifier |
| `collector_id` | Collector that produced the log entry |
| `event` | Structured event name |
| `duration_ms` | Operation duration |

For LLM calls, additional fields: `provider_id`, `model`, `input_tokens`, `output_tokens`, `cost_estimate_usd`, `enrichment_type`.

OpenTelemetry tracing is enabled by default. Disable with `expose serve --no-otel` for local development.

### Health Checks

```bash
# API liveness probe (no database dependency)
curl http://localhost:8090/healthz
# {"status": "ok"}

# Database migration status
expose db current
```

Collector health checks run at the start of each pipeline run. Collectors that fail their health check are skipped for that run. Health check results are recorded in the canonical artifact.

For egress profile health:

| Profile | Health Check |
|---|---|
| Direct | Always healthy |
| SOCKS5 | TCP connect to proxy host:port |
| WireGuard | Interface operstate in `/sys/class/net/<iface>/operstate` |
| HTTP CONNECT | TCP connect to proxy host:port |

# EXPOSE User Guide

_Comprehensive feature walkthrough for operators and security analysts deploying and using EXPOSE._

**Version:** 0.1.0-dev | **Audience:** Security operators, CTEM analysts, red team leads

---

## 1. Getting Started

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
git clone https://github.com/pitt-street-labs/expose.git
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
git clone https://github.com/pitt-street-labs/expose.git
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

### Configuration

EXPOSE is configured through environment variables, the tenant configuration API, and Helm values. The following environment variables control the database connection (required for persistent operation):

| Variable | Default | Description |
|---|---|---|
| `EXPOSE_DB_HOST` | `localhost` | PostgreSQL host |
| `EXPOSE_DB_PORT` | `5432` | PostgreSQL port |
| `EXPOSE_DB_DATABASE` | `expose` | Database name |
| `EXPOSE_DB_USER` | `expose` | Database user |
| `EXPOSE_DB_PASSWORD` | (empty) | Database password |
| `EXPOSE_SECRETS_BACKEND` | `memory` | Secrets backend: `memory`, `env`, or `vault` |
| `EXPOSE_NO_OTEL` | (unset) | Set to `1` to disable OpenTelemetry |

Docker Compose configures these automatically. For manual or Kubernetes deployments, set them as environment variables or mount a `.env` file.

### Creating Your First Tenant

Every resource in EXPOSE is scoped by a tenant. Create one via the API or the interactive demo:

**Via API:**

```bash
# Start the server
expose serve --port 8090

# Create a tenant
curl -X POST http://localhost:8090/v1/tenants/ \
  -H "Content-Type: application/json" \
  -d '{"name": "acme-corp"}'
# Response: 201 {"id": "<uuid>", "name": "acme-corp", "state": "active", ...}
```

**Via interactive demo (creates a tenant, scans example.com, and shows results):**

```bash
expose serve --port 8090 &
expose demo --port 8090
```

Tenant states follow a lifecycle: `active` (default) -> `suspended` (via PATCH) -> `pending_deletion` (via DELETE). Only active tenants can run scans.

### Provisioning API Credentials

EXPOSE collectors use upstream API keys (Shodan, Censys, SecurityTrails, etc.) for enriched results. Three import methods are available:

**SpiderFoot import** -- bulk import from existing SpiderFoot credential JSON:

```bash
curl -X POST http://localhost:8090/v1/tenants/{tenant_id}/credentials/import/spiderfoot \
  -H "Content-Type: application/json" \
  -d '{
    "credentials": {
      "sfp_shodan.api_key": "your-shodan-key",
      "sfp_securitytrails.api_key": "your-st-key",
      "sfp_virustotal.api_key": "your-vt-key"
    }
  }'
```

**Native bundle import** -- import using EXPOSE credential slot IDs:

```bash
curl -X POST http://localhost:8090/v1/tenants/{tenant_id}/credentials/import/bundle \
  -H "Content-Type: application/json" \
  -d '{
    "credentials": {
      "shodan_api_key": "your-shodan-key",
      "censys_api_id": "your-censys-id",
      "censys_api_secret": "your-censys-secret",
      "github_token": "ghp_...",
      "binaryedge_api_key": "your-be-key",
      "securitytrails_api_key": "your-st-key",
      "chaos_api_key": "your-chaos-key"
    }
  }'
```

**Manual per-slot** -- configure individual credential slots through the dashboard's API Keys panel. Use the **Test** button to validate each credential against its upstream API.

Available credential slots:

| Slot ID | Display Name | Collector(s) |
|---|---|---|
| `shodan_api_key` | Shodan API Key | `shodan-iwide` |
| `securitytrails_api_key` | SecurityTrails API Key | `pdns-securitytrails` |
| `virustotal_api_key` | VirusTotal API Key | `dns-passive-history` |
| `censys_api_id` | Censys API ID | `scan-censys` |
| `censys_api_secret` | Censys API Secret | `scan-censys` |
| `binaryedge_api_key` | BinaryEdge API Key | `scan-binaryedge` |
| `github_token` | GitHub Token | `github-exposed` |
| `passivetotal_api_key` | PassiveTotal API Key | `pdns-passivetotal` |
| `greynoise_api_key` | GreyNoise API Key | (future) |
| `urlscan_api_key` | urlscan.io API Key | (future) |
| `chaos_api_key` | ProjectDiscovery Chaos API Key | `dns-chaos` |

Credentials are stored through the configured secrets backend. The in-memory backend persists to `~/.expose-credentials.json` across restarts. For production, use the HashiCorp Vault backend (`EXPOSE_SECRETS_BACKEND=vault`).

---

## 2. Running Scans

### Triggering a Scan via API

Scans are triggered via `POST /v1/tenants/{tenant_id}/runs` and return 202 Accepted immediately. The scan executes asynchronously in the background.

```bash
# Start a scan with domain seeds
curl -X POST http://localhost:8090/v1/tenants/{tenant_id}/runs \
  -H "Content-Type: application/json" \
  -d '{"seeds": ["example.com"]}'
# Response: 202 {"run_id": "<uuid>", "state": "pending", "message": "..."}

# Start a scan with multiple seeds
curl -X POST http://localhost:8090/v1/tenants/{tenant_id}/runs \
  -H "Content-Type: application/json" \
  -d '{"seeds": ["example.com", "93.184.216.34", "93.184.216.0/24"]}'

# Start a scan with organization seeds (M&A discovery)
curl -X POST http://localhost:8090/v1/tenants/{tenant_id}/runs \
  -H "Content-Type: application/json" \
  -d '{
    "seeds": ["example.com"],
    "organization_seeds": ["Example Corp", "Acquired Subsidiary Inc"]
  }'
```

**Via CLI:**

```bash
# Scan a domain with all Tier-1 (passive) collectors
expose run start example.com \
  --tenant 00000000-0000-0000-0000-000000000001

# Scan with real database persistence
expose run start example.com \
  --tenant 00000000-0000-0000-0000-000000000001 --live

# Scan an IP address
expose run start 93.184.216.34 \
  --tenant 00000000-0000-0000-0000-000000000001

# Scan a CIDR block
expose run start 93.184.216.0/24 \
  --tenant 00000000-0000-0000-0000-000000000001
```

### Seed Types

Seed type is auto-detected from the input value. The detection order is: IP address, then CIDR network, then fallback to domain. Override with `--seed-type` in the CLI or `"seed_type"` in the API request body.

| Seed Type | Examples | Detection |
|---|---|---|
| `domain` | `example.com`, `api.internal.example.com` | Fallback when not IP or CIDR |
| `ip` | `93.184.216.34`, `2001:db8::1` | Parsed by `ipaddress.ip_address()` |
| `cidr` | `93.184.216.0/24`, `2001:db8::/32` | Parsed by `ipaddress.ip_network()` |
| `organization` | `Example Corp` | Via `organization_seeds` field only (API) |

Organization seeds are always typed `ORGANIZATION` and enable registrant-pivot discovery and M&A correlation across organizational boundaries.

### Collector Selection

When no collectors are specified, all Tier-1 (passive) collectors run by default. You can explicitly select which collectors to use:

**Via API:**

```json
{
  "seeds": ["example.com"],
  "collector_ids": ["ct-crtsh", "rdap-whois", "cloud-ranges", "bgp-ripestat"]
}
```

**Via CLI:**

```bash
expose run start example.com \
  --tenant <uuid> \
  --collector ct-crtsh \
  --collector rdap-whois \
  --collector active-dns-resolve
```

EXPOSE ships collectors across three sensitivity tiers:

**Tier 1 -- Passive (9 collectors).** No direct contact with target infrastructure. Safe to run without authorization scope restrictions.

| Collector | ID | Source |
|---|---|---|
| crt.sh CT Logs | `ct-crtsh` | Certificate Transparency |
| Certstream CT | `ct-certstream` | crt.sh (recency-filtered) |
| RDAP/WHOIS | `rdap-whois` | RDAP bootstrap (RFC 9083) |
| Cloud IP Ranges | `cloud-ranges` | AWS/Azure/GCP manifests |
| BGP (HE Toolkit) | `bgp-he-toolkit` | bgp.he.net |
| BGP (RIPEstat) | `bgp-ripestat` | stat.ripe.net API |
| BGP (Team Cymru) | `bgp-team-cymru` | Team Cymru DNS |
| SPF/DKIM/DMARC | `spf-dkim-dmarc` | DNS TXT records |
| GitHub Exposed | `github-exposed` | GitHub Search API |

**Tier 2 -- Targeted (1 collector).** Query data about specific discovered entities. Still passive.

| Collector | ID | Source |
|---|---|---|
| Favicon Hash | `favicon-hash` | Target host HTTP |

**Tier 3 -- Active (4 collectors).** Send packets directly to target infrastructure. Dispatch is attribution-gated: a Tier-3 collector only runs against entities with `confirmed` or `high` attribution, or entities explicitly listed in the tenant's authorization scope.

| Collector | ID | Source |
|---|---|---|
| Active DNS | `active-dns-resolve` | System resolver |
| Active TLS | `active-tls-handshake` | TLS handshake (port 443) |
| Active HTTP | `active-http-fingerprint` | HTTP probe (ports 80, 443) |
| Active Port Surface | `active-port-surface` | TCP connect (27 ports) |

Default ports for `active-port-surface`: 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 2222, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 9200, 9443, 27017.

### Multi-Pass Discovery (Seed Expansion)

Seeds are expanded before dispatch. For example, a domain seed undergoes DNS subdomain enumeration, multi-TLD expansion with DNS pre-check, and CT log subdomain discovery. Each discovered entity can become a new seed for subsequent passes, building out the full attack surface graph.

The pipeline follows a staged execution model:

1. **Stage 1 -- Seed expansion:** Initial seeds are expanded into derived seeds (subdomains, related IPs, parent orgs).
2. **Stage 2 -- Passive collection:** Tier-1 collectors run against all expanded seeds concurrently (semaphore-bounded at 15 parallel dispatches).
3. **Stage 3 -- Attribution:** The rule evaluation engine scores each discovered entity against the tenant's scope rules and rule pack.
4. **Stage 4a -- Active collection:** Tier-3 collectors run against entities that pass the attribution gate.
5. **Stage 4b -- LLM enrichment:** When configured, entities in the 0.4-0.7 confidence band are enriched via the LLM provider.
6. **Stage 5 -- Lead scoring:** All entities are scored for investigation priority.

### Monitoring Progress

**SSE (Server-Sent Events)** -- real-time event stream for dashboard and programmatic consumers:

```bash
curl -N http://localhost:8090/v1/tenants/{tenant_id}/runs/{run_id}/events
```

Event types emitted during a run:

| Event | Payload | Description |
|---|---|---|
| `run_started` | `{}` | Pipeline execution began |
| `collector_started` | `{"collector_id": "ct-crtsh"}` | Individual collector dispatched |
| `collector_completed` | `{"collector_id": "ct-crtsh", "observation_count": 5}` | Collector finished |
| `collector_failed` | `{"collector_id": "ct-crtsh", "error": "timeout"}` | Collector error |
| `entities_discovered` | `{"entities": [...]}` | New entities found |
| `attribution_updated` | `{"entity_id": "...", "old_status": "...", "new_status": "..."}` | Attribution changed |
| `run_completed` | `{}` | Pipeline finished (stream auto-closes) |

**Run log API** -- incremental polling for structured log entries:

```bash
# Get log entries (incremental via 'since' offset)
curl http://localhost:8090/v1/tenants/{tenant_id}/runs/{run_id}/log?since=0
# Response: {"entries": [{"ts": "...", "level": "info", "msg": "..."}], "total": 42}
```

The dashboard polls the log endpoint and displays entries in a terminal-style panel that updates in real time.

**Run status:**

```bash
# Poll run state
curl http://localhost:8090/v1/tenants/{tenant_id}/runs/{run_id}
```

Run states: `pending` -> `running` -> `completed` | `partial` | `failed`.

- `completed` -- all dispatches succeeded.
- `partial` -- some dispatches succeeded, some failed.
- `failed` -- all dispatches failed or the run was cancelled.

**Scan duration estimate:**

```bash
curl "http://localhost:8090/v1/admin/scan-estimate?seed_count=3&collector_count=14"
# Response: {"estimated_seconds": 9.0, "total_dispatches": 42}
```

---

## 3. Understanding Results

### Entity Types

Discovered assets are modeled as entities with a canonical identifier and type:

| Entity Type | Identifier Examples | Discovered By |
|---|---|---|
| `domain` | `example.com`, `api.staging.example.com` | CT logs, DNS, subdomain enumeration |
| `ip_address` | `93.184.216.34`, `2001:db8::1` | DNS resolution, RDAP/WHOIS, BGP |
| `certificate` | `*.example.com` (wildcard), SHA-256 fingerprint | Certificate Transparency, TLS handshake |
| `organization` | `Example Corp` | RDAP/WHOIS registrant, seed anchor |
| `cloud_resource_id` | AWS account `123456789012` | Cloud IP range matching |
| `provider` | `Cloudflare`, `AWS CloudFront` | WAF/CDN detection, cloud range matching |

### Attribution Status

Each entity is assigned an attribution tier reflecting how confidently it belongs to the target organization:

| Tier | Confidence Range | Meaning |
|---|---|---|
| `confirmed` | >= 0.9 | Deterministically attributed via scope rules (e.g., seed itself, subdomain of authorized apex, IP in authorized CIDR) |
| `high` | 0.7 -- 0.9 | Strong multi-source corroboration (e.g., matching WHOIS registrant + shared certificate chain) |
| `medium` | 0.4 -- 0.7 | Single-source or partial match (e.g., reverse PTR pattern match only) |
| `requires_review` | < 0.4 | Insufficient evidence for automated attribution; requires operator judgment |

Attribution is not a static label -- the rule evaluation engine recomputes confidence as new observations arrive. Trust degradation detection flags entities whose confidence drops between runs, indicating infrastructure changes, domain transfers, or hosting migrations.

### Lead Scoring and Priority Tiers

Every entity receives a composite lead score (0-100) that answers "what should I investigate first?" The score aggregates signals from multiple analysis modules:

| Signal | Points | Source |
|---|---|---|
| Non-production exposed | +30 | Environment classifier (staging, dev, internal endpoints on the internet) |
| No WAF/CDN protection | +20 | WAF detection (direct IP exposure without Cloudflare/Akamai/CloudFront) |
| DNSBL listed | +15 to +25 | DNS blacklist check (IP reputation) |
| Trust degradation | +10 to +15 | Cross-run confidence drop (infrastructure changes) |
| Post-acquisition asset | +10 | M&A transitive discovery |
| Unexpected SaaS product | +10 | SPF/DKIM analysis (shadow IT) |
| Security indicator in page | +10 | Screenshot/banner vision analysis |
| Missing security headers | +5 | HTTP fingerprinting (no HSTS, no CSP) |
| Weak/self-signed certificate | +5 to +10 | TLS handshake analysis |
| Debug mode detected | +10 | Environment classifier (stack traces visible, debug headers) |

Priority tiers map from the composite score:

| Tier | Score Range | Recommended Action |
|---|---|---|
| **Critical** | 70-100 | Immediate investigation; likely exposed non-production or unprotected asset |
| **High** | 40-69 | Investigate within 24 hours; significant exposure signals |
| **Medium** | 20-39 | Scheduled review; moderate risk indicators |
| **Low** | 0-19 | Informational; well-secured or fully attributed |

### Findings API

The findings endpoint returns entities ranked by lead score, highest risk first:

```bash
# Get top 20 findings (default)
curl http://localhost:8090/v1/tenants/{tenant_id}/findings/

# Get top 10 findings with minimum score of 50
curl "http://localhost:8090/v1/tenants/{tenant_id}/findings/?limit=10&min_score=50"
```

Each finding includes:

- `rank` -- position in the priority-sorted list
- `entity_identifier` -- the asset identifier (domain, IP, etc.)
- `entity_type` -- type classification
- `score` -- composite lead score (0-100)
- `priority_tier` -- `critical`, `high`, `medium`, or `low`
- `justification` -- human-readable explanation of why this entity is high-priority
- `signals` -- list of contributing signals with individual weights

The response includes an `is_placeholder` flag indicating whether the data comes from real pipeline results or demonstration data.

Subdomain takeover findings are automatically detected and surfaced as critical-priority entries when the pipeline identifies dangling CNAMEs pointing to unclaimed cloud services.

---

## 4. Rule Packs

### What Rule Packs Are

Rule packs are declarative JSON files that define how the attribution engine evaluates entity ownership. They are data, not code -- the engine consumes rule packs and applies them deterministically. Rule packs cannot extend the predicate vocabulary; only engine updates can. This separation ensures that attribution logic is auditable, version-controlled, and reproducible.

Each rule pack contains:

- **Attribution rules** -- conditional logic that adjusts entity confidence scores
- **Lead score formula** -- weighted aggregation formula for computing priority scores
- **Tier thresholds** -- confidence boundaries for the `confirmed`/`high`/`medium` tiers

Rule packs are validated against the `schemas/rulepack-v1.json` JSON Schema (Draft 2020-12) at load time. Three example packs ship with EXPOSE in `examples/rulepacks/`:

| Pack | ID | Strategy |
|---|---|---|
| Baseline | `baseline` | Balanced rules for general-purpose scanning |
| Cloud-First | `cloud-first` | Elevated weight for cloud account and IP range matching |
| Conservative | `conservative` | Stricter thresholds; fewer false positives, more manual review |

### The 12 Predicates

Rule conditions reference a closed vocabulary of 12 predicates. Each predicate tests a specific property of an entity against the tenant's scope context:

| Predicate | Tests |
|---|---|
| `target_subdomain_of_authorized_apex` | Entity is a subdomain of an apex domain in scope |
| `target_in_explicit_authorization_scope` | Entity is explicitly listed in the authorization scope |
| `target_ip_in_authorized_cloud_account_range` | Entity IP falls within an authorized cloud account's IP range |
| `target_registrant_matches_authorized_pattern` | WHOIS registrant matches a scope-defined organization pattern |
| `target_has_certificate_with_san_in_scope` | Certificate SAN contains a domain that is in scope |
| `target_shares_cert_chain_with_attributed_target` | Entity shares a certificate chain with an already-attributed entity |
| `target_nameserver_matches_authorized_pattern` | Entity's nameservers match the target's nameserver pattern |
| `target_asn_in_authorized_list` | Entity's ASN is in the authorized ASN list |
| `target_observed_by_collectors_count_gte` | Entity was observed by at least N distinct collectors |
| `target_first_observed_within_days` | Entity was first observed within N days |
| `target_has_exposure_indicator` | Entity has specific exposure indicators (open ports, weak TLS) |
| `target_responds_with_authorized_naming_convention` | HTTP response matches the target's naming conventions |

### Creating Custom Rule Packs

A rule pack is a JSON file with this structure:

```json
{
  "pack_id": "my-custom-pack",
  "pack_version": "1.0.0",
  "pack_format_version": "v1",
  "description": "Custom attribution rules for my organization",
  "attribution_rules": [
    {
      "rule_id": "cert-san-match",
      "rule_version": "1.0.0",
      "description": "Promote entities with certificates containing in-scope SANs",
      "category": "high_confidence_join",
      "when": {
        "predicate": "target_has_certificate_with_san_in_scope"
      },
      "then": {
        "outcome": "promote",
        "confidence_delta": 0.3
      },
      "priority": 90,
      "enabled": true
    },
    {
      "rule_id": "multi-collector-corroboration",
      "rule_version": "1.0.0",
      "description": "Promote entities observed by 3+ collectors",
      "category": "infrastructure_correlation",
      "when": {
        "predicate": "target_observed_by_collectors_count_gte",
        "params": {"min_count": 3}
      },
      "then": {
        "outcome": "promote",
        "confidence_delta": 0.15
      },
      "priority": 80,
      "enabled": true
    }
  ],
  "lead_score_formula": {
    "formula_version": "1.0.0",
    "weights": {
      "attribution_confidence": 20,
      "exposure_severity_max": 30,
      "tech_stack_risk": 25,
      "freshness": 10,
      "cloud_provider_factor": 15
    },
    "modifiers": []
  }
}
```

**Conditions** support boolean composition:

- `{"predicate": "..."}` -- single predicate check
- `{"all_of": [...]}` -- AND: all conditions must match
- `{"any_of": [...]}` -- OR: at least one condition must match
- `{"not": {...}}` -- NOT: condition must not match

**Actions** define the outcome when a rule matches:

| Outcome | Behavior | Requires `confidence_delta`? |
|---|---|---|
| `promote` | Increase attribution confidence | Yes |
| `demote` | Decrease attribution confidence | Yes |
| `neutral` | No confidence change; may flag for review | No |
| `reject` | Mark entity as out-of-scope | No |

**Rule categories** classify the type of logic:

- `high_confidence_join` -- deterministic ownership signals (cert SAN, subdomain)
- `registrant_pivot` -- WHOIS registrant matching
- `infrastructure_correlation` -- multi-source corroboration
- `naming_heuristic` -- pattern-based naming conventions
- `cloud_authoritative` -- cloud provider IP range and account matching
- `rejection_rule` -- explicit exclusion logic

### Eval Harness for Testing Rules

The `expose eval` command runs your rule pack against curated datasets and reports accuracy metrics:

```bash
# Evaluate against a specific dataset category
expose eval --dataset confirmed_yours \
  --rulepack examples/rulepacks/example-baseline.json

# Evaluate against all four dataset categories
expose eval --all \
  --rulepack examples/rulepacks/example-baseline.json

# Output as JSON for CI integration
expose eval --all \
  --rulepack my-rulepack.json \
  --json-output

# Set a custom pass threshold (default is 80%)
expose eval --all \
  --rulepack my-rulepack.json \
  --threshold 0.90
```

The four dataset categories:

| Category | Tests |
|---|---|
| `confirmed_yours` | Entities that should be attributed to the target |
| `confirmed_not_yours` | Entities that should NOT be attributed |
| `ambiguous` | Edge cases requiring nuanced evaluation |
| `adversarial` | Deliberately crafted inputs to test robustness |

The eval report includes accuracy, precision, recall, F1, confusion matrix, and per-case wall clock timing. Exit code is 0 if overall accuracy meets the threshold, 1 otherwise -- suitable for CI/CD gates.

---

## 5. Graph Visualization

### Entity Relationship Graph

The EXPOSE dashboard renders a D3 force-directed graph of all discovered entities and their relationships. The graph API endpoint provides D3-compatible data:

```bash
curl http://localhost:8090/v1/tenants/{tenant_id}/graph
```

Response structure:

```json
{
  "nodes": [
    {
      "id": "<uuid>",
      "label": "example.com",
      "entity_type": "domain",
      "attribution_status": "confirmed",
      "attribution_confidence": 0.95,
      "collector_count": 3,
      "first_observed": "2026-05-10T08:00:00Z"
    }
  ],
  "edges": [
    {
      "source": "<from-uuid>",
      "target": "<to-uuid>",
      "relationship_type": "resolves_to",
      "collector_id": "active-dns-resolve"
    }
  ]
}
```

### Edge Types and Colors

Relationship edges represent how entities connect to each other. Each edge records the collector that discovered the relationship and the observation type:

| Edge Type | Meaning | Example |
|---|---|---|
| `resolves_to` | DNS A/AAAA record resolution | `example.com` -> `93.184.216.34` |
| `subdomain_of` | Subdomain hierarchy | `api.example.com` -> `example.com` |
| `cert_covers` | Certificate SAN coverage | `*.example.com` -> `api.example.com` |
| `hosted_on` | Cloud/hosting relationship | `example.com` -> `AWS us-east-1` |
| `registered_by` | WHOIS registrant | `example.com` -> `Example Corp` |
| `mail_for` | MX record relationship | `mail.example.com` -> `example.com` |

Node colors in the dashboard indicate attribution status:

| Color | Meaning |
|---|---|
| Seed | Operator-provided input seeds |
| Discovered | Newly found, unattributed |
| Corroborated | Multiple sources confirm existence |
| High | Strong attribution confidence |
| Confirmed | Deterministically attributed to the target |
| Review | Requires operator review |

Toggle between **Force** and **Radial** layouts using the button in the graph pane header.

### Filtering (Planned)

Graph filtering by entity type, attribution tier, and collector source is tracked in issue #114. The current implementation renders all entities and relationships for the selected tenant.

### Provenance Chain

Every entity has a provenance chain that answers "why do we think this entity belongs to the target?" Query it via the provenance API:

```bash
curl http://localhost:8090/v1/tenants/{tenant_id}/entities/{entity_id}/provenance
```

The provenance response includes:

- **Observations** -- which collectors observed this entity and when
- **Rules applied** -- which attribution rules fired, their outcomes, and confidence deltas
- **Relationships** -- connected entities with edge types and target identifiers

This chain provides a full audit trail for every attribution decision, supporting operator review and regulatory compliance.

---

## 6. Integrations

### SIEM Adapters

EXPOSE ships three SIEM integration adapters for streaming observations and findings to security operations platforms:

| Adapter | ID | Target Platform |
|---|---|---|
| Splunk | `splunk` | Splunk HEC (HTTP Event Collector) |
| Microsoft Sentinel | `sentinel` | Azure Log Analytics Data Collector API |
| Google Chronicle | `chronicle` | Chronicle Ingestion API |

Each adapter implements the `SIEMAdapter` interface with three operations:

- `send_observations` -- batch delivery of discovery observations
- `send_finding` -- individual finding/alert delivery
- `health_check` -- endpoint reachability and authentication validation

Adapter configuration:

```json
{
  "adapter_type": "splunk",
  "endpoint": "https://splunk.example.com:8088/services/collector",
  "auth_token": "your-hec-token",
  "enabled": true,
  "batch_size": 100
}
```

Built-in resilience features:

- **Exponential backoff retry** on HTTP 429 (rate-limited) and 5xx (server error) responses, with `Retry-After` header support
- **Circuit breaker** -- after 5 consecutive delivery failures, the adapter enters an open state for 60 seconds, short-circuiting all calls. After the cooldown, a single probe attempt determines whether to re-close (success) or re-open (failure) the breaker
- **SSRF protection** -- endpoint URLs are validated against RFC 1918, RFC 4193, link-local, and loopback ranges to prevent server-side request forgery

### Artifact Export

**CSV export** with filtering:

```bash
# Export all entities as CSV
curl "http://localhost:8090/v1/tenants/{tenant_id}/export/csv" -o export.csv

# Export with filters
curl "http://localhost:8090/v1/tenants/{tenant_id}/export/csv?\
entity_type=domain&\
attribution_tier=confirmed&\
environment=production&\
limit=500" -o filtered-export.csv
```

CSV columns: `entity_identifier`, `entity_type`, `attribution_tier`, `confidence`, `collectors`, `first_seen`, `last_seen`, `environment`, `risk_summary`.

Filter parameters (all optional, combined with AND):

| Parameter | Values | Default |
|---|---|---|
| `entity_type` | `domain`, `ip_address`, `certificate`, `organization` | All |
| `attribution_tier` | `confirmed`, `high`, `medium`, `requires_review` | All |
| `collector_id` | Any registered collector ID | All |
| `environment` | `production`, `staging`, `development`, `internal` | All |
| `limit` | 1 -- 10,000 | 10,000 |

**JSON export** -- the findings endpoint returns structured JSON suitable for downstream processing:

```bash
curl http://localhost:8090/v1/tenants/{tenant_id}/findings/ | jq .
```

**Credential export** (masked values for verification, not backup):

```bash
curl http://localhost:8090/v1/tenants/{tenant_id}/credentials/export/bundle
```

### Scheduling (Cron-Based Recurring Scans)

EXPOSE supports cron-based recurring scans via the scheduler API. Schedules are per-tenant and require bearer token authentication:

```bash
# Create a schedule (daily at 02:00 UTC)
curl -X POST http://localhost:8090/v1/scheduler/schedules \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "<uuid>",
    "cron_expression": "0 2 * * *",
    "collector_ids": ["ct-crtsh", "rdap-whois", "active-dns-resolve"],
    "seeds": [{"seed_type": "domain", "value": "example.com"}]
  }'

# List schedules
curl http://localhost:8090/v1/scheduler/schedules \
  -H "Authorization: Bearer <token>"

# Get schedule for a tenant
curl http://localhost:8090/v1/scheduler/schedules/{tenant_id} \
  -H "Authorization: Bearer <token>"

# Delete a schedule
curl -X DELETE http://localhost:8090/v1/scheduler/schedules/{tenant_id} \
  -H "Authorization: Bearer <token>"
```

Standard 5-field cron format: `minute hour day-of-month month day-of-week`.

| Example | Schedule |
|---|---|
| `0 2 * * *` | Daily at 02:00 UTC |
| `0 */6 * * *` | Every 6 hours |
| `0 8 * * 1` | Every Monday at 08:00 UTC |
| `*/30 * * * *` | Every 30 minutes |

Schedule responses include health tracking: `last_run_at`, `last_attempted_at`, `next_run_at`, `consecutive_failures`, and `last_error`.

### Webhook Notifications

Webhook notifications deliver HTTP callbacks for run lifecycle events. Configure via the webhooks API:

```bash
# Register a webhook
curl -X POST http://localhost:8090/v1/tenants/{tenant_id}/webhooks/ \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://ops.example.com/hooks/expose",
    "secret": "your-webhook-secret-min-16-chars",
    "event_types": ["run_completed", "entities_discovered"],
    "enabled": true
  }'

# List registered webhooks
curl http://localhost:8090/v1/tenants/{tenant_id}/webhooks/

# Test a webhook (sends a synthetic event)
curl -X POST http://localhost:8090/v1/tenants/{tenant_id}/webhooks/{webhook_id}/test

# Delete a webhook
curl -X DELETE http://localhost:8090/v1/tenants/{tenant_id}/webhooks/{webhook_id}
```

Webhook payloads are signed with the configured secret for verification. The test endpoint sends a `webhook.test` event and returns the delivery result including success/failure status, HTTP response code, and any error message.

---

## 7. Commercial Modules

EXPOSE follows an open-core model (per ADR-009). The Apache 2.0-licensed core engine handles reconnaissance and attribution. Two commercial modules extend capabilities into regulated and intelligence domains:

### Threat Context (EXPOSE Threat Context)

Provides threat intelligence enrichment beyond core reconnaissance:

- **Dark web aggregator queries** -- searches public APIs (HIBP, IntelX, DeHashed) for indicators associated with discovered entities
- **Indicator classification** -- categorizes findings as Indicators of Compromise (IoC), Indicators of Interest (IoI), Indicators of Activity (IoAc), or Indicators of Presence (IoP)
- **MITRE ATT&CK mapping** -- maps findings to Resource Development (TA0042) techniques

The dark web indicators collector (`dark-web-indicators`) is gated behind the Threat Context license check.

### Identity Surface (EXPOSE Identity Surface)

Provides registrant-identity correlation and organizational graph construction:

- **Registrant pivot** -- clusters domains registered by the same entity despite name variations, using fuzzy matching to catch typos and abbreviation differences
- **Organization graph** -- builds a directed graph of parent/subsidiary, org-to-domain, org-to-IP-range, and org-to-email-infrastructure relationships from registrant pivots, M&A discovery, and DNS data

Both operations require `per_tenant_authorization=True` before performing any operations. See `IDENTITY_SURFACE_ETHICS.md` for scope limitations, prohibited uses, data retention, and consent requirements.

### Licensing Model

Commercial module activation is controlled via license checks:

- `check_license()` returns `True` when the module is activated for the deployment
- Currently returns `True` unconditionally (development phase)
- Production deployments will validate a license key or entitlement token

Product surfaces (per ADR-009): **EXPOSE Core** (open-source engine), **EXPOSE Threat Context** (dark web intelligence), **EXPOSE Identity Surface** (registrant correlation), **EXPOSE Research** (future academic/research tier).

---

## 8. Administration

### Audit Logging

EXPOSE implements NIST SP 800-53 AU-2/AU-3 compliant audit logging. Every security-relevant action emits an `AuditEvent` with the following fields:

| Field | AU-3 Requirement | Description |
|---|---|---|
| `timestamp` | When | UTC time of the event |
| `actor` | Who | Authenticated principal or `"system"` |
| `action` | What | Human-readable description |
| `resource` | On what | Identifier of the affected resource |
| `outcome` | Outcome | `"success"` or `"failure"` |
| `details` | Additional context | Free-form key-value pairs |
| `source_ip` | -- | Originating IP address (when available) |
| `tenant_id` | -- | Multi-tenancy scope (per ADR-007) |
| `correlation_id` | -- | Cross-system correlation token |
| `retention_category` | AU-11 | Retention tier (default `"standard"`) |

Auditable event types (AU-2 catalog):

| Category | Events |
|---|---|
| Run lifecycle | `run_started`, `run_completed`, `run_failed` |
| Entity lifecycle | `entity_created`, `entity_updated` |
| Scope enforcement | `scope_denial` |
| Tenant lifecycle | `tenant_created`, `tenant_deleted` |
| Credential operations | `credential_accessed`, `credential_rotated` |
| Data lifecycle | `data_export`, `data_deletion` |
| Configuration | `config_changed` |
| Authentication | `auth_success`, `auth_failure` |
| Artifact signing | `artifact_signed` |
| Scheduling | `schedule_created`, `schedule_deleted` |

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

### Evidence Storage

Evidence blobs (raw HTTP responses, certificate PEMs, DNS responses, screenshots) are stored content-addressed by their SHA-256 digest (via the FIPS adapter per ADR-010). The evidence manager provides:

- **Content-addressed deduplication** -- identical content always resolves to the same storage key regardless of how many entities or runs reference it
- **Entity association** -- metadata tracks which entity produced the evidence, enabling per-entity evidence queries
- **TTL-based lifecycle** -- each blob carries a retention value (default 90 days); expired blobs are removed on expiry scan
- **Integrity validation** -- retrieval re-hashes stored bytes and raises an error if the digest no longer matches, catching silent corruption

Storage backends:

| Backend | Use Case |
|---|---|
| Local filesystem | Development and single-node deployments |
| S3-compatible | Production, multi-node, and cloud deployments |

### Credential Management

Credential storage is managed through the secrets backend abstraction:

| Backend | Config | Use Case |
|---|---|---|
| In-Memory | Default (persists to `~/.expose-credentials.json`) | Development and testing |
| Environment Variables | `EXPOSE_SECRETS_BACKEND=env` | Kubernetes with mounted secrets |
| HashiCorp Vault | `EXPOSE_SECRETS_BACKEND=vault` | Production deployments |

Security properties:

- No secret values are logged at any level
- Export endpoints mask values by default (last 4 characters visible)
- Credential testing validates keys against upstream APIs without exposing the stored value
- The backend interface is tenant-scoped -- credentials are isolated per tenant

Administrative credential operations:

```bash
# List all credential slots and their status
curl http://localhost:8090/v1/tenants/{tenant_id}/credentials/

# Test a single credential
curl -X POST http://localhost:8090/v1/tenants/{tenant_id}/credentials/{credential_id}/test

# Test all credentials at once (admin endpoint)
curl -X POST http://localhost:8090/v1/admin/tenants/{tenant_id}/credentials/test-all
```

### Multi-Tenancy

Every resource in EXPOSE is scoped by `tenant_id` (UUID). Tenants are fully isolated:

- Separate seed sets and observation graphs
- Independent collector configurations and rate limits
- Per-tenant authorization scope (7 rule types)
- Isolated credential storage in the secrets backend
- Per-tenant quota enforcement and misuse detection
- Cross-tenant entity invisibility (a cross-tenant query returns 404, not 403)

Tenant lifecycle management:

```bash
# Create a tenant
curl -X POST http://localhost:8090/v1/tenants/ \
  -H "Content-Type: application/json" \
  -d '{"name": "acme-corp"}'

# List tenants
curl http://localhost:8090/v1/tenants/

# Update tenant (name or state)
curl -X PATCH http://localhost:8090/v1/tenants/{tenant_id} \
  -H "Content-Type: application/json" \
  -d '{"state": "suspended"}'

# Delete tenant (two-phase: marks as pending_deletion)
curl -X DELETE http://localhost:8090/v1/tenants/{tenant_id}
```

Scope rules define the tenant's authorization boundary (7 types):

| Rule Type | Matching Behavior | Example Value |
|---|---|---|
| `apex_domain` | Includes all subdomains and the apex itself | `example.com` |
| `exact_domain` | Exact FQDN match only | `api.internal.example.com` |
| `ip_address` | Single IPv4 or IPv6 address | `93.184.216.34` |
| `cidr` | IP range containment | `93.184.216.0/24` |
| `asn` | ASN string match | `AS13335` |
| `cloud_account` | AWS account, Azure subscription, GCP project | `123456789012` |
| `registrant_org` | Case-insensitive substring match on WHOIS registrant | `Example Corp` |

Exclusion rules override inclusions. Set `is_exclusion: true` to explicitly exclude an entity from scope.

### Administrative Endpoints

System-level operations for platform operators:

```bash
# System-wide statistics (all tenants)
curl http://localhost:8090/v1/admin/stats
# Response: {"total_entities": N, "total_relationships": N, "total_runs": N,
#            "runs_by_state": {"completed": N, ...}, "registered_collectors": N}

# Cancel a running pipeline
curl -X POST http://localhost:8090/v1/admin/runs/{run_id}/cancel

# Delete a run (does not delete discovered entities)
curl -X DELETE http://localhost:8090/v1/admin/runs/{run_id}

# Organization name suggestions (fuzzy matching)
curl "http://localhost:8090/v1/admin/org-suggest?q=Examp"
```

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

### Air-Gapped Deployment

EXPOSE supports fully offline operation:

1. Use only passive collectors with pre-cached data (CT log exports, WHOIS bulk data, cloud IP range manifests).
2. Configure the `direct` egress profile. Disable Tier-3 active collectors.
3. Use the Ollama LLM provider with a locally hosted model for enrichment (or disable LLM entirely).
4. No external API dependencies after initial data import.

For the Ollama provider: lab-validated models include Qwen 2.5 7B and Llama 3.1 8B at Q4_K_M quantization.

### Cost Management (LLM Ceilings)

LLM enrichment is off by default and activates only when explicitly configured per tenant:

```json
{
  "llm_enabled": true,
  "llm_provider": "ollama",
  "llm_model": "qwen2.5:7b",
  "llm_cost_ceiling_per_run": 5.00
}
```

| Provider | Data Residency | Best For |
|---|---|---|
| `anthropic` | Anthropic cloud | Frontier quality (Claude) |
| `openai` | OpenAI cloud | Frontier alternative (GPT) |
| `gemini` | Google cloud | Frontier alternative (Gemini) |
| `ollama` | Operator-local | Air-gapped, data sovereignty, cost control |

The `CostTracker` enforces a hard per-run cost ceiling:

- **Default:** $10.00 per run (configurable via `llm_cost_ceiling_per_run`)
- Every LLM call logs `cost_estimate_usd` to the audit trail
- When accumulated cost exceeds the ceiling, `CostCeilingExceededError` stops LLM calls for the remainder of the run (the pipeline continues without enrichment)

Enrichment triggers are bounded by design:

| Enrichment Type | Trigger |
|---|---|
| Attribution analysis | Entities with confidence 0.4 -- 0.7 |
| Tech-stack inference | Entities from `active-http-fingerprint` collector |
| Noise classification | Entities with confidence < 0.4 |

### Tier-3 Enforcement

Active collectors are gated by attribution status and scope rules. Two enforcement modes control behavior when a dispatch is denied:

| Mode | Behavior |
|---|---|
| `medium` (default) | Denial is advisory; dispatcher logs a warning and records the refusal |
| `hard` | Denial is absolute; dispatcher records a `ScopeRefusalEvent` and the collector is not invoked |

Enforcement refusals are serialized into the run log at completion, showing how many dispatches were denied and which entity identifiers were affected.

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

**Stuck "pending" runs after server crash**

Runs that were in `pending` state when the server crashed will remain stuck. Fix via direct database update:

```sql
UPDATE runs SET state='failed', completed_at=NOW() WHERE state='pending';
```

**Tenant configuration lost after restart**

Tenant configuration is stored in-memory in Phase 1. Re-apply via the config API after restart:

```bash
curl -X PUT http://localhost:8090/v1/tenants/{tenant_id}/config \
  -H "Content-Type: application/json" \
  -d '{"llm_enabled": true, "llm_provider": "gemini", ...}'
```

Credentials persist to `~/.expose-credentials.json` and survive restarts.

### CLI Command Reference

```
expose --version                     Show version
expose --help                        Show help

expose serve [--host HOST] [--port PORT] [--reload] [--no-otel]
                                     Start the API server

expose demo [--host HOST] [--port PORT]
                                     Run interactive demo

expose run start SEED --tenant UUID [--collector ID ...] [--seed-type TYPE] [--live]
                                     Start a pipeline run

expose run status RUN_ID --tenant UUID
                                     Show run status

expose run list --tenant UUID        List recent runs

expose db upgrade [--revision REV]   Run database migrations forward
expose db downgrade [--revision REV] Run database migrations backward
expose db current                    Show current migration revision

expose eval --dataset CATEGORY --rulepack FILE [--threshold N] [--json-output]
                                     Evaluate a rule pack against a dataset

expose eval --all --rulepack FILE [--threshold N] [--json-output]
                                     Evaluate against all datasets
```

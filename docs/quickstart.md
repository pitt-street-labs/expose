# EXPOSE -- Quickstart Guide

**Status:** Advisory
**Date:** 2026-05-10
**Audience:** Developers and operators evaluating EXPOSE for the first time.

This guide walks through installing EXPOSE, running your first scan, and understanding the output. For the full specification, see `docs/SPEC.md`. For architecture diagrams, see `docs/architecture/`.

---

## 1. Installation

EXPOSE requires Python 3.12 or later.

### Using uv (recommended)

```bash
# Clone the repository
git clone https://github.com/korlogos/expose.git
cd expose

# Install in development mode with all optional dependencies
uv pip install -e ".[all]"
```

### Using pip

```bash
git clone https://github.com/korlogos/expose.git
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
| `collectors-dns` | `dnspython` -- required for `active-dns-resolve`, `bgp-team-cymru`, and `spf-dkim-dmarc` collectors |
| `llm-anthropic` | Anthropic SDK for LLM-assisted attribution (Phase 2) |
| `llm-openai` | OpenAI SDK for LLM-assisted attribution (Phase 2) |
| `llm-gemini` | Google GenAI SDK for LLM-assisted attribution (Phase 2) |
| `llm-all` | All LLM provider SDKs |
| `all` | Everything above |

---

## 2. First Scan

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

### Seed type auto-detection

The CLI automatically detects the seed type from the input value:

| Input | Detected type |
|---|---|
| `example.com` | Domain |
| `93.184.216.34` | IP |
| `93.184.216.0/24` | CIDR |

### Selecting specific collectors

By default, all registered collectors appropriate for the seed type are dispatched. The collectors enabled for a run are determined by the tenant configuration and the seed type.

### Live mode (against real Postgres)

For runs that persist results to a database rather than printing to stdout:

```bash
expose run start example.com \
  --tenant 00000000-0000-0000-0000-000000000001 \
  --live
```

Live mode requires a running PostgreSQL instance configured via the `DATABASE_URL` environment variable.

---

## 3. Understanding the Output

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
| `CT_LOG_ENTRY` | Certificate Transparency log entry | ct-crtsh, ct-certstream |
| `CLOUD_IP_RANGE` | IP matched to cloud provider range | cloud-ranges |
| `RDAP_REGISTRATION` | Domain/IP registration data | rdap-whois |
| `BGP_ASN_LOOKUP` | BGP routing and ASN information | bgp-he-toolkit, bgp-ripestat, bgp-team-cymru |
| `DNS_RECORD` | DNS record data (e.g., email auth) | spf-dkim-dmarc |
| `DNS_RESOLUTION` | Active DNS resolution results | active-dns-resolve |
| `TLS_HANDSHAKE` | TLS certificate and session metadata | active-tls-handshake |
| `HTTP_RESPONSE` | HTTP response fingerprint | active-http-fingerprint, favicon-hash |
| `PORT_SCAN_RESULT` | TCP port surface scan | active-port-surface |
| `SCANNER_HOST` | External data source match | github-exposed |

---

## 4. Configuring Collectors

### Collector tiers

Collectors are classified into three tiers based on the sensitivity of the data-collection method:

- **Tier 1 (Passive, Broad):** Query public databases. No target contact. Always safe to run.
- **Tier 2 (Passive, Targeted):** Query public APIs about specific discovered entities.
- **Tier 3 (Active, Attribution-Gated):** Send packets to the target. Gated by attribution tier or explicit authorization scope.

For a full catalog of all 14 built-in collectors with detailed payload documentation, see `docs/collectors.md`.

### Tier-3 authorization gating

Tier-3 collectors (active DNS, TLS, HTTP, port scan) will only execute against entities that meet one of two conditions:

1. The entity's attribution tier is `confirmed` or `high`.
2. The entity is explicitly listed in the tenant's authorization scope.

This prevents EXPOSE from probing infrastructure that may not belong to the target organization. The enforcement mode (`medium` or `hard`) is configured per tenant.

### Optional collector dependencies

Some collectors require optional Python packages:

```bash
# DNS-based collectors (active-dns-resolve, bgp-team-cymru, spf-dkim-dmarc)
pip install -e ".[collectors-dns]"
```

Collectors that depend on optional packages import cleanly when the package is absent. They raise a clear error message with installation instructions if invoked without the required dependency.

---

## 5. Multi-Tenant Setup

EXPOSE is designed for multi-tenancy from the ground up (per ADR-007). Each tenant has isolated:

- **Seeds and observations** -- all data is scoped by `tenant_id` (UUID).
- **Collector configuration** -- which collectors are enabled, rate limits, timeouts.
- **Authorization scope** -- which domains, IPs, ASNs, and cloud accounts the tenant is authorized to scan.
- **Credentials** -- per-tenant secrets stored in the configured secrets backend.

### Setting up a tenant

For local development, the CLI accepts any UUID as a tenant identifier. In a production deployment:

1. Create the tenant via the API: `POST /api/v1/tenants`.
2. Configure the tenant's authorization scope (apex domains, IP ranges, ASN numbers).
3. Store collector credentials in the secrets backend using the key convention `collector.{collector_id}.{key_name}`.
4. Start runs via the API or CLI.

### Secrets backends

| Backend | Configuration | Best for |
|---|---|---|
| In-Memory | Default for testing | Local development |
| Environment Variables | `EXPOSE_SECRETS_BACKEND=env` | Kubernetes with mounted secrets |
| HashiCorp Vault | `EXPOSE_SECRETS_BACKEND=vault` | Production deployments |

---

## 6. Running the API Server

EXPOSE includes a FastAPI-based HTTP API:

```bash
# Start the server (default: localhost:8000)
expose serve

# With custom host and port
expose serve --host 0.0.0.0 --port 9000
```

### Key API endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/runs` | Start a new scan run |
| `GET` | `/api/v1/runs/{run_id}` | Get run status and results |
| `GET` | `/api/v1/tenants` | List tenants |
| `POST` | `/api/v1/tenants` | Create a tenant |
| `GET` | `/api/v1/graph/entities` | Query the observation graph |
| `GET` | `/api/v1/events` | Server-sent events stream |

### Database migrations

Before starting the server with a database, run migrations:

```bash
# Apply all migrations
expose db upgrade

# Check current migration revision
expose db current
```

---

## 7. Next Steps

- **Full specification:** `docs/SPEC.md` -- the locked, authoritative system design.
- **Architecture diagrams:** `docs/architecture/` -- nine Mermaid diagrams covering pipeline stages, deployment topology, observation graph, multi-tenancy, egress profiles, and more.
- **ADRs:** `docs/adr/` -- ten architecture decision records covering data model, database, observability, LLM integration, multi-tenancy, authorized use, open-core licensing, and FIPS crypto.
- **Collector catalog:** `docs/collectors.md` -- detailed documentation for all 14 built-in collectors.
- **Strategic positioning:** `docs/positioning.md` -- how EXPOSE fits in the EASM market.
- **Contributing:** `CONTRIBUTING.md` -- development setup, testing, and pull request process.

<p align="center">
  <img src="assets/branding/expose-icon.png" alt="EXPOSE" width="128" />
</p>

<h1 align="center">EXPOSE</h1>

<p align="center">
Continuous external attack surface intelligence with signed, attributed artifacts.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License: Apache 2.0" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.12%2B-3776AB.svg" alt="Python 3.12+" /></a>
  <a href="#project-status"><img src="https://img.shields.io/badge/tests-3590%2B%20passing-brightgreen.svg" alt="Tests: 3590+ passing" /></a>
  <a href="#project-status"><img src="https://img.shields.io/badge/status-pre--release-yellow.svg" alt="Status: Pre-release" /></a>
</p>

---

## What is EXPOSE?

EXPOSE is an open-core External Attack Surface Intelligence (EASI) platform that discovers, attributes, and continuously monitors an organization's internet-facing surface. It produces cryptographically signed JSON artifacts with full provenance chains -- every claim is traceable to the collector, observation, and rule that justified it. Built for both defensive CTEM workflows and authorized red team operations, EXPOSE is self-hostable and designed to run inside your own authorization boundary.

No other EASM tool -- commercial or open-source -- produces tamper-evident, cryptographically signed deliverables with auditable attribution logic.

## Key Differentiators

- **Signed artifacts with provenance.** Every artifact is signed with Ed25519 or ECDSA P-256, content-hashed with FIPS SHA-256, and wrapped in SLSA-aligned provenance envelopes. Downstream consumers verify integrity offline -- no trust-the-vendor required.

- **Auditable attribution engine.** A rule-based evaluation engine with 12 predicates, AND/OR/NOT condition trees, and four confidence tiers (`confirmed`, `high`, `medium`, `requires_review`). Attribution logic ships as declarative, JSON Schema-validated rule packs -- data, not code. Every finding carries the MITRE ATT&CK Reconnaissance technique IDs that contributed to its score.

- **SOC-ready output.** SIEM push adapters for Splunk HEC, Microsoft Sentinel, and Google Chronicle ship out of the box. Lead scoring with priority tiers routes analyst attention to what matters first.

- **Federal-ready open core.** FIPS 140-3 validated cryptography, NIST SP 800-53 AU-2/AU-3 audit logging, air-gap deployment capability, and content-addressed evidence storage with integrity verification. Self-host inside your own ATO boundary without waiting for vendor authorization.

- **Operator-controlled LLM enrichment.** Four provider adapters (Anthropic, OpenAI, Gemini, Ollama) behind a SafeLLMClient that enforces structured-output schemas, per-run cost ceilings, and per-call audit logging. Run fully offline with Ollama.

## Feature Highlights

### Discovery -- 41 Collectors

41 built-in collectors across three sensitivity tiers, each mapped to MITRE ATT&CK Reconnaissance techniques. Tier 3 (active) collectors are attribution-gated: they execute only against entities with `confirmed` or `high` attribution, or explicit authorization scope membership.

| Tier | Count | Examples |
|------|-------|---------|
| **T1 Passive** | 22 | CT logs (crt.sh, Certstream, Censys, Certspotter), RDAP/WHOIS, BGP (HE, RIPEstat, Team Cymru), cloud IP ranges, SPF/DKIM/DMARC, GitHub exposed secrets, passive DNS history, M&A discovery, Common Crawl, Wayback Machine, OTX AlienVault, paste monitoring, Wikipedia edits, git commit emails, dark web indicators |
| **T2 Targeted** | 7 | Favicon hash, WAF/CDN detection, reverse PTR, robots.txt, security.txt, mail header analysis, SIP discovery |
| **T3 Active** | 12 | DNS resolution, TLS handshake + JARM fingerprint, HTTP fingerprinting, port surface scan, subdomain enumeration, zone transfer, WAF origin discovery, screenshot vision, Shodan, Censys, BinaryEdge, cloud storage exposure |

See [`docs/collectors.md`](docs/collectors.md) for the full catalog with credential requirements and output schemas.

### Attribution Engine

- **12 rule predicates** evaluated recursively over AND/OR/NOT condition trees
- **Customizable rule packs** per organizational profile (baseline, cloud-first, conservative, government)
- **Four confidence tiers** with numeric scores and per-claim evidence chains
- **Lead scoring** with priority tiers for analyst triage
- **Trust degradation detection** -- registrar changes, hosting migrations, CA switches
- **Environment classification** -- production, staging, QA, dev, test via correlated signals

### Analysis and Enrichment

- **Screenshot vision** -- multimodal page analysis to identify login portals, default pages, and technology indicators
- **WAF origin discovery** -- 5 methods, 6 CDN vendor signatures for finding real IPs behind CDNs
- **Tech-stack fingerprinting** and exposure indicators feeding numeric lead scores
- **Multi-provider LLM enrichment** with SafeLLMClient (Anthropic, OpenAI, Gemini, Ollama)
- **DNSBL reputation checking** across standard DNS blackhole lists

### Pipeline and Operations

- **Canonical artifact generation** with FIPS SHA-256 content hashing, Ed25519/ECDSA signing, and SLSA-aligned provenance envelopes
- **Full provenance chain** -- observation-to-attribution audit trail for every finding
- **Content-addressed evidence storage** with SHA-256 integrity verification
- **Run scheduling** -- cron-based with concurrent run limits
- **Delta computation** with six classified removal reasons
- **Webhook delivery** with HMAC-SHA256 payload signing and exponential-backoff retry
- **Four network egress profiles** -- direct, SOCKS5, WireGuard, HTTP CONNECT proxy
- **NIST SP 800-53 audit logging** -- AU-2/AU-3 compliant, append-only, retention-aware

### SIEM Integration

Complete adapters for three major SIEM platforms, shipping findings as structured events:

| Platform | Adapter | Protocol |
|----------|---------|----------|
| Splunk | HEC (HTTP Event Collector) | HTTPS |
| Microsoft Sentinel | Log Analytics API | HTTPS |
| Google Chronicle | Ingestion API | HTTPS |

### Dashboard and Visualization

- **Darkroom** -- web dashboard with D3.js force-directed observation graph (10 edge type colors), Alpine.js interactive controls, and real-time SSE event streaming
- **Graph visualization** with click-to-expand entity exploration
- **CSV export** with entity-type, attribution-tier, and environment filters
- **Admin panel** with scan log, credential management, and tenant configuration

### API and CLI

- **FastAPI REST API** with bearer token auth, tenant-scoped endpoints, and SSE event streaming
- **RBAC** with three roles (admin, operator, viewer) and tenant-scoped permissions
- **Click CLI** -- `expose run`, `expose serve`, `expose eval`, `expose db` with `--live` streaming
- **Eval harness** -- `expose eval` with precision/recall/F1 metrics for attribution accuracy
- **OpenTelemetry** distributed tracing, structured logging, and operational metrics
- **Grafana dashboards** for platform overview and per-tenant monitoring

## Quick Start

```bash
# Clone and start with Docker Compose
git clone https://github.com/korlogos/expose.git
cd expose
docker compose up -d

# Run a basic discovery against your own domain
expose run --seed-domain example.com --collectors ct-crtsh,active-dns-resolve

# Start the web dashboard
expose serve --port 8000
```

For Kubernetes deployment:

```bash
helm install expose ./deploy/helm-chart \
  --namespace expose --create-namespace \
  --values your-tenant-config.yaml
```

See [`docs/quickstart.md`](docs/quickstart.md) for full setup instructions.

## Architecture

EXPOSE executes a five-stage pipeline per run:

1. **Seed expansion** -- multi-TLD expansion with DNS pre-check
2. **Collection** -- parallel dispatch across tiered collectors
3. **Sanitization** -- input validation and normalization
4. **Attribution and enrichment** -- rule evaluation, lead scoring, LLM enrichment, SIEM push
5. **Artifact generation** -- signed canonical artifacts with provenance attestations

Four stages are fully deterministic. LLM enrichment in Stage 4 is bounded by SafeLLMClient and produces only structured outputs validated against a schema. See [`docs/adr/`](docs/adr/) for the 10 Architecture Decision Records.

```
docs/architecture/
  pipeline-stages.md        Five-stage pipeline flow
  deployment-topology.md    Single-node and Kubernetes topologies
  observation-graph.md      Entity-relationship graph model
  multi-tenancy.md          Tenant isolation architecture
  scanner-egress.md         Network egress profiles
  attribution-flow.md       Rule evaluation data flow
  product-surfaces.md       Open-core module boundaries
  federal-deployment.md     Air-gap and FedRAMP patterns
```

## Commercial Modules

EXPOSE follows an open-core model ([ADR-009](docs/adr/ADR-009-commercial-structure.md)). The Apache 2.0 engine ships with all 41 collectors, the attribution engine, artifact signing, and the Darkroom dashboard. Commercial modules extend the platform for enterprise and federal customers:

| Module | Capability |
|--------|-----------|
| **Threat Context** | Dark web indicators, threat actor profiling, IOC packaging for SOC teams |
| **Identity Surface** | Registrant pivot analysis, organizational graph construction, M&A-aware asset discovery |
| **SOC Package** | STIX 2.1 bundles, MISP events, LLM-generated hunt recommendations, SIEM field mapping |
| **CISO Report** | Executive threat landscape, attraction assessment, ranked target analysis |

See [`docs/positioning.md`](docs/positioning.md) for the full product structure.

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/SPEC.md`](docs/SPEC.md) | Full specification -- architecture, threat model, observation graph, collectors, attribution engine, LLM integration, artifact format |
| [`docs/adr/`](docs/adr/) | 10 Architecture Decision Records |
| [`docs/collectors.md`](docs/collectors.md) | Collector catalog with credential requirements and output schemas |
| [`docs/quickstart.md`](docs/quickstart.md) | Setup and first-run guide |
| [`docs/why-expose.md`](docs/why-expose.md) | Design rationale and positioning |
| [`docs/use-cases.md`](docs/use-cases.md) | Persona-driven use cases |
| [`docs/architecture/`](docs/architecture/) | Mermaid diagrams -- pipeline, deployment, observation graph, multi-tenancy, egress, attribution, product surfaces, federal deployment |
| [`docs/glossary.md`](docs/glossary.md) | Term definitions |
| [`docs/strategy/`](docs/strategy/) | Advisory documents -- federal deployment, air-gap deployment, production runbook, network security, SBOM, competitive analysis, framework mapping |
| [`schemas/`](schemas/) | JSON Schema (Draft 2020-12) -- canonical artifact, manifest, rule pack |
| [`examples/rulepacks/`](examples/rulepacks/) | Example rule packs (baseline, cloud-first, conservative) |
| [`examples/eval-datasets/`](examples/eval-datasets/) | Eval datasets (confirmed, not-yours, ambiguous, adversarial) |

## Contributing

Contributions are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines, development setup with `uv`, pre-commit hooks, and the full testing workflow.

All commits require [Developer Certificate of Origin](https://developercertificate.org/) sign-off (`Signed-off-by:` line), enforced by DCO bot. Pre-commit hooks handle linting (ruff), secret scanning (gitleaks), schema validation, and Helm chart linting.

## Security

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## License

[Apache License 2.0](LICENSE).

The engine is open source. Commercial modules (Threat Context, Identity Surface) are licensed separately under proprietary terms. See [`docs/positioning.md`](docs/positioning.md) and [ADR-009](docs/adr/ADR-009-commercial-structure.md) for the product structure.

## Project Status

**Pre-release.** The specification is locked. Phase 1 implementation is active.

| Metric | Value |
|--------|-------|
| Python source files | 188 across 22 sub-packages |
| Test files | 138 |
| Tests passing | 3,590+ |
| Collectors built | 41 (22 passive, 7 targeted, 12 active) |
| Attribution predicates | 12 |
| SIEM adapters | 3 (Splunk, Sentinel, Chronicle) |
| LLM provider adapters | 4 (Anthropic, OpenAI, Gemini, Ollama) |
| Architecture decisions | 10 ADRs |
| JSON schemas | 3 (canonical artifact, manifest, rule pack) |
| Helm chart templates | 12 |

This is not yet recommended for production use -- expect breaking changes to configuration and schema formats before v1.0.

# EXPOSE

Continuous external attack surface intelligence with signed, attributed artifacts.

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB.svg)](https://www.python.org/)
[![Tests: ~1800 passing](https://img.shields.io/badge/tests-~1800%20passing-brightgreen.svg)](#project-status)
[![Coverage: 91%](https://img.shields.io/badge/coverage-91%25-brightgreen.svg)](#project-status)
[![Status: Pre-release](https://img.shields.io/badge/status-pre--release-yellow.svg)](#project-status)

## What is EXPOSE?

EXPOSE is an open-source External Attack Surface Intelligence (EASI) platform that discovers, attributes, and continuously monitors an organization's internet-facing surface. It produces cryptographically signed JSON artifacts with full provenance chains -- every claim traceable to the collector, observation, and rule that justified it. Built for both defensive CTEM workflows and authorized red team operations, EXPOSE is self-hostable and designed to run inside your own authorization boundary. See [`docs/SPEC.md`](docs/SPEC.md) for the full specification.

## Key Differentiators

- **Signed artifacts with provenance.** Every artifact is signed with Ed25519 or ECDSA P-256, with SLSA-aligned provenance attestations and FIPS SHA-256 content hashing. Downstream consumers verify integrity offline. No other EASM tool -- commercial or open-source -- produces tamper-evident, cryptographically signed deliverables.

- **Open, auditable attribution.** Confidence tiers (`confirmed`, `high`, `medium`, `requires_review`) with numeric scores and full evidence chains back to source observations. Attribution logic is defined as declarative, JSON Schema-validated rule packs -- data, not code. Every finding carries the ATT&CK Reconnaissance technique IDs that contributed to its attribution.

- **Operator-controlled LLM enrichment.** Four provider adapters (Anthropic, OpenAI, Gemini, Ollama) behind a SafeLLMClient that enforces structured-output schemas, per-run cost ceilings, prompt-injection defenses, and per-call audit logging. The operator chooses the provider, sees the prompts, and sets the budget. Run fully offline with Ollama.

- **Federal-ready open core.** Apache 2.0 engine with FedRAMP-ready architecture. FIPS 140-3 validated cryptography, NIST 800-53 control alignment, AU-family audit logging. Self-host inside your own ATO boundary without waiting for vendor authorization.

- **Dual-audience architecture.** A single platform serves both defensive CTEM teams and authorized red team operators. Authorization scope enforcement with configurable medium/hard modes separates who can scan what from what role they serve.

- **Deterministic, reproducible output.** Same seeds, same rule pack, same configuration yields the same canonical artifact. Reproducibility enables academic citation, audit evidence, and delta tracking across runs.

## Features

### Discovery (21 collectors)

21 built-in collectors across three sensitivity tiers. Tier 3 (active) collectors are attribution-gated: they execute only against entities with `confirmed` or `high` attribution, or explicit authorization scope membership.

| Collector | ID | Tier | Source |
|---|---|---|---|
| crt.sh CT Logs | `ct-crtsh` | T1 Passive | Certificate Transparency via crt.sh |
| Certstream CT | `ct-certstream` | T1 Passive | Near-real-time CT log stream |
| RDAP / WHOIS | `rdap-whois` | T1 Passive | RDAP bootstrap + WHOIS fallback |
| Cloud IP Ranges | `cloud-ranges` | T1 Passive | AWS, Azure, GCP published manifests |
| BGP (HE Toolkit) | `bgp-he-toolkit` | T1 Passive | Hurricane Electric BGP Toolkit |
| BGP (RIPEstat) | `bgp-ripestat` | T1 Passive | RIPEstat Data API |
| BGP (Team Cymru) | `bgp-team-cymru` | T1 Passive | Team Cymru DNS service |
| SPF/DKIM/DMARC | `spf-dkim-dmarc` | T1 Passive | DNS TXT record queries |
| GitHub Exposed | `github-exposed` | T1 Passive | GitHub Search API |
| DNSBL Blacklist | `dns-blacklist` | T1 Passive | DNS-based blackhole lists |
| Passive DNS History | `dns-passive-history` | T1 Passive | SecurityTrails + VirusTotal pDNS |
| M&A Discovery | `ma-discovery` | T1 Passive | Subsidiary and acquisition search |
| Favicon Hash | `favicon-hash` | T2 Targeted | HTTP favicon fetch + MurmurHash3 |
| Reverse PTR | `dns-reverse-ptr` | T2 Targeted | Reverse DNS lookup for IP seeds |
| WAF/CDN Detection | `waf-detection` | T2 Targeted | CDN and WAF fingerprinting |
| Active DNS | `active-dns-resolve` | T3 Active | Direct DNS resolution |
| Active TLS | `active-tls-handshake` | T3 Active | TLS handshake + JARM fingerprint |
| Active HTTP | `active-http-fingerprint` | T3 Active | HTTP headers + response fingerprinting |
| Active Port Surface | `active-port-surface` | T3 Active | TCP connect scan (curated port set) |
| Subdomain Enumeration | `dns-subdomain-enum` | T3 Active | Wordlist-based subdomain brute-force |
| DNS Zone Transfer | `dns-zone-transfer` | T3 Active | AXFR against authoritative nameservers |

See [`docs/collectors.md`](docs/collectors.md) for the full collector catalog with credential requirements and output schemas.

### Attribution

- **8-rule-type scope matcher** producing four confidence tiers with numeric scores and per-claim evidence chains
- **Trust degradation detection** -- identifies registrar changes, hosting migrations, certificate authority switches, and other infrastructure shifts that may signal compromise or abandonment
- **Environment classification** -- multi-signal categorization of endpoints as production, staging, QA, development, or test based on correlated DNS, HTTP, TLS, and content signals
- **SaaS product alignment** -- matches observations against a product-signature knowledge base to identify known SaaS footprint and surface gaps
- **Declarative rule packs** (JSON Schema-validated) for reproducible, auditable attribution logic

### Analysis

- **Multi-provider LLM enrichment** via SafeLLMClient with Anthropic, OpenAI, Gemini, and Ollama adapters
- **Vision analysis** -- multimodal screenshot and banner analysis to identify login portals, default pages, and technology indicators that header analysis alone misses
- **Tech-stack fingerprinting** and exposure indicators contributing to numeric lead scores
- **WAF/CDN detection** and origin-IP discovery for assets behind content delivery networks
- **DNSBL reputation checking** across standard DNS blackhole lists

### Pipeline & Operations

- **Canonical artifact generation** with FIPS SHA-256 content hashing, Ed25519/ECDSA signing, and SLSA-aligned provenance envelopes
- **Delta computation** with six classified removal reasons against previous runs
- **Webhook delivery** with HMAC-SHA256 payload signing, typed event headers, and exponential-backoff retry
- **Per-tenant quota enforcement** and misuse detection
- **GDPR/CCPA compliance** with data export and deletion capabilities
- **Configurable data retention** with automated pruning
- **Four network egress profiles**: direct, SOCKS5, WireGuard, HTTP CONNECT proxy

### Dashboard

- **Darkroom** -- web-based dashboard with D3.js observation graph visualization, Alpine.js interactive controls, and real-time SSE event streaming
- **CSV export** with entity-type, attribution-tier, and environment filters

### API & Integration

- **FastAPI REST API** with bearer token authentication, tenant-scoped endpoints, and SSE event streaming
- **RBAC** with three roles (admin, operator, viewer) and tenant-scoped permission enforcement
- **Webhook subscriptions** for event-driven integration with external systems
- **Credential management API** with SpiderFoot import, bundle import/export, and per-credential testing
- **Click CLI** with `run`, `serve`, and `db` commands plus `--live` flag for streaming output
- **OpenTelemetry** distributed tracing, structured logging, and five operational metrics
- **Grafana dashboards** for platform overview and per-tenant monitoring

## Quick Start

```bash
# Clone and start with Docker Compose
git clone https://github.com/pitt-street-labs/expose.git
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

See [`docs/quickstart.md`](docs/quickstart.md) for full setup instructions and [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup with `uv`, pre-commit hooks, and the test suite.

## Documentation

| Document | Description |
|---|---|
| [`docs/SPEC.md`](docs/SPEC.md) | Full specification -- architecture, threat model, observation graph, collectors, attribution engine, LLM integration, artifact format |
| [`docs/adr/`](docs/adr/) | 10 Architecture Decision Records |
| [`docs/collectors.md`](docs/collectors.md) | Collector catalog with credential requirements and output schemas |
| [`docs/quickstart.md`](docs/quickstart.md) | Setup and first-run guide |
| [`docs/why-expose.md`](docs/why-expose.md) | Design rationale and positioning |
| [`docs/use-cases.md`](docs/use-cases.md) | Persona-driven use cases |
| [`docs/architecture/`](docs/architecture/) | Mermaid diagrams -- pipeline, deployment topology, observation graph, multi-tenancy, scanner egress, attribution flow |
| [`docs/glossary.md`](docs/glossary.md) | Term definitions |
| [`docs/strategy/`](docs/strategy/) | Advisory strategy documents -- federal deployment, air-gap deployment, production runbook, network security, SBOM and signing |
| [`schemas/`](schemas/) | JSON Schema (Draft 2020-12) -- canonical artifact, manifest, rule pack |
| [`examples/rulepacks/`](examples/rulepacks/) | Example rule packs (baseline, cloud-first, conservative) |

## Architecture

EXPOSE executes a five-stage pipeline per run: seed expansion, collection, sanitization, attribution and enrichment, and artifact generation. Four stages are fully deterministic; LLM enrichment in Stage 4b is bounded by SafeLLMClient and produces only structured outputs validated against a schema. See [`docs/adr/`](docs/adr/) for the 10 Architecture Decision Records covering language choice, graph storage, deployment model, output format, LLM integration, licensing, multi-tenancy, ethics, commercial structure, and FedRAMP readiness.

## Contributing

Contributions are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines, development setup, and the full testing workflow.

All commits require [Developer Certificate of Origin](https://developercertificate.org/) sign-off (`Signed-off-by:` line), enforced by DCO bot. Pre-commit hooks handle linting (ruff), secret scanning (gitleaks), schema validation, and Helm chart linting.

## Security

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## License

[Apache License 2.0](LICENSE).

The engine is open source. Commercial modules (Threat Context, Identity Surface) are licensed separately. See [`docs/positioning.md`](docs/positioning.md) for the product structure.

## Project Status

**Pre-release.** The specification is complete and locked. Phase 1 implementation is active.

| Metric | Value |
|---|---|
| Python source files | 133 across 21 sub-packages |
| Test files | 94 |
| Tests passing | ~1,800 |
| Test coverage | 91% |
| Collectors built | 21 (12 passive T1, 3 targeted T2, 6 active T3) |
| LLM provider adapters | 4 (Anthropic, OpenAI, Gemini, Ollama) |
| Architecture decisions | 10 ADRs |
| JSON schemas | 3 (canonical artifact, manifest, rule pack) |
| Helm chart templates | 12 |

This is not yet recommended for production use -- expect breaking changes to configuration and schema formats before v1 GA.

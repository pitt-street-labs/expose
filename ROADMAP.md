# EXPOSE Roadmap

EXPOSE is an open-core External Attack Surface Intelligence (EASI) platform that produces continuous, attributed, cryptographically signed artifacts from public data sources. It is designed for both defensive Continuous Threat Exposure Management (CTEM) workflows and authorized red team operations, with a federal-deployable open-source substrate.

This roadmap reflects current development state and planned direction. Dates are approximate. The project is pre-release; APIs and schemas may change before v1.0.

Source: [github.com/pitt-street-labs/expose](https://github.com/pitt-street-labs/expose)

---

## What's built (v0.1 -- current)

The deterministic engine, attribution pipeline, and core infrastructure are operational.

### Discovery and collection

- **14 data collectors** spanning Certificate Transparency (crt.sh), BGP/ASN (via RIPEstat and RouteViews), active DNS resolution, RDAP/WHOIS, TLS certificate analysis, active HTTP fingerprinting, cloud provider IP range manifests (AWS, Azure, GCP), email authentication records (SPF, DKIM, DMARC), favicon hashing, and GitHub organization enumeration
- **Seed expansion** from minimal inputs (organization name, brand strings, known apex domains) to progressively attributed external surface
- **Egress profiles** with direct, SOCKS5, WireGuard, and HTTP CONNECT proxy support for scanner traffic isolation

### Attribution and analysis

- **Attribution engine** with 8-rule-type scope matcher producing confidence tiers (`confirmed`, `high`, `medium`, `requires_review`) with full evidence chains back to source observations
- **Multi-provider LLM enrichment** via `SafeLLMClient` supporting Anthropic, OpenAI, Gemini, and Ollama -- operator chooses the provider, sees the prompt, sets the cost ceiling, validates the output
- **Declarative rule packs** (JSON Schema-validated) for reproducible, auditable attribution logic
- **Canonical artifact generation** with FIPS SHA-256 content hashing and full provenance on every claim
- **Tech-stack fingerprinting** and exposure indicators contributing to numeric lead scores

### Pipeline and operations

- **Pipeline orchestration** with dispatcher, executor, artifact planner, validator, and delta computation against previous runs
- **Per-tenant quota enforcement** and misuse detection
- **GDPR/CCPA compliance** with data export and deletion capabilities
- **Retention pruner** with configurable policy-based artifact lifecycle management
- **SpiderFoot credential import** for migration from existing recon workflows
- **Secrets management** with Vault, environment variable, and in-memory backends

### API and interface

- **FastAPI REST API** with bearer token authentication, SSE event streaming, and tenant-scoped endpoints for runs, graph queries, and event subscriptions
- **Darkroom dashboard** -- Jinja2 + D3.js observation graph + Alpine.js interactive controls
- **Click CLI** with `run`, `serve`, and `db` commands plus `--live` flag for interactive operation

### Infrastructure and security

- **Helm chart** with NetworkPolicy and PodSecurity hardening
- **Multi-stage, multi-arch Dockerfile** (buildx)
- **CI pipeline** with lint, test, schema-sync, FIPS gate, Helm lint, multi-arch container build, and aggregated gate check
- **Pre-commit hooks** with Ruff, gitleaks, JSON Schema validation, and Helm lint
- **OpenTelemetry tracing** and structlog-based structured logging with 5 operational metrics
- **SQLAlchemy ORM** with Alembic migrations and async tenant-scoped repositories
- **1059 tests, 92% coverage** across 50 test files and 94 source files

---

## Coming soon (v0.2)

Distributed operation, scheduling, and supply-chain integrity.

- **NATS JetStream-mediated distributed dispatch** -- decouple collector execution from the pipeline coordinator for horizontal scaling
- **Run scheduling** -- cron-based re-scan with configurable cadence per tenant, enabling true continuous monitoring
- **Cosign artifact signing + SLSA provenance** -- every artifact is cosign-signed with SLSA Level 2+ attestations; downstream consumers verify integrity offline
- **Full Helm chart** with per-component deployments (API, workers, scheduler, NATS) and production-ready resource limits
- **Multimodal screenshot analysis** -- LLM vision models analyze captured screenshots to identify login portals, default pages, and technology indicators that header analysis alone cannot detect
- **SBOM generation** for the container image and all transitive dependencies
- **Authenticated HTTPS API** for CTEM platform retrieval (the artifact becomes queryable, not just file-delivered)

---

## Planned (v0.3+)

Commercial modules, deeper analysis, and enterprise integration.

### EXPOSE Threat Context (commercial module)

Adversary-infrastructure monitoring anchored in MITRE ATT&CK Resource Development (TA0042):

- Dark web indicator enrichment (Indicators of Compromise, Interest, and Preparation)
- APT targeting profile correlation
- Historical point-in-time enrichment for longitudinal analysis
- Social media brand-impersonation detection
- Legal and regulatory exposure indicators

### EXPOSE Identity Surface (commercial module)

Registrant correlation and authorized personnel reconnaissance (scope-gated, off by default, elevated ethics bar):

- WHOIS/RDAP registrant pivot and cross-domain correlation
- Authorized social-media tangential target mapping
- Organization-graph construction from public records

### Platform capabilities

- **WAF detection and origin IP discovery** -- identify assets behind CDN/WAF layers that traditional scanning misses
- **Trust degradation scoring** -- track how attribution confidence changes over time as infrastructure shifts
- **CTEM platform adapters** for Splunk, Microsoft Sentinel, and Google Chronicle -- structured artifact ingestion with field mapping
- **FedRAMP authorization pathway** for the commercial Korlogos managed-service offering (Moderate baseline, Agency ATO sponsorship)
- **Reference attribution datasets** published under CC BY 4.0 for academic and federal-research use via EXPOSE Research

---

## Future exploration

Ideas under consideration that have not been committed to a timeline.

- **EXPOSE Research offering** -- academic and research licensing with curated reference graph datasets, schemas, and benchmarks for attribution-methodology research and reproducible security science
- **Bedrock and Vertex AI provider adapters** -- extend the multi-provider LLM abstraction to AWS and GCP managed inference
- **Real-time CT log streaming** via WebSocket for event-driven certificate discovery (complementing the daily batch cadence)
- **Air-gapped deployment mode** with local-only LLM inference (Ollama) and no external API dependencies beyond initial seed data
- **StateRAMP and CMMC authorization pathways** for state-government and defense-contractor customers
- **Eval harness public benchmarks** -- published leaderboards for attribution-methodology accuracy using EXPOSE's open eval framework

---

## How to follow along

EXPOSE is Apache 2.0 licensed. The engine, schemas, rule packs, and eval datasets are open source. Commercial modules (Threat Context, Identity Surface) are separately licensed.

- Repository: [github.com/pitt-street-labs/expose](https://github.com/pitt-street-labs/expose)
- License: Apache 2.0 (engine) / CC BY 4.0 (research datasets)
- Security policy: See `SECURITY.md`
- Contributing: See `CONTRIBUTING.md`

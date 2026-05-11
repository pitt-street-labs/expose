# Changelog

All notable changes to EXPOSE are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project has not yet reached its first tagged release; all entries below
are under **Unreleased**.

## [Unreleased]

### Added

- Core reconnaissance engine with rule-based pipeline dispatcher and run executor
- 14 built-in data collectors: Certificate Transparency (crt.sh, Certstream), BGP/ASN (HE Toolkit, RIPE, Team Cymru), Cloud IP Ranges, RDAP/WHOIS, Active DNS, Active HTTP, Active TLS, Active Port Surface, Favicon Hash, Email Authentication (SPF/DKIM/DMARC), and GitHub Exposure
- 7 additional collectors: DNSBL blacklist checking, passive DNS history (SecurityTrails + VirusTotal), reverse PTR lookup, subdomain enumeration (wordlist-based), DNS zone transfer (AXFR), M&A / subsidiary discovery, and WAF/CDN detection
- 3 internet-wide scan ingest collectors (Censys, Shodan, BinaryEdge) -- implemented, pending registry activation
- Pluggable collector framework with tiered classification (passive, semi-active, active) and a collector registry
- Multi-provider LLM enrichment client with Anthropic, OpenAI, Gemini, and Ollama adapters
- Multimodal vision analysis (Stage 4c) for screenshot and banner analysis via LLM vision models -- identifies login portals, default pages, technology indicators, and security misconfigurations
- Observation graph data model backed by PostgreSQL with Alembic schema migrations
- NATS JetStream message broker integration for asynchronous pipeline stages
- Artifact pipeline: generator, planner, validator, delta comparison, and manifest builder
- Artifact signing with Ed25519 and ECDSA P-256 keys plus SLSA Level 2+ provenance envelope generation
- Seed expansion to derive reconnaissance targets from initial scope definitions
- 8-rule-type scope authorization matcher with hard enforcement boundary
- Trust degradation detection -- registrar changes, DNS provider changes, hosting migrations, certificate authority changes, certificate expiry, nameserver changes, IP address changes, and tech-stack changes
- Environment classification -- multi-signal categorization (production, staging, QA, development, test) from correlated DNS, HTTP, TLS, and content signals
- SaaS product-to-endpoint alignment analysis with inbound fingerprinting and outbound expected-surface validation
- Multi-tenant isolation with per-tenant credential resolution and quota tracking
- RBAC with three built-in roles (admin, operator, viewer) and tenant-scoped permission enforcement via FastAPI dependency injection
- Webhook delivery engine with HMAC-SHA256 payload signing, typed event headers (`X-EXPOSE-Signature`, `X-EXPOSE-Event`, `X-EXPOSE-Delivery`), and exponential-backoff retry
- CSV export API with entity-type, attribution-tier, environment, and collector-id filters
- Credential management API with CRUD operations, SpiderFoot import, bundle import/export, and per-credential connectivity testing
- Four network egress profiles: Direct, SOCKS5, WireGuard, and HTTP CONNECT proxy
- Data retention policies with automated pruning
- GDPR compliance module: data export, data deletion, and misuse detection
- Secrets management with in-memory, HashiCorp Vault, and environment variable backends
- PII sanitization and text canonicalization across all pipeline outputs
- FIPS 140-2 compliant SHA-256 cryptographic adapter
- SpiderFoot data importer for migrating existing reconnaissance results
- Attribution evaluation harness with dataset loaders and scoring metrics
- FastAPI REST API with bearer token authentication
- API endpoints for tenant management, scan runs, observation graph queries, and server-sent events
- Click-based CLI with `run`, `serve`, and `db` commands and a `--live` streaming flag
- Web-based Darkroom dashboard UI with D3.js graph visualization, Alpine.js interactivity, and real-time SSE event streaming
- Three JSON Schemas (Draft 2020-12): canonical artifact, manifest, and rule pack
- Three example rule packs: baseline, cloud-first, and conservative scanning profiles
- Example evaluation datasets for attribution accuracy testing
- Multi-stage, multi-architecture Docker container build
- Helm chart with 12 templates: control-plane deployment, collector-worker deployment, scanner-worker deployment, NATS StatefulSet, services, ConfigMap, Ingress, NetworkPolicy, PodSecurity, ServiceAccount
- Object storage abstraction with local filesystem and S3 backends
- OpenTelemetry distributed tracing and structured logging with five custom metrics
- Grafana dashboards for platform overview and per-tenant monitoring
- SBOM generation script and container image signing guide (cosign)
- CI pipeline: linting, tests, schema sync verification, FIPS gate, Helm lint, and multi-arch container build
- Pre-commit hooks: Ruff linter, Gitleaks secret scanning, JSON Schema validation, and Helm lint
- ~1,800 automated tests across 94 test files with 91% coverage
- Apache 2.0 open-source license with commercial module separation
- Architecture Decision Records (ADR-001 through ADR-010) covering language, graph storage, deployment, output format, LLM integration, licensing, multi-tenancy, ethics, commercial structure, and FedRAMP readiness
- Full specification document defining the engine contract and extension points
- Architecture diagrams: pipeline stages, two-environment model, deployment topology, observation graph, multi-tenancy, scanner egress, attribution flow, product surfaces, and federal deployment pattern
- Competitive analysis and functional equivalence analysis against top 5 EASM competitors
- Module specifications for Threat Context and Identity Surface commercial modules
- AI-leverage technology roadmap
- Secure Development Lifecycle Plan (SDLP)
- Framework annotation with per-collector MITRE ATT&CK TA0043 mapping
- Federal customer deployment guide, air-gap deployment guide, and production runbook
- PostgreSQL deployment guide, network security guide, and egress deployment guide
- SBOM and signing guide
- Ethics policy with quarterly review schedule
- Security policy and coordinated vulnerability disclosure process
- Code of Conduct and contribution guidelines with DCO sign-off requirement
- Responsible AI usage documentation
- GitHub issue templates (bug, feature, collector request) and pull request template

### Fixed

- Dashboard template rendering compatibility with current Starlette API
- Rule pack schema now accepts `$schema` self-reference property
- Context variable unification across concurrent pipeline runs
- Input sanitization coverage gaps in collector outputs
- Race condition in parallel artifact generation
- Egress profile wiring for proxy-based collection paths

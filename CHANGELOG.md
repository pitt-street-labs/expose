# Changelog

All notable changes to EXPOSE are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project has not yet reached its first tagged release; all entries below
are under **Unreleased**.

## [Unreleased]

### Added

- Core reconnaissance engine with rule-based pipeline dispatcher and run executor
- 14 built-in data collectors: Certificate Transparency (crt.sh, Certstream), BGP/ASN (HE Toolkit, RIPE, Team Cymru), Cloud IP Ranges, RDAP/WHOIS, Active DNS, Active HTTP, Active TLS, Active Port Surface, Favicon Hash, Email Authentication (SPF/DKIM/DMARC), and GitHub Exposure
- Pluggable collector framework with tiered classification (passive, semi-active, active) and a collector registry
- Multi-provider LLM enrichment client with Anthropic, OpenAI, Gemini, and Ollama adapters
- Observation graph data model backed by PostgreSQL with Alembic schema migrations
- NATS JetStream message broker integration for asynchronous pipeline stages
- Artifact pipeline: generator, planner, validator, delta comparison, and manifest builder
- Seed expansion to derive reconnaissance targets from initial scope definitions
- 8-rule-type scope authorization matcher with hard enforcement boundary
- Multi-tenant isolation with per-tenant credential resolution and quota tracking
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
- Web-based dashboard UI with D3.js graph visualization, Alpine.js interactivity, and real-time SSE event streaming
- Three JSON Schemas (Draft 2020-12): canonical artifact, manifest, and rule pack
- Three example rule packs: baseline, cloud-first, and conservative scanning profiles
- Example evaluation datasets for attribution accuracy testing
- Multi-stage, multi-architecture Docker container build
- Helm chart skeleton with NetworkPolicy and PodSecurity hardening
- Object storage abstraction with local filesystem and S3 backends
- OpenTelemetry distributed tracing and structured logging with five custom metrics
- Grafana dashboards for platform overview and per-tenant monitoring
- SBOM generation script and container image signing guide (cosign)
- CI pipeline: linting, tests, schema sync verification, FIPS gate, Helm lint, and multi-arch container build
- Pre-commit hooks: Ruff linter, Gitleaks secret scanning, JSON Schema validation, and Helm lint
- 805 automated tests across 50 test files
- Apache 2.0 open-source license with commercial module separation
- Architecture Decision Records (ADR-001 through ADR-010) covering language, graph storage, deployment, output format, LLM integration, licensing, multi-tenancy, ethics, commercial structure, and FedRAMP readiness
- Full specification document defining the engine contract and extension points
- Architecture diagrams: pipeline stages, two-environment model, deployment topology, observation graph, multi-tenancy, scanner egress, attribution flow, product surfaces, and federal deployment pattern
- Competitive analysis, framework annotation, and strategic positioning documents
- Secure Development Lifecycle Plan (SDLP)
- Federal customer deployment guide, air-gap deployment guide, and production runbook
- PostgreSQL deployment guide and network security guide
- Threat Context and Identity Surface module specifications
- AI-leverage technology roadmap
- Ethics policy with quarterly review schedule
- Security policy and coordinated vulnerability disclosure process
- Code of Conduct and contribution guidelines with DCO sign-off requirement

### Fixed

- Dashboard template rendering compatibility with current Starlette API
- Rule pack schema now accepts `$schema` self-reference property
- Context variable unification across concurrent pipeline runs
- Input sanitization coverage gaps in collector outputs
- Race condition in parallel artifact generation
- Egress profile wiring for proxy-based collection paths

# Changelog

All notable changes to EXPOSE are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-05-12

### Added

- API key authentication (`EXPOSE_API_KEY` env var, Bearer/X-API-Key headers, /healthz exempt)
- Scan delta/comparison API (`GET /v1/tenants/{tid}/runs/{rid}/delta?baseline_run_id=...`)
- Email delivery API (`POST /v1/tenants/{tid}/reports/ciso/deliver` with configurable SMTP)
- Active port probe collector (Tier 3, direct TCP connect scan on 30 common ports + TLS handshake)
- Registrar/nameserver supply chain risk scoring (GoDaddy +15, single NS dependency +10, no DNSSEC +5)
- CISO report finding rules: internal hostname leakage, sensitive IP exposure, missing HTTPS, single registrar
- Context-specific report justifications (registrar data, internal patterns, port exposure, TLS issues)
- CT log retry logic (3x exponential backoff on 5xx/network errors, 45s timeout floor)
- Attribution inheritance (subdomains inherit medium attribution from parent domains)
- Community rule pack contribution framework and docs
- Competitive positioning, pricing tiers, MSSP licensing, data provider roadmap docs
- RDAP collector extracts DNSSEC status from secureDNS.delegationSigned
- LLM enrichment auto-enables when EXPOSE_GEMINI_API_KEY is set

### Fixed

- ISP contamination in multi-pass expansion (582 optimum.com entities → 0 via scope-anchored seed feedback)
- Entity properties merge instead of overwrite (Postgres jsonb || operator preserves data from all collectors)
- Tier-3 dispatch gate timing (operator seeds bypass attribution gate, pass 2+ seeds carry attribution)
- Tenant config persists to database (config_jsonb column, survives container restarts)
- Lead scoring signals accept Shodan/Censys/BinaryEdge data (collector ID + property key mapping)
- Attribution scoring no longer downgrades seed entities from medium to unattributed
- DNSSEC absent treated as no DNSSEC (was only firing on explicit False)

### Security

- API authentication required for all endpoints (except /healthz)
- Pre-publication PII redaction, secret scrub, org name unification
- Gemini Pro security review completed (DNS rebinding, timing attacks flagged for future hardening)

## [0.2.0] - 2026-05-11

### Added

- Rule evaluation engine with 12 attribution predicates and customizable rule packs
- Lead scoring with priority tiers wired into pipeline
- SSE event publishing for real-time run monitoring
- Run scheduling API with cron expressions and concurrent run limits
- Enforcement logging for scope denial audit trail
- Ed25519/ECDSA artifact signing with FIPS-compliant hashing
- MITRE ATT&CK technique mapping for all 31 collectors
- Seed entity attribution (confirmed/1.0 for seeds)
- Tier-3 dispatch gating on attribution status
- Graph edge types: certificate_for, hosts, belongs_to
- Provenance chain API and UI
- NIST AU-2/AU-3 audit logging schema
- Screenshot vision collector with Stage 4c analysis
- Eval harness CLI (`expose eval`) with P/R/F1 metrics
- WAF origin discovery collector (5 methods, 6 CDN vendors)
- Grafana dashboards (overview + tenant, 24 panels)
- Content-addressed evidence storage
- Dark web indicator module (HIBP, IntelX, DeHashed)
- SIEM adapters complete (Splunk HEC, Sentinel, Chronicle)
- Identity surface module (registrant pivot, org graph)
- Type safety: Pydantic models for core pipeline data structures

### Fixed

- Scheduler API authentication (CVSS 9.1)
- Circuit breaker race condition
- Egress profile mutation race
- Background task cleanup on shutdown
- SSRF endpoint validation in SIEM adapters
- Cross-tenant data leakage in SIEM delivery
- HTTP connection pooling in collectors
- Batch upsert deduplication (CardinalityViolationError)
- Relationship batch_create constraint reference
- State determination: skipped vs failed classification
- Test isolation bug in ct-crtsh cache

### Security

- Auth middleware on scheduler endpoints
- SSRF validation blocks internal IPs
- Tenant correlation on SIEM delivery
- Dispatch/enrichment timeouts (120s/60s)

## [0.1.0] - 2026-05-10

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

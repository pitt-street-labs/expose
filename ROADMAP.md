# EXPOSE Roadmap

EXPOSE is an open-core External Attack Surface Intelligence (EASI) platform that produces continuous, attributed, cryptographically signed artifacts from public data sources. It is designed for both defensive Continuous Threat Exposure Management (CTEM) workflows and authorized red team operations, with a federal-deployable open-source substrate.

This roadmap reflects current development state and planned direction. Dates are approximate. The project is pre-release; APIs and schemas may change before v1.0.

Source: [github.com/pitt-street-labs/expose](https://github.com/pitt-street-labs/expose)

---

## What's next (v0.3)

Medium-severity fixes, integration testing, and production hardening.

### Medium-severity findings (#147--#156)

- Rate limiting and abuse prevention on public API endpoints
- Credential rotation workflow without downtime
- Helm chart resource tuning (CPU/memory requests and limits per component)
- NATS JetStream consumer replay and dead-letter handling
- Collector timeout normalization (per-collector SLA)
- Retention pruner dry-run mode with preview report
- Quota enforcement edge cases (burst allowance, grace period)
- RBAC fine-grained permission audit (least-privilege review)
- OpenTelemetry trace sampling configuration for high-volume deployments
- Structured error codes across all API responses

### Integration and load testing

- End-to-end multi-tenant run with NATS dispatch under simulated load
- Concurrent scheduling stress test (overlapping cron windows)
- SIEM adapter delivery reliability under back-pressure
- Evidence storage write throughput benchmarking
- Pipeline stage timeout and circuit-breaker validation under degraded conditions

---

## Planned (v1.0)

GitHub publication, FedRAMP pathway, and MSSP packaging.

### GitHub publication (#112--#121)

- Public repository under `pitt-street-labs/expose` (consent-gated, pending trademark check)
- Polished README with quickstart, architecture diagram, and badge row
- Published container images (GHCR) with cosign signatures
- Helm chart on ArtifactHub
- Reference attribution datasets published under CC BY 4.0
- Discussion forums and issue triage workflow
- Contributor onboarding documentation
- Security advisory publication channel
- CI/CD pipeline hardened for public contributions (fork-safe, secret-safe)
- First tagged release with SLSA Level 2+ provenance

### FedRAMP authorization pathway

- FedRAMP Moderate baseline control mapping (AC, AU, IA, SC families)
- Agency ATO sponsorship engagement
- Air-gap deployment validation with local-only LLM inference
- FIPS 140-2 validated cryptographic module integration
- Continuous monitoring plan (ConMon) aligned with OSCAL

### MSSP packaging

- Multi-tenant SaaS deployment model with tenant isolation validation
- White-label artifact branding for managed-service resellers
- Usage-based metering and billing integration points
- Onboarding automation (tenant provisioning, credential seeding, first-run wizard)
- SLA monitoring dashboards and uptime reporting

---

## Future exploration

Ideas under consideration that have not been committed to a timeline.

- **EXPOSE Research offering** -- academic and research licensing with curated reference graph datasets, schemas, and benchmarks for attribution-methodology research and reproducible security science
- **Bedrock and Vertex AI provider adapters** -- extend the multi-provider LLM abstraction to AWS and GCP managed inference
- **Real-time CT log streaming** via WebSocket for event-driven certificate discovery (complementing the daily batch cadence)
- **StateRAMP and CMMC authorization pathways** for state-government and defense-contractor customers
- **Eval harness public benchmarks** -- published leaderboards for attribution-methodology accuracy using EXPOSE's open eval framework

---

## Completed

### v0.2 (2026-05-11)

Rule evaluation engine, scheduling, signing, commercial modules, and security hardening. Issues #96--#111.

- Rule evaluation engine with 12 attribution predicates and customizable rule packs
- Lead scoring with priority tiers wired into pipeline
- SSE event publishing for real-time run monitoring via RunEventBus
- Run scheduling API with cron expressions and concurrent run limits
- Enforcement logging for scope denial audit trail
- Ed25519/ECDSA artifact signing with FIPS-compliant hashing
- MITRE ATT&CK technique mapping for all 31 collectors
- Screenshot vision collector with Stage 4c multimodal analysis
- Eval harness CLI (`expose eval`) with precision/recall/F1 metrics
- WAF origin discovery collector (5 methods, 6 CDN vendors)
- Grafana dashboards (overview + tenant, 24 panels)
- Content-addressed evidence storage
- Dark web indicator module (HIBP, IntelX, DeHashed)
- SIEM adapters (Splunk HEC, Microsoft Sentinel, Google Chronicle)
- Identity surface module (registrant pivot, org graph)
- NIST AU-2/AU-3 audit logging schema
- Provenance chain API and UI
- Graph edge types: certificate_for, hosts, belongs_to
- Type safety: Pydantic models for core pipeline data structures
- Scheduler API auth fix (CVSS 9.1), SSRF validation, tenant correlation, timeouts

### v0.1 (2026-05-10)

Deterministic engine, attribution pipeline, and core infrastructure. 31 collectors, 3590+ tests.

- 31 data collectors spanning CT, BGP/ASN, DNS, RDAP/WHOIS, TLS, HTTP, cloud ranges, email auth, favicon hash, GitHub, DNSBL, passive DNS, reverse PTR, subdomain enumeration, zone transfer, M&A discovery, WAF/CDN detection, Censys, Shodan, BinaryEdge, CertSpotter, Common Crawl, AlienVault OTX, Wayback Machine, robots.txt, Wikipedia edits, security.txt, DNS Chaos, mail headers, screenshot capture
- Multi-provider LLM enrichment (Anthropic, OpenAI, Gemini, Ollama)
- Observation graph backed by PostgreSQL with Alembic migrations
- NATS JetStream message broker integration
- Artifact pipeline: generator, planner, validator, delta comparison, manifest builder
- Seed expansion, 8-rule-type scope matcher, trust degradation detection
- Environment classification, SaaS product-to-endpoint alignment
- Multi-tenant isolation with RBAC (admin, operator, viewer)
- Webhook delivery with HMAC-SHA256 signing and retry
- Credential management API with SpiderFoot import
- Four egress profiles (Direct, SOCKS5, WireGuard, HTTP CONNECT)
- GDPR compliance, data retention, PII sanitization, FIPS SHA-256
- FastAPI REST API, Darkroom dashboard (D3.js + Alpine.js), Click CLI
- Helm chart with NetworkPolicy and PodSecurity hardening
- CI pipeline, pre-commit hooks, OpenTelemetry tracing
- Apache 2.0 license, ADR-001 through ADR-010, full specification document
- Architecture diagrams, competitive analysis, federal deployment guide

---

## How to follow along

EXPOSE is Apache 2.0 licensed. The engine, schemas, rule packs, and eval datasets are open source. Commercial modules (Threat Context, Identity Surface) are separately licensed.

- Repository: [github.com/pitt-street-labs/expose](https://github.com/pitt-street-labs/expose)
- License: Apache 2.0 (engine) / CC BY 4.0 (research datasets)
- Security policy: See `SECURITY.md`
- Contributing: See `CONTRIBUTING.md`

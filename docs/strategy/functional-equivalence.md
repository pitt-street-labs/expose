# EXPOSE Functional Equivalence Analysis

_Advisory -- not locked. Product analysis for internal planning._

**Status:** Advisory -- not locked. Open for revision in subsequent sessions.
**Date:** 2026-05-10
**Author context:** AI-assisted analysis comparing EXPOSE v0.1 feature set against the top 5 EASM competitors. Draws on EXPOSE implementation state from ROADMAP.md and CLAUDE.md, competitor data from publicly documented vendor features, marketing materials, and analyst reports as of May 2026.
**Public name:** EXPOSE / **Internal codename:** FF6K

This document complements `competitive-analysis.md` (Session B), which covers 13 comparison axes and 13 vendors at a strategic level. This document goes deeper and narrower: feature-by-feature comparison of EXPOSE v0.1 against the top 5 competitors to identify functional gaps, parity points, and differentiated capabilities. It informs engineering prioritization and roadmap sequencing, not strategic positioning.

---

## Purpose

Feature-by-feature comparison of EXPOSE v0.1 against the top 5 EASM competitors to identify functional gaps, parity points, and differentiated capabilities. The goal is honest assessment of where EXPOSE stands today, what must close before GA, and what constitutes genuine differentiation.

---

## Methodology

Compared publicly documented features from vendor documentation, marketing materials, pricing pages, product changelogs, API documentation, and analyst reports (Gartner EASM Market Guide, Forrester ASM Wave) as of May 2026. EXPOSE capabilities were assessed against the actual v0.1 implementation as described in ROADMAP.md, SPEC.md, and the collector catalog (`docs/collectors.md`).

**Limitations:**
- Competitor feature depth is assessed from public documentation; internal capabilities may exceed what is documented.
- Features marked with `?` indicate uncertainty -- the vendor may or may not have this capability but public documentation is ambiguous.
- Competitor features change rapidly; this analysis represents a point-in-time snapshot.
- "Enterprise contract" pricing means public pricing is not available; actual costs vary by deal.

---

## Competitors Assessed

| Vendor | Product | Pricing Model | FedRAMP Status | Key Differentiator |
|--------|---------|---------------|----------------|--------------------|
| Palo Alto Networks | Cortex Xpanse | Per-asset enterprise | FedRAMP High (Jan 2025) | Active Response remediation playbooks |
| Microsoft | Defender EASM | $0.011/asset/day | FedRAMP High (Azure Gov) | Microsoft 365/Sentinel/Defender XDR integration |
| Mandiant / Google | Attack Surface Management | Enterprise contract | FedRAMP Ready High (platform) | Mandiant threat intel integration |
| Censys | Attack Surface Management | Tiered SaaS | None | Internet-wide scan dataset depth |
| SpiderFoot | SpiderFoot HX (Intel 471) | Open-source + SaaS | None | 200+ OSINT modules, OSS community |

---

## Feature Matrix

### 1. Discovery and Collection

| Feature | EXPOSE v0.1 | Cortex Xpanse | Defender EASM | Mandiant ASM | Censys ASM | SpiderFoot HX |
|---------|-------------|---------------|---------------|--------------|------------|---------------|
| **Certificate Transparency monitoring** | Yes (crt.sh, 2 collectors) | Yes | Yes | Yes | Yes (native CT dataset) | Yes |
| **BGP/ASN enumeration** | Yes (3 collectors: HE, RIPEstat, Team Cymru) | Yes | Yes | Yes | Yes | Yes |
| **WHOIS/RDAP lookup** | Yes (RDAP via RFC 9083) | Yes | Yes (RiskIQ heritage) | Yes | Yes | Yes |
| **Cloud IP range matching** | Yes (AWS, Azure, GCP manifests) | Yes (all major clouds) | Yes (Azure-native + others) | Yes | Yes | Partial (via modules) |
| **Active DNS resolution** | Yes (Tier 3, attribution-gated) | Yes | Yes | Yes | Yes | Yes |
| **Active TLS handshake** | Yes (Tier 3, cert chain + cipher) | Yes | Yes | Yes | Yes (native scanning) | Yes |
| **Active HTTP fingerprinting** | Yes (Tier 3, headers + title + banner) | Yes | Yes | Yes | Yes | Yes |
| **Port scanning** | Yes (27 common ports, TCP connect) | Yes (comprehensive) | Yes | Yes | Yes (full port range) | Yes |
| **Subdomain enumeration** | Partial (via CT + DNS; no brute-force) | Yes (multi-source) | Yes | Yes | Yes | Yes (extensive) |
| **Web fingerprinting / tech stack** | Yes (HTTP headers + LLM inference) | Yes (Expander engine) | Yes | Yes | Yes | Yes (Wappalyzer-style) |
| **Email auth records (SPF/DKIM/DMARC)** | Yes (dedicated collector) | Partial ? | Partial ? | Partial ? | No ? | Yes |
| **Favicon hashing** | Yes (SHA-256 + MurmurHash3 stub) | No ? | No ? | No ? | Yes (Censys dataset) | Yes |
| **GitHub org enumeration** | Yes (API search for code/repos) | No ? | No ? | No ? | No | Yes |
| **Passive DNS** | Planned (SecurityTrails, Validin, Farsight in spec; not built) | Yes (multiple feeds) | Yes (RiskIQ pDNS) | Yes | Yes | Yes |
| **Internet-wide scan ingest** | Planned (Censys, Shodan, BinaryEdge in spec; not built) | Yes (proprietary scanning) | Yes (RiskIQ data) | Yes | Yes (native) | Yes (API modules) |
| **Dark web monitoring** | No (v0.3+ Threat Context module) | No ? | No | Yes (Mandiant CTI) | No | Yes (Tor crawling) |
| **Social media monitoring** | No (v0.3+ Threat Context module) | No | No | No ? | No | Yes (multiple modules) |
| **Subdomain brute-forcing** | No | Yes ? | Yes ? | Yes ? | No | Yes |
| **Seed expansion from minimal input** | Yes (org name + brand + apex domains) | Yes (org name + domains) | Yes (domain seeds) | Yes | Yes | Yes (various seed types) |
| **Cloud account API enumeration** | No (range matching only; no API auth) | Yes (AWS/Azure/GCP API) | Yes (Azure-native API) | Yes ? | No | No |
| **WHOIS history** | No (live RDAP only) | Yes | Yes (RiskIQ archive) | Yes | Yes ? | Yes (via WhoisXML) |
| **Multimodal screenshot analysis** | No (v0.2 planned) | No ? | Yes (screenshot capture) | No ? | No ? | No |
| **Real-time CT log streaming** | No (future exploration) | Yes | Yes ? | Yes ? | Yes (real-time ingestion) | No |

**Summary:** EXPOSE v0.1 covers the core passive and active discovery categories with 14 built-in collectors. Primary gaps are passive DNS (specified but not yet implemented), internet-wide scan dataset ingest (specified but not built), subdomain brute-forcing, cloud account API-authenticated enumeration, and WHOIS history. Dark web and social media monitoring are planned as commercial Threat Context module features (v0.3+).

---

### 2. Attribution and Analysis

| Feature | EXPOSE v0.1 | Cortex Xpanse | Defender EASM | Mandiant ASM | Censys ASM | SpiderFoot HX |
|---------|-------------|---------------|---------------|--------------|------------|---------------|
| **Confidence scoring (tiered)** | Yes (4 tiers: confirmed/high/medium/requires_review) | Yes (proprietary scoring) | Yes (state-based) | Yes (proprietary) | Yes (>95% accuracy claim) | No (manual) |
| **Evidence chains / provenance** | Yes (per-claim collector + observation + rule chain) | No ? | No ? | No ? | No ? | No |
| **Rule-based attribution** | Yes (8 rule types, declarative JSON rule packs) | Yes (proprietary engine) | Yes (proprietary) | Yes (proprietary) | Yes (proprietary) | Partial (correlation rules) |
| **Open/auditable rule packs** | Yes (JSON Schema-validated, Apache 2.0) | No (proprietary) | No (proprietary) | No (proprietary) | No (proprietary) | Partial (OSS core) |
| **LLM/AI-powered enrichment** | Yes (multi-provider SafeLLMClient; 4 providers) | Yes (AI-driven SOC) | Yes (Copilot for Security) | Yes (Mandiant AI) | No ? | No |
| **Operator-controlled LLM provider** | Yes (choose Ollama/Anthropic/OpenAI/Gemini) | No (vendor-managed) | No (Microsoft-managed) | No (Google-managed) | N/A | N/A |
| **Tech-stack inference** | Yes (HTTP + LLM inference) | Yes (deep fingerprinting) | Yes | Yes | Yes (banner analysis) | Yes (Wappalyzer) |
| **Lead scoring** | Yes (deterministic weighted formula, auditable) | Yes (priority scoring) | Yes (severity scoring) | Yes | Yes | No |
| **Scope enforcement** | Yes (authorization_scope with medium/hard modes) | Yes (automated scoping) | Yes (org-based scoping) | Yes | Yes (automated) | No |
| **Manual review workflow** | Partial (requires_review tier flags for analyst) | Yes (UI-based review) | Yes (full UI workflow) | Yes (Mandiant Advantage UI) | Yes (dashboard-based) | No |
| **Observation graph model** | Yes (Postgres-backed, typed nodes + edges) | Yes (proprietary graph) | Yes (RiskIQ graph) | Yes (proprietary) | Yes (Censys data model) | Partial (relationship view) |
| **Historical attribution tracking** | Partial (first_observed/last_observed per entity) | Yes (full timeline) | Yes (RiskIQ history) | Yes | Yes | No |
| **Trust degradation scoring** | No (v0.3+ planned) | Yes ? | No ? | No ? | No ? | No |
| **Exploitability analysis** | No (explicit non-goal) | Yes (Active Response) | Yes (CVE correlation) | Yes (adversary-informed) | Yes (risk scoring) | No |
| **WAF/CDN detection** | No (v0.3+ planned) | Yes | Yes | Yes ? | Yes | Partial |
| **MITRE ATT&CK mapping** | Yes (per-collector TA0043 Reconnaissance annotation) | Yes ? | Yes ? | Yes (adversary-informed) | No ? | No |

**Summary:** EXPOSE's attribution architecture is structurally differentiated -- per-claim evidence chains, open auditable rule packs, and operator-controlled LLM provider are unique in the category. Primary gaps are exploitability analysis (explicit non-goal), mature manual review UI workflow (Darkroom dashboard exists but is basic), trust degradation scoring, and WAF/CDN detection. Historical attribution depth is limited compared to vendors with multi-year datasets.

---

### 3. Pipeline and Operations

| Feature | EXPOSE v0.1 | Cortex Xpanse | Defender EASM | Mandiant ASM | Censys ASM | SpiderFoot HX |
|---------|-------------|---------------|---------------|--------------|------------|---------------|
| **Continuous monitoring** | Partial (daily batch; scheduling is v0.2) | Yes (continuous) | Yes (continuous) | Yes (periodic) | Yes (continuous) | Yes (scheduled scans) |
| **Scheduled runs** | Partial (cron config exists; scheduler is v0.2) | Yes (continuous) | Yes (continuous) | Yes | Yes | Yes |
| **Delta detection** | Yes (6 removal-reason classifications) | Yes | Yes | Yes | Yes | No (full-scan reports) |
| **Artifact signing (cosign)** | Partial (architecture ready; cosign signing is v0.2) | No | No | No | No | No |
| **SLSA provenance attestation** | No (v0.2 planned) | No | No | No | No | No |
| **SBOM generation** | No (v0.2 planned; script exists) | No ? | No ? | No ? | No ? | No |
| **Deterministic/reproducible output** | Yes (same input = same artifact) | No (proprietary) | No (proprietary) | No (proprietary) | No (proprietary) | No |
| **Pipeline health reporting** | Yes (per-collector health, partial-run semantics) | Yes | Yes | Yes | Yes | Partial |
| **Data retention management** | Yes (configurable per-tenant pruning) | Yes (vendor-managed) | Yes (vendor-managed) | Yes (vendor-managed) | Yes (vendor-managed) | Partial |
| **GDPR/CCPA compliance** | Yes (data export + deletion capabilities) | Yes | Yes (GDPR controls) | Yes | Yes (privacy controls) | Partial |
| **SpiderFoot credential import** | Yes (31 API key migration) | No | No | No | No | N/A (native) |
| **Multi-tenant support** | Yes (logical isolation, cross-tenant test suite) | Yes (enterprise) | Yes (Azure tenants) | Yes (enterprise) | Yes (workspace-based) | No |
| **Run cost tracking** | Yes (per-run LLM cost logging via OTel) | No (SaaS-managed) | No (SaaS-managed) | No (SaaS-managed) | No (SaaS-managed) | No |
| **Partial-run degradation** | Yes (collector failure does not abort run) | Yes | Yes | Yes | Yes | Partial |

**Summary:** EXPOSE's pipeline has structural strengths in delta detection granularity (6 removal reasons vs. binary add/remove), deterministic reproducibility, and run-cost transparency. The primary gap is that continuous monitoring depends on the v0.2 scheduler -- v0.1 requires manual or external cron triggers. Artifact signing and SLSA attestation are v0.2 deliverables; the architecture supports them but they are not yet operational.

---

### 4. API and Integration

| Feature | EXPOSE v0.1 | Cortex Xpanse | Defender EASM | Mandiant ASM | Censys ASM | SpiderFoot HX |
|---------|-------------|---------------|---------------|--------------|------------|---------------|
| **REST API** | Yes (FastAPI, bearer token auth, tenant-scoped) | Yes (Cortex API) | Yes (Azure REST API) | Yes (Mandiant API) | Yes (Censys API) | Yes (HX API) |
| **SSE event streaming** | Yes (run events via SSE) | No ? | No | No ? | No ? | No |
| **GraphQL API** | No | No ? | No | No ? | No ? | No |
| **Webhooks** | No | Yes | Yes (Logic Apps) | Yes ? | Yes | Yes |
| **CLI** | Yes (Click CLI: run/serve/db commands) | Yes (xpanse-cli) | Yes (Azure CLI) | No ? | Yes (censys-cli) | Yes (spiderfoot CLI) |
| **Web dashboard** | Yes (Darkroom: D3.js graph + Alpine.js controls) | Yes (full enterprise UI) | Yes (Azure portal integration) | Yes (Mandiant Advantage UI) | Yes (full SaaS UI) | Yes (SpiderFoot web UI) |
| **Splunk integration** | No (v0.3+ adapter planned) | Yes (native) | Partial (via Sentinel) | Yes (via Chronicle) | Yes (Splunk TA) | No ? |
| **Microsoft Sentinel integration** | No (v0.3+ adapter planned) | Yes (XSOAR/Sentinel) | Yes (native, deep) | Yes (Sentinel connector) | Yes (Sentinel connector) | No |
| **Google Chronicle integration** | No (v0.3+ adapter planned) | Yes (XSOAR) | No ? | Yes (native) | Yes ? | No |
| **Jira integration** | No | Yes (XSOAR) | No ? | No ? | Yes | No ? |
| **ServiceNow integration** | No | Yes (XSOAR) | No ? | No ? | Yes | No ? |
| **JSON artifact output** | Yes (canonical JSON, schema-validated) | Yes (JSON export) | Yes (JSON export) | Yes (API responses) | Yes (API responses) | Yes (JSON/CSV export) |
| **STIX/TAXII output** | No | No ? | No ? | Yes (Mandiant CTI native) | No ? | No |
| **OpenTelemetry telemetry** | Yes (traces, metrics, logs via OTLP) | No ? | No (Azure Monitor) | No (Google Cloud Ops) | No | No |
| **Programmatic rule management** | Yes (JSON rule pack API) | No | No | No | No | Partial (module config) |

**Summary:** EXPOSE has a functional REST API with SSE streaming and a CLI, which exceeds SpiderFoot HX's API maturity and matches the basic integration surface of commercial vendors. The critical gap is the absence of out-of-the-box SIEM integrations (Splunk, Sentinel, Chronicle) and ticketing system integrations (Jira, ServiceNow). These are correctly deferred to v0.3+ per ADR-004, but they are table-stakes in enterprise procurement conversations. The JSON artifact output is a strength -- structured, schema-validated, and designed for machine consumption.

---

### 5. Security and Compliance

| Feature | EXPOSE v0.1 | Cortex Xpanse | Defender EASM | Mandiant ASM | Censys ASM | SpiderFoot HX |
|---------|-------------|---------------|---------------|--------------|------------|---------------|
| **FedRAMP authorization** | No (architecture ready per ADR-010; self-host pathway) | Yes (FedRAMP High) | Yes (Azure Gov, FedRAMP High) | FedRAMP Ready High (platform) | No | No |
| **FIPS 140-3 crypto** | Yes (architecture-level, FIPS SHA-256 adapter) | Yes (platform-level) | Yes (Azure-level) | Yes (GCP-level) | No ? | No |
| **NIST 800-53 control mapping** | Yes (AU-family audit logging, design-level mapping) | Yes (platform-level) | Yes (Azure-level) | Yes (GCP Assured Workloads) | No | No |
| **Audit logging** | Yes (structured, tenant-scoped, sensitive-op separation) | Yes | Yes (Azure Activity Log) | Yes | Yes | Partial |
| **RBAC** | No (single-role in v0.1; multi-role deferred) | Yes (Cortex RBAC) | Yes (Azure RBAC) | Yes (Google IAM) | Yes (workspace roles) | Partial (admin/viewer) |
| **Multi-tenancy isolation** | Yes (logical, with cross-tenant test suite) | Yes (physical + logical) | Yes (Azure tenant-level) | Yes | Yes (workspace isolation) | No |
| **Data export for DSAR** | Yes (GDPR export + deletion) | Yes | Yes (GDPR controls) | Yes | Yes | No ? |
| **Secrets management** | Yes (Vault + env var + in-memory backends) | Yes (vendor-managed) | Yes (Azure Key Vault) | Yes (GCP Secret Manager) | Yes (vendor-managed) | Partial |
| **Supply-chain integrity (SBOM/signing)** | Partial (v0.2: cosign, SLSA, SBOM planned) | No ? | No ? | No ? | No ? | No |
| **Authorized-use ethics framework** | Yes (ETHICS.md, scope enforcement, ADR-008) | No (terms of service only) | No (terms of service only) | No (terms of service only) | No (terms of service only) | Partial (OSS ethos) |
| **SOC 2 Type II** | No | Yes | Yes (Azure compliance) | Yes (Google compliance) | Yes | No |
| **GDPR compliance documentation** | Yes (compliance module with export/deletion) | Yes | Yes | Yes | Yes | Partial |
| **PII handling policy** | Yes (non-enrichment policy, explicit filtering) | Yes ? | Yes (GDPR controls) | Yes ? | Yes ? | No |

**Summary:** EXPOSE's security architecture is strong for a v0.1 product: FIPS 140-3 crypto, NIST 800-53 design-level mapping, structured audit logging, and an explicit authorized-use ethics framework. The primary gap is the absence of RBAC (multi-role access control) and any formal compliance certification (SOC 2, FedRAMP authorization). The FedRAMP-ready architecture provides a self-host pathway that bypasses the vendor-authorization requirement -- agencies deploy EXPOSE Core inside their existing ATO boundary -- but this is a nuanced conversation that requires the Federal Customer Deployment Guide (Session G) to land defensibly.

---

### 6. Deployment and Operations

| Feature | EXPOSE v0.1 | Cortex Xpanse | Defender EASM | Mandiant ASM | Censys ASM | SpiderFoot HX |
|---------|-------------|---------------|---------------|--------------|------------|---------------|
| **SaaS offering** | No | Yes (primary) | Yes (primary) | Yes (primary) | Yes (primary) | Yes (HX SaaS) |
| **Self-hosted deployment** | Yes (Apache 2.0, primary model) | No | No | No | No | Yes (OSS core) |
| **Container image** | Yes (multi-stage, multi-arch Dockerfile) | N/A (SaaS) | N/A (SaaS) | N/A (SaaS) | N/A (SaaS) | Yes (Docker) |
| **Helm chart** | Yes (NetworkPolicy + PodSecurity hardened) | N/A (SaaS) | N/A (SaaS) | N/A (SaaS) | N/A (SaaS) | No |
| **Kubernetes-native** | Yes (Helm, NetworkPolicy, PodSecurity) | N/A (SaaS) | N/A (SaaS) | N/A (SaaS) | N/A (SaaS) | No |
| **Air-gapped operation** | Partial (artifact portable; engine needs egress; future exploration) | No | No | No | No | Partial (OSS local) |
| **Multi-cloud portable** | Yes (cloud-agnostic architecture) | No (PAN cloud) | No (Azure-tied) | No (GCP-tied) | N/A (SaaS) | Yes (self-hosted) |
| **Open-source core** | Yes (Apache 2.0) | No | No | No | No | Yes (MIT/BSD) |
| **CI pipeline** | Yes (lint, test, schema-sync, FIPS gate, Helm lint, multi-arch build) | N/A | N/A | N/A | N/A | Yes (OSS CI) |
| **Pre-commit hooks** | Yes (Ruff, gitleaks, JSON Schema, Helm lint) | N/A | N/A | N/A | N/A | Partial |
| **Grafana dashboards** | Yes (2 dashboards) | N/A (vendor dashboards) | N/A (Azure Monitor) | N/A (Google Cloud Ops) | N/A (SaaS) | No |
| **Egress profile support** | Yes (direct, SOCKS5, WireGuard, HTTP CONNECT) | Yes (vendor-managed) | Yes (vendor-managed) | Yes (vendor-managed) | Yes (vendor-managed) | Partial |
| **Managed service option** | No (future Korlogos offering) | Yes | Yes | Yes | Yes | Yes (HX SaaS) |
| **Test coverage** | Yes (1059 tests, 92% coverage, 61 test files) | Unknown | Unknown | Unknown | Unknown | Partial |

**Summary:** EXPOSE is the only product in this comparison that offers a production-ready self-hosted deployment with Kubernetes-native packaging (Helm chart, NetworkPolicy, PodSecurity). This is a structural differentiator for self-host-preferring and federal-self-host buyers. The gap is the absence of a managed SaaS offering -- all four commercial competitors are SaaS-primary, and many enterprise buyers prefer managed service over self-operations. The managed-service offering is planned as a future Korlogos commercial product.

---

### 7. LLM/AI Capabilities

This category is assessed separately because it is an emerging differentiator where EXPOSE's architectural approach is notably different from competitors.

| Feature | EXPOSE v0.1 | Cortex Xpanse | Defender EASM | Mandiant ASM | Censys ASM | SpiderFoot HX |
|---------|-------------|---------------|---------------|--------------|------------|---------------|
| **AI-powered attribution assist** | Yes (SafeLLMClient structured output) | Yes (Cortex AI) | Yes (Copilot for Security) | Yes (Mandiant AI) | No ? | No |
| **Natural language queries** | No | Yes (Cortex Copilot) | Yes (Copilot for Security) | No ? | No | No |
| **Automated triage** | Partial (LLM noise classification) | Yes | Yes | Yes | No ? | No |
| **Tech-stack inference via LLM** | Yes (structured-output, schema-validated) | Yes ? | Yes ? | No ? | No | No |
| **Operator-selectable LLM provider** | Yes (4 providers + local Ollama) | No | No | No | N/A | N/A |
| **Transparent LLM prompts** | Yes (prompts visible and auditable) | No | No | No | N/A | N/A |
| **LLM cost ceiling enforcement** | Yes ($5/run default, per-tenant configurable) | No (vendor-absorbed) | No (vendor-absorbed) | No (vendor-absorbed) | N/A | N/A |
| **Local/offline LLM option** | Yes (Ollama with Qwen 2.5 / Llama 3.1) | No | No | No | N/A | N/A |
| **LLM output validation** | Yes (JSON Schema validation, retry, fail-safe) | Unknown | Unknown | Unknown | N/A | N/A |
| **Per-call audit logging** | Yes (provider, model, tokens, latency, cost) | Unknown | Unknown | Unknown | N/A | N/A |
| **Prompt injection defense** | Yes (external_observation tags, system prompt isolation) | Unknown | Unknown | Unknown | N/A | N/A |

**Summary:** EXPOSE's LLM integration is architecturally differentiated. No competitor offers operator-controlled LLM provider selection, transparent auditable prompts, per-run cost ceilings, or a local offline LLM option. The gap is in higher-level AI features: natural language query interfaces and fully automated triage workflows. These are UI/UX investments the competitors have made on top of their AI backends; EXPOSE has the backend but not yet the interaction layer.

---

## Gap Analysis

### Critical Gaps (address before GA)

These are features competitors have that enterprise and federal customers will ask about during procurement.

| Gap | Competitors With It | Business Impact | Effort Estimate | Roadmap Status |
|-----|---------------------|-----------------|-----------------|----------------|
| **SIEM integrations (Splunk/Sentinel/Chronicle)** | All 4 commercial vendors | Table-stakes for enterprise security stacks; procurement blocker | Medium (adapter development) | v0.3+ planned |
| **Ticketing integration (Jira/ServiceNow)** | Xpanse, Censys | Common enterprise workflow requirement | Low-Medium | Not planned |
| **RBAC (multi-role access)** | All 4 commercial vendors | Required for enterprise multi-team deployments | Medium | Not explicitly planned |
| **Passive DNS collectors** | All 5 competitors | Major data source gap; limits subdomain discovery depth | Medium (3 collectors specified in SPEC) | Specified, not built |
| **Internet-wide scan ingest** | All 5 competitors | Limits discovery breadth vs. competitors with proprietary scanning | Medium (3 collectors specified in SPEC) | Specified, not built |
| **Run scheduling (automated continuous monitoring)** | All 5 competitors | "Continuous" is table-stakes; manual cron is not credible for GA | Low (v0.2 deliverable) | v0.2 planned |
| **Cosign artifact signing** | None (unique to EXPOSE when shipped) | Core value proposition; must ship before claiming it | Medium (v0.2 deliverable) | v0.2 planned |
| **Managed SaaS offering** | All 4 commercial vendors | Many buyers prefer managed service | High (infrastructure) | Future Korlogos product |
| **Webhooks** | Xpanse, Defender, Censys, SpiderFoot | Standard integration pattern for event-driven workflows | Low | Not planned |
| **Subdomain brute-forcing** | Xpanse, SpiderFoot, possibly others | Expected discovery method for comprehensive enumeration | Low | Not planned |

### Parity Points

Features where EXPOSE v0.1 matches or exceeds competitors.

| Feature | Assessment |
|---------|------------|
| **Core discovery (CT, BGP, WHOIS, DNS, TLS, HTTP, ports)** | Full parity with all 5 competitors on fundamental passive + active discovery techniques |
| **Cloud IP range matching** | Parity -- covers AWS, Azure, GCP manifests |
| **Multi-provider LLM enrichment** | Exceeds all competitors -- 4 providers, operator-controlled, auditable |
| **Delta detection** | Exceeds all competitors -- 6 classified removal reasons vs. binary add/remove |
| **Multi-tenancy** | Parity with commercial vendors; exceeds SpiderFoot HX (no multi-tenancy) |
| **Container/Kubernetes deployment** | Exceeds all competitors -- only product with Helm chart + NetworkPolicy |
| **Self-hosted deployment** | Exceeds all SaaS-only competitors; parity with SpiderFoot OSS |
| **REST API** | Parity -- FastAPI with bearer auth, tenant-scoped endpoints |
| **CLI tooling** | Parity with vendors that offer CLIs |
| **Audit logging** | Parity with commercial vendors; exceeds SpiderFoot HX |
| **GDPR/CCPA compliance** | Parity with commercial vendors |
| **Email auth record analysis** | Exceeds most competitors -- dedicated SPF/DKIM/DMARC collector |
| **Favicon hashing** | Parity with Censys and SpiderFoot; exceeds others |
| **GitHub org enumeration** | Exceeds most competitors -- not a standard EASM feature |
| **Egress profile support** | Exceeds most competitors -- SOCKS5, WireGuard, HTTP CONNECT options |

### Differentiated Capabilities

Features unique to EXPOSE that no competitor in this comparison offers.

| Feature | Competitive Significance |
|---------|--------------------------|
| **Open auditable attribution rule packs** | No competitor publishes reproducible attribution logic. Enables academic verification, customer customization, and transparent methodology -- critical for federal and research buyers |
| **Per-claim evidence chains with provenance** | No competitor traces every attribution decision back through collector observation to source data. Defensible scope decisions for red team engagements and federal audit requirements |
| **Operator-controlled LLM provider selection** | No competitor lets the operator choose their LLM provider, see the prompts, set cost ceilings, or run local inference. Addresses data-sovereignty, cost, and transparency concerns |
| **Deterministic reproducible artifact generation** | No competitor guarantees same-input-same-output reproducibility. Critical for federal continuous-monitoring evidence and academic research |
| **Dual-audience architecture (CTEM + red team)** | No competitor architecturally supports both defensive and authorized offensive use cases. Authorization scope enforcement with configurable medium/hard modes |
| **FIPS 140-3 crypto architecture** | No SaaS competitor exposes FIPS crypto at the application layer. Designed for federal self-host inside existing ATO boundaries |
| **Apache 2.0 engine with commercial modules** | SpiderFoot OSS is MIT/BSD but HX is SaaS-only. No other competitor offers an open-core model with separately licensable commercial modules |
| **CC BY 4.0 research datasets (planned)** | No EASM vendor publishes reference attribution datasets. Academic credibility pipeline that compounds into federal and commercial credibility |
| **Per-collector MITRE ATT&CK TA0043 mapping** | No commercial competitor maps individual collector operations to specific ATT&CK Reconnaissance sub-techniques |
| **Run cost transparency (LLM spend tracking)** | No SaaS competitor exposes per-run operational cost data. Operators know exactly what each scan costs |
| **Supply-chain integrity (cosign + SLSA, when shipped)** | No competitor signs their output artifacts. Unprecedented for EASM category. (v0.2 deliverable -- not yet operational) |

---

## Comparative Positioning Summary

| Category | EXPOSE v0.1 Verdict |
|----------|---------------------|
| **Discovery breadth** | Moderate. Core techniques covered; passive DNS and internet-wide scan ingest gaps limit depth compared to data-rich competitors (Censys, Mandiant, Defender). |
| **Attribution quality** | Strong. Only platform with open, auditable, reproducible attribution methodology. Evidence chains and confidence tiers are structurally superior. |
| **Pipeline maturity** | Moderate. Strong deterministic architecture and delta detection; lacks automated scheduling and artifact signing in v0.1. |
| **Integration ecosystem** | Weak. No SIEM adapters, no ticketing integration, no webhooks. REST API and JSON artifact exist but enterprise integration story is incomplete. |
| **Compliance readiness** | Strong for architecture; weak for certification. FIPS, NIST 800-53 mapping, audit logging are solid. No FedRAMP authorization, no SOC 2, no RBAC. |
| **Deployment flexibility** | Strong. Only product with self-hosted Kubernetes-native deployment. Lacks managed SaaS option. |
| **LLM/AI architecture** | Strong and differentiated. Most transparent and operator-controllable AI integration in the category. Lacks higher-level AI UX features. |

---

## Recommendations

Prioritized list of gap-closing actions, ordered by impact on competitive positioning and procurement readiness.

### Priority 1 -- Ship v0.2 deliverables (immediate)

These are already planned and directly close the most visible gaps:

1. **Run scheduling** -- transforms "daily batch" from a manual process into credible continuous monitoring. Without this, every competitor demo looks more mature. _Effort: already v0.2 scope._
2. **Cosign artifact signing + SLSA provenance** -- the signed-artifact story is EXPOSE's core differentiator against every competitor. Cannot credibly claim it without shipping it. _Effort: already v0.2 scope._
3. **SBOM generation** -- completes the supply-chain integrity story alongside cosign/SLSA. _Effort: already v0.2 scope._

### Priority 2 -- Close data-source gaps (pre-GA)

4. **Build passive DNS collectors** (SecurityTrails, Validin, Farsight) -- these are already specified in SPEC.md section 6.2 and represent the largest data-depth gap vs. competitors. Without passive DNS, subdomain discovery relies entirely on CT logs and active resolution. _Effort: medium (3 collectors, similar pattern to existing BGP collectors)._
5. **Build internet-wide scan ingest collectors** (Censys Search, Shodan, BinaryEdge) -- also specified in SPEC.md. Closes the gap with data-rich competitors and positions EXPOSE as a consumer of, not competitor to, internet-wide scan datasets. _Effort: medium (3 collectors)._

### Priority 3 -- Enterprise integration basics (pre-GA or GA)

6. **Webhook support** -- standard event-driven integration pattern. Lower effort than full SIEM adapters; enables customers to build their own integrations. _Effort: low._
7. **RBAC** -- multi-role access control is table-stakes for enterprise multi-team deployments. At minimum: admin, operator, viewer roles per tenant. _Effort: medium._
8. **Subdomain brute-forcing collector** -- common expectation for comprehensive enumeration. Wordlist-based, attribution-gated (Tier 3). _Effort: low._

### Priority 4 -- Enterprise integration depth (post-GA)

9. **SIEM adapters** (Splunk, Sentinel, Chronicle) -- already planned for v0.3+. Important for enterprise procurement but the JSON artifact is a workable interim for technical buyers. _Effort: medium per adapter._
10. **Ticketing integration** (Jira, ServiceNow) -- common enterprise workflow. Can be partially addressed by webhooks (Priority 3.6). _Effort: medium._

### Priority 5 -- Strategic investments (post-GA)

11. **Managed SaaS offering** -- addresses the "we don't want to operate it" objection. Requires infrastructure investment beyond software development. _Effort: high (infrastructure, operations, support)._
12. **RBAC maturation** -- fine-grained permissions, SSO/SAML integration, audit of access changes. _Effort: medium-high._
13. **Natural language query interface** -- leverages the existing LLM infrastructure to provide a Copilot-style query experience. _Effort: medium._

### Not recommended

- **Exploitability analysis / CVE correlation** -- explicit non-goal per SPEC.md section 1.2. EXPOSE produces leads; exploitation assessment is a different category. Adding it would blur positioning and compete with VM tools (Tenable, Qualys) where EXPOSE has no advantage.
- **Proprietary internet-wide scanning** -- building a scanning infrastructure to compete with Censys/Shodan is capital-intensive and unnecessary. EXPOSE consumes these as data sources, not competes with them.
- **Dark web monitoring in Core** -- correctly scoped as a commercial Threat Context module. Including it in Core would make the open-source engine harder to deploy and operate in regulated environments.

---

## Analysis Date

This analysis reflects the state of EXPOSE v0.1 and publicly documented competitor features as of 2026-05-10. Competitor features, pricing, and compliance status change frequently. This document should be reviewed and updated quarterly or when a major competitor release is announced.

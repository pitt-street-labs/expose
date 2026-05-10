# EXPOSE — Glossary

Term definitions used across the specification, ADRs, and codebase.

---

**Artifact (canonical artifact, JSON artifact)**
The signed JSON file produced by a single EXPOSE pipeline run, conforming to the schema in `schemas/canonical-artifact-v1.json`. Sole deliverable of the system.

**Attribution**
The process of deciding whether an observed external asset belongs to a tenant. Output is an attribution tier (`confirmed`, `high`, `medium`, `requires_review`, `not_yours`, `rejected`) with numeric confidence and reasoning trace.

**Attribution rule**
A declarative rule in a rule pack that contributes to attribution decisions. Each rule has a condition (`when`) and an action (`then`), evaluated against the observation graph for each candidate target.

**Authorization scope**
Per-tenant configuration declaring which assets the operator is authorized to analyze. Includes apex domains, cloud accounts, registrant patterns, ASN ranges, and exclusions. Has an `enforcement_mode` (`soft`, `medium`, `hard`).

**Cohabitation**
When multiple subdomains or services share a single IP address. Reverse-IP queries reveal cohabitation; useful for attribution but a source of false-positive correlation if not handled carefully.

**Collector**
A pluggable module that gathers observations from a specific external source (CT log, passive DNS provider, internet-wide scan API, etc.). Each collector implements the `Collector` abstract base class with a uniform contract.

**Collector tier**
Categorization of collectors by sensitivity. Tier 1 (passive, broad), Tier 2 (passive, targeted), Tier 3 (active, attribution-gated). Tier 3 collectors only execute against confirmed/high-tier targets or assets in authorization scope.

**Confidence (numeric)**
A 0.0-1.0 value representing the engine's confidence in an attribution decision. Computed by aggregating positive and negative deltas from rule evaluation. Maps to attribution tier via configurable thresholds.

**Confidence tier**
Categorical attribution confidence. v1 tiers: `confirmed` (≥0.95), `high` (≥0.75), `medium` (≥0.50), `requires_review` (below medium but flagged for analyst attention), `not_yours` (rejected by attribution), `rejected` (explicitly excluded).

**Cosign**
The Sigstore project's signing tool for container images and arbitrary blobs. EXPOSE uses cosign keyless signing via GitHub Actions OIDC for production artifacts.

**CTEM (Continuous Threat Exposure Management)**
The discipline of continuously identifying, prioritizing, and addressing exposures in an organization's attack surface. EXPOSE produces input feeds for CTEM platforms.

**Delta (delta_from_previous_run)**
Structured comparison between this run's artifact and the previous run's artifact, capturing added, removed, and changed targets with structured reasons.

**Discovery path**
For added targets, the ordered sequence of collectors and rules that led to the target's discovery. Recorded in the artifact's `delta.added` entries.

**EASM (External Attack Surface Management)**
The discovery and inventory of an organization's externally reachable assets. EXPOSE is, fundamentally, an EASM tool whose deliverable is structured for CTEM consumption.

**Egress profile**
Configuration determining how scanner workers route active probing traffic. Implementations: `direct`, `socks5`, `wireguard`, `http_connect`. Critical for attribution-isolation in deployments where scanner egress must not originate from the deployment's primary infrastructure.

**Environment 1**
The EXPOSE pipeline itself. Performs deterministic discovery, collection, sanitization, attribution, bounded LLM enrichment, and artifact generation. Subject of this specification.

**Environment 2**
The downstream operational environment that consumes EXPOSE artifacts. Performs open-ended narrative reasoning, red team lead briefings, and exploit hypothesis generation. May use Mythos-class capabilities under appropriate safeguards. Air-gapped from Environment 1 via manual JSON handoff.

**Evidence (evidence_ref, evidence store)**
Raw collected content (cert PEMs, raw HTTP responses, raw DNS responses) stored in object storage keyed by SHA-256 content hash. Graph entries reference evidence via `sha256:<hex>` pointers.

**Glasswing (Project Glasswing)**
Anthropic's coalition program providing Claude Mythos Preview access to selected technology companies and critical-infrastructure organizations. Out of scope for EXPOSE itself but relevant context for Environment 2.

**Helm chart**
The deployment artifact for EXPOSE. Single chart deploys to ARC, AWS, Azure, GCP, or customer-on-prem with different values files.

**Incidental data**
Observations about organizations or assets that are not the operator's. Inevitable in collection (CT log queries return cohort entries, passive DNS returns shared-infrastructure records). Stored in the graph for attribution context, filtered from the artifact, and pruned after retention window.

**Lead score**
Numeric value (0-100) computed deterministically from a target's attribution confidence, exposure severity, tech stack risk, freshness, and cloud factor. Higher is more interesting for red team prioritization. Categorized as `informational`, `low_priority`, `medium_priority`, `high_priority`, `critical_priority`.

**LLM enrichment**
Stage 4b of the pipeline. Bounded, structured-output LLM calls that sanity-check ambiguous attribution decisions, infer tech stacks, classify noise. Never invents observations. Strictly schema-validated outputs.

**Manifest (manifest.json)**
Separate JSON file accompanying each canonical artifact. Describes run provenance, integrity hash, signing metadata, LLM provider used. Conforms to `schemas/manifest-v1.json`.

**Multi-tenancy (logical, physical)**
Logical multi-tenancy: data isolation via `tenant_id` columns and middleware-enforced query scoping. v1 baseline. Physical multi-tenancy: per-tenant resource quotas, prioritized scheduling, isolated worker pools. Deferred to production-hardening.

**Mythos (Claude Mythos Preview)**
Anthropic's frontier model with significant cybersecurity capabilities. Out of scope for Environment 1; relevant to Environment 2 under Project Glasswing access or successor programs.

**Observation graph**
The pipeline's internal data model. Typed nodes (Domain, Subdomain, IP, Certificate, Service, CloudResource, Organization, Registrant, ASN) and typed edges (resolves_to, presented_cert, subject_alt_name_includes, etc.) stored in Postgres. Source of truth for attribution decisions and artifact serialization.

**Provenance**
The chain of evidence supporting a claim in the artifact. Every target carries source provenance (which collectors observed it, when) and evidence references (pointers to raw collected content).

**Rule pack**
A versioned, declarative collection of attribution rules and lead-score formulas conforming to `schemas/rulepack-v1.json`. Public packs ship in `examples/rulepacks/`; client-specific packs live in private repos.

**SafeLLMClient**
Wrapper around all LLM provider calls. Enforces input sanitization integrity, structured-output validation, audit logging, per-run cost ceiling, and tie-breaker escalation policies. Provider-independent.

**Sanitization**
Stage 3 of the pipeline. Strips control characters, normalizes encoding, length-caps fields, flags suspicious content. Defends against adversary-controlled content in cert SANs, banners, DNS TXT records.

**Scope (authorization scope)**
See "Authorization scope."

**Seed (seed graph)**
Operator-provided starting point for discovery: organization name, brand strings, known apex domains, cloud account IDs. Stage 1 expands seeds into a candidate graph for collection.

**Tenant**
A logical isolation boundary in EXPOSE. v1 ships with a single `default` tenant. Multi-tenant deployments serve N tenants with independent configuration, data, and artifacts.

**Tie-breaker**
LLM correlation tie-breaker. When the primary LLM produces ambiguous or low-confidence output, a different LLM provider is consulted as second opinion. Configurable triggers: schema validation failures, low self-confidence, rule disagreement.

**Tier (attribution tier, collector tier)**
See "Confidence tier" and "Collector tier."

**Trust boundary**
Architectural boundary across which content is treated as untrusted. EXPOSE has two: between collection (Stage 2) and sanitization (Stage 3), and between deterministic graph state (Stage 4a) and LLM context (Stage 4b).

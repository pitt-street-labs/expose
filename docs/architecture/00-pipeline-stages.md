# 00 — Pipeline stages

**What this shows.** The five-stage Environment 1 pipeline that produces the canonical signed JSON artifact, per SPEC §2.2. Each stage is annotated as deterministic or LLM-bearing. The two trust boundaries — between stages 2 and 3 (untrusted external content → sanitized canonical observations) and between stages 4a and 4b (deterministic graph state → LLM context) — are drawn explicitly because they shape the pipeline's safety properties.

This is the highest-level operational view of EXPOSE Core. Everything else in this directory is a closer look at one piece of this picture.

## Diagram

```mermaid
flowchart TD
  Operator[Operator-provided seeds<br/>org name, brands, apex domains]

  subgraph S1 ["Stage 1 — Seed Expansion (deterministic, no LLM, no probing)"]
    SE[Rule-based pivots<br/>against authoritative public data]
    SG[(Seed graph)]
    SE --> SG
  end

  subgraph S2 ["Stage 2 — Collection (deterministic, external)"]
    direction LR
    PASS[Passive collectors<br/>CT logs, pDNS, ASN/BGP,<br/>scan datasets, cloud IP]
    ACTV[Active probing<br/>DNS, TLS, HTTP, port surface<br/>attribution-tier-gated]
  end

  TB1{{Trust boundary<br/>untrusted external content<br/>↓<br/>sanitized canonical observations}}

  subgraph S3 ["Stage 3 — Sanitization & Normalization (deterministic)"]
    SAN[Strip control chars,<br/>NFC normalize, length-cap,<br/>flag suspicious content]
    CAN[Canonicalize:<br/>IDN, IP, cert hash, UTC ISO 8601]
    SAN --> CAN
  end

  OG[(Observation graph<br/>canonical, typed, tenant-scoped)]

  subgraph S4a ["Stage 4a — Rule-Based Attribution (deterministic)"]
    RP[Rule pack evaluator<br/>predicate vocabulary, priority order]
    CONF[Numeric confidence<br/>+ tier mapping]
    RP --> CONF
  end

  TB2{{Trust boundary<br/>deterministic graph state<br/>↓<br/>LLM context (structured-output, bounded)}}

  subgraph S4b ["Stage 4b — LLM Enrichment (bounded, structured-output)"]
    PRMPT[Prepare prompt<br/>external_observation tags]
    SAFE[SafeLLMClient<br/>schema validation, audit,<br/>cost ceiling, tie-breaker]
    PRMPT --> SAFE
  end

  ENR[Enriched candidates]

  subgraph S5 ["Stage 5 — Artifact Generation (deterministic)"]
    SER[Canonical JSON serializer]
    DEL[Delta vs. previous run]
    MAN[Manifest generator]
    SIG[cosign sign]
    SER --> DEL --> MAN --> SIG
  end

  ART[(canonical.json.gz<br/>+ .sig + manifest.json<br/>in object store)]

  Operator --> SE
  SG --> PASS
  SG --> ACTV
  PASS --> TB1
  ACTV --> TB1
  TB1 --> SAN
  CAN --> OG
  OG --> RP
  CONF -- "tier = confirmed → emit directly" --> SER
  CONF -- "tier = high/medium/requires_review<br/>→ optional enrichment" --> TB2
  CONF -- "tier = not_yours / rejected → filter (retain in graph)" --> X[/filtered/]
  TB2 --> PRMPT
  SAFE --> ENR
  ENR --> SER
  SIG --> ART
```

## What each stage does, briefly

**Stage 1 — Seed Expansion.** Deterministic. No LLM, no external probing. Operator-provided seeds (org name, brand strings, known apex domains, cloud account IDs) are expanded into a candidate seed graph using rule-based pivots against authoritative public data. The output is the input to Stage 2.

**Stage 2 — Collection.** Deterministic. Two parallel tracks. Passive collectors query Certificate Transparency logs, passive DNS providers, ASN/BGP data, internet-wide scan datasets, and cloud-provider IP-range manifests. Active probing executes DNS resolution, TLS handshakes, HTTP fingerprinting, and light port-surface enumeration — but only against entities whose attribution tier is `confirmed` or `high`, or which are explicitly in the tenant authorization scope. This gating is enforced at the collector dispatch layer per SPEC §6.3.

**Trust boundary (2 → 3).** Cert SAN values, HTTP banners, DNS TXT contents, WHOIS organization fields, and redirect targets are operator-influenced data. Adversaries plant content there to manipulate downstream tooling. Stage 3 enforces that no raw external content reaches stages 4 and 5 without canonicalization.

**Stage 3 — Sanitization & Normalization.** Deterministic. Strips ASCII control characters except `\t \n \r`, normalizes Unicode to NFC, length-caps fields per SPEC §7.1, flags suspicious content (HTML in plain-text fields, embedded JSON, very long strings, base64 blobs). Then canonicalizes — domain names lowercased and IDN-normalized, IP addresses to canonical representation, cert fingerprints from PEM to lowercase hex, timestamps to UTC ISO 8601. Canonicalization is idempotent.

**Stage 4a — Rule-Based Attribution.** Deterministic. The configured rule pack is applied to each candidate target. Rules fire in priority order, contributing positive (promote), negative (demote), or zero (informational) deltas to the target's numeric confidence. After all rules evaluate, the resulting numeric confidence maps to an attribution tier (`confirmed`, `high`, `medium`, `requires_review`, `not_yours`, `rejected`) via the rule pack's thresholds. `confirmed` targets are emitted directly to Stage 5; `not_yours` and `rejected` are filtered.

**Trust boundary (4a → 4b).** The LLM enrichment pass receives strictly structured input. Sanitized observation excerpts are wrapped in `<external_observation>` tags with system-prompt instructions to treat enclosed content as data, never as instructions. SafeLLMClient validates that this discipline is preserved per call.

**Stage 4b — LLM Enrichment.** LLM-bearing but bounded. Targets with tier `high`, `medium`, or `requires_review` may go through enrichment depending on configuration. The LLM performs bounded, structured-output tasks: attribution sanity-check, tech-stack inference, noise classification. The LLM never invents observations; output schema validation rejects malformed responses. SafeLLMClient enforces sanitization integrity, schema validation, per-call audit logging, per-run cost ceiling (default $5 USD), and optional tie-breaker escalation. Lead-narrative generation is explicitly out of scope for v1 in Environment 1.

**Stage 5 — Artifact Generation.** Deterministic. Serialize the attributed targets into the canonical JSON file (gzipped, indented, conforming to `schemas/canonical-artifact-v1.json`). Compute the delta from the previous run. Generate the manifest (small, quickly inspectable, references the canonical file's hash). Sign the canonical file with cosign — keyless via GitHub Actions OIDC for production deployments, or operator-controlled keypair for lab. Write to the configured object store. The deliverable is `runs/{tenant_id}/{run_id}/canonical.json.gz` plus `.sig` and `manifest.json`.

## Deterministic vs. LLM stages at a glance

| Stage | Deterministic? | LLM? | Notes |
|---|---|---|---|
| 1 — Seed Expansion | Yes | No | Pure pivots against public data |
| 2 — Collection | Yes | No | External APIs and probing; gating enforced |
| 3 — Sanitization | Yes | No | Idempotent; defends Stage 4 |
| 4a — Rule-Based Attribution | Yes | No | Rule pack is data, not code |
| 4b — LLM Enrichment | Bounded | **Yes** | SafeLLMClient-wrapped; structured-output only |
| 5 — Artifact Generation | Yes | No | cosign-signed, deterministic given same inputs |

The asymmetry is deliberate. Four of five stages are deterministic, and the LLM stage is bounded by the SafeLLMClient discipline so its behavior cannot leak past the structured outputs the pipeline expects. This is the architectural property that lets EXPOSE produce signed artifacts with confidence that the LLM did not inject unverified claims.

## What this diagram intentionally omits

- The work queue between control plane and workers (see diagram 20 for the deployment topology).
- Per-collector implementation details, rate limiting, partial-run semantics (see SPEC §6.5).
- Specific rule-pack DSL (see `schemas/rulepack-v1.json` and `examples/rulepacks/example-baseline.json`).
- Per-LLM-provider interaction details (see SPEC §8.4 and diagram 60).
- The Environment 1 → Environment 2 handoff (see diagram 10).

## References

- SPEC.md §2.2 — Pipeline stages
- SPEC.md §3 — Threat model (trust boundaries 2→3 and 4a→4b)
- SPEC.md §6.3 — Collector tiers and gating (Tier 3 attribution-gated)
- SPEC.md §7 — Sanitization and normalization
- SPEC.md §8 — Attribution and enrichment
- SPEC.md §9 — Artifact generation
- ADR-005 — LLM integration (multi-provider with SafeLLMClient)

# ADR-009: Commercial structure

**Status:** Accepted
**Date:** 2026-05-09
**Decision-makers:** Korlogos / Pitt Street Labs

## Context

The decision in ADR-006 established Apache 2.0 for the engine and a separate private repository for client-specific rule packs. That decision was made before the broader commercialization vision was articulated. The 2026-05-09 design conversations introduced specific commercial extensions:

1. **Risk-focused enrichment** — APT targeting profiles, dark-web Indicators of Interest (IoI), Indicators of Activity Against (IoAc), and Indicators of Proof of Concept (IoP), combined with clearnet correlation, to produce risk-prioritized intelligence views.
2. **Historical point-in-time enrichment** — endpoint configuration history, certificate history, banner/screenshot history, historical DNS, historical Shodan observations.
3. **WHOIS-personnel and social-media tangential reconnaissance** — personnel-graph pivots for authorized reconnaissance.
4. **Additional AI-leverage capabilities** — to be specified in a subsequent session, but anticipated to include capabilities that deepen attribution accuracy, accelerate analyst workflow, and produce inferences not feasible with rules alone.

These commercial extensions have a fundamental tension with the Apache 2.0 engine commitment: if everything is Apache 2.0, competitors can fork and resell the commercial features without contributing back. The structural decision is how to organize the codebase, repositories, and licensing to preserve open-source community engagement on the engine while protecting commercial value in the extensions.

A secondary consideration: the project will pursue federal markets (per ADR-010), which favor open-source tools agencies can self-host and audit, but also pay for commercial support, hosting, and value-added enrichment.

## Decision

**Open-core structure with three proprietary commercial modules and a separate open research dataset offering.**

### The four product surfaces

**1. EXPOSE Core (Apache 2.0)**

The open-source engine. Public repository. Includes:
- The discovery, sanitization, attribution, and artifact generation pipeline
- Core collector framework and free-tier collector implementations (CT logs, public DNS, ASN/BGP, cloud IP manifests, public WHOIS/RDAP, basic active probing)
- Attribution rule engine and rule pack format (rule packs are data, not code)
- LLM provider abstraction with OllamaProvider, AnthropicDirectProvider, OpenAIProvider, GeminiProvider implementations
- Canonical artifact schema and JSON Schema files
- Helm chart for self-deployment
- Example rule packs sufficient to demonstrate end-to-end operation
- Reference documentation including SPEC.md, threat model, ETHICS.md, federal customer deployment guide

License: Apache 2.0. DCO sign-off required for contributions. Public GitHub repository (when published; currently lab-only per consent gate).

**2. EXPOSE Threat Context (proprietary, separate license)**

Commercial module. Private repository. Consumes Core's signed artifact, produces an enriched artifact. Includes:
- APT targeting profile correlation
- Dark-web IoAc/IoI/IoP collection and correlation (with dedicated ethics surface)
- Historical point-in-time enrichment (cert history, DNS history, banner history, screenshot history)
- Adversary infrastructure detection (MITRE ATT&CK Resource Development tactic monitoring — typosquats, staging infrastructure, leaked credentials in markets)
- Risk-prioritized lens that combines Core attribution with threat actor targeting context
- Per-adapter commercialization-risk evaluation and licensing (some data sources have re-licensing constraints)

License: Korlogos commercial EULA. Available to commercial and federal customers under separate agreement. The artifact format produced is a documented superset of Core's canonical schema; downstream consumers can ingest either.

**3. EXPOSE Identity Surface (proprietary, separate license, higher ethics bar)**

Commercial module. Private repository. Includes:
- WHOIS-personnel correlation beyond what Core does (registrant graph analysis, historical registrant pivots)
- Authorized social-media tangential target discovery (LinkedIn, Twitter/X, Mastodon, Bluesky scope-gated reconnaissance for authorized red team operations)
- Personnel-graph attribution (organizational hierarchy inference from public signals)
- Off by default; requires explicit per-tenant authorization scope acknowledgment with an additional attestation beyond Core's authorization scope

License: Korlogos commercial EULA. Sold separately with stricter contractual terms covering authorized-use representations, GDPR/CCPA handling, and explicit prohibitions on unauthorized surveillance use cases. The ethics surface is materially larger than Core's; this module's separate licensing reflects that.

**4. EXPOSE Research (open dataset, separate data license)**

Public dataset offering. Includes:
- Periodic published reference graph datasets (anonymized or fully synthetic, depending on dataset)
- Reference rule packs demonstrating attribution patterns
- Benchmark datasets for evaluating EASI tools, attribution accuracy, and AI enrichment quality
- Dataset documentation, schemas, and reproducibility metadata

License: Creative Commons Attribution 4.0 (CC BY 4.0) for the data; Apache 2.0 for any companion tooling. Anyone can use, redistribute, modify with attribution. The data published is sourced from operator-authorized research targets (Korlogos's own infrastructure, partnered research domains) or from synthetic generation; never from customer deployments.

### Repository structure

```
github.com/korlogos/ff6k-core              (Apache 2.0, public — when consent gate lifts)
github.com/korlogos/ff6k-threat-context    (proprietary, private — commercial customers only)
github.com/korlogos/ff6k-identity-surface  (proprietary, private — commercial customers only)
github.com/korlogos/ff6k-research          (CC BY 4.0 datasets + Apache 2.0 tooling, public)
github.com/korlogos/ff6k-rulepacks         (proprietary, private — client-specific rule packs)
```

The Core repository depends on no proprietary code. Commercial modules depend on Core via published artifacts (the Apache 2.0 SDK in Core defines the integration surface). This preserves the property that Core can be used independently of commercial modules and that commercial modules can be developed without violating Apache 2.0 terms.

### Naming convention

The public name **EXPOSE** (EXtended Perimeter Ontology Security Evaluation) was selected in Session H on 2026-05-10 and propagated across all public-facing and spec artifacts via the mechanical rename pass. The internal codename **FF6K** (shortened from FatFinger6000) is preserved for development artifacts, internal communications, and historical references per HISTORY.md. All four product surfaces share the EXPOSE prefix: **EXPOSE Core**, **EXPOSE Threat Context**, **EXPOSE Identity Surface**, **EXPOSE Research**.

## Consequences

**Positive:**

- Open-source community engagement preserved on Core with all its associated benefits (external contribution, brand visibility, federal-customer self-host pathway, academic research adoption).
- Commercial value protected in the modules where investment justifies it. Competitors cannot fork commercial features without licensing them, even though they can fork Core.
- Federal customers have a clean path: self-host Core for free; add commercial modules under separate agreement when operational scale justifies; eventually migrate to Korlogos managed SaaS (per ADR-010) when full FedRAMP authorization is needed.
- Module separation keeps each codebase's ethics surface manageable. Core's ETHICS.md covers Core's threat model; Identity Surface has its own (stricter) ethics document covering the personnel-reconnaissance threat surface separately.
- Research dataset offering creates academic and federal-research credibility without diluting commercial value (the data is downstream-curated, not the live product).
- Open-core is the proven pattern for security tooling commercialization — Mandiant, Sigstore, OWASP-adjacent commercial offerings, Tenable's open-source projects, Palo Alto's Cortex XSOAR community edition, and many others operate this way.

**Negative:**

- Maintaining four product surfaces is operationally heavier than one. Release coordination, dependency management between Core and modules, integration testing across the matrix.
- Pricing and packaging conversations become more complex. Customers ask "do I need Core plus Threat Context, or is Core enough?" and the answer depends on use case.
- Identity Surface's ethics surface requires ongoing attention. The combination of personnel reconnaissance and AI enrichment is exactly the kind of capability that demands deliberate guardrails. This is real ongoing work, not a one-time setup.
- Federal customers occasionally prefer "everything in one license" over modular pricing. Module separation may require negotiated bundle pricing for federal RFPs.
- Open-source contributors may resent commercial modules they cannot contribute to. Mitigated by clear positioning that Core is the community project and modules are commercial extensions that fund Core's continued development.

## Alternatives considered

**Apache 2.0 everything.** Single repository, no commercial modules, all features open. Rejected because the commercialization ideas (dark-web crawling, historical enrichment, personnel reconnaissance) require investment that needs commercial protection. Without that protection, the work either doesn't get done at all or gets done by a competitor who forks Core, adds the features, and doesn't contribute back.

**Source-available everything (BUSL-1.1, PolyForm Strict).** Public repositories, code visible, commercial restrictions enforced by license. Rejected for v1 because (a) loses OSI-approved-license community engagement, (b) federal procurement preferences favor true open-source, (c) the engine itself does not need source-available protection because the value of EXPOSE is in the operational excellence and rule-pack tuning, not the code.

**Engine and modules in same repository, modules under different license.** Rejected because mixed-license repositories create endless confusion in dependency analysis, license auditing, and fork management. Clean separation between repositories with explicit Apache 2.0 SDK boundary in Core is much cleaner.

**Service-only commercial offering (no module licensing).** Korlogos sells managed service; modules don't exist as separately-licensable software. Customers only get commercial features through Korlogos-hosted SaaS. Rejected because federal customers and large enterprises specifically want to self-host; service-only forecloses that market segment.

**Two-tier (Core open + one big proprietary module).** Simpler, but conflates Threat Context (which is mostly about external threat data) with Identity Surface (which has personnel-reconnaissance ethics implications that warrant separate licensing). Rejected because the ethics surfaces are materially different.

## When to revisit

The four-surface structure is intended to be durable. Triggers for revisiting:

- **Significant commercial competitive threat that BUSL would meaningfully address.** Move from Apache 2.0 to BUSL on Core is a significant decision and would require contributor agreement; trigger only if open-source posture is genuinely costing meaningful commercial revenue.
- **Module consolidation pressure.** If Threat Context and Identity Surface have substantially overlapping infrastructure or customers always buy both, consolidation may simplify operations.
- **Research dataset gains independent strategic importance.** If EXPOSE Research becomes a major research-infrastructure contribution in its own right, it may warrant its own governance structure (foundation-hosted, with sponsorship, etc.).

## References

- ADR-006: Repository and licensing (predecessor decision; this ADR extends it)
- ADR-010: FedRAMP-ready posture (referenced for federal-customer deployment pathway)
- `docs/positioning.md` for full strategic positioning context

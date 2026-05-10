# EXPOSE Threat Context — Module Specification

**Status:** Draft — Session C deliverable. Subject to revision in Session D (novel AI-leverage roadmap), Session F (SDLP), and Session G (Federal Customer Deployment Guide). Not locked at the level of the SPEC.md or the ADRs.
**Date:** 2026-05-10
**Author context:** AI-assisted synthesis grounded in the locked spec-phase artifacts (SPEC.md, ADR-008, ADR-009, ADR-010, positioning.md), Session E framework annotation, and current (May 2026) public guidance on dark-web sourcing ethics, GDPR legitimate-interest doctrine, and FedRAMP Rev 5 red-team requirements.
**Public name:** EXPOSE Threat Context (per ADR-009 prefix convention) / **Internal codename:** FF6K Threat Context
**Source files cited:** `docs/SPEC.md`, `docs/positioning.md`, `docs/adr/ADR-008-authorized-use-and-ethics.md`, `docs/adr/ADR-009-commercial-structure.md`, `docs/adr/ADR-010-fedramp-ready-posture.md`, `docs/strategy/framework-annotation.md`, `docs/strategy/persona-analysis.md`, `schemas/canonical-artifact-v1.json`.

This document is the foundational specification for **EXPOSE Threat Context**, the first of two proprietary commercial modules defined in ADR-009 §"FF6K Threat Context" (renamed in Session H). It consumes the canonical signed artifact from EXPOSE Core and produces an enriched superset artifact carrying APT-targeting correlation, dark-web indicators, historical point-in-time enrichment, and adversary-infrastructure detection.

This spec is the contract between intent and implementation for the module. It is not a marketing document; pricing and packaging notes are intentionally bounded and deferred to a separate go-to-market session.

---

## 1. Module overview

### 1.1 What EXPOSE Threat Context is

EXPOSE Threat Context is a separately-licensed proprietary module that **consumes** the canonical signed JSON artifact produced by EXPOSE Core (`schemas/canonical-artifact-v1.json`) and **produces** an enriched signed JSON artifact (`schemas/threat-context-enrichment-v1.json`, defined in §7) that is a documented superset of Core's schema. Downstream consumers can ingest either artifact; the enriched artifact carries additional fields under a top-level `threat_context_enrichment` block plus per-target `threat_context` blocks.

The module's deliverable is the same kind of object Core's deliverable is: a deterministic, attributable, cryptographically signed JSON file with full provenance, suitable for the same Environment 2 handoff disciplines defined in SPEC.md §2.1. There is no live API contract, no streaming feed, no human-readable narrative output — the artifact is the API.

### 1.2 Why Threat Context is a separate module rather than a Core capability

ADR-009 establishes the four-surface structure (Core, Threat Context, Identity Surface, Research) on three grounds: open-source community engagement preservation, commercial-value protection, and ethics-surface manageability. Threat Context specifically lives outside Core because:

- **Different MITRE ATT&CK anchor.** Core anchors in Reconnaissance (TA0043). Threat Context anchors in **Resource Development (TA0042)** monitoring — detecting adversary infrastructure being prepared against the operator. `positioning.md` §2.2 calls out the bundling-into-one-product trap explicitly: it creates a "we do everything" pitch that is harder to defend technically and harder to position commercially.
- **Different data sources.** Core's collectors are public-internet observable (CT logs, passive DNS, ASN/BGP, internet-wide scans, cloud IP manifests, public WHOIS/RDAP, light active probing). Threat Context's collectors include closed-source commercial intelligence feeds and dark-web sources, each with re-licensing constraints, ethical-review requirements, and per-source contractual posture.
- **Different ethics surface.** Core's ethics layer (ADR-008) is sufficient for public-internet observation. Threat Context's ethics layer (§5 of this document) covers dark-web sourcing, attribution-of-attribution concerns, and intelligence-cycle responsibilities that Core's ETHICS.md does not contemplate.
- **Different threat model.** Core's threat model (SPEC.md §3) covers adversary-controlled inputs in public observation. Threat Context's threat model (§4) extends with dark-web data-source compromise, source-feed integrity, and threat-actor counterintelligence considerations.

### 1.3 What the module produces

For every target in the input Core artifact whose attribution tier is `confirmed`, `high`, `medium`, or `requires_review`, the module may produce per-target enrichment in a `threat_context` block covering APT targeting correlation, historical point-in-time enrichment, and adversary-infrastructure indicators. Aggregated module-level outputs (campaign-tracking summaries, market-surveillance digests) appear in the top-level `threat_context_enrichment` block.

For every target where enrichment is suppressed by per-tenant policy, license constraint, or source unavailability, the artifact records the suppression reason in a `threat_context.suppressed` field rather than silently dropping enrichment. This is the same discipline Core uses for `removal_uncertain_collector_failure` — analysts must see the difference between "we looked and nothing was there" and "we did not look."

---

## 2. Capabilities scope

ADR-009 §"FF6K Threat Context" defines four capability categories. This section expands each into concrete capability bundles with explicit in-scope and out-of-scope rationale.

### 2.1 APT targeting profile correlation

**In scope.** Correlation of operator targets against published APT (Advanced Persistent Threat) targeting profiles maintained by mainstream commercial CTI providers (subject to re-licensing terms), open MITRE ATT&CK group profile data, government-published advisories (CISA Known Exploited Vulnerabilities, NSA cybersecurity advisories, FBI flash alerts), and Korlogos-curated targeting overlays for federal-customer-relevant threat actors.

For each target, the module computes a `targeting_correlation` block listing APT groups whose published targeting profile (industry sector, geography, technology stack, observed operational patterns) overlaps the target's attributes. Each correlation entry carries a confidence tier (mirroring Core's attribution tier conventions: `confirmed`, `high`, `medium`, `requires_review`), a reasoning narrative generated from rule-based evaluation of the targeting overlap, and a citation chain identifying the source advisories.

**Out of scope.** Real-time APT activity attribution to specific operators (i.e., "this target was attacked by APT41 last Tuesday"). The module does not consume live telemetry from the operator's defensive stack. Attribution-of-attack events to specific groups is a downstream IR-team activity, not a Threat Context output.

### 2.2 Dark-web IoAc / IoI / IoP collection and correlation

The three indicator categories per ADR-009 design discussion:

| Category | Expansion | What it surfaces |
|---|---|---|
| **IoAc** | Indicators of Activity Against | Observed threat-actor discussion, planning, or staging directed against the operator's attributed surface. Examples: forum posts naming the operator; marketplace listings of credentials matching operator-attributed domains; staging infrastructure cohabiting with operator-attributed cloud ranges. |
| **IoI** | Indicators of Interest | Observed threat-actor interest signals that fall short of explicit activity. Examples: reconnaissance discussion referencing operator-attributed assets without operational planning; interest-marker queries against breach-data brokers for operator domains. |
| **IoP** | Indicators of Proof of Concept | Observed proof-of-concept exploitation material referencing the operator's tech stack as discovered in Core. Examples: published exploitation walk-throughs targeting versions of CMSes / load balancers / cloud configurations Core inferred for the operator. |

**In scope.** Crawling and correlation against curated dark-web sources (Tor hidden services, I2P, paste sites, breach-data forums, malware sample repositories) where the source has been added to the module's source-registry with documented ethical-review approval (§5.4). Aggregation of commercial dark-web intelligence feeds where licensing permits re-distribution to operators in the form of derived correlation notes.

**Out of scope.** Direct purchase of stolen data on behalf of operators. Direct interaction with threat actors (engagement, negotiation, ransom payment intermediation). Re-publishing raw stolen data in the artifact — only derived correlation metadata is included; raw breach material stays in evidence-store back-end with restricted access. Real-time alerting on individual posts (the daily-batch cadence of SPEC.md §1.2 is preserved).

### 2.3 Historical point-in-time enrichment

For each target, the module attaches historical observations from commercial historical-data partners and Korlogos-internal observation history:

- **Certificate history.** All historical TLS certificates observed for the target's identifiers across CT log history (typically 5+ years deep where the partner's history extends).
- **DNS history.** All historical A/AAAA/CNAME/MX/NS/TXT records observed for the target's identifiers (typically 10+ years deep at gold-standard partners like Farsight DNSDB).
- **Banner history.** All historical HTTP/banner observations from internet-wide scan history (Censys, Shodan historical archives where licensing permits redistribution).
- **Screenshot history.** Historical web-screenshot observations where partner data is licensed for redistribution.
- **Configuration history.** Historical cloud-resource configuration observations where the operator has explicitly opted into upload of their own historical configuration snapshots.

**In scope.** Read-only ingest from named partners with explicit licensing for redistribution-as-derived-product. Per-source license metadata is recorded in the artifact's `provenance.sources[].license_terms` field (a Threat Context schema addition).

**Out of scope.** Capturing historical configuration about third parties without their consent. Historical observations about non-operator-attributed assets are filtered out of the per-target enrichment, mirroring ADR-008 §Layer 3 incidental-data discipline.

### 2.4 Adversary-infrastructure detection (Resource Development tactic monitoring)

ADR-009 anchors this capability against MITRE ATT&CK Tactic TA0042 (Resource Development) and explicitly enumerates: typosquats, staging infrastructure, leaked credentials in markets. This module is the only EXPOSE surface that monitors Resource Development.

**In scope:**

- **Typosquat scanners.** For each apex domain in the operator's authorization scope, the module scans permutations (character substitution, character insertion, character omission, homoglyph substitution, IDN/punycode confusables) and resolves them to discover registered look-alike domains. Each look-alike is correlated against Core's attribution graph to distinguish operator-controlled defensive registrations from third-party registrations and from candidate adversary preparation.
- **Staging-infrastructure detection.** Cohabitation analysis between operator-attributed infrastructure and known adversary-staging patterns (newly-registered domains co-hosted with operator-mimicking content; staging certs that name operator subdomains in their SANs without operator attribution).
- **Market surveillance for leaked credentials.** Crawling of credential-broker forums and breach-data marketplaces for matches against operator-attributed identities (domain-suffixed email patterns, organization names, registrant patterns from Core's WHOIS observations). Matches are reported as derived metadata only; raw credential strings are not included in the artifact.
- **Newly-issued certificate surveillance.** CT log streaming surveillance for newly-issued certificates that name operator-attributed apex domains in their SANs but were not requested by the operator (potential malicious issuance for staging).

**Out of scope.** Active engagement with adversary infrastructure (no exploitation, no credential testing, no honeypot placement). Procurement of stolen data even for operator-defensive purposes (operator-driven purchase of their own leaked credentials is a separate operator-side decision, not a module function). Takedown coordination — the module reports; operators or their dedicated takedown providers act.

### 2.5 Risk-prioritized lens

The module produces a risk-prioritized re-ranking of Core's targets that combines Core's lead-score formula with Threat Context's targeting-correlation, IoAc/IoI/IoP indicators, and Resource Development indicators. Each target gets an additional `threat_context_priority` score on the same 0-100 numeric scale Core uses, with the same auditable formula-version discipline.

Operators can configure whether their downstream tooling consumes Core's `lead_score` field (red-team prioritization), Threat Context's `threat_context_priority` field (defensive prioritization with adversary context), or both. The module never overwrites Core's `lead_score`; both fields coexist.

---

## 3. Module-only capabilities not in Core

To make the boundary explicit, the following capabilities exist **only** in Threat Context and are not, will not be, and should not be replicated in Core:

| Capability | Why Core-excluded |
|---|---|
| Dark-web crawling (Tor, I2P, paste-site surveillance) | Ethics-surface escalation; per-source contractual constraints; would require Core to inherit a much larger ethical-review apparatus. |
| Commercial CTI feed integration (Recorded Future, Mandiant Intelligence, etc.) | Per-source re-licensing constraints incompatible with Apache 2.0 distribution. |
| Resource Development tactic monitoring | ADR-009 §"FF6K Threat Context" explicit boundary; positioning.md §2.2 explicit non-bundle decision. |
| Historical commercial-data ingestion (Farsight DNSDB historical depth, DomainTools deep history) | Per-source re-licensing constraints. |
| APT-group correlation against curated profiles | Curated-profile maintenance is commercial work; Core consumes only public ATT&CK group data. |

---

## 4. Threat model (extends Core's)

This section extends SPEC.md §3. All Core threats remain in scope for the module's deployment; the additions below are specific to Threat Context's operational surface.

### 4.1 Additional adversaries and their goals

**Compromised dark-web data-source partner.** A commercial intelligence partner the module integrates with is compromised; adversary-controlled data flows into the module's ingest path and from there into operator artifacts. The compromised partner could be a curated forum-monitoring service, a credential-breach aggregator, or a dark-web crawler cooperative.

*Mitigation:* Source-feed integrity checks via per-partner signature verification where supported; per-partner anomaly detection on observation rate and content distribution; per-source provenance recorded in artifact `provenance.sources` with `license_terms` and `partner_signature_verified` fields; operators are surfaced any source-feed integrity warnings via `tenant_quota_warnings`.

**Threat-actor counterintelligence against the module's crawlers.** Adversaries operating in the dark web detect module fingerprints (TLS fingerprints, request patterns, content of queries), feed misleading content to the module specifically to corrupt operator artifacts, or attribute the crawling activity back to Korlogos.

*Mitigation:* Diversified egress with per-tenant tunnel isolation; rotation of crawler fingerprints; never queries that name operator identifiers in the clear (queries are constructed from hashed identifiers where the crawler protocol permits); explicit attribution-resistance posture in operational docs.

**Source-feed integrity attacks via adversary-planted false positives.** A threat actor publishes deliberately-false content naming an operator (e.g., a forum post claiming to have "owned" the operator) to either generate alert fatigue, drive the operator to false remediation actions, or harm the operator's reputation if the false claim is amplified by a defensive consumer of the module's output.

*Mitigation:* Multi-source corroboration requirement before any IoAc reaches `confirmed` tier; explicit `requires_review` tier for single-source claims; reasoning chain documents the source set in plain language; the module never generates narrative claims of breach or compromise without analyst review.

**Counter-intelligence inference from operator subscription patterns.** An adversary infers Korlogos's customer list by observing which operators receive enrichment for which threat actors (e.g., subscription patterns become a side-channel revealing federal customer relationships).

*Mitigation:* Per-tenant query isolation; uniform crawl breadth across tenants where licensing permits (the module crawls broadly and filters per-tenant rather than crawling per-tenant queries); aggregate-level subscription metadata is not surfaced to source partners.

**Module artifact compromise to inject false threat context.** An adversary tampers with the module's enriched artifact between Environment 1 and Environment 2 to inject false threat-actor attribution and drive operator decisions.

*Mitigation:* Cosign signing of the enriched artifact (separate signing identity from Core's); the enriched artifact references Core's artifact by signed hash so consumers can verify both layers; signature verification documented in module SECURITY.md.

**Re-licensing constraint violations by the module itself.** A bug in the artifact serialization includes raw partner content (rather than derived metadata) in violation of partner license terms, exposing Korlogos to contractual liability.

*Mitigation:* Per-source serialization policy enforced at artifact-generation time; license-policy unit tests gate CI; periodic license-audit of artifact samples.

### 4.2 What the module explicitly does not defend against

The module does not defend against operator misuse of dark-web indicators (e.g., an operator using IoAc data to identify and retaliate against alleged threat actors). The medium-mode authorization-scope discipline of ADR-008 carries forward but does not extend to retaliation activities; ETHICS.md §5 documents the operational posture.

The module does not defend against dark-web partner provider compromise of provider-internal records. If a partner is compromised at the provider level (e.g., an attacker exfiltrates the partner's customer list), the module's deployment is downstream of that exposure; partner trust evaluation is the operator's responsibility.

The module does not defend against legal compulsion to share enrichment data with third parties (e.g., subpoenas for operator-specific threat context). Operators concerned with this risk should evaluate their own legal exposure and the module's data-handling agreement before subscribing.

---

## 5. ETHICS surface for Threat Context

This section is distinct from Core's ETHICS.md. Where Core's ethics layer covers public-observation discipline, Threat Context's ethics layer covers the additional ethical responsibilities that emerge from dark-web sourcing, attribution-of-attribution, and the intelligence cycle.

### 5.1 Dark-web data sourcing ethics

The module crawls and consumes data from sources that exist explicitly because their participants want to operate outside conventional legal and norm constraints. Three principles govern Korlogos's posture:

**Cite-the-source norm.** Every IoAc, IoI, IoP indicator in the artifact carries an explicit source citation in its `provenance.sources` block, including the source's name (or a stable per-source pseudonym where naming the source would compromise crawler operations), the source category (forum, marketplace, paste site, broker), and the partner-license posture. Operators can audit which sources contributed which indicators and discount sources whose reliability they question.

**No-active-engagement norm.** The module's crawlers are read-only. They do not post, do not respond to messages, do not register accounts beyond the minimum needed to access publicly-listable content, do not negotiate, do not purchase. Adversaries who attempt to engage the crawler will see no engagement.

**No-raw-redistribution norm.** Raw breach content (cleartext credentials, exfiltrated documents, intercepted communications) is never included in the artifact. Only derived metadata reaches operators (e.g., "12 credentials matching domain pattern \\*@operator.example were observed in marketplace listing X on date Y"). Raw content stays in the evidence store with strictly controlled access (§8.2).

### 5.2 Attribution-of-attribution concerns

When the module attributes activity to APT groups, it is making a meta-attribution claim — claiming that an attribution claim made by a third-party CTI provider applies to operator-attributed surface. This is a higher-risk claim than Core's first-order attribution.

**Conservative confidence tiers.** APT-correlation tier `confirmed` requires multi-source corroboration plus an explicit operator-surface-overlap rationale; `high` requires multi-source or single-high-credibility-source plus surface overlap; `medium` requires single-source plus surface overlap; everything else is `requires_review`. The default operator-facing dashboard surfaces only `high` and `confirmed` correlations to reduce signal-to-noise.

**Attribution-uncertainty disclosure.** Each APT-correlation entry includes a `correlation_uncertainty_notes` field that documents the meta-attribution risks: alternative groups whose targeting profile also overlaps; the time-decay of the third-party attribution (the more time has passed since the original attribution, the less weight it carries); and known intentional misattribution patterns (e.g., adversaries who plant false-flag indicators).

**No public-attribution-claim generation.** The module never generates claims like "Operator X is being targeted by APT41" suitable for public disclosure. The artifact is operator-internal; downstream public-attribution claims are operator-side decisions with their own evidence requirements.

### 5.3 Intelligence-cycle responsibilities

Adopting Threat Context places the operator inside a CTI consumer role with associated responsibilities:

- **Disclosed-target responsibility.** When the module observes adversary-infrastructure indicators against a third party (e.g., a typosquat registered to attack an operator's customer or partner), the operator inherits a responsibility to consider disclosure to the affected third party. The module does not auto-disclose; the operator's decision is supported by the artifact's clear identification of disclosed-versus-not third parties.
- **Information-sharing reciprocity.** Korlogos's commercial license includes a clause encouraging (not requiring) operators to contribute generalized indicators back into Korlogos's curation pool when they confirm an adversary indicator the module surfaced. This supports the broader intelligence ecosystem; per ADR-009, EXPOSE Research provides the publication pathway for de-identified contributed indicators.
- **Source-protection responsibility.** Operators must not reverse-engineer the module's source registry to identify dark-web sources. The license includes an explicit prohibition; operators who do so jeopardize the entire customer base's source access.

### 5.4 Per-source ethical review

Adding a new source to the module's source registry requires an ethical review before integration. The review covers:

| Review dimension | Question |
|---|---|
| Legality | Is the source a legal source under Korlogos's operational jurisdiction (US federal + state law applicable to Pitt Street Labs, North Carolina) and the operational jurisdictions of typical customers (federal contractors, regulated industries)? |
| Crawl compliance | Does the source's terms of service or community norms prohibit crawling? If the source is technically permissive but normatively hostile, the source is rejected. |
| Re-licensing | Are derived observations from this source redistributable to operators as derived metadata? Per-partner license review documented. |
| Source reliability | Has the source historically produced reliable signals or is it dominated by hoaxes / disinformation? Sources dominated by hoaxes are rejected. |
| Source safety | Does crawling this source put Korlogos personnel at risk (e.g., sources tied to violent organizations)? Sources with personnel-safety concerns are rejected. |
| Operator-jurisdiction concerns | Are there operator jurisdictions where access to this source would create operator legal exposure? If yes, source access is per-jurisdiction gated. |

The review is documented in the source registry with an approving reviewer identity and a quarterly re-review cadence. Sources that fail re-review are removed from active crawl with grandfathered indicators retained per data-retention policy.

### 5.5 Ethics surface for the module's own operators

Korlogos personnel operating the module's crawlers are exposed to materials that may be illegal, traumatic, or ethically charged (CSAM-adjacent forum content, violent extremism, evidence of ongoing harm). The module's operational posture includes:

- Crawler-output content classification gates that suppress content of certain categories from operator review screens (CSAM is hard-blocked at ingest with mandatory reporting per US federal law).
- Mental-health support resources for personnel exposed to traumatic content.
- Rotation of high-exposure roles to limit cumulative traumatic exposure.
- Explicit non-tolerance for personnel who consume crawled material outside their operational role.

This is not a checkbox; it is operational reality for any organization that crawls dark-web content. The module's commercial pricing reflects the personnel-cost dimension of these obligations.

---

## 6. Architecture

### 6.1 Relationship to Core

The module is a **separate codebase** in a **separate repository** (`github.com/korlogos/ff6k-threat-context`, private per ADR-009 §"Repository structure") with **no source-code dependency on Core**. The module consumes Core's published artifact via the documented schema contract (`schemas/canonical-artifact-v1.json`) and produces an enriched artifact in its own schema (`schemas/threat-context-enrichment-v1.json` introduced in §7).

The module **does not modify** Core's artifact. The enriched artifact is a new file (`canonical-enriched.json.gz`), independently signed, that references Core's artifact by signed hash. Consumers can verify both layers and choose to consume one or both.

### 6.2 Deployment topology

The module deploys as a **separate worker pool** in a **separate cluster** in a **separate cloud account** from Core. This separation is operational, not just architectural, for three reasons:

- **Egress isolation.** The module's crawlers route through Tor/I2P-aware egress that must not commingle with Core's collector egress. Operator-attribution risk would otherwise extend to Core's deployments.
- **Blast-radius containment.** A compromise of Threat Context's worker fleet (e.g., through a malicious partner-feed payload that escapes sanitization) must not pivot into Core's deployment or into the operator's authorization-context infrastructure.
- **Cost-account isolation.** Dark-web crawling costs (commercial feed subscriptions, egress proxy services, storage of evidence-store partner data) are separately accounted from Core's infrastructure costs.

Component containers, in addition to those defined for Core in SPEC.md §4.1:

- **`expose-tc-control-plane`** — orchestrator API for Threat Context, ingests Core artifacts via signed pull, dispatches enrichment jobs, generates enriched artifacts.
- **`expose-tc-darkweb-worker`** — dark-web crawler worker pool. Routes through Tor/I2P-aware egress. Strict per-worker isolation; workers do not share state.
- **`expose-tc-historical-worker`** — historical-data partner ingest worker. Pulls historical observations from licensed partners on a per-target basis.
- **`expose-tc-typosquat-worker`** — typosquat permutation generation and resolution worker.
- **`expose-tc-cti-worker`** — commercial CTI feed ingest worker (APT-targeting profile correlation).
- **`expose-tc-postgres`** — separate Postgres instance for the module's enrichment graph; not shared with Core.
- **`expose-tc-evidence-store`** — separate object-store bucket for the module's evidence (raw partner data, raw crawl content). Strictly access-controlled; separate IAM boundary from Core's evidence store.

State is externalized identically to Core (managed Postgres, object-store-compatible bucket, secrets backend abstraction).

### 6.3 Trust boundaries (extends Core's)

Three additional trust boundaries beyond SPEC.md §2.3:

**Untrusted partner-feed content → sanitized correlation observations** (between partner ingest and module enrichment). Partner data, even from contractually-trusted sources, may contain adversary-planted content. Sanitization for partner-feed content reuses Core's stage-3 discipline (control-character stripping, length-capping, suspicious-content flagging) plus additional partner-specific normalization (e.g., breach-record format normalization).

**Untrusted dark-web crawl content → sanitized observations** (between crawl ingest and module enrichment). Dark-web content is treated as adversary-controlled by default. The same `<external_observation>` tag wrapping Core uses for LLM prompts (SPEC.md §7.3) applies to any dark-web content surfaced to LLM enrichment.

**Module's enrichment state → enriched artifact** (between graph state and artifact generation). The same deterministic-to-LLM-context discipline Core uses (SPEC.md §2.3) extends here; LLM enrichment in Threat Context is bounded to the same structured-output, no-tool-access discipline.

### 6.4 LLM enrichment in Threat Context

The module reuses Core's `LLMProvider` abstraction and `SafeLLMClient` wrapper (SPEC.md §8.4). Threat Context-specific LLM jobs:

- **APT-correlation reasoning generation.** Given a target's attributes and a candidate APT group's targeting profile, generate a structured reasoning narrative documenting the overlap. Bounded structured output; no narrative claims that the operator is being attacked.
- **IoAc/IoI/IoP source-corroboration scoring.** Given a candidate indicator and its source set, score the credibility of the indicator using a structured rubric. Output is a numeric score with a documented reasoning trace.
- **Typosquat-confusability scoring.** Given a discovered look-alike domain, score its confusability against the operator's apex domain using a structured rubric. Useful for prioritizing review effort.

Cost discipline mirrors Core's (per-run ceiling, prompt caching, Ollama path). The module's default per-run ceiling is higher ($50 USD vs. Core's $5) reflecting both the larger enrichment volume and the typically-higher LLM-cost-tolerance of commercial Threat Context customers.

---

## 7. Schema additions (`canonical-enriched-v1`)

### 7.1 Top-level structure

The enriched artifact is a documented superset of `canonical-artifact-v1.json`. It carries every field Core's artifact carries (so consumers can ingest the enriched artifact wherever they would ingest Core's) plus the additions below.

```
{
  "schema_version": "expose-threat-context/v1",
  "core_artifact_ref": {
    "artifact_path": "...",
    "artifact_sha256": "...",
    "core_run_id": "..."
  },
  // ... all fields from canonical-artifact-v1.json ...
  "threat_context_enrichment": {
    "module_version": "...",
    "rule_pack_version": "...",
    "enrichment_run_id": "...",
    "started_at": "...",
    "completed_at": "...",
    "campaign_summaries": [...],
    "market_surveillance_digest": {...},
    "apt_group_index": [...],
    "adversary_infrastructure_summary": {...},
    "tc_collector_health": {...}
  }
}
```

Each `Target` object in the enriched artifact's `targets` array carries an additional optional `threat_context` block:

```
{
  "target_id": "...",
  // ... Core's Target fields ...
  "threat_context": {
    "targeting_correlation": [...],
    "ioac_indicators": [...],
    "ioi_indicators": [...],
    "iop_indicators": [...],
    "historical_enrichment": {
      "certificate_history": [...],
      "dns_history": [...],
      "banner_history": [...],
      "screenshot_history": [...]
    },
    "adversary_infrastructure": {
      "typosquats": [...],
      "staging_observations": [...],
      "newly_issued_certs": [...]
    },
    "threat_context_priority": {
      "score": 0-100,
      "formula_version": "...",
      "inputs": {...},
      "category": "informational | low | medium | high | critical"
    },
    "suppressed": null | {
      "reason": "license_unavailable | tenant_policy_disabled | source_unavailable | ethical_review_pending",
      "details": "..."
    }
  }
}
```

### 7.2 Per-source license metadata

Each source in `provenance.sources[]` for a Threat Context-derived observation carries additional fields beyond Core's:

```
{
  "collector_id": "...",
  "collector_version": "...",
  "first_observed_at": "...",
  "last_observed_at": "...",
  "observation_count": ...,
  "license_terms": {
    "redistribution_allowed": "derived_metadata_only | full | none",
    "attribution_required": true | false,
    "embargo_until": "..." | null,
    "partner_signature_verified": true | false
  },
  "ethical_review_id": "..."
}
```

### 7.3 APT correlation entry structure

```
{
  "apt_group_id": "...",
  "apt_group_aliases": ["..."],
  "correlation_tier": "confirmed | high | medium | requires_review",
  "correlation_confidence": 0.0-1.0,
  "reasoning": "...",
  "correlation_uncertainty_notes": "...",
  "source_advisories": [
    {
      "source": "...",
      "advisory_id": "...",
      "advisory_date": "...",
      "url": "..."
    }
  ],
  "decision_path": [...]
}
```

### 7.4 Indicator entry structure (IoAc / IoI / IoP)

```
{
  "indicator_id": "...",
  "indicator_type": "ioac | ioi | iop",
  "tier": "confirmed | high | medium | requires_review",
  "confidence": 0.0-1.0,
  "summary": "...",
  "first_observed_at": "...",
  "last_observed_at": "...",
  "source_set": [
    {
      "source_pseudonym": "...",
      "source_category": "forum | marketplace | paste_site | breach_broker | malware_repo | cti_partner",
      "ethical_review_id": "...",
      "license_terms": {...}
    }
  ],
  "evidence_refs": ["sha256:..."],
  "review_required": true | false
}
```

Note: `source_pseudonym` rather than `source_url`. The module never includes raw dark-web URLs in operator-facing artifacts; the pseudonym is stable per-source for analyst correlation but does not leak source identity.

### 7.5 Schema validation

The enriched-artifact schema is published in `schemas/canonical-enriched-v1.json` (in the private Threat Context repository). The schema is **structurally compatible** with `canonical-artifact-v1.json`: every field present in Core's schema is present in the enriched schema with identical semantics. Consumers using only Core's schema and ignoring `threat_context_enrichment` and `threat_context` blocks will see a valid Core-compatible document.

---

## 8. Collector matrix (Threat Context-specific)

Collectors in Threat Context follow Core's pluggable-collector contract (SPEC.md §6.1) extended with per-collector commercialization-risk evaluation.

### 8.1 Adversary-infrastructure collectors

| Collector ID | Source | Cost | License Constraint | Commercialization Risk | Tier |
|---|---|---|---|---|---|
| `tc-typosquat-permute` | Internal (permutation generation) | Compute only | None | Low | Adversary-Infrastructure |
| `tc-typosquat-resolve` | Public DNS + WHOIS | API quota | None (public data) | Low | Adversary-Infrastructure |
| `tc-typosquat-content-fetch` | Active HTTP probing of look-alike domains | Compute + light egress | None | Medium (probing third-party-controlled hosts) | Adversary-Infrastructure |
| `tc-newcert-stream` | Certificate Transparency log streams | Free | None | Low | Adversary-Infrastructure |
| `tc-staging-cohabit` | Internet-wide scan archives | Partner license | Per-partner re-license | Medium | Adversary-Infrastructure |
| `tc-credential-broker-scan` | Curated credential-breach broker forums | Partner license + ethical review | Derived-metadata-only redistribution | High | Adversary-Infrastructure |

### 8.2 Dark-web collectors

| Collector ID | Source Category | Ethical Review Status | License Posture | Commercialization Risk |
|---|---|---|---|---|
| `tc-dw-forum-cooperative` | Cooperative forum-monitoring partner | Approved (quarterly review) | Derived-metadata-only | High |
| `tc-dw-marketplace-aggregate` | Aggregated marketplace surveillance partner | Approved | Derived-metadata-only | High |
| `tc-dw-paste-site-scan` | Paste-site crawl (operator-direct) | Approved | None | Medium |
| `tc-dw-malware-repo-scan` | Malware sample repository (operator-direct) | Approved | Per-platform terms | Medium |
| `tc-dw-i2p-curated` | I2P curated-source partner | Approved | Derived-metadata-only | High |

Each dark-web collector carries an `ethical_review_id` referencing its entry in the source registry (§5.4).

### 8.3 Commercial CTI partnerships

| Collector ID | Partner | Partnership Posture | Commercialization Risk |
|---|---|---|---|
| `tc-cti-mitre-attack-groups` | MITRE ATT&CK public group profiles | Public CC BY 4.0 | Low |
| `tc-cti-cisa-kev` | CISA Known Exploited Vulnerabilities | Public, attribution required | Low |
| `tc-cti-cisa-advisories` | CISA cybersecurity advisories | Public, attribution required | Low |
| `tc-cti-fbi-flash` | FBI flash alerts (public-distribution subset) | Public, attribution required | Low |
| `tc-cti-commercial-A` | Commercial CTI partner A | Negotiated EULA | Medium-High |
| `tc-cti-commercial-B` | Commercial CTI partner B | Negotiated EULA | Medium-High |
| `tc-cti-korlogos-curated` | Korlogos-curated overlay (federal-customer-relevant actors) | Korlogos-internal | Low |

(Specific commercial partner names omitted from this spec until partnerships are contractually finalized; the slot reservations exist.)

### 8.4 Historical-enrichment collectors

| Collector ID | Source | License Constraint | Commercialization Risk |
|---|---|---|---|
| `tc-hist-ct-deep` | Deep CT log archives | Public + partner indexes | Low |
| `tc-hist-pdns-farsight` | Farsight DNSDB historical | Negotiated EULA | Low |
| `tc-hist-pdns-securitytrails` | SecurityTrails historical | Standard SecurityTrails terms | Low |
| `tc-hist-banner-censys` | Censys historical banner archive | Negotiated EULA | Medium |
| `tc-hist-banner-shodan` | Shodan historical archive | Standard Shodan terms | Medium |
| `tc-hist-screenshot-A` | Screenshot history partner | Negotiated EULA | Medium |
| `tc-hist-config-operator-uploaded` | Operator-uploaded historical configuration snapshots | Operator owns the data | Low (operator self-data) |

### 8.5 Per-collector commercialization-risk evaluation

For each collector, the commercialization-risk evaluation documents:

1. **Re-licensing constraints** — what derived data may be redistributed to operators, in what form, with what attribution requirements.
2. **Embargo requirements** — some commercial CTI feeds require an embargo before derived indicators may be redistributed (typically 24-72 hours after partner publication).
3. **Per-partner kill switches** — every commercial partnership has a documented termination procedure that ensures clean removal of partner-derived data from active artifacts and the evidence store.
4. **Customer-disclosure requirements** — what the operator's commercial agreement must disclose to operator-side legal review about the partner's data practices.

This evaluation is documented in the source registry alongside the ethical review (§5.4) and is reviewed quarterly.

---

## 9. Per-tenant configuration

Threat Context configuration is added as an additional block in tenant configuration (extending SPEC.md §10.1). The module is **not enabled by default** for any tenant; activation requires both a commercial license check and an explicit tenant-side opt-in.

```yaml
threat_context:
  enabled: true | false   # explicit opt-in; default false
  license_id: <commercial-license-uuid>

  capability_scope:
    apt_correlation: true | false
    ioac_collection: true | false
    ioi_collection: true | false
    iop_collection: true | false
    historical_enrichment: true | false
    adversary_infrastructure_detection: true | false

  dark_web_sources:
    enabled: true | false   # global opt-in for any dark-web sourcing
    source_categories_enabled:
      - forum
      - marketplace
      - paste_site
      - breach_broker
    source_categories_disabled: []
    operator_jurisdiction: <ISO-country-code>   # gates per-jurisdiction source access

  apt_groups_focus:
    explicit_inclusion: []   # if non-empty, only these groups are correlated
    explicit_exclusion: []   # always excluded

  historical_depth:
    certificate_history_years: 5
    dns_history_years: 10
    banner_history_years: 5
    screenshot_history_years: 3

  prioritization:
    publish_threat_context_priority: true | false
    weight_overrides: {}   # operator-specific weighting in the priority formula

  partner_data_handling:
    cleartext_credential_inclusion: false   # always false in v1; reserved for future opt-in
    raw_breach_record_retention_days: 30
    derived_metadata_retention_days: 365

  llm:
    cost_ceiling_usd_per_run: 50.00
    enrichment_policy: high_priority_targets_only | all_targets

  attribution_uncertainty_disclosure:
    dashboard_min_tier: high | confirmed   # which tier reaches operator dashboards
```

The default values are conservative: every capability defaults to `false` until explicitly enabled, and the per-source dark-web posture is granular so operators can scope-limit their exposure to specific source categories.

---

## 10. Pricing and packaging notes (high-level)

Detailed pricing is deferred to a discrete go-to-market session. This section captures only the structural commitments that affect the spec.

- **Separate license from Core.** Operators pay a separate license fee for Threat Context regardless of Core deployment posture (self-host vs. managed).
- **Tiered by capability scope.** A baseline Threat Context license includes APT correlation and adversary-infrastructure detection; dark-web IoAc/IoI/IoP and historical enrichment are higher tiers.
- **Per-tenant minimum spend.** Threat Context is sold to organizations with operational scale to consume it; the per-tenant minimum is a guard against under-resourced operators acquiring capability they cannot operate responsibly.
- **Federal-customer pricing.** Federal customers receive a documented bundle pricing pattern for RFP responses (per persona-analysis.md §Strategic recommendation 5). Bundle pricing reflects that federal operators typically need Core + Threat Context + Federal Customer Deployment Guide integration support.
- **Partner-feed pass-through.** Some commercial CTI partner feeds carry per-end-user usage fees that are passed through to operators with a documented markup.

---

## 11. Federal-customer considerations

Federal customers have specific operational characteristics that interact with the module's design. This section is upstream input to Session G (Federal Customer Deployment Guide); it does not pre-empt that document.

### 11.1 Authorization-boundary considerations

Because the module's worker pool runs in a separate cloud account from Core (§6.2), federal customers self-hosting EXPOSE Core within their authorization boundary face a deployment-topology question for Threat Context:

- **Option A: Federal customer self-hosts Threat Context.** The module's worker pool runs inside the agency's authorization boundary alongside Core. The agency's ATO must extend to cover the dark-web egress path, partner-feed ingest, and crawler operational posture. This is operationally heavy.
- **Option B: Korlogos-managed Threat Context with Core self-hosted.** The agency self-hosts Core; Threat Context runs in Korlogos's cloud account. The enriched artifact is delivered to the agency via authenticated transport. This is the recommended pattern but depends on the future Korlogos commercial offering's FedRAMP authorization (per ADR-010 Commitment 3).
- **Option C: Hybrid.** Some module capabilities run in-agency (e.g., APT correlation against public ATT&CK data); others run in Korlogos's cloud (dark-web crawling). This is operationally complex and likely only justified for the largest federal deployments.

### 11.2 Higher-sensitivity data sourcing

Federal 3PAOs reviewing the module's data-handling will scrutinize:

- **Partner-feed contractual terms.** Each commercial partner's data-handling agreement must align with FedRAMP-ish data-handling expectations even when the partner itself is not FedRAMP-authorized. Korlogos's partner agreements include FedRAMP-aware addenda for federal use.
- **Dark-web source vetting documentation.** The §5.4 source registry must be available to 3PAOs in summary form; specific source identities are protected, but the review process is auditable.
- **Personnel-exposure mitigations.** The §5.5 personnel-exposure protections must be documented and demonstrably operational for federal contracting purposes.

### 11.3 Continuous-monitoring integration

The enriched artifact integrates into agency continuous-monitoring evidence streams identically to Core's artifact (per ADR-010 §"Federal-customer integration evidence"), with the additional consideration that Threat Context's `threat_context_priority` field provides an explicit RA-3 (risk assessment) input distinct from Core's lead score. Agencies can choose which prioritization signal feeds their CDM (Continuous Diagnostics and Mitigation) downstream.

### 11.4 Control inheritance from Core

For each NIST 800-53 control mapping in `framework-annotation.md` §5, the module's deployment inherits Core's posture and adds module-specific extensions:

| Control | Core Coverage | Threat Context Extension |
|---|---|---|
| AU-2, AU-3, AU-12 (audit logging) | Satisfies | Extends with per-source license-event logging, per-partner integrity-check events, ethical-review approval events |
| SC-8, SC-28 (transmission/at-rest encryption) | Satisfies | Extends with per-partner credential isolation, dark-web egress encryption discipline |
| SI-7, SI-7(15) (integrity, code authentication) | Satisfies | Extends with separate signing identity for the enriched artifact |
| SI-10 (input validation) | Satisfies | Extends with partner-feed sanitization and dark-web content sanitization |
| RA-3 (risk assessment) | Provides evidence for | Extends with explicit `threat_context_priority` field as RA-3 input |
| CA-7 (continuous monitoring) | Provides evidence for | Extends with daily-cadence enriched artifact stream |

The module never weakens Core's control posture; each extension either preserves or strengthens the inherited posture.

### 11.5 ATT&CK technique coverage

The module covers ATT&CK techniques that `framework-annotation.md` §2.1 marks as out-of-scope-for-Core:

| ATT&CK Technique | Module Coverage |
|---|---|
| T1597 (Search Closed Sources) | **Implements.** Dark-web crawling and commercial CTI feed ingest. |
| T1589.001 (Credentials) | **Implements (defensive).** Credential-broker scanning surfaces leaked credentials matching operator-attributed surface. |
| T1583, T1584, T1585, T1587, T1588 (Resource Development sub-techniques) | **Monitors.** Adversary-infrastructure detection covers the principal Resource Development tactic surface. |

---

## 12. Phase plan

Threat Context's phase plan is distinct from Core's. Threat Context **cannot ship before Core's Phase 1 lab launch** because the module depends on the canonical artifact contract (`schemas/canonical-artifact-v1.json`) being stable.

### 12.1 Phase TC-0 — Foundation (4 weeks, parallel with Core's Phase 2)

- Repository setup: private repository, commercial EULA, SECURITY.md, ETHICS.md (separate from Core's), CONTRIBUTING.md.
- Source registry framework: schema for source-registry entries, ethical-review workflow, per-source license-metadata recording.
- Enriched-artifact schema: `schemas/canonical-enriched-v1.json` and JSON Schema validation.
- Module-side cosign signing identity provisioned; signing-key custody documented.
- Cross-tenant isolation test suite extended for the module.

### 12.2 Phase TC-1 — Adversary-infrastructure detection (6 weeks)

This is the lowest-ethics-surface capability and ships first to validate the module's architecture before higher-risk capabilities go live.

- Typosquat scanners (`tc-typosquat-permute`, `tc-typosquat-resolve`, `tc-typosquat-content-fetch`).
- Newly-issued certificate streaming (`tc-newcert-stream`).
- Staging-infrastructure cohabitation analysis.
- Per-target adversary-infrastructure block in the enriched artifact.

### 12.3 Phase TC-2 — APT targeting profile correlation (4 weeks)

- MITRE ATT&CK group profile ingest.
- CISA / FBI advisory ingest.
- Korlogos-curated overlay framework (curation work itself is ongoing, not phase-bounded).
- LLM-assisted correlation reasoning generation.
- Per-target targeting-correlation block in the enriched artifact.

### 12.4 Phase TC-3 — Historical point-in-time enrichment (4 weeks)

- Partner integration with Farsight DNSDB, SecurityTrails historical, Censys historical, Shodan historical.
- Per-target historical-enrichment block in the enriched artifact.
- License-policy enforcement at artifact serialization time.

### 12.5 Phase TC-4 — Dark-web IoAc/IoI/IoP (8 weeks)

This is the highest-ethics-surface capability and ships last after the module's operational maturity is established.

- Source registry populated with initial dark-web partners (subject to ethical review).
- Dark-web crawler workers operational with full egress isolation.
- Per-target IoAc/IoI/IoP indicator blocks in the enriched artifact.
- Personnel-exposure mitigations operational.

### 12.6 Phase TC-5 — Risk-prioritized lens and tuning (ongoing)

- `threat_context_priority` formula deployment and tuning.
- Quarterly source-registry re-review.
- Quarterly per-collector commercialization-risk re-evaluation.
- Quarterly ethics-review cadence.

---

## 13. Open questions

These items are explicitly unresolved and shape future work. They do not block the module's specification.

| Question | Why it matters | Suggested resolution path |
|---|---|---|
| **Initial dark-web source partner identification.** Which specific cooperative forum-monitoring and marketplace-surveillance partners will Korlogos integrate with for Phase TC-4? | Drives the first-customer experience and the initial ethics-review caseload. | Sales-pipeline-driven; partners with FedRAMP-aware data-handling postures preferred. Document selected partners in source registry quarterly. |
| **Korlogos-curated APT overlay scope.** The federal-customer-relevant actor coverage in the curated overlay is open-ended; what is the v1 scope? | Drives federal-customer credibility for APT correlation. | Define an initial actor list from CISA + FBI advisory frequency analysis; expand quarterly based on customer feedback. |
| **Embargo handling for commercial CTI partners.** Some commercial CTI feeds require 24-72 hour embargoes before redistribution; how does the module communicate embargoed-but-unreported indicators to operators? | Affects time-to-detection for federal customers with high-tempo SOC operations. | Embargo flag on indicator; surface "embargoed indicator pending" in the artifact's `tenant_quota_warnings` section without leaking the indicator content; document partner-by-partner embargo terms. |
| **Multi-source corroboration thresholds for `confirmed` tier.** What specific thresholds (number of sources, source-class diversity, time-window) qualify an IoAc indicator for `confirmed` tier? | Affects false-positive rate; over-conservative thresholds suppress real indicators, under-conservative thresholds amplify hoaxes. | Tune via eval datasets against historical confirmed-and-disconfirmed indicators; re-tune quarterly. |
| **Per-jurisdiction source access controls.** How granular should jurisdiction-based source access be? | Affects operator legal exposure when subscribing across jurisdictions. | Initial v1: country-level. Expand to sub-national if customer demand emerges (e.g., US state-level for state-government customers). |
| **Partner data-handling agreement template.** What template language ensures FedRAMP-alignable handling across all commercial partners? | Federal customers will require uniform partner-handling terms. | Draft template with federal-customer-aware addenda; review with legal counsel before first commercial partnership. |
| **Operator-contributed indicator pathway to EXPOSE Research.** How do operators contribute confirmed indicators back to Korlogos's curation pool, and how do those flow to EXPOSE Research's CC BY 4.0 publication? | Affects the broader-ecosystem-contribution narrative central to ADR-009 §"EXPOSE Research". | Define explicit operator-contribution workflow with de-identification gates; require explicit operator opt-in per-contribution; document publication-to-Research pathway. |
| **Takedown coordination posture.** Should the module include or exclude takedown-coordination integration (e.g., handing typosquat indicators to a third-party takedown provider)? | Operators frequently want takedown integration; it raises a different set of partner relationships. | v1: exclude (out-of-scope per §2.4). Reconsider in v2 based on customer demand and the operational/contractual cost of takedown-provider integration. |
| **Mythos-class consumption in Environment 2.** How does the enriched artifact serve Environment 2's downstream LLM workflows differently than Core's artifact? | Affects the air-gap handoff discipline and Environment 2's tooling expectations. | Document in a follow-up artifact alongside Core's Environment 2 boundary; the `threat_context` blocks are explicit Environment 2 inputs that downstream tooling can prioritize. |
| **External ethics review board for the module.** Should the module establish an external ethics review board to vet new dark-web sources and review the module's ethics posture annually? | Adds independent scrutiny; valuable for federal customer trust and for Korlogos's defensible ethics posture. | Recommend external advisory ethics board with rotating membership before Phase TC-4 ships. Less stringent than the equivalent recommendation for Identity Surface (which warrants a board *before* public availability), but still recommended. |

---

## 14. Document maintenance

This is a working specification. It will be revised as Threat Context's phases land and as customer feedback shapes the module's operational posture.

Triggers for revision:

- Each phase completion (TC-0 through TC-5).
- New source additions to the registry (quarterly source-registry review documented in this spec's source-registry summary).
- New commercial partner integrations (per-partnership commercialization-risk evaluation documented).
- Schema changes to `canonical-enriched-v1.json` (versioned; back-compat preserved within v1).
- Material changes to Core's `canonical-artifact-v1.json` (the module's superset relationship requires re-validation).
- ADR-009 or ADR-010 revisions (the module inherits structural decisions from those ADRs).
- Material legal-landscape changes (GDPR enforcement evolution, CCPA/DROP enforcement, EU AI Act enforcement of high-risk system categorization, dark-web-source legality changes).

Revision cadence: quarterly review or per phase completion, whichever is earlier.

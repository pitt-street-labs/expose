# ADR-008: Authorized use and ethics

**Status:** Accepted
**Date:** 2026-05-09
**Decision-makers:** Korlogos / Pitt Street Labs

## Context

EXPOSE is genuinely capable — it attributes external assets to organizations, identifies cloud resources, fingerprints tech stacks, scores leads for red team prioritization. It can be misused. The Apache 2.0 public posture (Decision 5) means anyone can clone and run it, including with intent the project's positioning documents say is unintended.

This decision establishes:

- The project's intended-use posture and how it is communicated.
- Runtime behavior that nudges operators toward authorized use.
- Handling of incidental data — observations about organizations that aren't the operator's.
- Explicit non-goals that scope what EXPOSE will and will not do.

## Decision

**Three-layer authorized-use posture:**

### Layer 1: Project-level positioning

`README.md`, `SECURITY.md`, and `ETHICS.md` explicitly state intended use and non-goals:

- **Intended use:** defensive CTEM workflows, authorized red team operations, own-perimeter mapping.
- **Non-goals:** active exploitation, PII enrichment beyond public records, adversarial use against third parties, unauthorized reconnaissance.
- **Capability disclosure:** plain-language description of what the tool does.
- **Adversary-controlled inputs:** acknowledgment that sanitization is a security property, not just code quality.
- **Downstream workflow boundary:** Environment 2 (separate, downstream LLM tooling) has its own safety responsibilities; EXPOSE produces structured input for those workflows.

These documents are maintained, not one-time writes. Quarterly review cadence.

### Layer 2: Runtime authorization-scope enforcement

Tenant configuration includes an authorization scope: a list of apex domains, cloud accounts, registrant patterns, and ASN ranges the operator is authorized to analyze. The scope has an `enforcement_mode`:

- **`soft`** — log scope mismatches in audit log only.
- **`medium`** — **v1 default.** Scope mismatches are flagged in the artifact (`outside_authorized_scope: true` on relevant targets, aggregated summary at top level). No blocking; operators with external authorization can extend scope deliberately.
- **`hard`** — active probing refuses to execute against any asset not in `confirmed` or `high` attribution tier or not explicitly in the scope. Passive collection remains broad. Available for stricter deployments (regulated industries, scope-contracted customer engagements). Implementation in v1 framework with full activation in production-hardening.

The medium default makes scope a first-class concept the operator must engage with. Loud warnings in artifacts surface scope mismatches to consumers without hard-blocking legitimate workflows.

### Layer 3: Incidental data handling

Collection inevitably produces observations about organizations that aren't the operator's — neighbors in cloud IP space, cohabiting hosts on shared infrastructure, cohort entries in CT log queries. These are necessary for attribution (you need to know what's *not* yours to be confident about what is) but should not appear in the deliverable artifact.

**The contract:**

- Collection observes broadly from queried sources.
- The observation graph stores everything observed, with `attribution_status`. Non-yours assets get status `not_yours` with structured reasoning.
- The artifact filters: only assets with status `confirmed`, `high`, `medium`, or `requires_review` (within authorized scope) appear. `not_yours` and `rejected` stay in the graph for context but never reach the artifact.
- Graph retention: non-yours observations are pruned from the graph after a configurable retention window (default 30 days) unless re-observed in subsequent runs.

This means the deliverable is *only* about the operator's own assets, the graph remembers context for attribution quality, and incidental data has bounded retention.

### Explicit non-goals

The following are out of scope for EXPOSE — not deferred, not future-work, but deliberately not part of the project:

- **Active exploitation, vulnerability validation, or post-discovery offensive action.** EXPOSE produces leads. Exploitation toolchains (Nuclei, Metasploit, manual red team) are different categories.
- **PII enrichment beyond public records.** Registrant emails are PII but publicly disclosed; the tool treats them as such. The tool does not enrich with private data sources, paid identity-resolution services, or social-graph correlation.
- **Adversarial use against third parties.** The medium-mode default warns; ETHICS.md positions; the tool cannot prevent misuse but does not facilitate it.
- **Open-ended narrative reasoning, exploit hypothesis generation, red team briefing prose.** These are Environment 2's responsibility.

## Consequences

**Positive:**

- Clear positioning reduces the likelihood of bad actors thinking the project is for them.
- Provides Korlogos with documented intent that can be cited when bad actors show up anyway.
- Scope-aware artifacts give downstream consumers (analysts, CTEM tools) immediate visibility into authorization context.
- Incidental data filtering keeps the artifact crisp and focused.
- Retention pruning bounds data-protection compliance scope.
- Hard mode is available for deployments needing strict enforcement.

**Negative:**

- Operators who want broader collection without scope warnings will find the medium default chatty. They can configure soft mode if they accept the audit-log-only posture.
- Hard mode is a v1 framework with full activation deferred. Strict-enforcement deployments get the framework but not all the polish.
- The tool cannot prevent misuse. Open-source projects in this category never can. ETHICS.md and SECURITY.md provide framing, not control.

## Alternatives considered

**Soft enforcement default (audit log only).** Operator is on the honor system. Rejected because scope-aware warnings in the artifact provide downstream consumers with context, which is valuable; the medium mode delivers this without blocking workflows.

**Hard enforcement default.** Strictest posture. Rejected for v1 because legitimate workflows often have external authorization the engine cannot verify (scope contracts referenced by ID, evolving M&A inheritance, analyst-curated additions). Hard mode is available; not default.

**No incidental data filtering — emit everything in the artifact.** Maximum transparency, but pollutes the deliverable with non-actionable noise and creates compliance complexity. Rejected.

**No retention pruning — keep all observations forever.** Operationally simpler but compliance-hostile. Rejected.

**No explicit non-goals.** Tempting to leave open. Rejected because clear scope statements help operators evaluate whether EXPOSE fits their needs and reduce ambiguous adoption that could lead to misuse.

## When to revisit

Authorized-use posture is durable. What will evolve:

- **ETHICS.md positioning** in response to capability changes, threat landscape evolution, regulatory updates (NIST AI RMF, EU AI Act enforcement). Quarterly review cadence.
- **Hard mode adoption** as customer engagements with scope contracts emerge.
- **Authorization scope schema** evolution — v1 has flat lists; future versions may add time bounds, asset-type restrictions, scope inheritance across affiliated tenants.
- **PII handling** as GDPR/CCPA requests emerge; redaction options for forwarding artifacts to lower-trust environments.

## References

- Decision recorded in design conversation 2026-05-09.
- Six deferred-issues in the authorized-use epic. See `docs/issues-backlog.md`.
- ETHICS.md is a v1 deliverable.
- Incidental data graph retention pruning is a v1 deliverable.

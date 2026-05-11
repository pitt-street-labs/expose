# EXPOSE -- Architecture Diagrams

**Status:** Advisory -- visual companions to the locked spec, not a substitute for it.
**Date:** 2026-05-10
**Public name:** EXPOSE (EXtended Perimeter Ontology Security Evaluation)

This directory holds Mermaid-rendered architecture diagrams for EXPOSE. Each diagram visualizes one slice of the system as defined in the locked spec (`docs/SPEC.md`) and the architecture decision records (`docs/adr/`). The diagrams are reference material for technical reviewers, federal customers, and onboarding engineers; the spec remains the source of truth when the two appear to disagree.

GitHub renders Mermaid natively. Each `.md` file in this directory contains one or more `mermaid` code blocks plus surrounding prose explaining what the diagram shows, what is intentionally left out, and which spec sections / ADRs / issues anchor it.

---

## Diagram Index

### [00 -- Pipeline Stages](./00-pipeline-stages.md)

**Type:** Flowchart
**Spec anchor:** SPEC section 4 (Pipeline Architecture)

The five-stage Environment 1 pipeline with trust-boundary annotations and deterministic-vs-LLM markers. Shows the flow from seed ingestion through collection, sanitization, graph construction, and attribution to the signed canonical artifact. Start here for a top-level understanding of what EXPOSE does.

### [10 -- Two-Environment Model](./10-two-environment-model.md)

**Type:** Sequence diagram + flowchart
**Spec anchor:** SPEC section 4.1 (Two-Environment Model), ADR-005

The manual air-gapped handoff from Environment 1 (EXPOSE engine -- deterministic, auditable) to Environment 2 (downstream LLM analysis -- non-deterministic, out of scope). Shows signed-artifact verification at the boundary. Explains why the artifact is the deliverable and what happens after.

### [20 -- Deployment Topology](./20-deployment-topology.md)

**Type:** Component graph
**Spec anchor:** SPEC section 4.2, ADR-002, ADR-003

Container topology showing the control plane, three worker types (collector, scanner, LLM), PostgreSQL, object store, secrets backend, and optional Ollama. Annotates data-plane and control-plane separation. Essential for understanding what runs where in a deployed EXPOSE instance.

### [30 -- Observation Graph](./30-observation-graph.md)

**Type:** ER diagram
**Spec anchor:** SPEC sections 5.2-5.3, ADR-001

The typed observation graph -- 10 entity types, 10 edge types, tenant scoping, and evidence references. All entity tables include `tenant_id` per ADR-007. Shows the data model that backs the pipeline's storage layer and the canonical artifact's target section.

### [40 -- Multi-Tenancy](./40-multi-tenancy.md)

**Type:** Sequence diagram + flowchart
**Spec anchor:** ADR-007 (Multi-Tenancy)

Tenant context flow from API request through middleware, control plane, work queue, and workers. Shows cross-tenant isolation boundaries and where tenant ID propagation is enforced. Critical for reviewers evaluating data isolation guarantees.

### [50 -- Scanner Egress](./50-scanner-egress.md)

**Type:** Component graph
**Spec anchor:** SPEC section 6.3, ADR-008

The `EgressProfile` abstraction with four implementations: direct, SOCKS5, WireGuard, and HTTP CONNECT. Shows where scan provenance records the egress mode, how active collectors (Tier 3) route their traffic, and the relationship between egress isolation and attribution.

### [60 -- Attribution and LLM Enrichment](./60-attribution-and-llm-enrichment.md)

**Type:** Flowchart
**Spec anchor:** SPEC section 8 (Attribution), ADR-005, ADR-006

Two-pass attribution: rule-based scoring (Stage 4a) maps entities to attribution tiers, then optional `SafeLLMClient`-wrapped LLM enrichment (Stage 4b) produces enriched candidates. Shows how the deterministic and non-deterministic paths interact and where the trust boundary lies.

### [70 -- Product Surfaces](./70-product-surfaces.md)

**Type:** Component graph
**Spec anchor:** ADR-009 (Open-Core Licensing)

The four product surfaces: EXPOSE Core (Apache 2.0), EXPOSE Threat Context (proprietary), EXPOSE Identity Surface (proprietary), and EXPOSE Research (proprietary dataset). Shows the license boundaries between open-source and commercial components and what ships with the free tier vs. paid modules.

### [80 -- Federal Deployment Pattern](./80-federal-deployment-pattern.md)

**Type:** Component graph
**Spec anchor:** Federal Customer Deployment Guide (docs/strategy/)

The federal-customer self-host pattern showing: agency ATO boundary, EXPOSE Core sub-boundary, CDM/SIEM ingestion points, dedicated cloud egress, and the EXPOSE update channel as the only inbound exception. Designed for SSP appendix preparation and FedRAMP-equivalent positioning.

---

## Reading Order

For a first-time reader, the recommended sequence is:

| Order | Diagram | What you learn |
|---|---|---|
| 1 | `00-pipeline-stages` | What the system does, end to end |
| 2 | `10-two-environment-model` | Why the artifact is the deliverable and what happens after |
| 3 | `20-deployment-topology` | What runs where |
| 4 | `30-observation-graph` | What the data looks like |
| 5 | `60-attribution-and-llm-enrichment` | How attribution decisions are produced |
| 6 | `40-multi-tenancy` | How the same engine serves multiple tenants safely |
| 7 | `50-scanner-egress` | How active probing is isolated from the operator's own IP space |
| 8 | `70-product-surfaces` | How Core relates to the commercial modules and the research dataset |
| 9 | `80-federal-deployment-pattern` | How a federal agency self-hosts within an existing ATO |

A reviewer focused on the open-source engine alone can stop after diagram 6. A reviewer evaluating commercial structure or federal procurement should read through diagram 9.

---

## Related Documents

| Document | Relationship |
|---|---|
| `docs/SPEC.md` | Source of truth. When a diagram and the spec disagree, the spec wins. |
| `docs/adr/ADR-001..010` | Architectural decisions that constrain the diagrams. |
| `docs/collectors.md` | Detailed collector catalog -- complements diagram 00 (pipeline stages) and 50 (scanner egress). |
| `docs/quickstart.md` | Getting started guide -- references these diagrams for deeper exploration. |
| `docs/strategy/federal-customer-deployment-guide.md` | The canonical view for SSP work. Diagram 80 generalizes the pattern; the federal-customer document is authoritative. |

---

## Conventions

- **Mermaid features used:** `flowchart TD` / `flowchart LR`, `sequenceDiagram`, `erDiagram`, `graph TB`. These render reliably in GitHub, GitLab, and most Markdown renderers (mkdocs-material, Obsidian, VS Code preview).
- **Component names** match the spec exactly: `expose-control-plane`, `expose-collector-worker`, `expose-scanner-worker`, `expose-llm-worker`, `postgres`, `minio`, `ollama`, `vaultwarden`. Lowercase, hyphenated.
- **Entity-type names** match SPEC section 5.2 exactly: `Domain`, `Subdomain`, `IP`, `CIDR`, `Certificate`, `Service`, `CloudResource`, `Organization`, `Registrant`, `ASN`. CamelCase singular.
- **Edge-type names** match SPEC section 5.3 exactly: `resolves_to`, `presented_cert`, `subject_alt_name_includes`, `nested_under`, `same_registrant_as`, `hosted_in_asn`, `cohabits_ip_with`, `in_cloud_range`, `registrant_of`, `cloud_resource_belongs_to`. Snake_case.
- All entity tables in `erDiagram` blocks include `tenant_id` per ADR-007.
- The internal codename never appears in diagram labels; only EXPOSE.

## What This Directory Does Not Do

- Does not invent architecture beyond the spec. Where the spec is silent, diagrams are silent.
- Does not include implementation-level call graphs, sequence-level message wire formats, or specific Postgres index choices.
- Does not duplicate the federal-customer-deployment-guide's authorization-boundary diagram. Diagram 80 generalizes the pattern; the federal-customer document remains the canonical view for SSP work.
- Does not replace the locked spec's textual definitions. When the diagrams and the spec disagree, the spec wins and the diagram is in error.

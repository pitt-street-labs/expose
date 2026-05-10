# EXPOSE — Architecture diagrams

**Status:** Advisory — visual companions to the locked spec, not a substitute for it.
**Date:** 2026-05-09
**Public name:** EXPOSE (EXtended Perimeter Ontology Security Evaluation)
**Internal codename:** FF6K (development artifacts only per HISTORY.md)

This directory holds Mermaid-rendered architecture diagrams for EXPOSE. Each diagram visualizes one slice of the system as defined in the locked spec (`docs/SPEC.md`) and the architecture decision records (`docs/adr/`). The diagrams are reference material for technical reviewers, federal customers, and onboarding engineers; the spec remains the source of truth when the two appear to disagree.

GitHub renders Mermaid natively. Each `.md` file in this directory contains one or more `mermaid` code blocks plus surrounding prose explaining what the diagram shows, what is intentionally left out, and which spec sections / ADRs / issues anchor it.

## Index

| File | Diagram | One-line description |
|---|---|---|
| [`00-pipeline-stages.md`](./00-pipeline-stages.md) | Flowchart | The five-stage Environment 1 pipeline with trust-boundary annotations and deterministic-vs-LLM markers |
| [`10-two-environment-model.md`](./10-two-environment-model.md) | Sequence + flowchart | Manual air-gapped handoff from Environment 1 (EXPOSE) to Environment 2 (downstream LLM analysis), with signed-artifact verification |
| [`20-deployment-topology.md`](./20-deployment-topology.md) | Component graph | Container topology — control plane, three worker types, Postgres, object store, secrets backend, optional Ollama — with data plane / control plane separation |
| [`30-observation-graph.md`](./30-observation-graph.md) | ER diagram | The typed observation graph — entity types, edge types, tenant scoping, evidence references |
| [`40-multi-tenancy.md`](./40-multi-tenancy.md) | Sequence + flowchart | Tenant context flow from API request through middleware, control plane, work queue, workers; cross-tenant isolation test boundary |
| [`50-scanner-egress.md`](./50-scanner-egress.md) | Component graph | EgressProfile abstraction — direct, SOCKS5, WireGuard, HTTP CONNECT — and where scan provenance records the egress mode |
| [`60-attribution-and-llm-enrichment.md`](./60-attribution-and-llm-enrichment.md) | Flowchart | Two-pass attribution: rule-based (4a) → tier mapping → optional SafeLLMClient-wrapped enrichment (4b) → enriched candidates → artifact |
| [`70-product-surfaces.md`](./70-product-surfaces.md) | Component graph | The four product surfaces from ADR-009 — EXPOSE Core (Apache 2.0), Threat Context, Identity Surface, Research — and the license boundaries between them |
| [`80-federal-deployment-pattern.md`](./80-federal-deployment-pattern.md) | Component graph | Federal-customer self-host pattern — agency ATO boundary, EXPOSE Core sub-boundary, CDM/SIEM ingestion, dedicated cloud egress, EXPOSE update channel as the only inbound exception |

## Reading order

For a first-time reader, the recommended sequence is:

1. **`00-pipeline-stages.md`** — what the system does, end to end
2. **`10-two-environment-model.md`** — why the artifact is the deliverable and what happens after
3. **`20-deployment-topology.md`** — what runs where
4. **`30-observation-graph.md`** — what the data looks like
5. **`60-attribution-and-llm-enrichment.md`** — how attribution decisions are produced
6. **`40-multi-tenancy.md`** — how the same engine serves multiple tenants safely
7. **`50-scanner-egress.md`** — how active probing is isolated from the operator's own IP space
8. **`70-product-surfaces.md`** — how Core relates to the commercial modules and the research dataset
9. **`80-federal-deployment-pattern.md`** — how a federal agency self-hosts within an existing ATO

A reviewer focused on the open-source engine alone can stop after diagram 6. A reviewer evaluating commercial structure or federal procurement should read through diagram 9.

## Related diagrams in other documents

Where existing locked artifacts already contain a diagram of the same system slice, this directory cross-references rather than duplicating:

- `docs/strategy/federal-customer-deployment-guide.md` §3.4 — Mermaid view of the agency-ATO-embedded EXPOSE deployment, paired with an ASCII-art equivalent in §3.3. Diagram 80 in this directory generalizes the deployment pattern; it does not replace the federal-customer-deployment-guide's view, which is canonical for SSP authoring.

## Status header convention

This README uses the same status-header convention as `docs/strategy/persona-analysis.md`:

- **Status:** Advisory or Locked
- **Date:** when the artifact was produced or last revised
- **Context lines** identifying public name, internal codename, and audience

Individual diagram files in this directory follow a lighter header (just the title and a "What this shows" intro) because they are visual companions, not foundation documents.

## Editing conventions

- Mermaid features used: `flowchart TD` / `flowchart LR`, `sequenceDiagram`, `erDiagram`, `graph TB`. These render reliably in GitHub, GitLab, and most Markdown renderers (mkdocs-material, Obsidian, VS Code preview).
- Component names match the spec exactly: `expose-control-plane`, `expose-collector-worker`, `expose-scanner-worker`, `expose-llm-worker`, `postgres`, `minio`, `ollama`, `vaultwarden`. Lowercase, hyphenated.
- Entity-type names match SPEC §5.2 exactly: `Domain`, `Subdomain`, `IP`, `CIDR`, `Certificate`, `Service`, `CloudResource`, `Organization`, `Registrant`, `ASN`. CamelCase singular.
- Edge-type names match SPEC §5.3 exactly: `resolves_to`, `presented_cert`, `subject_alt_name_includes`, `nested_under`, `same_registrant_as`, `hosted_in_asn`, `cohabits_ip_with`, `in_cloud_range`, `registrant_of`, `cloud_resource_belongs_to`. Snake_case.
- All entity tables in `erDiagram` blocks include `tenant_id` per ADR-007.
- The internal codename FF6K never appears in diagram labels; only EXPOSE.

## What this directory does not do

- Does not invent architecture beyond the spec. Where the spec is silent, diagrams are silent.
- Does not include implementation-level call graphs, sequence-level message wire formats, or specific Postgres index choices — these are implementation concerns and may evolve.
- Does not duplicate the federal-customer-deployment-guide's authorization-boundary diagram. Diagram 80 generalizes the pattern; the federal-customer document remains the canonical view for SSP work.
- Does not replace the locked spec's textual definitions. When the diagrams and the spec disagree, the spec wins and the diagram is in error.

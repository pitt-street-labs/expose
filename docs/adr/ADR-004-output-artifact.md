# ADR-004: Output artifact

**Status:** Accepted
**Date:** 2026-05-09
**Decision-makers:** Korlogos / Pitt Street Labs

## Context

EXPOSE's purpose is to drive downstream CTEM workflows and red team lead review. The question is how the pipeline delivers its output: as a live API surface that consumers query in real time, as a streaming feed, as files in object storage, or some combination.

This decision interacts strongly with the two-environment model. Environment 1 (this codebase) produces structured intelligence. Environment 2 (separate, downstream) consumes it for narrative reasoning under appropriate safeguards. The handoff between environments is air-gapped.

## Decision

**The signed JSON file is the sole deliverable.** No live API surface, no streaming feed, no webhook delivery. CTEM platform integration is a downstream concern (small import scripts, Logic Apps, Lambdas — operator's choice).

Per run, three files are produced:

- **`canonical.json.gz`** — gzipped, indented JSON conforming to the canonical artifact schema. The deliverable.
- **`canonical.json.gz.sig`** — detached cosign signature.
- **`manifest.json`** — separate manifest describing run provenance and artifact integrity.

Optional derived partition views (`partitions/by-cloud-provider/aws.json`, `partitions/by-tier/confirmed.json`) are produced alongside as convenience. Partitions are filtered subsets of the canonical file and are not signed independently.

Artifact identity:

- Schema versioned as `expose/v1`. Backward-compatible changes within v1 guaranteed; breaking changes are major version bumps.
- Custom JSON Schema, not STIX 2.1. STIX is a general threat intelligence ontology; EXPOSE's domain is narrower and benefits from purpose-built semantics.
- File granularity: single canonical file per run, not partitioned. Partition views are derived, not authoritative.

Delta semantics:

- Each artifact includes `delta_from_previous_run` with structured change types.
- Removal reasons distinguish `no_longer_observed` from `removal_uncertain_collector_failure`. A passive DNS provider's bad day does not silently drop assets from analyst view.
- Deltas are deterministic — given two consecutive runs, the diff is reproducible.

Signing:

- Cosign keyless via GitHub Actions OIDC for production. Lab deployments may use cosign keypair signing or run unsigned (manifest notes status).
- Transparency log entries (Sigstore Rekor) in keyless mode for tamper-evident audit history.
- Verification documented with one-command examples in SECURITY.md.

Storage and delivery:

- v1 lab: artifacts written to MinIO on ARC. Operator retrieves via shell access or local mount. No HTTPS API, no bucket credentials issued.
- Production-hardening (deferred): cloud-hosted S3-compatible bucket, authenticated HTTPS API on the control plane, optional read-only bucket credentials for consumers who prefer object-store integration.

## Consequences

**Positive:**

- Maximum portability of the output. JSON is universally consumable.
- Maximum auditability. Files are diffable with `git diff` and `jq`. Signature verification is offline, cosign-based.
- Simplifies the v1 architecture significantly. No live feed API to operate, no webhook delivery, no CTEM-vendor adapters.
- Air-gapped handoff to Environment 2 is the natural pattern — file plus signature plus manifest, transferred manually.
- Backward-compatible schema evolution preserves consumer integrations.
- Reproducibility — deterministic generation from inputs means two runs on the same source data produce the same file.

**Negative:**

- No real-time consumption. Consumers see updates only at run cadence (daily for v1).
- Large tenants will produce large files (estimate 10-250 MB per run). Compressed JSON is fine but consumers must handle gzipped files.
- Operators wanting CTEM platform integration write their own import logic. We do not ship CTEM-specific adapters.
- Webhook push delivery is not supported. Consumers pull when ready.

## Alternatives considered

**STIX 2.1 with custom extensions.** Standard threat intelligence format with broad ecosystem support. Rejected because STIX's ontology (Indicator, Observed-Data, Infrastructure, Identity, Relationship) is designed for sharing IoCs and threat actor activity, not for representing one's own external surface. Forcing EXPOSE's domain into STIX means either misusing the ontology or wrapping in custom extensions until effectively writing a custom schema with extra ceremony. CTEM platforms don't natively consume STIX particularly well anyway.

**Live HTTPS API as primary delivery for v1.** Real-time consumption, supports versioning, supports auditing. Rejected for v1 because it adds operational complexity inappropriate for the lab phase (auth, rate limiting, audit logging, durability of the API itself). Deferred to production-hardening.

**Webhook push delivery.** Notifies consumers when a run completes. Rejected because webhooks are operationally annoying — delivery retries, signature verification on the receiver side, debugging delivery failures, dead letter queues. The "pull when you're ready" model is more reliable. Consumers who want push semantics can build a thin layer that polls and webhook-forwards.

**Multiple per-vendor JSON variants.** Different output schemas tuned to specific CTEM tools. Rejected as fragmenting the output contract; one canonical schema with operator-built import logic is cleaner.

## When to revisit

The "JSON file is the sole deliverable" decision is durable for the foreseeable future. What will be revisited:

- **Production-hardening triggers an HTTPS API** for retrieval, but the underlying artifact is unchanged. The API is a transport, not a different output.
- **Schema evolves within v1** as new attribution signals, exposure indicators, or LLM enrichment outputs are added. These are backward-compatible additions.
- **Schema goes to v2** if a structural redesign is warranted. v1 consumers continue to consume v1 artifacts; v2 is opt-in.

## References

- Decision recorded in design conversation 2026-05-09.
- Five deferred-issues in the production-hardening epic for live API delivery, retention, and storage migration. See `docs/issues-backlog.md`.
- Schema: `schemas/canonical-artifact-v1.json`.
- Manifest schema: `schemas/manifest-v1.json`.

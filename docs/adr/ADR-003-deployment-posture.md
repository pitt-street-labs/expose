# ADR-003: Deployment posture

**Status:** Accepted
**Date:** 2026-05-09
**Decision-makers:** Korlogos / Pitt Street Labs

## Context

FatFinger6000 needs to run in Korlogos's ARC lab at Pitt Street Labs for v1, but must be deployable to cloud (AWS/Azure/GCP) and to customer on-prem environments without architectural rework. Portability is a first-class requirement, not a future-work item.

The system has three workloads with distinct infrastructure preferences:

- **Control plane** — orchestrator, attribution engine, artifact generator, Postgres, object store. CPU/memory bound, low external bandwidth, high security sensitivity.
- **Collector workers** — talking to external APIs. Mostly outbound HTTPS.
- **Active scanner workers** — DNS resolution, TLS handshakes, HTTP fingerprinting against tenant-attributed assets. Source IP and attribution-isolation are real concerns.

## Decision

**Container-based, OCI-image-based, deployed via Helm chart**, with a Compose file as a minimum-viable fallback for the smallest deployments.

Specific stack:

- **Containers:** OCI images, multi-stage Dockerfiles, distroless or chainguard base where feasible. SBOM via syft, signed via cosign keyless (GitHub Actions OIDC), SLSA Level 2 provenance attestations (target Level 3).
- **Orchestration:** Kubernetes-native (k3s on ARC for v1, EKS/AKS/GKE for cloud, customer-provided for on-prem). Helm chart as the distribution unit.
- **Configuration:** 12-factor — environment variables for runtime config, secrets via mounted files or external secrets operator. No baked-in config in images.
- **Observability:** OpenTelemetry traces, metrics, logs. Exported via OTLP to whatever backend the deployment provides (Prometheus + Loki + Tempo on ARC, CloudWatch in AWS, etc.).
- **Secrets:** External `SecretsProvider` abstraction. v1 implementations: Vaultwarden (ARC), AWS Secrets Manager. Vault and Azure Key Vault deferred.
- **Inter-service comms:** gRPC for internal RPCs, HTTP for external APIs and admin surfaces.
- **Job queue:** Generic abstraction; concrete implementation deferred (Temporal vs. Celery vs. NATS JetStream — recommendation pending Phase 1 throughput data).
- **Multi-architecture:** x86_64 + arm64 from day one. Built via `docker buildx`, published as multi-arch manifests.

State is externalized: Postgres connection string, object store credentials, secrets backend reference are deployment-provided. Application has no Postgres-specific operational logic; backups, replication, and version upgrades are the deployment's responsibility.

**Scanner egress is configured via an `EgressProfile` abstraction**, not assumed. ARC deployments need a cloud-hosted egress proxy (separate AWS/Azure account, no other footprint) to avoid scanning third parties from home/lab IP space. Full-cloud deployments egress directly. The egress profile is logged in scan provenance.

## Consequences

**Positive:**

- v1 lab deployment on ARC is straightforward — k3s, MinIO, Vaultwarden, self-managed Postgres.
- Same Helm chart deploys to AWS/Azure/GCP/customer-on-prem with different values files.
- Modern security posture — signed images, SBOMs, supply-chain hygiene from day one.
- arm64 support enables Apple Silicon dev laptops (no qemu emulation pain) and Graviton cost savings in cloud.
- Network policies and east-west traffic isolation built into the Helm chart.
- Observability is portable — OTLP works with any backend.

**Negative:**

- "Modern stack" complexity must be maintained. Helm chart, multi-arch builds, signing pipeline all have ongoing cost.
- Postgres-in-container is documented as dev-only; operators must provision real Postgres for production. Some operators will get this wrong.
- Scanner egress profile abstraction adds configuration surface. ARC deployments require a cloud-hosted egress proxy as ongoing infrastructure (~$10-20/month).
- Air-gapped deployments are not supported — pipeline requires internet egress to specific allowlisted API providers. Documented explicitly.

## Alternatives considered

**Self-hosted on ARC only.** Simpler operational story for v1, no cloud bill, full data residency control. Rejected because portability to customer environments is a first-class requirement; "runs on Jeffro's home lab" is a hard sell to clients.

**Cloud-hosted only (dedicated AWS/Azure account).** Cleaner threat model, professional posture, scanner egress comes from cloud IP space which is operationally correct. Rejected because Korlogos has ARC infrastructure and wants to use it for v1; the portable architecture preserves the option to migrate later.

**Hybrid (control plane on ARC, scanner egress in cloud).** Technically optimal — control plane on ARC where you have full control and zero recurring cost, scanner egress in cloud where attribution-isolation is correct. This is effectively what we land on for v1: control plane on ARC, scanner egress through a small cloud-hosted egress proxy. Filed as a deployment-portability issue rather than baked into the architecture.

## When to revisit

The portable Helm chart pattern is durable. The specific implementations of state services (Postgres, object store, secrets backend) may evolve as deployments diversify, but the abstraction stays the same.

Multi-arch builds are forever. Image signing is forever (or until a better technology than cosign emerges).

## References

- Decision recorded in design conversation 2026-05-09.
- Eight deferred-issues in the deployment-portability epic. See `docs/issues-backlog.md`.

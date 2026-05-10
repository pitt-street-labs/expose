# EXPOSE — Issue backlog

This document consolidates the deferred-issues backlog across all eight architectural decisions. Issues are organized by epic for project-board import. Each issue has the `epic:<name>` label specified for direct GitHub Issues import via `gh` CLI or scripted creation.

Epics:

- [`deployment-portability`](#epic-deployment-portability) — Decision 3 follow-ups (8 issues)
- [`production-hardening`](#epic-production-hardening) — Decision 4 follow-ups (5 issues)
- [`llm-quality`](#epic-llm-quality) — Decision 4-revisited follow-ups (3 issues)
- [`eval-harness`](#epic-eval-harness) — LLM evaluation infrastructure (1 issue)
- [`repo-governance`](#epic-repo-governance) — Decision 5 follow-ups (5 issues)
- [`multi-tenancy`](#epic-multi-tenancy) — Decision 6 follow-ups (6 issues)
- [`authorized-use`](#epic-authorized-use) — Decision 7 follow-ups (6 issues)

**v1 deliverables flagged inline.** Items not flagged are deferred work tracked here for the project board.

Total: 34 issues, 4 are v1 deliverables (cross-tenant isolation testing, incidental data graph retention, initial ETHICS.md, multi-arch image builds).

---

## Epic: deployment-portability

Decision 3 generated infrastructure work that doesn't block v1 lab launch but matters for cloud and customer-on-prem deployments.

### Active scanner egress profile abstraction

**Labels:** `epic:deployment-portability`, `area:scanning`, `priority:high`, `type:feature`

**Summary**
ARC-hosted v1 cannot run active scanner workers from home/lab IP space without scanning third parties from inappropriate egress points. Need an `EgressProfile` abstraction in scanner workers so deployments can route active probing through controlled egress points.

**Acceptance criteria**
- `EgressProfile` interface with implementations: `direct`, `socks5`, `wireguard`, `http_connect`.
- Scanner worker config takes an egress profile reference; control plane enforces that scanner workers cannot dispatch jobs without one configured.
- ARC deployments document running a small cloud-hosted egress proxy (recommended: dedicated AWS account, `t4g.nano` Ubuntu instance with `tinyproxy` or WireGuard endpoint, ~$10-20/month).
- Cloud deployments use direct egress.
- Egress profile is logged in scan provenance for auditability.
- Documentation: when each profile is appropriate, threat model implications.

**Estimated effort:** 1-2 sprints

### Postgres production deployment documentation

**Labels:** `epic:deployment-portability`, `area:database`, `priority:high`, `type:documentation`

**Summary**
Helm chart includes Postgres for dev/lab use. Production deployments should use managed Postgres (RDS, Cloud SQL, Azure Database) or self-managed with proper HA/backup. Need clear documentation distinguishing modes.

**Acceptance criteria**
- README and Helm values explicitly mark in-cluster Postgres as dev-only.
- Production deployment guide documents:
  - Connection string injection from Kubernetes secret.
  - Required Postgres version and extensions.
  - Sizing guidance (storage, IOPS, RAM) per tenant scale tier.
  - Backup verification procedure.
  - Migration procedure for major Postgres version upgrades.
- Sizing reference: small (1-3 tenants, ~100k entities) → 2 vCPU/8GB RAM/100GB SSD; medium → 4 vCPU/16GB RAM/500GB SSD with read replica; large → managed instance with HA.

**Estimated effort:** 1 sprint

### Multi-arch image builds (x86_64 + arm64) — v1 deliverable

**Labels:** `epic:deployment-portability`, `area:build`, `priority:high`, `type:feature`, `v1`

**Summary**
v1 ships with multi-arch images so it runs on Apple Silicon developer laptops without emulation, Graviton in AWS, and Ampere VMs.

**Acceptance criteria**
- All container images built as multi-arch manifests.
- CI builds both architectures via `docker buildx`.
- Helm chart pulls correct architecture per node.
- Documentation includes multi-arch publishing in release process.

**Estimated effort:** Few days within Phase 1 sprint 1-2.

### Network policy and pod-to-pod traffic restrictions

**Labels:** `epic:deployment-portability`, `area:security`, `priority:medium`, `type:feature`

**Summary**
Helm chart should ship default Kubernetes NetworkPolicies restricting east-west traffic between components to required paths only.

**Acceptance criteria**
- NetworkPolicies for: control plane → Postgres, control plane → object store, control plane → workers (via job queue), collector workers → external APIs (allowlist), scanner workers → egress profile only, LLM workers → LLM provider endpoints only.
- Default-deny posture with explicit allows.
- Tested on k3s and one cloud-managed Kubernetes (GKE or EKS).
- Operators can override per deployment if needed.

**Estimated effort:** 1 sprint

### Container image signing and SBOM publication

**Labels:** `epic:deployment-portability`, `area:supply-chain`, `priority:high`, `type:feature`

**Summary**
Sign all container images with cosign keyless via GitHub Actions OIDC. Generate SBOMs with syft and publish alongside images. Target SLSA Level 2 build provenance, with SLSA Level 3 as ongoing improvement.

**Acceptance criteria**
- All images signed with cosign keyless via GitHub Actions OIDC at release time.
- SBOMs (SPDX format) generated with syft and published to release.
- Verification documented (`cosign verify` example commands in SECURITY.md).
- Operator-provided keypair signing supported as alternate path.

**Estimated effort:** 1 sprint

### Air-gap deployment limitations and documentation

**Labels:** `epic:deployment-portability`, `area:operations`, `priority:medium`, `type:documentation`

**Summary**
EXPOSE cannot run fully air-gapped because the discovery stage requires internet egress to specific allowlisted API providers. The artifact itself can be transported to air-gapped environments, but the pipeline cannot run there. Document explicitly.

**Acceptance criteria**
- README and SECURITY.md explicitly state air-gap limitation.
- Documentation enumerates required egress endpoints (CT log APIs, passive DNS providers, cloud IP range manifests, LLM provider endpoints if frontier providers used).
- Environment 2 air-gap separation documented as the architectural pattern: artifact + signature transferred manually to air-gapped Environment 2.

**Estimated effort:** 1 day

### Bundled observability stack subchart (optional)

**Labels:** `epic:deployment-portability`, `area:observability`, `priority:low`, `type:feature`

**Summary**
Operators without existing observability infrastructure benefit from a bundled "everything included" deployment option. Optional subchart deploys Prometheus + Loki + Tempo + Grafana with EXPOSE dashboards pre-configured.

**Acceptance criteria**
- Optional Helm subchart (`expose-observability`) bringing Prometheus + Loki + Tempo + Grafana.
- Pre-built EXPOSE dashboards: per-tenant run health, attribution decision rates, LLM costs, collector success rate.
- Audit log dashboards distinguishing tenant operations.
- Documented as optional convenience; production deployments should use existing observability infrastructure.

**Estimated effort:** 2 sprints

### Secrets backend abstraction with non-Vaultwarden implementations

**Labels:** `epic:deployment-portability`, `area:security`, `priority:medium`, `type:feature`

**Summary**
Secrets are fetched via a `SecretsProvider` abstraction. v1 implementations: Vaultwarden (ARC), AWS Secrets Manager. Vault and Azure Key Vault implementations needed for broader deployments.

**Acceptance criteria**
- `SecretsProvider` interface defined with `get_secret(secret_ref) -> str` and `list_secrets(prefix) -> list[str]`.
- HashiCorp Vault implementation (Token, AppRole, Kubernetes auth methods).
- Azure Key Vault implementation (Managed Identity preferred).
- GCP Secret Manager implementation (Workload Identity preferred).
- Secrets are fetched just-in-time per call, never cached in long-lived application memory.
- Audit log records secret access (secret reference, not value).

**Estimated effort:** 1-2 sprints

---

## Epic: production-hardening

Decision 4 deferred several items needed when moving from lab to production-grade.

### Cloud object storage migration (S3, Azure Blob, GCS)

**Labels:** `epic:production-hardening`, `area:storage`, `priority:high`, `type:feature`

**Summary**
v1 lab uses MinIO on ARC for artifact storage. Production deployments need cloud-hosted object storage with appropriate retention, replication, and access controls.

**Acceptance criteria**
- Object storage backend abstraction supports S3-compatible (MinIO, AWS S3), Azure Blob, GCS.
- Configuration determines which backend is used; application code is backend-agnostic.
- Bucket lifecycle policies (production-hardening): hot for 1 year, cold for 7 years, delete after — operator configurable.
- Cross-region replication option for disaster recovery.
- Access logged to deployment audit log.

**Estimated effort:** 1-2 sprints

### Authenticated HTTPS API for artifact retrieval

**Labels:** `epic:production-hardening`, `area:api`, `priority:high`, `type:feature`

**Summary**
v1 lab requires shell access to retrieve artifacts. Production needs an authenticated HTTPS API for retrieval, with bearer-token auth, audit logging, and tenant isolation.

**Acceptance criteria**
- HTTPS API endpoints: `GET /v1/tenants/{tenant_id}/runs/{run_id}/canonical.json.gz`, `GET /v1/tenants/{tenant_id}/runs/{run_id}/manifest.json`, `GET /v1/tenants/{tenant_id}/runs/{run_id}/canonical.json.gz.sig`, `GET /v1/tenants/{tenant_id}/runs` (list).
- Bearer-token auth with tenant-scoped permissions.
- Tenant isolation enforced at the API layer.
- Audit logging of every retrieval.
- Rate limiting per tenant.
- OpenAPI specification published.

**Estimated effort:** 2 sprints

### Read-only bucket credential issuance

**Labels:** `epic:production-hardening`, `area:integration`, `priority:medium`, `type:feature`

**Summary**
Some consumers prefer pulling artifacts directly from object storage rather than via the HTTPS API. Issue read-only, scope-limited credentials per consumer.

**Acceptance criteria**
- Per-consumer credential issuance API (admin operation).
- Credentials scoped to specific tenant + read-only on artifact paths.
- Time-bound credentials (default 90 days, renewable).
- Audit logging of credential issuance and use.

**Estimated effort:** 1-2 sprints

### Artifact and evidence retention policies

**Labels:** `epic:production-hardening`, `area:storage`, `priority:high`, `type:feature`

**Summary**
Artifacts and evidence accumulate. Configurable retention policies prevent storage from growing unbounded.

**Acceptance criteria**
- Per-tenant retention policy: hot tier (default 1 year), cold tier (default 7 years), delete after.
- Retention enforced via bucket lifecycle policies where supported, or via scheduled cleanup jobs.
- Operator can override per-tenant.
- Documentation includes legal/compliance considerations (litigation hold, data subject requests).

**Estimated effort:** 1 sprint

### Lab-to-production migration runbook

**Labels:** `epic:production-hardening`, `area:operations`, `priority:high`, `type:documentation`

**Summary**
v1 ships lab-deployed on ARC. Document the path from lab to production cloud deployment.

**Acceptance criteria**
- Step-by-step runbook covering: data export from lab Postgres, schema migration to managed Postgres, evidence migration to cloud object store, configuration migration, DNS cutover, verification procedure.
- Rollback procedure documented.
- Tested with at least one lab-to-cloud migration before deployments rely on it.

**Estimated effort:** 1 sprint (after first cloud deployment)

---

## Epic: llm-quality

Decision 4-revisited deferred LLM-specific quality and capacity work.

### GPU upgrade path documentation

**Labels:** `epic:llm-quality`, `area:llm`, `priority:medium`, `type:documentation`

**Summary**
v1 lab uses RTX 2080 Super (8GB VRAM) for local Ollama. This caps usable models at 7B-class with Q4_K_M quantization. Document upgrade path for operators needing higher local capacity.

**Acceptance criteria**
- Documentation covers: 16GB VRAM (RTX 4060 Ti 16GB, A4000) unlocks 14B-class with Q4 quantization; 24GB VRAM (RTX 3090, RTX 4090, A5000) unlocks 32B with Q4 or 70B with Q3; 48GB+ unlocks 70B with Q4 or larger.
- Performance benchmarks for EXPOSE-style enrichment workloads at each tier.
- Cost-benefit analysis: local hardware vs. frontier provider API costs at various tenant scales.

**Estimated effort:** 1 day documentation effort, ongoing as hardware evolves.

### Tie-breaker escalation policy

**Labels:** `epic:llm-quality`, `area:llm`, `priority:medium`, `type:feature`

**Summary**
v1 has the tie-breaker escalation framework but a default policy is needed for when escalation is appropriate.

**Acceptance criteria**
- Default tie-breaker policy: escalate when (a) primary LLM produces schema-validation-failing output 2+ times, OR (b) primary LLM self-reported confidence < 0.4, OR (c) rule engine and primary LLM strongly disagree on attribution tier.
- Per-tenant configuration to override the default.
- Per-tenant cost ceiling for tie-breaker calls (separate from primary cost ceiling).
- Audit logging of every tie-breaker invocation.
- Tie-breaker results recorded in artifact `LLMEnrichment` fields.

**Estimated effort:** 1 sprint

### Ollama instance pool with load balancing

**Labels:** `epic:llm-quality`, `area:llm`, `priority:low`, `type:feature`

**Summary**
Single Ollama instance becomes a bottleneck for tenants with high enrichment volumes. Support running an Ollama instance pool with load balancing.

**Acceptance criteria**
- Configuration supports multiple Ollama endpoints in a pool.
- Round-robin or least-loaded dispatch.
- Health checks remove unhealthy instances from rotation.
- Documentation: when to scale Ollama horizontally, sizing per node.

**Estimated effort:** 1 sprint

---

## Epic: eval-harness

LLM evaluation infrastructure. Single epic, single primary issue.

### Held-out eval datasets and CLI eval harness

**Labels:** `epic:eval-harness`, `area:llm`, `priority:high`, `type:feature`

**Summary**
LLM enrichment quality cannot be assessed without held-out datasets and an eval harness. Build the harness in Phase 2 to enable provider/model comparison.

**Acceptance criteria**
- Eval datasets in four categories: `confirmed_yours` (target attribution should be confirmed/high), `confirmed_not_yours` (target attribution should be not_yours), `ambiguous_with_resolution` (rules give medium confidence; LLM should sanity-check), `adversarial_injection` (cert SAN, banner, TXT contain prompt-injection-style payloads).
- Initial dataset size: a few dozen of each category. Grows over time from analyst-flagged real cases.
- CLI: `expose eval run --provider <p> --model <m> --dataset <d>`.
- Metrics: attribution accuracy, schema validation rate, sanitization integrity rate, cost per case, latency per case.
- Quarterly re-evaluation procedure documented.
- CI gate: changes to LLM enrichment logic re-run a fast subset of evals.

**Estimated effort:** 2-3 sprints (datasets are ongoing; harness itself is bounded).

---

## Epic: repo-governance

Decision 5 deferred items related to repository operations and governance.

### Trademark registration

**Labels:** `epic:repo-governance`, `area:legal`, `priority:low`, `type:legal`

**Summary**
"EXPOSE" trademark not registered. Apache 2.0 does not grant trademark rights, so forks may use the name. Defer until project visibility justifies the legal work.

**Acceptance criteria**
- Trademark search before registration.
- Registration in relevant jurisdictions (US first; EU/UK if international visibility warrants).
- Documentation in CONTRIBUTING.md and TRADEMARK.md if registration completes.

**Estimated effort:** 1-2 weeks legal work + filing fees, when triggered.

**Triggers:** External adoption produces forks with the EXPOSE name; commercial competitors use the name.

### CLA vs. DCO contributor model

**Labels:** `epic:repo-governance`, `area:legal`, `priority:medium`, `type:decision`

**Summary**
v1 starts with DCO (Developer Certificate of Origin sign-off via `Signed-off-by:`). DCO is lighter weight than CLA, doesn't require contributors to sign agreements, but provides less commercial protection than a CLA. Revisit when commercial pressure or significant external contributions emerge.

**Acceptance criteria**
- DCO enforced via DCO bot from v1.
- Documented in CONTRIBUTING.md.
- Decision to switch to CLA (if ever) is a deliberate decision with rationale documented in this issue.

**Estimated effort:** Few hours for DCO setup; CLA migration is significant if undertaken.

### SECURITY.md with disclosure policy and SLA

**Labels:** `epic:repo-governance`, `area:security`, `priority:high`, `type:documentation`

**Summary**
Security disclosure policy needs to be documented before public visibility grows. Time-bound disclosure SLA, communication channels, severity classification.

**Acceptance criteria**
- SECURITY.md covering: how to report vulnerabilities (private GitHub Security Advisory or `security@`), expected response time (acknowledgment within 72 hours, triage within 7 days, fix or mitigation within 90 days for high-severity), severity classification, coordinated disclosure approach.
- Bug bounty: explicitly out of scope for v1; revisit when warranted.
- Public CVE process documented.

**Estimated effort:** 1 day for initial document; ongoing maintenance.

### Example rule pack library

**Labels:** `epic:repo-governance`, `area:documentation`, `priority:medium`, `type:feature`

**Summary**
v1 ships with one example rule pack (`example-baseline.json`). Library of additional examples helps adoption.

**Acceptance criteria**
- Example packs covering common scenarios: `aws-public-cloud-baseline`, `multi-cloud-enterprise`, `consulting-engagement-template`, `government-municipal`.
- Each pack has its own README explaining the scenario it targets and the design choices.
- Example packs are tested via integration tests using synthetic seed data.

**Estimated effort:** 1 sprint for initial library; ongoing as patterns emerge.

### Code of Conduct enforcement procedures

**Labels:** `epic:repo-governance`, `area:community`, `priority:medium`, `type:documentation`

**Summary**
CODE_OF_CONDUCT.md (Contributor Covenant 2.1) is in v1. Need clear enforcement procedures: who handles reports, escalation path, enforcement actions, transparency.

**Acceptance criteria**
- CoC enforcement procedure documented in CODE_OF_CONDUCT.md or separate ENFORCEMENT.md.
- Reporting channel (`conduct@`) with response SLA.
- Enforcement ladder: warning → temporary ban → permanent ban.
- Transparency report cadence (annual summary of CoC actions).

**Estimated effort:** 1 day for initial procedures; ongoing as community grows.

---

## Epic: multi-tenancy

Decision 6 deferred multi-tenancy features beyond the v1 baseline (logical tenant scoping with single `default` tenant).

### Tenant lifecycle API

**Labels:** `epic:multi-tenancy`, `area:api`, `priority:high`, `type:feature`

**Summary**
v1 has a hardcoded `default` tenant. Multi-tenant deployments need create, configure, suspend, delete operations.

**Acceptance criteria**
- Admin API endpoints: `POST /v1/tenants`, `GET /v1/tenants/{tenant_id}`, `PATCH /v1/tenants/{tenant_id}`, `DELETE /v1/tenants/{tenant_id}`, `POST /v1/tenants/{tenant_id}/suspend`, `POST /v1/tenants/{tenant_id}/resume`.
- Tenant suspension halts scheduled runs, preserves data.
- Tenant deletion is two-step (mark for deletion → grace period → final deletion) with audit log of every action.
- Bulk operations supported (list with pagination, batch suspend).

**Estimated effort:** 1-2 sprints.

### Per-tenant resource quotas and prioritized scheduling

**Labels:** `epic:multi-tenancy`, `area:scheduling`, `priority:high`, `type:feature`

**Summary**
v1 has logical isolation only — tenant A's run can starve tenant B for compute. Multi-tenant deployments need physical isolation: per-tenant quotas, prioritized scheduling.

**Acceptance criteria**
- Tenant config supports: max concurrent runs, max collector API calls per minute (across all collectors), max LLM tokens per run, max storage bytes.
- Scheduler enforces quotas at dispatch time.
- Priority levels (low, normal, high) allow some tenants to bypass others in queue.
- Quota events surfaced to artifact via `tenant_quota_warnings`.

**Estimated effort:** 2 sprints.

### Per-tenant collector and LLM credentials

**Labels:** `epic:multi-tenancy`, `area:security`, `priority:high`, `type:feature`

**Summary**
v1 has deployment-global collector credentials shared across all tenants. Multi-tenant deployments need per-tenant credentials so customers can use their own API keys.

**Acceptance criteria**
- Tenant config supports: per-collector secret reference (resolved against the secrets backend), per-LLM-provider secret reference.
- Credentials fetched just-in-time per call with tenant context.
- Audit log of credential access tagged with tenant_id.
- Cross-tenant credential leakage tests in CI.

**Estimated effort:** 1-2 sprints.

### GDPR/CCPA tenant data export and deletion

**Labels:** `epic:multi-tenancy`, `area:compliance`, `priority:medium`, `type:compliance`

**Summary**
Multi-tenant deployments handling EU/CA-resident data need data subject request handling: export of all tenant data, deletion on request.

**Acceptance criteria**
- Tenant data export: full graph dump, all artifacts, audit log entries (excluding ones marked for separate retention).
- Tenant data deletion: tenant config, graph data, artifacts, evidence — with safeguards against accidental deletion.
- Deletion within 30 days of request (configurable).
- PII inventory: admin can list all PII references in tenant data.
- Audit log records data subject request handling.

**Estimated effort:** 2 sprints.

### Tenant-aware observability dashboards

**Labels:** `epic:multi-tenancy`, `area:observability`, `priority:medium`, `type:feature`

**Summary**
Observability dashboards need to be tenant-scoped or aggregated by tenant. Operators viewing tenant A's dashboard should not see tenant B's data unless they have multi-tenant operator role.

**Acceptance criteria**
- Per-tenant Grafana dashboards (parameterized by tenant_id).
- Aggregate dashboards for operators (tenant counts, total runs, total LLM spend).
- Audit log dashboards distinguish tenant operations.
- Alert rules: per-tenant SLO violations, per-tenant cost ceiling breaches.

**Estimated effort:** 1 sprint.

### Cross-tenant isolation testing — v1 deliverable

**Labels:** `epic:multi-tenancy`, `area:testing`, `priority:high`, `type:testing`, `v1`

**Summary**
v1 ships with a cross-tenant isolation test suite even though only one tenant is configured by default. Tests prevent regressions as the codebase evolves.

**Acceptance criteria**
- Test suite exercises synthetic tenant_ids, verifies that:
  - Tenant A cannot read tenant B's artifacts via any API endpoint.
  - Tenant A's runs cannot reference tenant B's seeds, rules, or graph data.
  - Bearer tokens (when added) are tenant-scoped.
  - Database queries always scope by tenant_id.
  - Caching layer keys include tenant_id.
  - Background jobs preserve tenant context across async boundaries.
  - Audit logs from tenant A operations are not visible to tenant B admin.
- Tests run on every PR, fail-fast on isolation breaches.

**Estimated effort:** 1 sprint within Phase 1.

---

## Epic: authorized-use

Decision 7 deferred authorization-scope refinements and ethics-related work.

### Hard authorization-scope enforcement mode

**Labels:** `epic:authorized-use`, `area:scope`, `priority:medium`, `type:feature`

**Summary**
v1 default is medium mode (warn, no block). Hard mode is in the framework but full implementation needs polish for stricter deployments.

**Acceptance criteria**
- `tenant.authorization_scope.enforcement_mode: hard` fully respected by collection and attribution.
- Active probing refuses to execute against any asset not in `confirmed`/`high` tier or explicitly in scope.
- Passive collection remains broad.
- Refusal events emit structured logs.
- Artifact manifest records hard-mode refusal count.
- Test coverage for hard-mode refusals.
- Documentation: when to use hard mode, scope-contract integration.

**Estimated effort:** 1 sprint.

### Authorization scope schema evolution

**Labels:** `epic:authorized-use`, `area:scope`, `priority:medium`, `type:design`

**Summary**
v1 scope is flat lists. Future scope schema needs time bounds, asset-type restrictions, scope inheritance.

**Acceptance criteria**
- Schema evolution: time bounds (`valid_from`, `valid_until` per scope entry), asset-type restrictions, exclusions, scope inheritance from parent tenants.
- Schema versioned and audit-logged.
- Validation tooling: `expose scope validate <file>`.
- Visualization: `expose scope show --tenant <id>`.
- Backward-compatible evolution from v1 flat-list form.

**Estimated effort:** 1-2 sprints.

### Incidental data graph retention pruning — v1 deliverable

**Labels:** `epic:authorized-use`, `area:data`, `priority:high`, `type:feature`, `v1`

**Summary**
v1 default 30-day retention for non-yours observations. Pruning is implemented as scheduled job in v1.

**Acceptance criteria**
- Daily pruning job removes graph entries with `attribution_status: not_yours` and `last_observed_at` older than retention window.
- Re-observation extends retention.
- Tenant-scoped retention policy.
- Pruning never deletes entries currently referenced by active attribution decisions.
- Pruning never deletes entries that produced an artifact within audit retention.
- Audit log records pruning batches.
- Idempotent and safe to re-run.

**Estimated effort:** 1 sprint within Phase 1.

### PII handling in registrant and contact data

**Labels:** `epic:authorized-use`, `area:compliance`, `priority:medium`, `type:compliance`

**Summary**
WHOIS, certificate registration data contains PII. Even though publicly disclosed, deliberate handling needed.

**Acceptance criteria**
- Schema documentation labels PII fields.
- Per-tenant config: `tenant.pii_handling.include_in_artifact` controls whether PII fields appear in artifacts.
- Redaction option: PII fields replaced with hashed tokens for correlation.
- Audit logs containing PII tagged for separate retention.
- PII inventory API for data subject requests.

**Estimated effort:** 1-2 sprints.

### Misuse-detection patterns

**Labels:** `epic:authorized-use`, `area:security`, `priority:low`, `type:design`

**Summary**
Public Apache 2.0 release means misuse is possible. Engine should include warning patterns making obvious misuse easier to detect.

**Acceptance criteria**
- Warning patterns: tenant authorization scope appears to target a large organization the operator likely doesn't own; unusual attribution rates; frequent target-hopping.
- Warnings to operator audit log only (not to tenant).
- Documentation: how operators monitor for misuse.

**Estimated effort:** 1 sprint.

### ETHICS.md and intended-use documentation maintenance — v1 deliverable

**Labels:** `epic:authorized-use`, `area:documentation`, `priority:high`, `type:documentation`, `v1`

**Summary**
ETHICS.md is a v1 deliverable. Maintenance cadence and review process documented for ongoing updates.

**Acceptance criteria**
- Initial ETHICS.md covering: intended use, non-goals, capability disclosure, adversary-controlled-input acknowledgment, downstream workflow boundary.
- README intended-use section linking to ETHICS.md.
- SECURITY.md aligned with ETHICS.md.
- Quarterly review cadence documented.
- Process for updating in response to capability changes or external guidance.

**Estimated effort:** 1 day for initial document; ongoing minor.

---

## Cross-epic priority summary

**v1 deliverables (must ship in Phase 1):**
- Multi-arch image builds (deployment-portability)
- Cross-tenant isolation testing (multi-tenancy)
- Incidental data graph retention pruning (authorized-use)
- ETHICS.md initial document (authorized-use)

**Phase 1 critical path beyond v1 deliverables:**
- Active scanner egress profile abstraction (deployment-portability)
- Postgres production deployment documentation (deployment-portability)
- Container image signing and SBOM publication (deployment-portability)

**Phase 2 priorities (LLM enrichment phase):**
- Held-out eval datasets and CLI eval harness (eval-harness)
- Tie-breaker escalation policy (llm-quality)
- GPU upgrade path documentation (llm-quality)

**Phase 3 priorities (production hardening):**
- Cloud object storage migration (production-hardening)
- Authenticated HTTPS API (production-hardening)
- Tenant lifecycle API (multi-tenancy)
- Per-tenant resource quotas (multi-tenancy)
- Per-tenant credentials (multi-tenancy)

**Ongoing / community-driven:**
- Code of Conduct enforcement procedures (repo-governance)
- Example rule pack library (repo-governance)
- Misuse-detection patterns (authorized-use)
- Ollama instance pool (llm-quality)
- Bundled observability subchart (deployment-portability)
- Trademark registration (repo-governance)

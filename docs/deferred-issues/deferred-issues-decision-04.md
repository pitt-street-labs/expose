# Deferred issues — Decision 4 (output artifact and delivery)

These issues capture the production-grade delivery and storage concerns that
were intentionally deferred from v1 lab deployment on ARC. They will become
relevant when the system moves to a customer-facing or production posture.

Filed against the `production-hardening` epic.

---

## Issue: Production object storage migration (ARC MinIO → cloud-hosted S3-compatible)

**Labels:** `epic:production-hardening`, `area:storage`, `priority:high`, `type:infrastructure`

**Summary**
v1 stores canonical JSON files, signatures, and manifests in MinIO on ARC. For
production deployment, migrate to a cloud-hosted S3-compatible bucket (AWS S3
preferred) with proper lifecycle policies, replication, and access controls.

**Acceptance criteria**
- Object store backend is configurable via Helm values; MinIO and S3 both supported
- AWS S3 bucket provisioned with: versioning enabled, server-side encryption (SSE-KMS
  with customer-managed keys), bucket policy denying any non-TLS access, MFA-delete
  on the lifecycle configuration, lifecycle rules transitioning runs older than 90
  days to Glacier Instant Retrieval and older than 1 year to Glacier Deep Archive
- Cross-region replication to a second bucket for disaster recovery
- Access logs enabled, written to a separate logging bucket with restricted access
- Migration runbook for moving existing ARC MinIO content to cloud bucket without
  signature invalidation
- Terraform module for the bucket provisioning, parameterized for AWS/Azure/GCP

**Out of scope**
On-prem customer deployment with their own object store (separate issue).

**Dependencies**
None. Trigger when first non-lab deployment is committed.

**Estimated effort:** 1 sprint

---

## Issue: Authenticated HTTPS delivery API with bearer token auth

**Labels:** `epic:production-hardening`, `area:api`, `priority:high`, `type:feature`

**Summary**
v1 produces canonical JSON files and stores them in object storage. Production
deployment needs an authenticated HTTPS API exposing the canonical files and
metadata to consumers (CTEM tools, red team operators, downstream automation).

**Acceptance criteria**
- API surface as specified in Decision 4c:
  - `GET /runs/latest`
  - `GET /runs/{run_id}`
  - `GET /runs/{run_id}/canonical`
  - `GET /runs/{run_id}/canonical.sig`
  - `GET /runs/{run_id}/manifest`
  - `GET /runs/{run_id}/diff`
  - `GET /runs`
- Bearer token authentication, tokens scoped per consumer
- Tokens issued with read-only access to a specific tenant's runs
- Token issuance, rotation, and revocation via admin API
- Audit logging: every consumer pull logged with consumer ID, run ID, response
  size, latency, source IP
- Rate limiting per token (default 60 req/min, configurable)
- Streaming response support for large canonical files
- Range request support for resumable downloads
- OpenAPI 3.x spec for the API, generated from code
- Reference client libraries: Python and Bash one-liner

**Dependencies**
- Multi-tenancy decision (Decision 8) determines token scoping model
- Secrets backend abstraction (filed under deployment-portability epic)

**Estimated effort:** 2 sprints

---

## Issue: Read-only object store credential delivery (secondary delivery pattern)

**Labels:** `epic:production-hardening`, `area:api`, `priority:medium`, `type:feature`

**Summary**
For consumers who prefer object-store integration over HTTPS API consumption,
provide read-only scoped credentials to a path within the production bucket.

**Acceptance criteria**
- Credential provisioning via admin API, scoped to a tenant's run prefix
- Time-bound credentials (default 24 hours, configurable up to 30 days)
- Bucket policy enforces read-only access to the scoped path
- Credentials issued via STS-style temporary credentials, not long-lived IAM users
- Audit logging of credential issuance and bucket access via the credentials
- Documentation: which delivery pattern is appropriate for which consumer profile

**Dependencies**
Production object storage migration (above).

**Estimated effort:** 1 sprint

---

## Issue: Run retention policy and historical query

**Labels:** `epic:production-hardening`, `area:storage`, `priority:medium`, `type:design`

**Summary**
Production deployments will accumulate runs indefinitely. Need explicit retention
policy, archival to cold storage, and the ability to query historical runs
without rehydrating the full canonical file.

**Acceptance criteria**
- Retention policy configurable per tenant: default 1 year hot, 7 years cold,
  delete after that (overridable for compliance use cases)
- Lightweight historical index in Postgres: target identifier → list of runs
  in which the target appeared, with attribution tier, lead score, and pointer
  to the run's canonical file
- Index allows queries like "show me every run in which target X.example.com
  appeared with tier ≥ HIGH" without loading any canonical files
- Cold-storage runs are still verifiable (signatures preserved, retrieval is
  slower but works)
- Documentation: retention policy choice rationale, GDPR-style data subject
  request handling for runs containing personal data (registrants, contacts)

**Dependencies**
Production object storage migration.

**Estimated effort:** 1-2 sprints

---

## Issue: Lab-to-production deployment runbook

**Labels:** `epic:production-hardening`, `area:operations`, `priority:medium`, `type:documentation`

**Summary**
Document the complete process for migrating from ARC lab deployment to a
production cloud deployment, including data migration, signature continuity,
DNS cutover, and consumer notification.

**Acceptance criteria**
- Runbook covering: snapshot lab Postgres, migrate to cloud-managed Postgres,
  migrate MinIO contents to cloud bucket, validate signatures preserved,
  redeploy with production Helm values, cut over DNS for HTTPS API
- Rollback procedure for each step
- Communication template for consumers (new endpoint, new credentials, schedule)
- Verification checklist confirming production deployment matches lab feature
  parity

**Estimated effort:** 1 sprint

---

## Tracking summary

| Issue | Priority | Effort | Trigger |
|---|---|---|---|
| Production object storage migration | High | 1 sprint | First non-lab deployment commit |
| Authenticated HTTPS delivery API | High | 2 sprints | Concurrent with object storage migration |
| Read-only object store credentials | Medium | 1 sprint | After HTTPS API exists, on consumer demand |
| Run retention policy | Medium | 1-2 sprints | Within 6 months of production deployment |
| Lab-to-production runbook | Medium | 1 sprint | Concurrent with object storage migration |

All five are deferred to the production-hardening epic. None blocks v1 lab
deployment. The HTTPS API and object storage migration are tightly coupled and
should be planned together.

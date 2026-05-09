# Deferred issues — Decision 6 (multi-tenancy)

These issues capture multi-tenancy concerns that are deferred from v1 logical
multi-tenancy. v1 ships with `tenant_id` baked into the data layer and API
contracts but with only a single `default` tenant configured. These issues
activate physical isolation, tenant lifecycle management, and the
operator-facing tenancy surface.

Filed against the `multi-tenancy` epic.

---

## Issue: Tenant lifecycle management API and admin tooling

**Labels:** `epic:multi-tenancy`, `area:api`, `priority:high`, `type:feature`

**Summary**
v1 hardcodes a single `default` tenant. Production multi-tenant deployments
need APIs and CLI tooling to create, configure, suspend, and delete tenants.

**Acceptance criteria**
- Admin API endpoints (separate auth from tenant-scoped APIs):
  - `POST /admin/tenants` — create tenant with initial configuration
  - `GET /admin/tenants` — list all tenants
  - `GET /admin/tenants/{id}` — tenant details
  - `PATCH /admin/tenants/{id}` — update tenant configuration
  - `POST /admin/tenants/{id}/suspend` — suspend tenant (no new runs, existing
    artifacts remain accessible)
  - `POST /admin/tenants/{id}/resume` — resume suspended tenant
  - `DELETE /admin/tenants/{id}` — schedule tenant deletion (soft delete with
    retention period, then hard delete)
- CLI tooling: `fatfinger6000 tenant create|list|show|update|suspend|delete`
- Admin authentication separate from tenant bearer tokens (deployment-level
  admin credentials, not tenant-issued)
- Audit log entries for every tenant lifecycle event
- Tenant deletion includes cascade behavior: artifacts archived to
  long-term storage with deletion-pending tag, then permanently removed
  after retention period (default 90 days, configurable)
- Tenant configuration schema versioned with migration support

**Dependencies**
- Authenticated HTTPS delivery API (production-hardening epic)
- Production object storage migration (production-hardening epic)

**Estimated effort:** 2 sprints

---

## Issue: Per-tenant resource quotas and isolation

**Labels:** `epic:multi-tenancy`, `area:performance`, `priority:medium`, `type:design`

**Summary**
v1 multi-tenancy is logical only. Tenant A's run can starve tenant B's run for
compute, LLM tokens, collector API quota, or storage. Production deployments
serving multiple paying tenants need enforced quotas.

**Acceptance criteria**
- Per-tenant configuration of:
  - Maximum candidate count per run
  - Maximum LLM tokens per run (across all providers)
  - Maximum LLM spend per run (USD ceiling)
  - Maximum collector API calls per provider per day
  - Maximum storage bytes for artifacts (with archival policy)
  - Maximum concurrent runs (default 1)
- Quota enforcement at the appropriate layer — pre-flight checks before
  starting a run, in-flight monitoring with graceful degradation when limits
  approach, hard stops when limits hit
- Quota usage telemetry exposed via admin API and observability stack
- Quota exceeded events surface to the tenant in their next artifact's
  manifest (`tenant_quota_warnings: [...]`)
- Per-tenant priority levels for compute scheduling when contention exists
- Documentation: how to size quotas for typical tenant profiles

**Dependencies**
Tenant lifecycle management (above).

**Estimated effort:** 2 sprints

---

## Issue: Tenant-scoped collector credentials and API key isolation

**Labels:** `epic:multi-tenancy`, `area:security`, `priority:high`, `type:security`

**Summary**
v1 collector API keys are deployment-global (Censys key, Shodan key, etc.
shared across all tenants). In production multi-tenancy, some tenants will
provide their own credentials; others will share pooled credentials with
appropriate billing attribution.

**Acceptance criteria**
- Per-tenant API key configuration: tenant can provide their own keys for
  any collector source
- Credential resolution order: tenant-provided → tenant-pool → deployment-default
- Collector pool: a deployment can provision a pool of credentials for a
  given source (e.g., 10 Shodan keys), distributed across tenants who
  haven't provided their own, with rate-limit-aware distribution
- Per-tenant usage attribution: tenant's runs only consume from their own
  credentials or from credentials they have access to
- Audit logging: every external API call logged with tenant ID, credential
  source, request shape (no response payloads in logs)
- Documentation: tenant credential onboarding flow, credential rotation,
  emergency revocation procedure

**Dependencies**
- Secrets backend abstraction (deployment-portability epic)
- Tenant lifecycle management (above)

**Estimated effort:** 2 sprints

---

## Issue: Tenant data export and deletion (GDPR / data subject rights)

**Labels:** `epic:multi-tenancy`, `area:compliance`, `priority:medium`, `type:compliance`

**Summary**
Multi-tenant deployments will encounter data subject requests under GDPR,
CCPA, and similar regimes. Some tenant data may include personal information
(registrant contacts, email addresses in WHOIS, etc.). Need a clean process
for export and deletion.

**Acceptance criteria**
- Per-tenant export: complete dump of all artifacts, run metadata, audit logs,
  configuration, in a portable format (zipped JSON archive)
- Per-tenant deletion: cascade across all storage including object storage,
  database, audit logs (with retention exceptions for legally-required
  records), backups (acknowledge that backup deletion is delayed)
- Within-tenant data subject requests: identify all references to a specific
  email/registrant/contact across the tenant's data, support redaction or
  deletion
- Documented retention policy per tenant, configurable
- Compliance audit trail: every export/deletion request logged with operator,
  timestamp, scope, completion confirmation

**Dependencies**
- Tenant lifecycle management (above)
- Run retention policy (production-hardening epic)

**Estimated effort:** 2-3 sprints

---

## Issue: Tenant-aware observability and dashboards

**Labels:** `epic:multi-tenancy`, `area:observability`, `priority:medium`, `type:infrastructure`

**Summary**
Operations team needs per-tenant visibility into pipeline health: which
tenant's runs are succeeding/failing, which are exceeding quotas, which are
generating concerning data patterns. Default observability should not leak
tenant data across tenants in dashboards or alerts.

**Acceptance criteria**
- All telemetry tagged with `tenant_id` label
- Pre-built Grafana dashboards: per-tenant run health, per-tenant quota
  usage, per-tenant attribution accuracy trends, per-tenant LLM costs
- Tenant-scoped views: tenant-facing dashboards show only their own data
  (relevant if customers ever get direct dashboard access)
- Operator-scoped views: cross-tenant aggregate dashboards for operations
  team
- Alert routing: per-tenant alerts go to tenant contacts (when configured)
  and operations team; cross-tenant patterns go to operations only
- No tenant data in operator-facing alerts unless explicitly authorized
  (alert says "tenant <id> exceeded quota," not "tenant <id> exceeded quota
  while scanning <specific assets>")

**Dependencies**
- Optional bundled observability stack (deployment-portability epic)
- Tenant lifecycle management (above)

**Estimated effort:** 1-2 sprints

---

## Issue: Cross-tenant data leakage testing in CI

**Labels:** `epic:multi-tenancy`, `area:security`, `priority:high`, `type:security`

**Summary**
Multi-tenant systems leak cross-tenant data via bugs in middleware, query
construction, or caching. Need explicit test coverage that exercises
tenant-boundary enforcement and fails CI on regression.

**Acceptance criteria**
- Test suite: `test_tenant_isolation.py` (or equivalent) with tests covering:
  - Tenant A cannot read tenant B's artifacts via API (every endpoint)
  - Tenant A's runs cannot reference tenant B's seeds, rules, or graph data
  - Bearer tokens scoped to tenant A return 403 for tenant B resources
  - Database query construction always scopes by tenant_id (verified via
    query interception in test mode)
  - Caching layer keys include tenant_id (no cache bleed)
  - Background jobs preserve tenant context across async boundaries
  - Audit logs from tenant A operations are not visible to tenant B admin
- CI gate: any failure in tenant isolation tests blocks merge regardless of
  PR scope
- Periodic red-team-style review of tenant boundaries (quarterly)

**v1 status:** This test suite goes in v1 codebase even though only the
default tenant exists, so the boundary enforcement is verified continuously
as code evolves. Tests can run against synthetic tenant_ids without
requiring multi-tenant deployment.

**Estimated effort:** 1 sprint for initial suite, ongoing maintenance

---

## Tracking summary

| Issue | Priority | Effort | Trigger |
|---|---|---|---|
| Tenant lifecycle management API | High | 2 sprints | Before second tenant is created |
| Per-tenant resource quotas | Medium | 2 sprints | After 3+ tenants exist |
| Tenant-scoped collector credentials | High | 2 sprints | First tenant providing own keys |
| Tenant data export and deletion | Medium | 2-3 sprints | First GDPR/CCPA request, or proactive |
| Tenant-aware observability | Medium | 1-2 sprints | Concurrent with tenant lifecycle |
| Cross-tenant isolation testing | High | 1 sprint (v1 + ongoing) | v1 codebase |

One issue (cross-tenant isolation testing) goes into the v1 codebase. Even
with only a default tenant, the test suite verifies tenant boundaries are
enforced as code evolves — preventing regression at the moment a second tenant
is added.

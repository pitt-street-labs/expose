# ADR-007: Multi-tenancy

**Status:** Accepted
**Date:** 2026-05-09
**Decision-makers:** Korlogos / Pitt Street Labs

## Context

FatFinger6000's v1 deployment is lab-only on ARC, serving a single org's surface (Korlogos's own perimeter and active client engagements). Multi-tenancy is not strictly required for v1 to ship.

The question is whether the codebase should be designed with multi-tenancy as a first-class concept (so it can be activated later via configuration) or designed single-tenant and refactored when needed.

This decision is shaped by two factors:

- The project will be public Apache 2.0 (per Decision 5). External operators will deploy it; some will want to run it for multiple orgs they consult for.
- The Korlogos roadmap likely includes serving multiple client engagements through a single deployment as the practice scales.

## Decision

**Multi-tenant from day one in code, single-tenant in v1 deployment.**

Concretely:

- Every relevant database table carries `tenant_id UUID NOT NULL` with foreign key to a `tenants` table.
- v1 ships with a single `default` tenant configured at deployment time.
- All v1 queries are scoped to that tenant via middleware that injects tenant context into every query.
- API contracts (admin API, future delivery API in production-hardening) are tenant-scoped from day one.
- Per-tenant configuration: enabled collectors, API keys (production-hardening), rule pack, LLM provider, authorization scope, retention policies.
- Artifact paths include tenant ID: `runs/{tenant_id}/{run_id}/canonical.json.gz`.

Resource isolation between tenants is **logical only** in v1 — tenant A's run can starve tenant B's run for compute, LLM tokens, collector API quota. Physical isolation (per-tenant resource quotas, prioritized scheduling) is deferred to production-hardening.

Cross-tenant isolation testing ships in v1 codebase. Test suite exercises synthetic tenant_ids verifying that:

- Tenant A cannot read tenant B's artifacts via any API endpoint.
- Tenant A's runs cannot reference tenant B's seeds, rules, or graph data.
- Bearer tokens (when production-hardening adds them) are tenant-scoped.
- Database query construction always scopes by tenant_id.
- Caching layer keys include tenant_id.
- Background jobs preserve tenant context across async boundaries.
- Audit logs from tenant A operations are not visible to tenant B admin.

CI fails on regressions in tenant isolation tests regardless of PR scope.

## Consequences

**Positive:**

- Activating multi-tenancy is a configuration change, not a refactor.
- External operators using FatFinger6000 for consulting work can serve multiple clients without forking.
- The data layer's tenant scoping is enforced from day one; no risk of "we'll add tenant_id later" creating gaps.
- Cross-tenant isolation tests prevent regressions even before a second tenant exists.
- The marginal complexity is small — `WHERE tenant_id = $1` in queries and a tenant context in request handlers — compared to the design and ops complexity already committed elsewhere.

**Negative:**

- Slightly more code complexity in the data layer and auth middleware.
- The `tenant_id` parameter threading through application code is omnipresent; new contributors must learn it.
- Tenant lifecycle management (create, configure, suspend, delete) is deferred but its absence in v1 means the single `default` tenant is hardcoded. This is a small operational papercut.

## Alternatives considered

**Single-tenant for v1, multi-tenant on the roadmap.** Database schemas don't carry tenant IDs; code assumes a single org. Rejected because retrofit cost is real (weeks of refactoring across the codebase) and the marginal v1 cost of building tenancy is small.

**Single-tenant forever, with operator running multiple deployments.** Each tenant gets their own deployment. Rejected because operational tax is real (N copies of the system to maintain, monitor, upgrade) and the multi-tenant code model is genuinely cheap.

**Internal-only, no tenancy concept.** Functionally identical to single-tenant. Rejected for the same reason as above.

## When to revisit

Multi-tenancy logical-only is the right v1 stance. Triggers for evolving:

- **Second tenant configured.** Tenant lifecycle management API becomes immediately useful. Filed as production-hardening.
- **3+ tenants with contention.** Per-tenant resource quotas become necessary. Filed as production-hardening.
- **First tenant providing own collector credentials.** Per-tenant credential isolation becomes necessary. Filed as production-hardening.
- **First GDPR/CCPA data subject request.** Tenant data export and deletion become necessary. Filed as production-hardening.

These are foreseeable and tracked. None blocks v1 launch.

## References

- Decision recorded in design conversation 2026-05-09.
- Six deferred-issues in the multi-tenancy epic. See `docs/issues-backlog.md`.
- Cross-tenant isolation test suite is a v1 deliverable.

# Deferred issues — Decision 7 (authorized use, ethics, operational scope)

These issues capture authorization-scope, incidental-data-handling, and
ethics-posture concerns that are deferred from v1 baseline implementation.
v1 ships with the medium authorization-scope option as default, basic
incidental data filtering, and the project ethics documentation in place.
These issues activate stricter enforcement modes, richer scope tooling, and
compliance-grade data handling.

Filed against the `authorized-use` epic.

---

## Issue: Hard authorization-scope enforcement mode

**Labels:** `epic:authorized-use`, `area:scope`, `priority:medium`, `type:feature`

**Summary**
v1 default is the medium option: warnings on out-of-scope collection, no
blocking. The hard option is available per-tenant via configuration but
needs full implementation, testing, and documentation before it can be
relied on for stricter deployments (regulated industries, customer
engagements with explicit scope contracts).

**Acceptance criteria**
- `tenant.authorization_scope.enforcement: hard` configuration value
  fully respected by all collection and attribution paths
- Active probing (DNS resolution, TLS handshake, HTTP fingerprint, port
  scan) refuses to execute against any asset not in `confirmed` or `high`
  attribution tier OR not explicitly listed in tenant authorization scope
- Passive collection (CT logs, passive DNS, ASN data) remains broad — the
  hard option scopes only active collection, not observation
- Refusal events emit structured logs with: tenant ID, refused asset
  identifier, refusal reason, suggested remediation
- Artifact manifest records hard-mode refusal count per run
- Test coverage: tenant configured for hard mode cannot perform active
  probing against any asset outside scope, even if attribution rules would
  otherwise promote it
- Documentation: when hard mode is appropriate, how to configure scope to
  match a customer engagement contract, escalation procedure for legitimate
  out-of-scope discoveries

**Triggers**
- First customer engagement with explicit scope contract requiring
  enforcement
- First regulated-industry deployment

**Estimated effort:** 1 sprint

**v1 status:** The configuration value should be parseable and the
enforcement points should be coded as guard hooks even if v1 only
implements warnings. This way activating hard mode later is a configuration
change, not a code change.

---

## Issue: Authorization scope schema and rule pack integration

**Labels:** `epic:authorized-use`, `area:scope`, `priority:medium`, `type:design`

**Summary**
Authorization scope in v1 is a flat list of apex domains, cloud account
IDs, and registrant identities per tenant. This is sufficient for simple
cases but does not handle nuanced scenarios like time-bounded engagements,
asset-type-specific scope, or scope inheritance across affiliated tenants.

**Acceptance criteria**
- Formal `authorization_scope.yaml` schema:
  - Apex domains (with optional subdomain inclusion/exclusion)
  - Cloud accounts (AWS account IDs, Azure subscriptions, GCP projects)
  - Registrant identities (organization names, email patterns)
  - ASN ranges
  - Time bounds (`valid_from`, `valid_until` per scope entry)
  - Asset-type restrictions (e.g., scope covers DNS but not HTTP probing)
  - Exclusions (explicit "this is not in scope even if rules would attribute it")
- Scope changes are versioned and audit-logged
- Each artifact records which scope version was in effect during the run
- Validation tooling: `fatfinger6000 scope validate <file>` checks consistency
- Visualization: `fatfinger6000 scope show --tenant <id>` emits a human-readable
  summary
- Rule pack integration: rule packs can declare which scope dimensions they
  rely on; scope mismatches produce loud warnings

**Estimated effort:** 1-2 sprints

**v1 status:** v1 implements the simple form (flat lists). Schema evolution
to the full form is a backward-compatible expansion.

---

## Issue: Incidental data graph retention and pruning

**Labels:** `epic:authorized-use`, `area:data`, `priority:high`, `type:feature`

**Summary**
v1 defaults to 30-day retention for non-yours observations in the graph.
Pruning needs to be implemented as a scheduled job with safe behavior under
edge cases (re-observation, in-flight attribution decisions, audit
requirements).

**Acceptance criteria**
- Daily pruning job removes graph entries with `attribution_status: not_yours`
  and `last_observed_at` older than retention window
- Re-observation extends retention: an entry observed in today's run resets
  the retention timer
- Pruning is tenant-scoped: each tenant has independent retention policy
- Pruning never deletes entries currently referenced by an active or recent
  attribution decision
- Pruning never deletes entries that produced an artifact within the audit
  retention window (even if attribution status is now `not_yours`)
- Audit log records pruning batches: tenant, count of entries pruned,
  oldest and newest pruned entry timestamps (no entry IDs in audit log)
- Pruning is idempotent and safe to re-run
- Configuration: `tenant.data_retention.incidental_days` (default 30)

**Estimated effort:** 1 sprint

**v1 status:** Implement the pruning job in v1 with the default 30-day
window. Configurable retention per tenant deferred until tenant lifecycle
management exists.

---

## Issue: PII handling in registrant and contact data

**Labels:** `epic:authorized-use`, `area:compliance`, `priority:medium`, `type:compliance`

**Summary**
WHOIS data, certificate registration, and similar public records contain
personal data — registrant emails, contact names, sometimes phone numbers.
Even though publicly disclosed, this data is still PII under GDPR/CCPA and
needs deliberate handling.

**Acceptance criteria**
- Schema defines which fields are PII-classified (registrant email, contact
  name, contact phone, etc.)
- PII fields in the JSON artifact are clearly labeled in the schema
  documentation
- Per-tenant configuration: `tenant.pii_handling.include_in_artifact`
  controls whether PII fields are emitted in artifacts (default: true,
  since the operator authorized the run)
- PII redaction option: per-tenant config can suppress PII fields from
  artifacts entirely (replace with hashed tokens for correlation), useful
  for tenants forwarding artifacts to lower-trust environments
- Audit log entries containing PII are tagged for separate retention
- Tenant-scoped PII inventory: admin API can list all PII references in a
  tenant's data for data subject request handling
- Documentation: GDPR/CCPA position statement, PII handling in artifacts,
  redaction option usage

**Dependencies**
Tenant data export and deletion (multi-tenancy epic).

**Estimated effort:** 1-2 sprints

---

## Issue: Misuse-detection patterns and rate-limit-based abuse signals

**Labels:** `epic:authorized-use`, `area:security`, `priority:low`, `type:design`

**Summary**
Public Apache 2.0 release means anyone can run FatFinger6000. Some will
run it with intent the project's posture documents say is unintended.
While the project cannot prevent misuse, the engine can include logging
patterns and warnings that make obvious-misuse cases easier to detect by
the operator running the deployment.

**Acceptance criteria**
- Warning patterns for likely-misuse:
  - Tenant authorization scope appears to target a specific large
    organization the operator likely doesn't own (heuristic: scope is
    primarily one large-brand apex with no plausible operator-org affinity)
  - Run produces unusual attribution rates (very high non-yours observation
    counts, suggesting broad scanning rather than focused attribution)
  - Tenant configuration changes frequently in patterns suggesting
    target-hopping
- Warnings emitted to operator audit log only (not to the tenant)
- Documentation: how operators monitor for misuse in their deployments,
  appropriate response procedures
- Explicit non-goal: the engine does not block any tenant based on these
  signals. It surfaces them for operator review.

**Estimated effort:** 1 sprint

**v1 status:** Out of scope for v1. Useful when the project has external
adoption.

---

## Issue: ETHICS.md and intended-use documentation maintenance

**Labels:** `epic:authorized-use`, `area:documentation`, `priority:high`, `type:documentation`

**Summary**
The ethics and intended-use documentation needs to be a maintained artifact,
not a one-time write. It evolves with project capability, threat landscape,
and adoption patterns.

**Acceptance criteria**
- Initial `ETHICS.md` covering:
  - Intended use (defensive CTEM, authorized red team support, own-perimeter
    mapping)
  - Non-goals (no active exploitation, no PII enrichment beyond public
    records, no adversarial use against third parties)
  - Capability disclosure (what the tool actually does, plainly stated)
  - Adversary-controlled input acknowledgment (sanitization is a security
    property, not just code quality)
  - Downstream workflow boundary (Mythos-class workflows are separate
    concerns; this codebase produces structured input for them)
- README intended-use section linking to ETHICS.md
- SECURITY.md aligned with ETHICS.md positioning
- Quarterly review cadence documented
- Process for updating in response to capability changes or external
  guidance (e.g., new framework like NIST AI RMF revisions, EU AI Act
  enforcement updates)

**v1 status:** Initial ETHICS.md is a v1 deliverable. Maintenance cadence
and review process are deferred.

**Estimated effort:** 1 day for initial document, ongoing minor

---

## Tracking summary

| Issue | Priority | Effort | Trigger |
|---|---|---|---|
| Hard authorization-scope enforcement | Medium | 1 sprint | First strict-scope customer engagement |
| Authorization scope schema evolution | Medium | 1-2 sprints | When flat-list form becomes limiting |
| Incidental data graph retention | High | 1 sprint | v1 codebase |
| PII handling in registrant data | Medium | 1-2 sprints | First GDPR/CCPA-conscious deployment |
| Misuse-detection patterns | Low | 1 sprint | After public adoption |
| ETHICS.md maintenance process | High | Ongoing | v1 deliverable |

Two are v1 deliverables (incidental data retention pruning, initial
ETHICS.md). The rest activate as the project grows beyond lab use.

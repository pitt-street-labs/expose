# EXPOSE Identity Surface -- Ethics Policy

This document defines the ethical boundaries for the EXPOSE Identity Surface
module. All contributors and operators MUST comply with these requirements.

## Scope Limitations

1. **Authorized targets only.** Identity Surface operations are restricted to
   entities explicitly authorized by the tenant's scope configuration. Cross-
   correlating registrant data outside the tenant's authorized perimeter is
   prohibited.

2. **Public data sources only.** The module processes WHOIS/RDAP data, public
   DNS records, and publicly available M&A filings. It MUST NOT ingest data
   obtained through unauthorized access, social engineering, or legally
   privileged channels.

3. **Organizational entities, not individuals.** Registrant pivots target
   organizational identities (companies, subsidiaries, holding companies).
   Correlation on individual persons (natural persons) is out of scope and
   prohibited unless the individual is acting in a registered organizational
   capacity (e.g., a sole proprietor listed as registrant org).

4. **No behavioral profiling.** The module correlates registration metadata. It
   does not track, profile, or infer the behavior, habits, or intentions of
   any person or organization.

## Prohibited Uses

1. **Stalking or harassment.** Using Identity Surface outputs to locate, track,
   or harass any individual is strictly prohibited.

2. **Competitive intelligence beyond attack-surface scope.** The module exists
   to map an organization's own external attack surface and that of its
   authorized subsidiaries. Using it to map competitors' infrastructure for
   business intelligence purposes is prohibited.

3. **Mass surveillance.** Bulk correlation of registrant data across
   non-authorized domains for the purpose of population-scale surveillance is
   prohibited.

4. **Circumventing WHOIS privacy.** The module respects WHOIS privacy/proxy
   registrations. It MUST NOT attempt to de-anonymize privacy-protected
   registrations through inference or correlation.

5. **Law enforcement without legal process.** Identity Surface data MUST NOT
   be provided to law enforcement or government agencies without proper legal
   process (subpoena, warrant, or equivalent jurisdiction-appropriate
   instrument).

## Data Retention Requirements

1. **Tenant-scoped retention.** All Identity Surface data is tenant-scoped and
   subject to the tenant's configured data retention policy (per ADR-008).

2. **Maximum retention: 90 days for raw registrant data.** Raw WHOIS/RDAP
   registrant records used as pivot inputs MUST be purged within 90 days of
   collection. Derived outputs (cluster memberships, graph edges) follow the
   tenant's artifact retention schedule.

3. **Right to deletion.** Tenants may request deletion of all Identity Surface
   data at any time. The system MUST honor such requests within 72 hours.

4. **Audit trail.** All Identity Surface operations are logged in the tenant's
   audit trail (per ADR-008). Logs include the operator, timestamp, scope of
   the operation, and number of entities processed. Logs do NOT include raw
   registrant PII.

## Consent Requirements

1. **Per-tenant authorization gate.** The ``per_tenant_authorization`` parameter
   MUST be set to ``True`` for any Identity Surface operation. This parameter
   is not a formality -- it represents the operator's attestation that:
   - The tenant has authorized identity-correlation operations.
   - The scope configuration accurately reflects the tenant's authorized
     perimeter.
   - The operator has reviewed this ethics policy.

2. **Tenant onboarding acknowledgment.** Before enabling Identity Surface for a
   tenant, the tenant MUST acknowledge (in writing or via signed API call)
   that they understand the module correlates registrant identities across
   their authorized domains.

3. **Third-party registrant data.** When pivot results include registrant data
   for entities outside the tenant's direct organization (e.g., shared hosting
   providers, CDN operators), those entities are included only as contextual
   nodes in the organization graph. No notification to or consent from those
   third parties is required for passive, public-data-only correlation, but
   the tenant is informed that such nodes exist.

4. **Re-authorization on scope change.** If the tenant's authorized scope
   changes (domains added or removed), Identity Surface operations against the
   new scope require fresh authorization. Cached pivot results from the
   previous scope MUST be invalidated for removed domains.

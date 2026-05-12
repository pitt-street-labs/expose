# EXPOSE MSSP Licensing & Multi-Tenant Packaging

> **Created:** 2026-05-11 | **Status:** Advisory — not locked | **Issue:** #119

## MSSP Use Case

Managed Security Service Providers monitor attack surfaces for multiple client organizations. An MSSP running EXPOSE provisions one tenant per client, configures seeds and authorization scope per engagement, and operates all tenants from a single deployment. Analysts see cross-client dashboards; each client receives branded reports scoped to their tenant. EXPOSE's per-tenant credential isolation (ADR-007) means Client A's API keys never leak to Client B's scan jobs.

## Licensing Model

### Per-Tenant Volume Tiers

| Tier | Active Tenants | Per-Tenant/Year | Effective Discount |
|------|---------------|----------------|--------------------|
| Starter | 1-10 | $60,000 | 0% (Enterprise list) |
| Growth | 11-50 | $45,000 | 25% |
| Scale | 51-200 | $30,000 | 50% |
| Strategic | 200+ | Custom | Negotiated (floor $18K) |

All MSSP tiers include Enterprise-tier features (Threat Context, Identity Surface, CISO Reports, SOC Package, SIEM adapters, full API access). Federal add-on (FIPS, air-gap, STIG) is available at +$50K/tenant for MSSPs serving government clients.

### White-Label Option

Available at Growth tier and above (+15% surcharge on per-tenant price). Includes:

- Custom logo/branding on CISO executive reports and PDF exports
- Configurable "Prepared by" attribution block on all report outputs
- Custom domain for hosted API endpoint (CNAME delegation)
- White-labeled CSV/STIX/MISP exports with MSSP branding in metadata

### Billing Mechanics

- Annual commitment, quarterly true-up on active tenant count
- Tenant is "active" if it had at least one completed run in the billing quarter
- Dormant tenants (no runs in 90 days) excluded from count at next true-up
- Minimum 5-tenant annual commitment for MSSP pricing

## Technical Readiness

| Capability | Status | Notes |
|------------|--------|-------|
| Multi-tenancy isolation | DONE | `tenant_id` on all tables, middleware injection, cross-tenant test suite (ADR-007) |
| Per-tenant configuration | DONE | Seeds, collectors, rule packs, LLM provider, retention — all per-tenant YAML/JSONB |
| Tenant-scoped credentials | DONE | `CredentialResolver` with per-tenant + global fallback chain |
| Batch entity operations | DONE | `batch_upsert` with 500-entity chunking, savepoint isolation |
| Tenant provisioning API | DONE | `POST /v1/tenants/` with config, `GET/PUT/DELETE` lifecycle |
| Per-tenant resource quotas | NEEDED | Logical isolation only today; physical quotas deferred (SPEC 11.3) |
| MSSP admin API | NEEDED | Cross-tenant dashboard, aggregate metrics, fleet health endpoint |
| White-label report branding | NEEDED | Configurable logo/attribution in CISO report and export templates |
| Tenant onboarding wizard | NEEDED | Self-service UI for MSSP analysts to provision client tenants |
| Cross-tenant billing metrics | NEEDED | Run counts, entity counts, LLM spend per tenant for usage reporting |

### Implementation Priority (MSSP-Specific)

1. **MSSP admin API** — `GET /v1/mssp/dashboard` returning per-tenant run health, entity counts, attribution distribution, last-run timestamps. Estimated: 2-3 sprints.
2. **White-label reports** — Branding config in tenant JSONB (`report_branding: {logo_url, prepared_by, color_scheme}`). Estimated: 1 sprint.
3. **Billing metrics endpoint** — `GET /v1/mssp/billing` with active tenant counts, run totals, LLM costs per tenant per period. Estimated: 1 sprint.
4. **Per-tenant quotas** — Already scoped in production-hardening epic. Prevents noisy-neighbor across MSSP client tenants.

## Revenue Model

### Projected MSSP Revenue Contribution

| Scenario | MSSPs | Avg Tenants/MSSP | Avg Tier | MSSP ARR | % of Total ARR |
|----------|-------|-------------------|----------|----------|----------------|
| Conservative (Y1) | 2 | 8 | Starter | $960K | 40% of $2.4M |
| Moderate (Y2) | 5 | 25 | Growth | $5.6M | 50% of $11.2M |
| Aggressive (Y3) | 10 | 60 | Scale | $18.0M | 55% of $32.7M |

MSSPs are a force multiplier: one MSSP sale creates 10-50 tenant subscriptions. The Growth and Scale tiers offer margin compression per-tenant but dramatically increase total contract value and reduce per-customer acquisition cost to near zero for downstream clients.

### Channel Incentives

- **MSSP partner certification** — free training, dedicated support channel, early access to new modules
- **Co-marketing** — joint case studies, "Powered by EXPOSE" badge program
- **Referral credit** — MSSP earns 10% credit on direct Enterprise deals they refer

## Related Issues

- #119 — This document
- #109 — Identity Surface module (MSSP upsell)
- #113 — CISO threat report (white-label target)
- #115 — SOC threat package (MSSP core value)

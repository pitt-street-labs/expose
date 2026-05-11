# EXPOSE Commercial Moat & Revenue Strategy

> **Created:** 2026-05-11 (Sprint 3-4 session)
> **Status:** Working draft — refine with market validation
> **Classification:** Internal / Confidential

## Core Thesis

Competitors sell asset inventories. EXPOSE sells **intelligence** — attribution confidence, threat context, and SOC-ready action packages. The platform bridges the gap between external attack surface management (EASM) and internal security operations, creating a category that doesn't cleanly exist today.

## Moat Layers

### Layer 1: Attribution Intelligence (Deepest — Hardest to Replicate)

EXPOSE doesn't just enumerate assets; it provides **confidence-scored ownership attribution** via a rule-based evaluation engine with customizable rule packs. An analyst sees "this IP is yours at 94% confidence because of cert chain overlap + registrant match + ASN authorization," not just "this IP exists."

- **12 attribution predicates** evaluated recursively (AND/OR/NOT condition trees)
- **Configurable rule packs** per organizational profile (cloud-first, conservative, government)
- **Tier thresholds** (confirmed >= 0.95, high >= 0.75, medium >= 0.5)
- No competitor provides programmatic, auditable attribution logic

### Layer 2: SOC Threat Package (Strongest Commercial Differentiator)

When EXPOSE discovers target-owned endpoints that appear on blocklists, have poor trust scores, or show compromise indicators, it packages them as **actionable IoCs/IoAs** for SOC teams to hunt internally.

- **Output:** STIX 2.1 bundles, MISP events, CSV with SIEM field mapping, JSON IoC feed
- **LLM-generated hunt recommendations** (E2 environment): what logs to search, what patterns to look for, suggested Splunk/KQL/Chronicle queries
- **SIEM push integration** via Splunk HEC, Microsoft Sentinel, Google Chronicle adapters
- **No competitor does this natively** — today this requires manual analyst effort to bridge EASM findings into SOC workflows

### Layer 3: CISO Strategic Report

Automated executive-level reporting that includes:

- Target market/sector/vertical analysis and threat landscape
- Threat actor profiling (which groups target this vertical, their TTPs, motivation)
- Attraction assessment (what makes this org interesting to attackers)
- Ranked likely targets based on exposed surface + threat intelligence

Mandiant sells this as consulting at $50K-$200K per engagement. EXPOSE automates it.

### Layer 4: Two-Environment Architecture

Deterministic engine (E1, auditable, reproducible) separated from LLM analysis (E2, powerful but non-deterministic). This matters for:

- **Regulators** who need to audit the decision chain
- **Federal customers** who require deterministic systems
- **Legal teams** who need to defend attribution decisions
- Competitors either have no LLM integration or mix it in opaquely

### Layer 5: Federal-Ready Architecture

- FIPS 140-2 compliant cryptography (all crypto via fips_adapter)
- NIST SP 800-53 AU-2/AU-3 audit logging (append-only, retention-aware)
- Air-gap deployment capability (offline mode, no cloud dependency)
- Ed25519/ECDSA artifact signing with provenance chains
- Content-addressed evidence storage with integrity verification

This represents 12-18 months of compliance engineering that competitors would need to replicate.

### Layer 6: Identity Surface Module

M&A-aware asset discovery via registrant pivot analysis and organizational graph construction:

- Fuzzy registrant matching across WHOIS/RDAP records
- Organizational hierarchy from M&A discovery + DNS + BGP data
- Finds assets that acquired companies forgot about
- Ethics-gated with explicit per-tenant authorization

### Layer 7: Open-Core Community Funnel

Apache 2.0 core engine drives adoption. Commercial modules (Threat Context, Identity Surface, SOC Package, CISO Report) drive revenue. Community-contributed rule packs improve accuracy for everyone, creating a network effect.

## Defensibility Analysis

| Moat Type | Strength | Durability |
|-----------|----------|------------|
| Attribution rule engine | Strong | High — network effect on community rule packs |
| SOC integration | Strong | High — switching cost once SIEM workflows are built |
| Federal compliance | Strong | High — 12-18 month replication barrier |
| Two-environment model | Medium | Medium — architectural choice, not a patent |
| Identity surface | Medium | Medium — data sources are public, analysis is the value |
| Open-core funnel | Medium | Medium — depends on community growth |
| CISO reporting | Medium | Low-Medium — LLM commoditization risk, but data pipeline is the moat |

## Revenue Model

### Pricing Tiers

| Tier | Components | Price Range | Target Segment |
|------|-----------|-------------|----------------|
| **EXPOSE Core** | Open-source engine, 29 collectors, attribution rules, graph UI | Free | Community, startups, researchers — adoption funnel |
| **EXPOSE Pro** | Core + Threat Context + SOC Package + SIEM adapters | $25K-$75K/yr | Mid-market (500-5,000 employees) |
| **EXPOSE Enterprise** | Pro + Identity Surface + CISO Reports + API access + priority support | $75K-$200K/yr | Enterprise, MSSP, large security teams |
| **EXPOSE Federal** | Enterprise + air-gap deployment + FIPS + STIG guide + FedRAMP pathway + dedicated support | $150K-$400K/yr | DoD, IC, civilian federal agencies |

### Revenue Drivers

1. **Module licensing** — per-tenant, per-year, per-module
2. **Managed service** — hosted EXPOSE with SLA (for orgs that don't want to self-host)
3. **Professional services** — rule pack customization, deployment assistance, integration engineering
4. **MSSP licensing** — volume pricing for managed security providers who resell EXPOSE-powered services

## Year 1 Revenue Projections (Post-Maturity)

Assumptions: Product market-ready, 1-2 person sales motion (founder-led), federal pipeline initiated but long cycle.

| Scenario | Customer Mix | Avg ACV | ARR |
|----------|-------------|---------|-----|
| **Conservative** | 8-12 mid-market Pro | $40K | $320K-$480K |
| **Moderate** | 15-25 mixed (Pro + Enterprise) | $55K | $825K-$1.4M |
| **Aggressive** | 20-35 commercial + 1 federal | $65K avg | $1.5M-$2.5M |

**The federal contract is the swing factor.** One DoD or IC contract at $200K-$400K transforms Year 1 economics. The open-core funnel fills mid-market while the federal pipeline (12-18 month cycle) builds.

## Market Context

- **EASM market size:** $1.5B+ (2026), growing ~25% YoY
- **Recent M&A:** Palo Alto acquired Expanse (~$800M), Microsoft acquired RiskIQ (~$500M), CrowdStrike acquired Reposify
- **Gap:** No open-core EASM platform with integrated SOC threat packaging and federal-ready architecture
- **Positioning:** EXPOSE occupies the intersection of EASM + threat intelligence + SOC automation — a category that currently requires 2-3 separate tools

## Key Risks

| Risk | Mitigation |
|------|-----------|
| Large vendor adds similar features | Speed to market + open-core community lock-in + federal compliance moat |
| LLM commoditization reduces CISO report value | Data pipeline and domain-specific prompts are the moat, not the LLM itself |
| Federal sales cycle too long for bootstrap | Mid-market Pro tier funds operations while federal pipeline builds |
| Community adoption doesn't materialize | Focus on researcher/pentester persona first — they drive word-of-mouth |
| Pricing too high for mid-market | Offer monthly billing, usage-based pricing for Pro tier |

## Related Issues

- #112 — Artifact download API endpoint
- #113 — CISO threat report (commercial module)
- #114 — Interactive graph filters
- #115 — SOC threat package (urgent feature)

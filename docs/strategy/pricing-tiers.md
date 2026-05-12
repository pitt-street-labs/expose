# EXPOSE -- Pricing Tiers & Packaging Structure

> **Status:** Advisory -- not locked
> **Date:** 2026-05-11
> **Issue:** #116 -- Define pricing tiers and packaging structure
> **Audience:** Internal strategy; informs sales conversations and RFP responses

---

## 1. Tier Structure

| | **Core (Free/OSS)** | **Pro** | **Enterprise** | **Federal** |
|---|---|---|---|---|
| **Price** | $0 (Apache 2.0) | $249/mo per target domain | Custom (starts ~$6K/mo) | Custom pricing |
| **Deployment** | Self-hosted | Self-hosted or managed | Self-hosted or managed | On-premise only |
| **Target segment** | Researchers, startups, pentesters | Mid-market security teams (50-5,000 employees) | Enterprise, MSSP, large security orgs | DoD, IC, civilian federal agencies |
| **Support** | Community (GitHub Issues) | Community + email (72h SLA) | Dedicated support (8h SLA), named CSM | Dedicated federal support team (4h SLA) |
| **Contract** | Apache 2.0 license | Annual subscription | Annual subscription, custom terms | Annual or multi-year, FAR/DFARS compliant |

---

## 2. Feature Matrix

| Feature | Core | Pro | Enterprise | Federal |
|---|:---:|:---:|:---:|:---:|
| **Discovery & Attribution** | | | | |
| Collector framework (26 OSS collectors) | x | x | x | x |
| Confidence-scored attribution (4 tiers) | x | x | x | x |
| Declarative JSON rule packs | x | x | x | x |
| 5 basic lead scoring signals | x | x | x | x |
| Rule evaluation engine | x | x | x | x |
| Multi-pass expansion | x | x | x | x |
| **Threat Context Module** | | | | |
| 14 advanced lead scoring signals | -- | x | x | x |
| Vendor vulnerability DNA (NVD, 25 CPE) | -- | x | x | x |
| Temporal banner analysis (5 detectors) | -- | x | x | x |
| Full provider fingerprint DB (20 vendors) | -- | x | x | x |
| Dark-web indicator enrichment | -- | x | x | x |
| **Identity Surface Module** | | | | |
| Registrant pivot analysis | -- | -- | x | x |
| Organizational graph construction | -- | -- | x | x |
| M&A-aware asset discovery | -- | -- | x | x |
| Ethics-gated per-tenant authorization | -- | -- | x | x |
| **Reporting & Output** | | | | |
| CSV export | x | x | x | x |
| REST API | x | x | x | x |
| Interactive graph UI | x | x | x | x |
| CISO strategic reports | -- | x | x | x |
| SOC threat packages (STIX 2.1/MISP/IoC) | -- | x | x | x |
| Email report delivery | -- | x | x | x |
| Scheduled/automated scans | -- | x | x | x |
| **Integration** | | | | |
| SIEM adapters (Splunk/Sentinel/Chronicle) | -- | -- | x | x |
| Custom rule pack development | -- | -- | x | x |
| Artifact signing (Ed25519/ECDSA) | x | x | x | x |
| **Operations** | | | | |
| Multi-tenancy | -- | -- | x | x |
| SSO/SAML | -- | -- | x | x |
| SLA | -- | -- | x | x |
| **Federal & Compliance** | | | | |
| FIPS 140-3 validated crypto | -- | -- | -- | x |
| FedRAMP-ready deployment patterns | -- | -- | -- | x |
| Air-gap support (offline mode) | -- | -- | -- | x |
| IL4/IL5 classification guide | -- | -- | -- | x |
| NIST 800-53 control mapping | -- | -- | -- | x |
| STIG-aligned hardening guide | -- | -- | -- | x |

---

## 3. Pricing Rationale

**Why per-domain (Pro) instead of per-seat or per-asset:**

- **Per-seat** penalizes team growth and discourages broad adoption within security teams. EASM value scales with surface coverage, not headcount.
- **Per-asset** (Defender EASM's model at ~$0.011/asset/day) creates unpredictable cost -- a single scan discovering 10,000 assets generates a surprise $40K/yr bill. Buyers hate this.
- **Per-domain** is predictable and aligns cost with operational scope. A mid-market company monitoring 3-5 domains pays $750-$1,250/mo -- well within security tool budgets and far below incumbent pricing.

**Market rate comparison:**

| Vendor | Model | Typical annual cost |
|--------|-------|-------------------|
| Censys ASM | Enterprise SaaS (unlisted) | ~$30K-$100K/yr |
| Palo Alto Cortex Xpanse | Enterprise SaaS (unlisted) | ~$60K-$120K/yr |
| Microsoft Defender EASM | Per-asset ($0.011/asset/day) | ~$20K-$80K/yr (scale-dependent) |
| CrowdStrike Falcon Surface | Platform bundle (unlisted) | ~$40K-$100K/yr |
| **EXPOSE Pro** | **Per-domain ($249/mo)** | **$3K-$15K/yr (1-5 domains)** |
| **EXPOSE Enterprise** | **Custom** | **$72K-$200K/yr** |

EXPOSE Pro undercuts incumbents by 5-10x at mid-market scale, creating a wedge for initial adoption. Enterprise pricing is competitive with incumbents but adds Identity Surface, multi-tenancy, and SIEM integration that justify the price floor.

---

## 4. Revenue Projections (Year 1-3)

Assumptions: Product market-ready mid-2027. Year 1 is founder-led sales. Year 2 adds 1-2 AEs. Year 3 adds federal contract pipeline maturity.

### Conservative

| Year | Pro customers | Enterprise | Federal | ARR |
|------|:---:|:---:|:---:|---:|
| Y1 | 15 (avg 3 domains) | 2 | 0 | $279K |
| Y2 | 40 (avg 4 domains) | 5 | 0 | $838K |
| Y3 | 70 (avg 4 domains) | 10 | 1 ($250K) | $1.84M |

### Moderate

| Year | Pro customers | Enterprise | Federal | ARR |
|------|:---:|:---:|:---:|---:|
| Y1 | 25 (avg 4 domains) | 4 | 0 | $588K |
| Y2 | 60 (avg 5 domains) | 10 | 1 ($300K) | $1.90M |
| Y3 | 100 (avg 5 domains) | 20 | 3 ($250K avg) | $3.94M |

### Aggressive

| Year | Pro customers | Enterprise | Federal | ARR |
|------|:---:|:---:|:---:|---:|
| Y1 | 40 (avg 5 domains) | 6 | 1 ($300K) | $1.21M |
| Y2 | 80 (avg 5 domains) | 15 | 3 ($350K avg) | $3.64M |
| Y3 | 150 (avg 6 domains) | 30 | 6 ($300K avg) | $7.34M |

**Key driver:** Federal contracts are the swing factor. A single DoD/IC deal at $250K-$400K transforms unit economics. The open-core funnel fills mid-market Pro while the federal pipeline (12-18 month cycle) builds. MSSP volume licensing (not modeled) is additional upside -- one MSSP deal at 50+ domains replaces 10 individual Pro customers.

---

## Related Documents

- `docs/strategy/commercial-moat-and-revenue.md` -- moat layers and revenue model
- `docs/strategy/competitive-positioning.md` -- vendor displacement strategy
- `docs/strategy/persona-analysis.md` -- per-persona buying motions
- `docs/adr/ADR-009-commercial-structure.md` -- product surface definitions

# EXPOSE — Competitive Positioning

**Status:** Advisory — not locked
**Date:** 2026-05-11
**Issue:** #120 — Competitive positioning: EXPOSE vs Censys/Shodan/Expanse/RiskIQ
**Audience:** Technical buyer evaluating EASM options

This document distills the full competitive analysis (`competitive-analysis.md`) into a concise positioning reference for technical buyers, sales conversations, and RFP responses. It covers the six vendors a buyer is most likely comparing against, EXPOSE's differentiators, and an honest assessment of gaps.

---

## 1. Market Landscape

The EASM market ($1.5B+, ~25% YoY growth) has consolidated through acquisition. The six players a technical buyer will encounter most often:

| Vendor | Parent | Positioning | Est. Pricing |
|--------|--------|-------------|-------------|
| **Censys ASM** | Censys | Data-depth leader; productized internet-wide scan dataset | Enterprise SaaS (unlisted) |
| **Shodan Monitor** | Shodan | Developer-oriented internet scanning; lightweight monitoring | Freemium; $69-$1099/mo |
| **Palo Alto Cortex Xpanse** | Palo Alto Networks | Enterprise active ASM with remediation playbooks; FedRAMP High | Enterprise SaaS (unlisted) |
| **Microsoft Defender EASM** | Microsoft (ex-RiskIQ) | Microsoft-ecosystem-integrated EASM; aggressive per-asset pricing | $0.011/asset/day |
| **CrowdStrike Falcon Surface** | CrowdStrike | Adversary-driven EASM bundled with Falcon platform | Falcon bundle (unlisted) |
| **Mandiant ASM** | Google Cloud | Adversary-informed EASM with CTI integration; FedRAMP Ready (High) | Enterprise SaaS (unlisted) |

**Common pattern:** All six are commercial SaaS, all are defensive-only, none produce cryptographically signed artifacts, none offer an open-source self-hosted engine. EXPOSE occupies a different architectural position.

---

## 2. Positioning Matrix

| Axis | Censys ASM | Shodan Monitor | Cortex Xpanse | Defender EASM | Falcon Surface | Mandiant ASM | **EXPOSE** |
|------|-----------|---------------|---------------|--------------|----------------|-------------|-----------|
| **Deployment model** | SaaS-only | SaaS-only | SaaS-only | SaaS-only | SaaS-only | SaaS-only | **Self-hosted (Apache 2.0) + future managed SaaS** |
| **Data sovereignty** | Vendor cloud | Vendor cloud | Vendor cloud | Azure | Vendor cloud | Google Cloud | **Operator-controlled; artifacts are portable files** |
| **Open source** | None | None | None | None | None | None | **Open-core: engine + schemas + rule packs (Apache 2.0)** |
| **Federal/air-gap** | No FedRAMP for ASM | None | FedRAMP High | Via Azure Gov | Via GovCloud | FedRAMP Ready (High) | **Self-host inside existing ATO; FIPS 140-3; air-gap artifact consumption** |
| **Pricing transparency** | Unlisted | Published tiers | Unlisted | Published ($0.011/asset/day) | Bundled (unlisted) | Unlisted | **$0 (Core); commercial modules separately priced** |
| **Scan customization** | Fixed platform logic | Fixed queries | Fixed platform logic | Fixed platform logic | Fixed platform logic | Fixed platform logic | **Declarative JSON rule packs: community, vertical-specific, custom** |
| **Active vs passive** | Both (first-party scanning) | Passive + limited active | Active-first | Both | Both | Both | **40 collectors across 3 tiers; Tier 3 active gated by attribution confidence** |
| **MITRE ATT&CK mapping** | None | Informal | None | None | None | None | **Per-collector TA0043 technique annotation** |
| **Multi-tenancy** | Yes | Limited | Yes | Yes (Azure tenant) | Yes (Falcon tenant) | Yes | **Built-in: per-tenant config, rule packs, credentials, scoping** |
| **LLM integration** | None visible | None | None visible | Copilot for Security (opaque) | Charlotte AI (opaque) | None visible | **Multi-provider (Anthropic/OpenAI/Gemini/Ollama); operator sees every prompt; cost-capped; structured-output validated** |

---

## 3. EXPOSE Differentiators — Top 5

### 3.1 Self-hosted with data sovereignty

EXPOSE is the only EASM platform that runs inside the operator's infrastructure. Scan data, attribution decisions, and historical artifacts never leave your network. The engine is Apache 2.0; deploy it inside your authorization boundary, your VPC, or your air-gapped enclave. Every competitor requires sending your attack surface data to their cloud.

### 3.2 Open-core with auditable methodology

The attribution engine, JSON schemas, rule packs, and eval datasets are open source. When an auditor asks "how did you decide this asset belongs to us?", the answer is a data file with a provenance chain -- not "our proprietary algorithm determined it." Community-contributed rule packs improve accuracy for everyone. No other commercial EASM vendor exposes programmatic, auditable attribution logic.

### 3.3 Rule pack extensibility

Attribution logic is defined as JSON Schema-validated declarative files, not buried in vendor code. Ship with baseline, cloud-first, or conservative profiles. Write vertical-specific packs (financial services, healthcare, government). Share them across teams or contribute to the community. Every competitor uses fixed, opaque platform logic the operator cannot inspect or modify.

### 3.4 Federal-trajectory architecture

FIPS 140-3 validated cryptography via centralized `fips_adapter`. NIST SP 800-53 control alignment (AU-2/AU-3 audit logging, CA-7 continuous monitoring, RA-5 scanning, SI-family integrity). Ed25519/ECDSA artifact signing with SLSA-aligned provenance. CDM-compatible output. Agencies deploy EXPOSE Core inside their existing High ATO without waiting for a vendor's FedRAMP authorization cycle -- a 12-18 month compliance engineering lead that competitors would need to replicate.

### 3.5 Deterministic, reproducible scoring

Given the same seeds, rule pack, and configuration, EXPOSE produces the same canonical artifact. Four confidence tiers (`confirmed` >= 0.95, `high` >= 0.75, `medium` >= 0.50, `requires_review`) with numeric scores and full evidence chains. LLM enrichment is optional and operator-controlled -- it supplements the deterministic engine but does not replace it. No black-box ML decides scope. Every attribution decision is auditable and reproducible.

---

## 4. Displacement Strategy

### vs. Censys ASM

**Wedge:** Data sovereignty + self-hosted deployment.

Censys has excellent scan data depth -- EXPOSE consumes Censys data via collector adapters and does not compete on raw internet scanning. The displacement argument is the layer above: Censys holds your attack surface data in their cloud, uses proprietary attribution logic you cannot inspect, and produces no signed artifacts. For buyers who need to control where data lives, audit how attribution decisions are made, or deploy inside their own authorization boundary, EXPOSE is the structural answer. Censys remains a complementary data source, not a competing platform.

### vs. Shodan Monitor

**Wedge:** Enterprise features + structured attribution scoring.

Shodan is a search engine, not an attribution platform. It surfaces raw data; the analyst does the attribution work. EXPOSE automates the attribution layer with confidence-scored ownership claims, evidence chains, and deltable artifacts for continuous monitoring. For buyers who have outgrown ad-hoc Shodan queries and need structured, defensible output for CTEM workflows, EXPOSE is the upgrade path. Shodan remains useful as an upstream data source (EXPOSE's `iwide-shodan` collector).

### vs. Palo Alto Cortex Xpanse

**Wedge:** Cost + open-core transparency + self-host alternative.

Cortex Xpanse holds FedRAMP High -- the strongest federal credential in the category. Do not compete head-to-head on managed-service FedRAMP evaluations. Instead, target buyers who prefer operating inside their own ATO, want open-source methodology they can audit, or cannot justify enterprise platform pricing. EXPOSE Core is $0; commercial modules are separately priced. The self-host pathway lets agencies adopt immediately without inheriting a vendor's authorization boundary.

### vs. Microsoft Defender EASM (ex-RiskIQ)

**Wedge:** Vendor lock-in escape + air-gap capability.

Defender EASM is the right answer for all-Microsoft shops with Sentinel as SIEM. Outside that ecosystem, the integration story collapses. Per-asset pricing ($0.011/asset/day) scales painfully at enterprise scale -- 10,000 assets is ~$40K/year for EASM alone. EXPOSE is ecosystem-agnostic, produces portable signed artifacts that feed any SIEM, and the $0 engine floor eliminates per-asset cost pressure. For federal buyers needing air-gap artifact consumption or non-Azure deployment, Defender EASM has no answer.

### vs. CrowdStrike Falcon Surface

**Wedge:** Standalone pricing + open-core methodology.

Falcon Surface is bundled with the broader Falcon platform -- buyers get EASM as part of an existing CrowdStrike relationship. The displacement case targets buyers evaluating EASM independently: standalone EXPOSE avoids platform-bundle pricing, offers open attribution methodology the buyer can audit, and provides self-hosted deployment for data sovereignty. Falcon Surface's adversary intelligence depth is strong, but the attribution logic is a black box.

### vs. Mandiant ASM

**Wedge:** Self-host pathway + dual-audience design.

Mandiant wins on CTI integration depth and Google Cloud ecosystem. EXPOSE wins where the buyer prefers self-hosted operation inside their own ATO, needs both defensive CTEM and authorized red team workflows from the same platform, or wants open methodology and signed artifacts. Mandiant's defensive-only positioning means red team operators need a separate toolchain; EXPOSE's dual-audience architecture eliminates that gap.

---

## 5. Weaknesses to Address

An honest assessment of where EXPOSE is weaker than incumbents. These are engineering and market realities, not positioning problems.

| Weakness | Impact | Mitigation |
|----------|--------|-----------|
| **Data coverage breadth** | Censys and Shodan have years of internet-wide scan history. EXPOSE consumes their data via APIs but does not replicate their scanning infrastructure. Historical depth depends on third-party data sources. | Position as a consumer of these data sources, not a replacement. The attribution and artifact layer is the value -- raw data is the commodity. |
| **Brand recognition** | Zero market presence against vendors with established analyst-relations, Gartner MQ placement, and Fortune 500 reference customers. | Lead with open-source adoption (researchers, pentesters, small security teams) to build credibility bottom-up. Academic papers and conference presence before enterprise sales. |
| **Support team size** | Single-developer project vs. vendor teams of hundreds. No 24/7 support, no SLA, no dedicated customer success. | Frame as open-source advantage: community support, transparent issue tracker, no vendor lock-in. Commercial support tiers follow adoption. |
| **FedRAMP authorization (not held)** | Architecture is FedRAMP-ready; authorization is roadmap-future. Cortex Xpanse holds FedRAMP High today. Buyers with hard FedRAMP-Authorized requirements will disqualify EXPOSE. | Self-host pathway: agencies deploy EXPOSE Core inside their existing ATO. Do not claim "authorized" -- claim "architecturally ready for self-host deployment within your authorization boundary." |
| **Integration polish** | No first-party Splunk app, no Sentinel connector in Azure Marketplace, no XSOAR content pack. SOC adapters exist but require manual configuration. | Prioritize SIEM adapter packaging in the commercial module roadmap. Core produces standard formats (STIX 2.1, MISP, JSON); integration is configuration, not engineering. |
| **Remediation automation** | EXPOSE identifies and attributes; it does not remediate. Cortex Xpanse has Active Response playbooks. Defender EASM has Sentinel integration for automated response. | Deliberate scope boundary per positioning.md: EXPOSE produces attributed leads, not automated remediation. This is a feature (no blast radius from automated remediation) for security-mature buyers, and a gap for buyers wanting turnkey response. |

---

## Related Documents

- `docs/strategy/competitive-analysis.md` -- full 13-vendor analysis with per-vendor deep dives
- `docs/why-expose.md` -- 12-axis comparison table and technical rationale
- `docs/positioning.md` -- locked strategic positioning (niche definition, competitive cut, federal framing)
- `docs/strategy/commercial-moat-and-revenue.md` -- moat layers, revenue model, pricing tiers
- `docs/strategy/persona-analysis.md` -- per-persona displacement framing

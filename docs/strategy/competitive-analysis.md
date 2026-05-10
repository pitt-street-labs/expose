# EXPOSE — Competitive Analysis

**Status:** Advisory — not locked. Open for revision in subsequent sessions.
**Date:** 2026-05-10
**Author context:** AI-assisted synthesis from the locked spec-phase artifacts (`docs/SPEC.md`, `docs/positioning.md`, `docs/adr/ADR-009-commercial-structure.md`, `docs/adr/ADR-010-fedramp-ready-posture.md`, `docs/strategy/persona-analysis.md`), supplemented by current vendor public material as of May 2026. Produced as Session B output to deepen the starting competitor matrix in `positioning.md` §3.
**Public name:** EXPOSE (selected 2026-05-10 in Session H) / **Internal codename:** FF6K

This document deepens the 13-vendor competitive matrix in `positioning.md` §3 with per-vendor positioning, comparison axes, and persona-aligned displacement framing. It is intended to inform EXPOSE marketing, sales motions, RFP responses, and analyst-relations conversations. It does **not** alter the locked positioning, ADRs, or specification — those remain authoritative.

This is advisory analysis. Treat it as input to subsequent go-to-market and module-specification work, not as a foundation document on the level of `positioning.md` or the ADRs.

---

## 1. Comparison axes

EXPOSE's defensible niche, per `positioning.md` §1.1, is the conjunction of seven properties no incumbent currently delivers cleanly. The following axes operationalize that niche into a comparison framework. Each axis is binary or low-cardinality where possible so the win/loss matrix in §13 stays scannable.

| # | Axis | Why it matters |
|---|---|---|
| 1 | **Continuous vs. point-in-time operation** | CTEM workflows require deltable artifacts; point-in-time tools cannot feed a continuous-monitoring program. |
| 2 | **Attribution rigor (confidence tiers + provenance chain)** | Defensible scope decisions require per-claim evidence; data-lake EASM blurs the line between "observed" and "yours". |
| 3 | **Cryptographically signed artifacts (cosign + SLSA)** | Federal continuous-monitoring evidence and supply-chain integrity (EO 14028, NSM-22) require tamper-evident outputs. |
| 4 | **Deployment posture (SaaS-only / self-hosted / hybrid)** | Federal customers and self-host-preferring enterprises cannot deploy SaaS-only tools inside their authorization boundary. |
| 5 | **FedRAMP authorization status** | Federal procurement gating; Authorized > In Process > Ready > self-host pathway > none. |
| 6 | **OSI-approved license vs. proprietary** | Apache 2.0 unlocks federal procurement preferences, academic adoption, and contributor pipelines. |
| 7 | **Dual-audience capability (defensive CTEM + authorized red team)** | Reduces tool sprawl for organizations that maintain both functions; reflects deliberate architectural separation of authorization scope from operator role. |
| 8 | **Pricing model and floor** | Open-source $0 floor versus per-asset / per-seat / enterprise-only pricing materially changes mid-market addressability. |
| 9 | **Integration patterns (API / JSON file / CTEM adapters)** | Determines friction of fitting into Splunk / Sentinel / Chronicle / XSOAR / Cortex XSIAM stacks. |
| 10 | **Research dataset offering (CC BY 4.0)** | Almost no commercial EASI vendor publishes reference datasets; underlies academic and federal-research credibility. |
| 11 | **LLM enrichment posture** | Whether the vendor exposes the LLM contract (provider abstraction, structured-output validation, cost ceilings) or hides it; affects auditability and operator control. |
| 12 | **Supply-chain integrity (SLSA, cosign, SBOM)** | A FedRAMP-aligned and EO 14028-aligned baseline; differentiator versus vendors that ship SBOMs only on request. |
| 13 | **MITRE ATT&CK Reconnaissance technique coverage** | Mapping every collector to TA0043 techniques is a defensibility marker for federal-customer and analyst conversations. |

Axes that are explicitly **out of scope** for this comparison: vulnerability-management depth (different category — Nessus / Qualys / Tenable.io), CAASM-style internal asset coverage (different category — JupiterOne / Axonius / runZero), bot-protection (PerimeterX / HUMAN), and exploitation tooling (Metasploit / Cobalt Strike). EXPOSE's positioning explicitly excludes these per `positioning.md` §1.2.

---

## 2. SpiderFoot HX — the closest analog

### 2.1 Positioning summary

SpiderFoot is the closest peer to EXPOSE Core in lineage. Created by Steve Micallef as an open-source OSINT automation framework (BSD-licensed), then acquired by Intel 471 (2022) which now operates **SpiderFoot HX** as the commercial SaaS layer on top of the open-source SpiderFoot codebase. HX adds correlation rules, change monitoring, Slack/email notifications, an HX-only module set, a documented API, 2FA, and Tor integration for dark-web crawling.

### 2.2 Where SpiderFoot HX wins

- **Breadth of data sources** is the franchise — over 200 OSINT modules covering CT, DNS, social, breach data, threat intel, dark web. EXPOSE Core's collector matrix (SPEC.md §6.2) is deliberately narrower and more curated.
- **Mature, battle-tested community.** A decade-plus of OSS users means SpiderFoot has reach, training material, and a familiar workflow for OSINT operators.
- **Dark-web crawling built in.** EXPOSE's equivalent is the Threat Context commercial module, not Core; HX bundles it.
- **Lower-friction onboarding.** Hosted SaaS that takes a target string and produces a report; EXPOSE Core requires deployment effort.

### 2.3 Where SpiderFoot HX loses

- **Point-in-time, not continuous-by-design.** HX has change monitoring and scheduled scans, but the operational model is "run a scan, get a report" rather than "produce a deltable artifact every day". This is a structural mismatch with the CTEM operating model.
- **No cryptographically signed artifacts.** Reports are unsigned; downstream consumers cannot verify integrity offline.
- **No FedRAMP-ready architecture.** Intel 471 has no public FedRAMP authorization for SpiderFoot HX; the SaaS architecture is not designed around FIPS 140-3 cryptography or NIST 800-53 control mapping in the way EXPOSE is per ADR-010.
- **No first-class attribution model.** SpiderFoot surfaces relationships; it does not produce per-asset attribution tiers (`confirmed`/`high`/`medium`/`requires_review`) with full provenance chains. The operator must do attribution work themselves on top of the data.
- **Open-source SpiderFoot is BSD; commercial features are SaaS-only.** No self-host commercial path. Federal customers wanting commercial features inherit a SaaS authorization burden.
- **No published research dataset.**

### 2.4 Where EXPOSE wins against SpiderFoot HX

| Axis | SpiderFoot HX | EXPOSE Core |
|---|---|---|
| Continuous deltable artifact | Scheduled scans; report-shaped output | Daily-cadence canonical JSON with `delta_from_previous_run` |
| Attribution tiers | Operator-assembled | First-class — confidence + tier + evidence chain |
| Signed artifacts | None | Cosign-signed canonical artifact + manifest |
| Federal-deployable substrate | OSS engine yes; commercial features no | Apache 2.0 engine self-hostable inside agency ATO |
| FIPS 140-3 architecture | Not designed for it | Built in (ADR-010) |
| LLM contract | Not exposed | Multi-provider abstraction with `SafeLLMClient` (SPEC.md §8.4) |
| Supply-chain integrity | SBOMs not standard | SLSA L2+ target, syft SBOMs, cosign keyless via OIDC |
| MITRE ATT&CK annotation | Informal | Per-collector TA0043 technique annotation (positioning.md §2.1) |

### 2.5 Neutral observations

SpiderFoot is not a like-for-like competitor. It is a recon framework that SaaS-wraps; EXPOSE is an attribution-and-artifact engine that happens to do recon. The operator who wants a single-button "scan this domain for everything" experience is a SpiderFoot user; the operator who wants a defensible artifact for CTEM evidence is an EXPOSE user. The categories overlap, but the sale is different.

The Intel 471 acquisition reframed SpiderFoot from a community OSS tool into a commercial CTI-adjacent product. That reframing pulls SpiderFoot HX away from the federal-deployable open-core position EXPOSE occupies, and toward CTI-tool territory where Recorded Future and Mandiant Threat Intelligence are larger competitors. EXPOSE is unlikely to lose head-to-head federal evaluations against SpiderFoot HX once federal procurement preferences and signed-artifact requirements enter the conversation.

---

## 3. Mandiant Advantage Attack Surface Management

### 3.1 Positioning summary

Mandiant Advantage ASM is the EASM module within Google Cloud's Mandiant Advantage platform (post-2022 Google acquisition of Mandiant). The product positions as **adversary-informed** EASM, drawing on Mandiant's threat-intelligence depth. Mandiant Advantage Automated Defense achieved FedRAMP Ready designation at the High Impact level in 2022; this is a Mandiant-platform designation that benefits ASM as a co-resident SaaS but is not an ASM-specific authorization.

### 3.2 Where Mandiant Advantage ASM wins

- **Brand and analyst-relations weight.** Gartner Magic Quadrant credibility, Mandiant-engagement reference-customer pool, deep public-sector relationships.
- **Threat-intelligence integration.** Native correlation between attack-surface findings and Mandiant's adversary research is a strong story for CTI-mature buyers.
- **Federal credibility.** FedRAMP Ready (High) designation on the broader platform, plus DoD and IC reference customers, is a procurement-conversation accelerator.
- **Google Cloud ecosystem.** Tight integration with Google SecOps (Chronicle), VirusTotal, Looker dashboards.

### 3.3 Where Mandiant Advantage ASM loses

- **SaaS-only.** No self-host pathway. Federal agencies wanting to operate within their existing ATO must use Mandiant's SaaS authorization rather than inheriting the engine.
- **No open-source substrate.** No academic adoption pipeline, no contributor community, no agency self-host.
- **No cryptographically signed artifacts.** Standard SaaS report-and-API output; no cosign-signed canonical deliverable.
- **Defensive-only positioning.** Marketing materials position ASM purely for defenders; authorized red team workflows are not a first-class use case.
- **No published research dataset offering.** Mandiant publishes threat reports, not reproducible reference graphs for EASI tool benchmarking.
- **No transparent LLM contract.** Mandiant deploys AI features but does not expose a multi-provider abstraction for operators to control LLM cost, model choice, or structured-output validation.

### 3.4 Where EXPOSE wins against Mandiant Advantage ASM

| Axis | Mandiant Advantage ASM | EXPOSE |
|---|---|---|
| Self-host pathway | None | Apache 2.0 self-host (Core) |
| FedRAMP for the open engine | N/A (SaaS-only) | Architecturally ready; agency self-host pattern |
| Signed artifacts | None | Cosign + SLSA |
| Dual audience (CTEM + red team) | Defensive-only | Both, by design |
| OSI-approved license | Proprietary | Apache 2.0 (Core); CC BY 4.0 (Research) |
| Pricing floor | Enterprise SaaS | $0 (Core OSS) |
| Operator control of LLM | None | Multi-provider, Ollama default |
| Research dataset | None | EXPOSE Research (CC BY 4.0) |

### 3.5 Neutral observations

Mandiant Advantage ASM and EXPOSE compete on different terrain even when they meet. Mandiant wins the buyer who wants a single-vendor relationship with Google Cloud-tier support and is willing to inherit Mandiant's authorization. EXPOSE wins the buyer who wants self-host control inside their own authorization boundary and the modular open-core path.

The displacement story is narrower: EXPOSE will not displace Mandiant in accounts where Mandiant Threat Intelligence is already the CTI source-of-truth and ASM is bundled. EXPOSE displaces Mandiant in accounts where the federal-deployable substrate or dual-audience flexibility is the higher-order requirement.

---

## 4. Censys Attack Surface Management

### 4.1 Positioning summary

Censys ASM is the productized layer on top of Censys's internet-wide scan dataset. The product leverages Censys's primary asset — **>95% claimed attribution accuracy** drawn from continuous internet scanning — and adds asset discovery, vulnerability detection, and change-monitoring features around it. Pricing is enterprise-tiered subscription; the platform is broadly recognized as data-rich but expensive for mid-market.

### 4.2 Where Censys ASM wins

- **Data depth, full stop.** Censys's underlying scan corpus is one of the two reference internet-wide datasets (Shodan being the other). EXPOSE consumes Censys via collector adapters; it does not compete on raw data depth.
- **Attribution accuracy claims.** Censys publishes 95%+ attribution accuracy; this is the clearest marketing story in the category for a single number.
- **First-party scanning.** Censys can scan non-standard ports, self-signed-cert hosts, and residential-network hosts — useful breadth.
- **Mature API and SIEM integrations.** Splunk, Chronicle, Sentinel, XSOAR adapters are standard.

### 4.3 Where Censys ASM loses

- **SaaS-only.** Same federal-deployment friction as Mandiant.
- **No public FedRAMP authorization for Censys ASM** as of May 2026. Self-host pathway does not exist.
- **No signed artifacts.** Reports and API outputs; no cosign-signed canonical deliverable.
- **No open-source substrate.** Censys publishes some research and a Python SDK, but the ASM product is closed.
- **No first-class red team posture.** Defensive-focused; authorized red team operators use Censys as a data source, not as an artifact-producing platform.
- **No published reference graph dataset.** Censys publishes scan-data summaries, not reproducible attribution-quality benchmarks.
- **Pricing model excludes mid-market.** Enterprise subscription floor; not addressable by smaller teams.

### 4.4 Where EXPOSE wins against Censys ASM

| Axis | Censys ASM | EXPOSE |
|---|---|---|
| Self-host | None | Apache 2.0 |
| Pricing floor | Enterprise SaaS | $0 |
| Signed artifacts | None | Cosign + SLSA |
| LLM enrichment posture | Hidden | Operator-controlled multi-provider |
| Federal self-host pathway | None | Per ADR-010 |
| Dual-audience use | Defensive | Both |
| Research dataset (CC BY) | None | EXPOSE Research |
| Reproducible attribution methodology | Closed | Open rule packs, predicate vocabulary |

### 4.5 Neutral observations

Censys's data is a moat EXPOSE does not attempt to replicate. The right framing is that EXPOSE Core is **a Censys consumer**, not a Censys competitor on raw data. EXPOSE's competitive advantage over Censys ASM is on the *layer above the data* — attribution discipline, signed artifacts, federal-deployable architecture, dual-audience operator model. In federal evaluations, Censys is often a complementary data source rather than a competing platform.

---

## 5. Microsoft Defender External Attack Surface Management

### 5.1 Positioning summary

Microsoft Defender EASM is the rebadged former RiskIQ platform (Microsoft acquisition closed 2021). It positions as continuous discovery and mapping of an organization's external digital surface, integrated with Microsoft Defender XDR and Sentinel. Pricing is consumption-based: **$0.011 per asset per day** after a 30-day free trial — the most aggressive per-asset pricing in the category.

### 5.2 Where Defender EASM wins

- **Microsoft 365 / Azure / Entra ecosystem integration.** For Microsoft-stack accounts, Defender EASM lands inside the existing tenant with native Sentinel and Defender XDR integration.
- **Aggressive per-asset pricing.** $0.011/asset/day undercuts every enterprise-SaaS competitor in the category at the floor.
- **RiskIQ heritage.** Long-running internet observation dataset.
- **Microsoft FedRAMP authorizations.** Microsoft 365 GCC High and Azure Government carry FedRAMP High authorization. Whether Defender EASM is in scope of these authorizations depends on the specific Azure environment; this is a procurement question federal buyers need to verify per deployment.

### 5.3 Where Defender EASM loses

- **SaaS-only and Microsoft-ecosystem-tied.** No self-host. Outside Microsoft tenants, the product loses much of its integration story.
- **No cryptographically signed artifacts.** Standard Microsoft Graph-style outputs; no cosign-signed canonical artifact.
- **No open-source substrate.** Closed.
- **Defensive-only.** Same posture as Mandiant and Censys.
- **No transparent LLM contract.** Microsoft is rapidly adding Copilot for Security AI features but does not expose a provider abstraction for operator control.
- **Per-asset pricing scales painfully.** What is cheap at small scale becomes expensive at enterprise asset counts (a Fortune 500 with 10,000 monitored assets is ~$110/day = ~$40K/year for EASM alone).
- **No published research dataset.**

### 5.4 Where EXPOSE wins against Defender EASM

| Axis | Defender EASM | EXPOSE |
|---|---|---|
| Self-host | None | Apache 2.0 |
| Ecosystem-agnostic | Microsoft-tied | Cloud-portable (SPEC.md §4.1) |
| Signed artifacts | None | Cosign + SLSA |
| Pricing model at scale | $0.011/asset/day (linear) | $0 software floor; commercial modules separately licensed |
| Dual-audience | Defensive | Both |
| Operator-controlled LLM | None | Multi-provider abstraction |
| Reference dataset | None | EXPOSE Research |
| Open attribution methodology | Closed | Open rule packs |

### 5.5 Neutral observations

Defender EASM is the right answer for an all-Microsoft shop with Sentinel as SIEM and limited appetite for vendor-stack diversity. EXPOSE is the right answer for federal-deployable, signed-artifact, dual-audience, or non-Microsoft-stack buyers. Head-to-head displacement is most likely in federal-adjacent accounts where Microsoft GCC pricing is tight and self-host is preferred.

The per-asset pricing tension is real for Defender EASM at enterprise scale. EXPOSE's $0 software floor is a decisive answer for procurement-sensitive buyers.

---

## 6. CrowdStrike Falcon Surface

### 6.1 Positioning summary

Falcon Surface is CrowdStrike's adversary-driven EASM module within the broader Falcon platform. It positions as continuous internet-wide scanning correlated with CrowdStrike's adversary intelligence. Falcon Surface is sold as a Falcon platform module rather than a standalone product; pricing is bundled with broader Falcon subscriptions.

### 6.2 Comparison

| Axis | Falcon Surface | EXPOSE |
|---|---|---|
| Continuous | Yes | Yes |
| Attribution tiers + provenance | Vendor-internal scoring | Per-claim provenance chain |
| Signed artifacts | None | Cosign + SLSA |
| Deployment | SaaS-only, Falcon platform | Self-host + future SaaS |
| FedRAMP | CrowdStrike Falcon has FedRAMP authorizations (Moderate) for parts of the platform; Falcon Surface scope varies by SKU | Architecturally ready; agency self-host |
| OSI-approved license | Proprietary | Apache 2.0 (Core) |
| Dual-audience | Defensive (Falcon is XDR-anchored) | Both |
| Research dataset (CC BY) | None | Yes |

**Where EXPOSE wins:** federal self-host, signed artifacts, dual-audience, open methodology, modular pricing. **Where Falcon Surface wins:** Falcon platform integration for CrowdStrike accounts; adversary-intelligence correlation depth; existing CrowdStrike vendor relationship.

**Neutral:** Falcon Surface is bundled with Falcon platform spend; the displacement opportunity exists only where the buyer is willing to consider non-Falcon vendors for EASM.

---

## 7. Tenable Attack Surface Management

### 7.1 Positioning summary

Tenable ASM (part of Tenable One exposure-management platform) integrates external attack-surface discovery with Tenable's vulnerability-management heritage. Tenable One bundles Tenable.io VM, Tenable.cs cloud security, Tenable.ad Active Directory security, and EASM into a unified exposure platform with predictive prioritization scoring.

### 7.2 Comparison

| Axis | Tenable ASM | EXPOSE |
|---|---|---|
| Continuous | Yes | Yes |
| Self-host | Tenable.sc on-prem option; Tenable.io and ASM are SaaS | Apache 2.0 self-host |
| FedRAMP | Tenable.io has FedRAMP Moderate; Tenable.sc on-prem inherits agency ATOs | Architecturally ready; agency self-host |
| Signed artifacts | None | Cosign + SLSA |
| OSS license | Proprietary (Tenable has open-source projects, ASM is not one) | Apache 2.0 |
| Dual-audience | Defensive | Both |
| Research dataset | None for ASM | Yes |
| ATT&CK Reconnaissance annotation | Informal | Per-collector TA0043 |

**Where EXPOSE wins:** federal self-host pathway with signed artifacts, dual-audience design, open methodology, no per-asset pricing pressure. **Where Tenable ASM wins:** integrates with Tenable's installed-base VM/cloud/AD posture; existing procurement relationship for current Tenable customers.

**Neutral:** EXPOSE will not displace Tenable in accounts where Tenable One is the unified exposure platform of record. EXPOSE displaces Tenable ASM where the buyer wants the EASM layer without inheriting the Tenable exposure-platform stack.

---

## 8. Palo Alto Cortex Xpanse

### 8.1 Positioning summary

Cortex Xpanse is Palo Alto Networks' ASM platform within the Cortex security operations suite. **Cortex achieved FedRAMP High Authorization in January 2025** (the first AI-driven SOC platform to do so), which is the strongest federal credential among the commercial EASM vendors. Xpanse positions as **active attack surface management** — continuous IPv4 scanning multiple times per day, plus an Active Response module with automated remediation playbooks.

### 8.2 Comparison

| Axis | Cortex Xpanse | EXPOSE |
|---|---|---|
| Continuous | Yes | Yes |
| Attribution discipline | Vendor-internal | Per-claim provenance chain |
| Signed artifacts | None | Cosign + SLSA |
| FedRAMP | **FedRAMP High (Cortex platform)** | Architecturally ready; agency self-host |
| Self-host | None | Apache 2.0 |
| OSS license | Proprietary | Apache 2.0 |
| Dual-audience | Defensive (Active Response is automated remediation) | Both |
| Active remediation | Yes (built-in playbooks) | Out of scope per ADR-008 |
| Research dataset | None | Yes |

**Where Cortex Xpanse wins:** **FedRAMP High authorization** — the strongest commercial credential in the category, full stop; Cortex platform integration; built-in Active Response automation. **Where EXPOSE wins:** self-host inside agency ATOs, signed artifacts, dual-audience, modular open-core path, $0 software floor.

**Neutral:** Cortex Xpanse is the toughest competitor for federal SaaS evaluations where FedRAMP High is a hard requirement and the buyer wants managed service. EXPOSE's federal answer is the self-host pathway: agencies adopt EXPOSE Core within their existing High ATO without waiting for a vendor authorization. The two products serve different federal procurement preferences. **Avoid framing EXPOSE as displacing Cortex Xpanse on managed-service FedRAMP High buyers; that is a losing fight in v1. Frame EXPOSE as the self-host alternative.**

---

## 9. Wiz EASM

### 9.1 Positioning summary

Wiz is the dominant cloud-native security platform; its EASM capability is part of the broader Wiz cloud security platform rather than a standalone product. Wiz's distinguishing approach is **graph-based exploitability analysis** — showing realistic attack chains from exposed assets through cloud permissions to sensitive data.

### 9.2 Comparison

| Axis | Wiz EASM | EXPOSE |
|---|---|---|
| Continuous | Yes | Yes |
| Cloud-native depth | Excellent (CSPM heritage) | Cloud-aware (cloud IP manifests, cloud account attribution) but not CSPM |
| Self-host | None | Apache 2.0 |
| Signed artifacts | None | Cosign + SLSA |
| FedRAMP | Wiz has FedRAMP Moderate authorization | Architecturally ready; agency self-host |
| OSS license | Proprietary | Apache 2.0 |
| Dual-audience | Defensive | Both |
| External-only scope | Mixed (CNAPP-anchored) | External-only (positioning §1.2) |
| Research dataset | None | Yes |

**Where Wiz wins:** cloud-native depth, exploitability graph, CNAPP integration. **Where EXPOSE wins:** external-only focus avoids CNAPP-scope creep, federal self-host, signed artifacts, dual-audience, $0 floor.

**Neutral:** Wiz and EXPOSE serve different scopes. Wiz buyers typically want a unified cloud security platform; EXPOSE buyers want a focused external-surface intelligence engine. Direct head-to-head displacement is rare; Wiz is more often a complementary deployment.

---

## 10. Detectify EASM

### 10.1 Positioning summary

Detectify (Swedish) combines automated EASM with insights from a crowdsourced ethical-hacker community (the Crowdsource program). Web-application focused — strongest where the attack surface is web apps and APIs.

### 10.2 Comparison

| Axis | Detectify | EXPOSE |
|---|---|---|
| Web-app vulnerability depth | Strong (Crowdsource feeds) | Out of scope (positioning §1.2) |
| Continuous | Yes | Yes |
| Self-host | None | Yes |
| Signed artifacts | None | Yes |
| FedRAMP posture | None | Architecturally ready |
| OSS license | Proprietary | Apache 2.0 |
| Dual-audience | Defensive | Both |
| Research dataset | None | Yes |

**Where Detectify wins:** web-app vulnerability detection from the Crowdsource program is genuinely differentiated; mid-market accessibility. **Where EXPOSE wins:** federal-deployable, signed artifacts, broader EASI scope, dual-audience.

**Neutral:** Detectify is mostly orthogonal to EXPOSE — different scope, different buyer. They might meet in mid-market web-property-heavy accounts, where EXPOSE wins on federal credibility and signed artifacts and Detectify wins on web-app vulnerability depth.

---

## 11. IBM Security Randori Recon

### 11.1 Positioning summary

IBM acquired Randori in 2022 and integrated Randori Recon into the IBM Security portfolio. Randori positions as **attacker's-perspective** ASM — continuous external discovery prioritized by what an attacker would target first. Integrates with IBM QRadar XDR.

### 11.2 Comparison

| Axis | Randori Recon | EXPOSE |
|---|---|---|
| Attacker-perspective framing | Yes (marketing differentiator) | Dual-audience by architecture, not framing |
| Continuous | Yes | Yes |
| Self-host | None | Yes |
| Signed artifacts | None | Yes |
| FedRAMP | IBM has multiple FedRAMP authorizations; Randori-specific scope varies | Architecturally ready |
| OSS license | Proprietary | Apache 2.0 |
| Dual-audience | Marketed as offensive-perspective; product is defensive-tool | Both, by design |
| QRadar integration | Native | Generic SIEM via JSON |
| Research dataset | None | Yes |

**Where Randori wins:** "attacker's perspective" framing resonates with red-team-influenced security programs; QRadar integration for IBM-stack accounts. **Where EXPOSE wins:** real dual-audience architecture (not framing), self-host, signed artifacts, open-source substrate.

**Neutral:** Randori's "attacker perspective" is a positioning claim, not an architectural difference — the product is consumed as a defensive tool. EXPOSE's dual-audience design is structural (authorization scope plus operator role), not marketing. This distinction matters for buyers who actually run authorized red team engagements.

---

## 12. Other commercial competitors (briefly)

### 12.1 SecurityScorecard ASI

Ratings-platform-tied EASM. SecurityScorecard's primary product is a vendor-risk scoring rating; ASI is an extension. Wins on vendor-risk-rating buyers; loses on signed artifacts, self-host, dual-audience, FedRAMP self-host pathway.

### 12.2 Recorded Future Attack Surface Intelligence

Recorded Future is a CTI platform first; ASI is an extension that leverages 10+ years of historical DNS/WHOIS/SSL data. Strong CTI integration story, mature Maltego transforms. **EXPOSE Threat Context is the closer commercial analog**, not Core. Recorded Future wins on CTI depth and historical data; loses on self-host, signed artifacts, OSS substrate.

### 12.3 ZeroFox

Brand-protection-focused EASM. Wins on brand impersonation, phishing-domain detection, social-media-based threat detection. Loses on broader EASI scope, federal self-host, signed artifacts, OSS substrate. Mostly orthogonal to EXPOSE Core; partial overlap with EXPOSE Threat Context (Resource Development tactic monitoring).

### 12.4 Bishop Fox CAST / Cosmos

Bishop Fox **Cosmos** (renamed from CAST) is a managed offensive-security service that combines Bishop Fox's expert pentesters with proprietary AI (Cosmos AI). It is a **service-with-tool**, not a pure product — Bishop Fox analysts deliver findings, AI accelerates discovery. The 2026 evolution doubled down on expert-AI augmentation. Fundamentally different category: EXPOSE is a product; Cosmos is a service. They might meet in managed-service procurement conversations where the buyer chooses between hiring a Bishop Fox engagement vs. operating EXPOSE in-house. EXPOSE wins on cost, self-host, and continuous in-house ownership; Cosmos wins on outsourced expertise and deliverable polish.

---

## 13. Open-source recon adjacents (different category, frequently asked about)

These are not EASM competitors in the commercial-procurement sense, but EXPOSE will be compared against them in technical and academic conversations.

### 13.1 OWASP Amass

DNS-focused subdomain enumeration; in-depth attack surface mapping with the Open Asset Model. Excellent at what it does. Included in Kali Linux. **Point-in-time tool**, not a continuous artifact-producing pipeline. No signed artifacts. No attribution tiers. No federal-deployment story beyond the OSS license itself.

**EXPOSE wins on:** continuous operation, attribution discipline, signed artifacts, federal-deployable architecture, dual-audience model, multi-stage pipeline.
**Amass wins on:** focused excellence at DNS enumeration, lighter operational footprint, mature Kali integration.

### 13.2 Recon-NG

Modular Python recon framework. Excellent for scripted point-in-time recon. No continuous mode, no signed artifacts, manual workflows. Same comparison shape as Amass.

### 13.3 theHarvester

Email and subdomain harvesting; narrow scope, point-in-time. Useful as an upstream collector EXPOSE can wrap; not a comparable platform.

### 13.4 Maltego

Graph-visualization tool with paid transforms (including Recorded Future, VirusTotal, Have I Been Pwned, etc.). Manual investigative workflow. Fundamentally a different operating model — analyst-driven graph exploration, not autonomous artifact production. Maltego is a **complement** for EXPOSE consumers who want interactive graph exploration of EXPOSE artifacts.

### 13.5 Shodan and Censys (raw data feeds)

Not products in the comparable sense — they are upstream data sources. EXPOSE consumes both via collector adapters (`iwide-shodan`, `iwide-censys`, `ct-censys` per SPEC.md §6.2). Comparing EXPOSE against Shodan or Censys as platforms is a category error.

---

## 14. Per-persona competitive recap

This section pairs the persona analysis (`docs/strategy/persona-analysis.md`) with displacement framing — for each persona, the 1-2 competitors EXPOSE most directly displaces and the framing that wins.

### 14.1 Red Teamer

**Most-displaced competitors:** SpiderFoot HX, IBM Randori Recon, Bishop Fox Cosmos (when the buyer is choosing between managed service and in-house tooling).

**Winning framing:** "EXPOSE produces a signed, deltable artifact you can hand to a client as engagement evidence — your scope decisions are defensible because every claim has a confidence tier and a provenance chain back to the collector observation. SpiderFoot gives you data; Randori gives you 'attacker perspective' marketing; Cosmos gives you a managed engagement. EXPOSE gives you the substrate you control, with continuous mode for retainer engagements and the same artifact contract whether the operator is doing CTEM or red team work."

**Avoid:** Framing wars against Bishop Fox engagement quality. Bishop Fox sells expert hours; EXPOSE sells software. Different sale.

### 14.2 Threat Researcher

**Most-displaced competitors:** Censys ASM (for academic and federal-research budgets), SpiderFoot OSS (for reproducible methodology research).

**Winning framing:** "EXPOSE Research is the only major EASI offering that publishes reference graph datasets under CC BY 4.0. Apache 2.0 engine means your university or lab can self-host, modify, and cite. The eval harness is the benchmark your attribution-methodology paper needs — Censys won't let you reproduce their attribution pipeline; EXPOSE's rule packs are open data. The deterministic-spine architecture means your published results are reproducible by reviewers."

**Avoid:** Promising research-dataset velocity that the eval-harness epic cannot sustain. The research-dataset claim is real but requires ongoing curation effort.

### 14.3 Corporate Security Director

**Most-displaced competitors:** Microsoft Defender EASM (for non-Microsoft-stack federal-adjacent buyers), Mandiant Advantage ASM (for buyers preferring self-host over SaaS authorization inheritance), Palo Alto Cortex Xpanse (for self-host-preferring buyers; **not** for managed-service FedRAMP High buyers).

**Winning framing:** "EXPOSE Core is open-source and self-host inside your existing authorization boundary — you don't wait for a vendor's FedRAMP authorization to mature, and your continuous-monitoring evidence stream includes signed artifacts you can verify offline. The architecture is FedRAMP-ready by design (FIPS 140-3 crypto, NIST 800-53 control mapping, AU-family audit logging). When operational scale justifies managed service, the future Korlogos commercial offering is the upgrade path. You're not locked into a vendor's authorization timeline."

**Avoid:** Claiming "FedRAMP-authorized" — the architecture is FedRAMP-ready; the authorization is roadmap-future for the commercial offering only. Federal buyers will hear "ready" and assume "authorized" without the Federal Customer Deployment Guide (Session G) to land the distinction defensibly. **Until Session G is produced, treat federal buyer conversations as architecture-credibility conversations, not authorization conversations.**

---

## 15. Win/loss/neutral matrix

Single condensed table — EXPOSE versus each major competitor across the 13 comparison axes. **W** = EXPOSE wins decisively; **L** = EXPOSE loses; **N** = neutral or context-dependent; **—** = axis not applicable to that competitor's category.

| Axis | SpiderFoot HX | Mandiant ASM | Censys ASM | Defender EASM | Falcon Surface | Tenable ASM | Cortex Xpanse | Wiz EASM | Detectify | Randori | SecScorecard ASI | Recorded Future ASI | ZeroFox | Bishop Fox Cosmos | Amass / Recon-NG / theHarvester |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1. Continuous | W | N | N | N | N | N | N | N | N | N | N | N | N | N | W |
| 2. Attribution rigor | W | W | N | W | W | W | W | W | W | W | W | W | W | N | W |
| 3. Signed artifacts | W | W | W | W | W | W | W | W | W | W | W | W | W | W | W |
| 4. Self-host posture | W | W | W | W | W | W | W | W | W | W | W | W | W | W | N |
| 5. FedRAMP status | W | L | N | N | L | L | **L** | L | W | L | N | N | W | N | N |
| 6. OSI-approved license | N (BSD core) | W | W | W | W | W | W | W | W | W | W | W | W | W | N |
| 7. Dual audience | W | W | W | W | W | W | W | W | W | W | W | W | W | N | W |
| 8. Pricing floor | W | W | W | W | W | W | W | W | W | W | W | W | W | W | N |
| 9. Integration patterns | N | L | L | L | L | L | L | L | N | L | L | L | N | — | W |
| 10. Research dataset | W | W | W | W | W | W | W | W | W | W | W | W | W | W | W |
| 11. LLM enrichment posture | W | W | W | W | W | W | W | W | W | W | W | W | W | N | W |
| 12. Supply-chain integrity | W | N | N | N | N | N | N | N | W | N | W | N | W | N | W |
| 13. ATT&CK Recon annotation | W | W | W | W | W | W | W | W | W | W | W | W | W | N | W |

**How to read:** EXPOSE's structural wins are concentrated in axes 2-4, 7-8, 10-13 — attribution discipline, signed artifacts, self-host, dual audience, $0 floor, research dataset, LLM transparency, supply-chain integrity, ATT&CK annotation. EXPOSE's structural losses are concentrated in axis 5 (FedRAMP authorization, where Cortex Xpanse holds the strongest position) and axis 9 (out-of-the-box CTEM-vendor adapters, correctly out of scope per ADR-004 but a frequent procurement-conversation friction point). The overall pattern: EXPOSE wins on architectural and integrity dimensions; loses on integration polish and authorized-managed-service maturity.

---

## 16. Strategic recommendations

1. **Lead with the four-property conjunction, not feature parity.** EXPOSE's defensible positioning is the conjunction of (a) continuous artifact, (b) attribution rigor, (c) cryptographic signing, (d) federal-deployable open-source substrate. No incumbent delivers all four. Marketing should anchor here rather than feature-by-feature comparison, where EXPOSE will lose on enrichment depth versus Mandiant, on data depth versus Censys, on remediation automation versus Cortex, on cloud-native depth versus Wiz. The conjunction is the wedge.

2. **Avoid the FedRAMP-authorized framing war against Cortex Xpanse.** Cortex Xpanse holds FedRAMP High and EXPOSE will not dislodge it from managed-service federal evaluations where FedRAMP High is a hard requirement. The right framing is the **self-host alternative** — agencies that want to operate within their own authorization boundary, agencies that prefer open-source over inherited vendor authorization, agencies that want the commercial-modular path rather than the platform-bundle path. Lead with self-host architectural credibility, not authorization head-to-head.

3. **Treat EXPOSE Research as the long-term marketing infrastructure.** The persona analysis already identified Research as the most underleveraged piece. Reinforced here: almost no commercial EASI vendor publishes reference datasets, and the academic-credibility-to-federal-credibility-to-commercial-credibility compounding loop is multi-year. Sponsor an academic conference paper or two before public launch. Treat the eval harness epic as marketing infrastructure, not a side artifact.

4. **Per-persona sales motions matter more than per-vendor sales decks.** The three personas have different objections, different procurement cycles, and different competitive matchups. The red teamer is comparing against SpiderFoot and Bishop Fox; the threat researcher is comparing against Censys and the OSS recon stack; the security director is comparing against Mandiant, Defender, and Cortex. A single sales deck that tries to address all three will lose all three. Build separate motions; the per-persona competitive recap in §14 is the starting scaffold.

5. **The supply-chain-integrity story is broader than FedRAMP.** Cosign signatures, SLSA L2+ attestations, and SBOMs serve EO 14028, NSM-22, and the broader software supply chain security movement that extends well beyond federal. Commercial buyers increasingly require this in vendor questionnaires (especially in financial services, healthcare, and critical infrastructure). EXPOSE should foreground supply-chain integrity in non-federal sales conversations too, not just federal. The signed-artifact story compounds.

6. **Dual-audience design is real but needs careful sales separation.** Defensive CTEM buyers (CISO + security director persona) are unsettled by the red-team angle; red-team buyers (operator persona) are unsettled by compliance-heavy framing. The three-layer pitch in `positioning.md` §5 already handles this — use the technical-buyer pitch for security architects and the strategic-buyer pitch for boards and federal program managers. **Do not collapse the two pitches into one slide deck**; the persona-analysis recommendation 1 holds. The red team angle is a moat in capability; it is a friction point in defensive-buyer sales conversations. Acknowledge that and separate the motions.

---

## 17. Open questions for follow-on work

These are surfaced for the orchestrating session and subsequent work, not addressed here:

- **CTEM platform adapter ecosystem (Splunk, Sentinel, Chronicle, Cortex XSIAM, XSOAR).** Out of scope for v1 per ADR-004 (artifact is the API). When the production-hardening epic adds the authenticated HTTPS API, adapter strategy becomes a competitive question.
- **Pricing decision tree for commercial modules.** When does a customer need Core only? Core + Threat Context? Core + Identity Surface? All three? Persona analysis recommendation 5 already flagged this.
- **Federal sponsoring-agency relationship.** ADR-010 makes FedRAMP authorization conditional on a sponsoring federal agency. The competitive position against Cortex Xpanse strengthens materially once that relationship exists.
- **Analyst-relations strategy for Gartner, Forrester, IDC.** None of the major EASM Magic Quadrants currently include open-source-substrate vendors; EXPOSE's category fit is non-obvious. Worth a separate session.
- **Reference-customer development for the dual-audience claim.** A documented red team consultancy reference and a documented federal-self-host reference would dramatically strengthen the dual-audience positioning. Both are post-implementation milestones.

---

## 18. Recommended follow-on work

- **Session C (module specifications):** Use the per-vendor analysis to scope what Threat Context and Identity Surface must do to compete with Recorded Future ASI (Threat Context) and the offensive-recon adjacents (Identity Surface). The Recorded Future analog is the relevant Threat Context comparison; SpiderFoot HX and Maltego with paid transforms are the relevant Identity Surface comparisons.
- **Session E (framework annotation):** The MITRE ATT&CK Reconnaissance per-collector annotation is a competitive differentiator that no commercial EASM vendor matches. Make the annotation visible in marketing materials and the canonical artifact.
- **Session G (Federal Customer Deployment Guide):** Upstream of any confident federal sales conversation against Cortex Xpanse. Prioritize.
- **A discrete go-to-market session** (not currently in the queue): per-persona sales decks, RFP response templates, Gartner/Forrester analyst-relations brief. Per recommendation 4 above and persona-analysis recommendation 5.

---

## Sources cited (May 2026)

- [Mandiant Advantage Attack Surface Management — Google Cloud](https://cloud.google.com/security/products/attack-surface-management)
- [Mandiant achieves FedRAMP Ready (High) designation](https://www.mandiant.com/company/press-releases/mandiant-deepens-commitment-public-sector-achieves-fedramp-ready-designation)
- [Microsoft Defender EASM pricing — Azure](https://azure.microsoft.com/en-us/pricing/details/defender-external-attack-surface-management/)
- [Microsoft Defender EASM overview — Microsoft Learn](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/overview)
- [SpiderFoot HX — Intel 471 acquisition](https://www.intel471.com/blog/intel-471-acquires-spiderfoot)
- [Censys Attack Surface Management](https://censys.com/solutions/attack-surface-management/)
- [Cortex achieves FedRAMP High Authorization (Jan 2025)](https://www.paloaltonetworks.com/blog/2025/01/cortex-achieve-fedramp-high-authorization/)
- [CrowdStrike Falcon Surface](https://www.crowdstrike.com/en-us/platform/exposure-management/easm/)
- [IBM Randori Recon](https://www.ibm.com/products/randori-recon)
- [OWASP Amass](https://owasp.org/www-project-amass/)
- [Bishop Fox Cosmos (formerly CAST)](https://www.bishopfox.com/continuous-attack-surface-testing/)
- [Wiz — Attack Surface Management Tools 2026 Comparison Guide](https://www.wiz.io/academy/cloud-security/attack-surface-management-tools)
- [Recorded Future Attack Surface Intelligence](https://www.recordedfuture.com/products/attack-surface-intelligence)
- [SLSA — Software attestations](https://slsa.dev/attestation-model)
- [ZeroFox External Attack Surface Management](https://www.zerofox.com/products/external-attack-surface-management/)
- [SecurityScorecard External Attack Surface Management](https://securityscorecard.com/platform/external-attack-surface-management/)

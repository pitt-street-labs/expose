# EXPOSE — Competitive Analysis

**Status:** Advisory — not locked. Open for revision in subsequent sessions.
**Date:** 2026-05-10
**Author context:** AI-assisted synthesis from the locked spec-phase artifacts (`docs/SPEC.md`, `docs/positioning.md`, `docs/adr/ADR-009-commercial-structure.md`, `docs/adr/ADR-010-fedramp-ready-posture.md`, `docs/strategy/persona-analysis.md`), supplemented by current vendor public material as of May 2026. Produced as Session B output to deepen the starting competitor matrix in `positioning.md` §3.
**Public name:** EXPOSE (selected 2026-05-10 in Session H) / **Internal codename:** FF6K

This document deepens the 13-vendor competitor matrix in `positioning.md` §3 with per-vendor analysis, comparison axes, and persona-aligned displacement framing. It informs marketing, sales motions, RFP responses, and analyst-relations conversations. It does **not** alter the locked positioning, ADRs, or specification.

This is advisory analysis. Treat it as input to subsequent go-to-market and module-specification work.

---

## 1. Comparison axes

EXPOSE's defensible niche (`positioning.md` §1.1) is the conjunction of seven properties no incumbent currently delivers cleanly. The following axes operationalize that niche.

| # | Axis | Why it matters |
|---|---|---|
| 1 | Continuous vs. point-in-time | CTEM workflows require deltable artifacts; point-in-time tools cannot feed continuous monitoring. |
| 2 | Attribution rigor (confidence tiers + provenance) | Defensible scope decisions require per-claim evidence chains. |
| 3 | Cryptographically signed artifacts (cosign + SLSA) | Federal continuous-monitoring evidence and supply-chain integrity (EO 14028, NSM-22). |
| 4 | Deployment posture (SaaS / self-hosted / hybrid) | Federal customers and self-host-preferring enterprises cannot deploy SaaS-only tools inside their AuthZ boundary. |
| 5 | FedRAMP authorization status | Federal procurement gating; Authorized > In Process > Ready > self-host pathway > none. |
| 6 | OSI-approved license vs. proprietary | Apache 2.0 unlocks federal procurement preferences, academic adoption, contributor pipelines. |
| 7 | Dual-audience (defensive CTEM + authorized red team) | Reduces tool sprawl; reflects deliberate separation of authorization scope from operator role. |
| 8 | Pricing model and floor | $0 OSS floor vs. per-asset / enterprise-only changes mid-market addressability. |
| 9 | Integration patterns (API / JSON / CTEM adapters) | Friction of fitting into Splunk / Sentinel / Chronicle / XSOAR stacks. |
| 10 | Research dataset offering (CC BY 4.0) | Almost no commercial EASI vendor publishes reference datasets. |
| 11 | LLM enrichment posture | Whether vendor exposes the LLM contract (provider abstraction, structured-output validation, cost ceilings). |
| 12 | Supply-chain integrity (SLSA, cosign, SBOM) | FedRAMP- and EO 14028-aligned baseline. |
| 13 | MITRE ATT&CK Reconnaissance (TA0043) annotation | Per-collector technique mapping is a federal-conversation defensibility marker. |

**Out of scope** (per `positioning.md` §1.2): vulnerability management (Nessus / Qualys), CAASM (JupiterOne / Axonius / runZero), bot-protection (PerimeterX / HUMAN), exploitation tooling (Metasploit / Cobalt Strike).

---

## 2. SpiderFoot HX — the closest analog

**Positioning.** Created by Steve Micallef as an OSS OSINT framework, acquired by Intel 471 in 2022. **SpiderFoot HX** is the commercial SaaS layer over open-source SpiderFoot — correlation rules, change monitoring, Slack/email notifications, HX-only modules, documented API, 2FA, Tor for dark-web crawling.

**Where SpiderFoot HX wins.** Breadth of data sources (200+ OSINT modules), mature community, dark-web crawling bundled in (EXPOSE's equivalent is the Threat Context commercial module), lower-friction SaaS onboarding.

**Where SpiderFoot HX loses.** Point-in-time scan-and-report model rather than continuous deltable artifact. No cosign-signed artifacts. No FedRAMP-ready architecture. No first-class attribution model — surfaces relationships but does not produce per-asset confidence tiers with provenance chains; the operator does that work themselves. No self-host commercial path (OSS is BSD; HX is SaaS-only). No published reference dataset.

**Where EXPOSE wins.**

| Axis | SpiderFoot HX | EXPOSE Core |
|---|---|---|
| Continuous deltable artifact | Scheduled scans; report-shaped | Daily canonical JSON with `delta_from_previous_run` |
| Attribution tiers | Operator-assembled | First-class — confidence + tier + evidence chain |
| Signed artifacts | None | Cosign + SLSA L2+ |
| Federal-deployable substrate | OSS yes; commercial no | Apache 2.0 self-host inside agency ATO |
| FIPS 140-3 architecture | Not designed for it | Built in (ADR-010) |
| LLM contract | Not exposed | Multi-provider `SafeLLMClient` (SPEC.md §8.4) |
| ATT&CK annotation | Informal | Per-collector TA0043 mapping |

**Neutral.** SpiderFoot is a recon framework that SaaS-wraps; EXPOSE is an attribution-and-artifact engine that happens to do recon. The Intel 471 acquisition pulled SpiderFoot HX toward CTI-tool territory. EXPOSE is unlikely to lose head-to-head federal evaluations once procurement preferences and signed-artifact requirements enter the conversation.

---

## 3. Mandiant Advantage Attack Surface Management

**Positioning.** EASM module within Google Cloud's Mandiant Advantage (post-2022 acquisition). Positions as **adversary-informed** EASM drawing on Mandiant's threat-intelligence depth. Mandiant Advantage Automated Defense achieved FedRAMP Ready (High) in 2022 — a Mandiant-platform designation, not ASM-specific.

**Where Mandiant wins.** Brand and analyst-relations weight (Gartner MQ credibility); native CTI integration; federal credibility from FedRAMP Ready (High) on the broader platform; Google Cloud / Chronicle / VirusTotal ecosystem.

**Where Mandiant loses.** SaaS-only; no self-host pathway. No open-source substrate, no academic adoption pipeline. No cosign-signed artifacts. Defensive-only positioning — authorized red team is not a first-class use case. No published research dataset. No transparent LLM contract.

**Where EXPOSE wins.**

| Axis | Mandiant ASM | EXPOSE |
|---|---|---|
| Self-host pathway | None | Apache 2.0 (Core) |
| FedRAMP for the open engine | N/A (SaaS) | Architecturally ready; agency self-host pattern |
| Signed artifacts | None | Cosign + SLSA |
| Dual audience (CTEM + red team) | Defensive | Both |
| OSI-approved license | Proprietary | Apache 2.0 + CC BY 4.0 (Research) |
| Pricing floor | Enterprise SaaS | $0 (Core) |
| Operator-controlled LLM | None | Multi-provider, Ollama default |

**Neutral.** Mandiant wins single-vendor Google Cloud accounts willing to inherit Mandiant's authorization. EXPOSE wins self-host buyers wanting control inside their own ATO. Will not displace Mandiant where Mandiant Threat Intel is already the CTI source-of-truth.

---

## 4. Censys Attack Surface Management

**Positioning.** Productized layer over the Censys internet-wide scan dataset. Marquee claim: **>95% attribution accuracy**. Enterprise-tiered subscription; broadly recognized as data-rich but expensive for mid-market.

**Where Censys wins.** Data depth (one of two reference internet-wide datasets, alongside Shodan); strong attribution-accuracy marketing story; first-party scanning of non-standard ports and self-signed-cert hosts; mature SIEM integrations (Splunk, Chronicle, Sentinel, XSOAR).

**Where Censys loses.** SaaS-only with no public FedRAMP authorization for ASM as of May 2026. No signed artifacts. No open-source substrate. Defensive-focused. No reference graph dataset for attribution-quality benchmarking. Pricing model excludes mid-market.

**Where EXPOSE wins.**

| Axis | Censys ASM | EXPOSE |
|---|---|---|
| Self-host | None | Apache 2.0 |
| Pricing floor | Enterprise SaaS | $0 |
| Signed artifacts | None | Cosign + SLSA |
| LLM enrichment posture | Hidden | Operator-controlled multi-provider |
| Federal self-host pathway | None | Per ADR-010 |
| Dual-audience use | Defensive | Both |
| Reproducible attribution methodology | Closed | Open rule packs, predicate vocabulary |
| Research dataset (CC BY) | None | EXPOSE Research |

**Neutral.** Censys's data is a moat EXPOSE does not attempt to replicate. The right framing: EXPOSE Core is **a Censys consumer** (via `iwide-censys` and `ct-censys` collectors per SPEC.md §6.2), not a Censys competitor on raw data. EXPOSE wins on the layer above — attribution discipline, signed artifacts, federal-deployable architecture, dual-audience operator model. In federal evaluations Censys is often a complementary data source rather than a competing platform.

---

## 5. Microsoft Defender External Attack Surface Management

**Positioning.** Rebadged former RiskIQ (Microsoft acquisition closed 2021). Continuous discovery integrated with Microsoft Defender XDR and Sentinel. Pricing: **$0.011 per asset per day** after a 30-day free trial — the most aggressive per-asset floor in the category.

**Where Defender EASM wins.** Microsoft 365 / Azure / Entra ecosystem integration (native Sentinel and Defender XDR); aggressive per-asset pricing at small scale; long-running RiskIQ heritage; potential FedRAMP scope via Microsoft 365 GCC High and Azure Government (deployment-dependent — federal buyers must verify per environment).

**Where Defender EASM loses.** SaaS-only and Microsoft-ecosystem-tied; outside Microsoft tenants the integration story collapses. No cosign-signed artifacts. No open-source substrate. Defensive-only. No transparent LLM contract (Microsoft Copilot for Security AI features but no provider abstraction). Per-asset pricing scales painfully — a Fortune 500 with 10,000 monitored assets costs ~$110/day = ~$40K/year for EASM alone. No reference dataset.

**Where EXPOSE wins.**

| Axis | Defender EASM | EXPOSE |
|---|---|---|
| Self-host | None | Apache 2.0 |
| Ecosystem-agnostic | Microsoft-tied | Cloud-portable (SPEC.md §4.1) |
| Signed artifacts | None | Cosign + SLSA |
| Pricing model at scale | $0.011/asset/day (linear) | $0 software floor; modules separately licensed |
| Dual-audience | Defensive | Both |
| Operator-controlled LLM | None | Multi-provider abstraction |

**Neutral.** Defender EASM is the right answer for an all-Microsoft shop with Sentinel as SIEM. EXPOSE is the right answer for federal-deployable, signed-artifact, dual-audience, or non-Microsoft buyers. The per-asset pricing tension at enterprise scale is real; EXPOSE's $0 floor is decisive for procurement-sensitive buyers.

---

## 6. Brief comparisons — additional commercial competitors

### 6.1 CrowdStrike Falcon Surface

Adversary-driven EASM bundled with the broader Falcon platform; native integration with CrowdStrike intelligence. **Where EXPOSE wins:** federal self-host, signed artifacts, dual-audience, open methodology, modular pricing, $0 floor. **Where Falcon Surface wins:** Falcon platform integration for existing CrowdStrike accounts, adversary-intelligence correlation depth. **Neutral:** Falcon Surface is bundled in Falcon platform spend; displacement only where the buyer is willing to consider non-Falcon EASM.

### 6.2 Tenable Attack Surface Management

Part of Tenable One exposure-management platform; integrates EASM with Tenable's VM, cloud, and AD security. **Where EXPOSE wins:** federal self-host with signed artifacts, dual-audience, open methodology, no per-asset pricing pressure. **Where Tenable wins:** integration with installed-base Tenable VM/cloud/AD; existing procurement relationship. **Neutral:** Will not displace Tenable in unified-exposure-platform accounts.

### 6.3 Palo Alto Cortex Xpanse

**Cortex achieved FedRAMP High Authorization in January 2025** (first AI-driven SOC platform). Active ASM with built-in remediation playbooks. **Where Cortex wins:** the strongest commercial federal credential in the category, full stop; Cortex platform integration; built-in Active Response. **Where EXPOSE wins:** self-host inside agency ATOs, signed artifacts, dual-audience, open-core path, $0 floor. **Neutral and tactical:** Cortex Xpanse is the toughest competitor for federal SaaS evaluations where FedRAMP High is a hard requirement. EXPOSE's federal answer is the **self-host pathway** — agencies adopt EXPOSE Core inside their existing High ATO without waiting for vendor authorization. **Avoid framing EXPOSE as displacing Cortex Xpanse on managed-service FedRAMP High buyers; that is a losing fight in v1.**

### 6.4 Wiz EASM

Wiz's EASM is part of the broader cloud-native security platform; distinguishing approach is graph-based exploitability analysis. Wiz holds FedRAMP Moderate. **Where EXPOSE wins:** external-only focus avoids CNAPP scope creep, federal self-host, signed artifacts, dual-audience, $0 floor. **Where Wiz wins:** cloud-native depth, exploitability graph, CNAPP integration. **Neutral:** Different scopes; direct head-to-head displacement is rare.

### 6.5 Detectify

Web-application focused; combines automated EASM with crowdsourced ethical-hacker insights (Detectify Crowdsource). **Where EXPOSE wins:** federal-deployable, signed artifacts, broader EASI scope, dual-audience. **Where Detectify wins:** web-app vulnerability detection from Crowdsource; mid-market accessibility. Mostly orthogonal.

### 6.6 IBM Security Randori Recon

Acquired by IBM in 2022; positions as **attacker's-perspective** ASM, integrates with IBM QRadar XDR. **Where EXPOSE wins:** real dual-audience architecture (not framing), self-host, signed artifacts, OSS substrate. **Where Randori wins:** attacker-perspective marketing resonates with red-team-influenced programs; QRadar integration for IBM-stack accounts. **Neutral:** Randori's "attacker perspective" is a positioning claim; the product is consumed as a defensive tool. EXPOSE's dual-audience design is structural (authorization scope plus operator role), not marketing.

### 6.7 SecurityScorecard ASI

Ratings-platform-tied EASM extension. Wins on vendor-risk-rating buyers; loses on signed artifacts, self-host, dual-audience, FedRAMP self-host pathway.

### 6.8 Recorded Future Attack Surface Intelligence

CTI platform first; ASI extension leverages 10+ years of historical DNS / WHOIS / SSL data. Strong CTI integration, mature Maltego transforms. **EXPOSE Threat Context is the closer analog**, not Core. Recorded Future wins on CTI depth and historical data; loses on self-host, signed artifacts, OSS substrate.

### 6.9 ZeroFox

Brand-protection-focused EASM (added EASM module Nov 2025). Wins on brand impersonation, phishing-domain detection, social-media threats. Loses on broader EASI scope, federal self-host, signed artifacts, OSS substrate. Partial overlap with EXPOSE Threat Context (Resource Development tactic monitoring).

### 6.10 Bishop Fox CAST / Cosmos

Bishop Fox **Cosmos** (renamed from CAST) is a managed offensive-security service combining expert pentesters with proprietary Cosmos AI. February 2026 evolution doubled down on expert-AI augmentation. **Service-with-tool**, not a pure product. They might meet in managed-service procurement where the buyer chooses Bishop Fox engagement vs. operating EXPOSE in-house. EXPOSE wins on cost, self-host, in-house ownership; Cosmos wins on outsourced expertise and deliverable polish. **Avoid framing wars on engagement quality.**

---

## 7. Open-source recon adjacents

Not EASM competitors in the commercial-procurement sense, but EXPOSE is compared against them in technical and academic conversations.

| Tool | Scope | Why EXPOSE wins | Why it wins (vs. EXPOSE) |
|---|---|---|---|
| **OWASP Amass** | DNS-focused subdomain enumeration; Open Asset Model; Kali-bundled | Continuous operation, attribution discipline, signed artifacts, federal-deployable, dual-audience, multi-stage pipeline | Focused excellence at DNS enumeration; lighter footprint; mature Kali integration |
| **Recon-NG** | Modular Python recon framework | Same shape as Amass | Scripted point-in-time recon for ad-hoc work |
| **theHarvester** | Email / subdomain harvesting; narrow scope | Not comparable platform | Useful as upstream collector EXPOSE can wrap |
| **Maltego** | Graph-visualization with paid transforms; analyst-driven | Different operating model — autonomous artifact production vs. interactive exploration | Interactive graph exploration of EXPOSE artifacts (complement, not competitor) |
| **Shodan / Censys (raw)** | Data sources, not products | N/A — category error to compare | EXPOSE consumes both via collector adapters |

---

## 8. Per-persona competitive recap

Pairs `docs/strategy/persona-analysis.md` with displacement framing.

### 8.1 Red Teamer

**Most-displaced:** SpiderFoot HX, IBM Randori Recon, Bishop Fox Cosmos (when buyer is choosing between managed service and in-house tooling).

**Winning framing:** "EXPOSE produces a signed, deltable artifact you can hand to a client as engagement evidence — your scope decisions are defensible because every claim has a confidence tier and a provenance chain back to the collector observation. SpiderFoot gives you data; Randori gives you 'attacker perspective' marketing; Cosmos gives you a managed engagement. EXPOSE gives you the substrate you control, with continuous mode for retainer engagements and the same artifact contract whether the operator is doing CTEM or red team work."

**Avoid:** Framing wars against Bishop Fox engagement quality. Bishop Fox sells expert hours; EXPOSE sells software. Different sale.

### 8.2 Threat Researcher

**Most-displaced:** Censys ASM (for academic and federal-research budgets), SpiderFoot OSS (for reproducible methodology research).

**Winning framing:** "EXPOSE Research is the only major EASI offering that publishes reference graph datasets under CC BY 4.0. Apache 2.0 engine means your university or lab can self-host, modify, and cite. The eval harness is the benchmark your attribution-methodology paper needs — Censys won't let you reproduce their attribution pipeline; EXPOSE's rule packs are open data. The deterministic-spine architecture means your published results are reproducible by reviewers."

**Avoid:** Promising research-dataset velocity that the eval-harness epic cannot sustain.

### 8.3 Corporate Security Director

**Most-displaced:** Microsoft Defender EASM (for non-Microsoft-stack federal-adjacent buyers), Mandiant Advantage ASM (for buyers preferring self-host over SaaS authorization inheritance), Palo Alto Cortex Xpanse (for self-host-preferring buyers; **not** for managed-service FedRAMP High buyers).

**Winning framing:** "EXPOSE Core is open-source and self-host inside your existing authorization boundary — you don't wait for a vendor's FedRAMP authorization to mature, and your continuous-monitoring evidence stream includes signed artifacts you can verify offline. The architecture is FedRAMP-ready by design (FIPS 140-3 crypto, NIST 800-53 control mapping, AU-family audit logging). When operational scale justifies managed service, the future Korlogos commercial offering is the upgrade path."

**Avoid:** Claiming "FedRAMP-authorized" — the architecture is FedRAMP-**ready**; authorization is roadmap-future for the commercial offering only. Federal buyers will hear "ready" and assume "authorized" without the Federal Customer Deployment Guide (Session G) to land the distinction defensibly. **Until Session G is produced, treat federal buyer conversations as architecture-credibility conversations, not authorization conversations.**

---

## 9. Win/loss/neutral matrix

EXPOSE versus each major competitor across the 13 axes. **W** = EXPOSE wins decisively; **L** = EXPOSE loses; **N** = neutral or context-dependent; **—** = axis not applicable.

| Axis | SpiderFoot HX | Mandiant ASM | Censys ASM | Defender EASM | Falcon Surface | Tenable ASM | Cortex Xpanse | Wiz EASM | Detectify | Randori | SecScorecard | Recorded Future | ZeroFox | Bishop Fox Cosmos | OSS recon (Amass et al.) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1. Continuous | W | N | N | N | N | N | N | N | N | N | N | N | N | N | W |
| 2. Attribution rigor | W | W | N | W | W | W | W | W | W | W | W | W | W | N | W |
| 3. Signed artifacts | W | W | W | W | W | W | W | W | W | W | W | W | W | W | W |
| 4. Self-host posture | W | W | W | W | W | W | W | W | W | W | W | W | W | W | N |
| 5. FedRAMP status | W | L | N | N | L | L | **L** | L | W | L | N | N | W | N | N |
| 6. OSI license | N (BSD) | W | W | W | W | W | W | W | W | W | W | W | W | W | N |
| 7. Dual audience | W | W | W | W | W | W | W | W | W | W | W | W | W | N | W |
| 8. Pricing floor | W | W | W | W | W | W | W | W | W | W | W | W | W | W | N |
| 9. Integration patterns | N | L | L | L | L | L | L | L | N | L | L | L | N | — | W |
| 10. Research dataset | W | W | W | W | W | W | W | W | W | W | W | W | W | W | W |
| 11. LLM enrichment posture | W | W | W | W | W | W | W | W | W | W | W | W | W | N | W |
| 12. Supply-chain integrity | W | N | N | N | N | N | N | N | W | N | W | N | W | N | W |
| 13. ATT&CK Recon annotation | W | W | W | W | W | W | W | W | W | W | W | W | W | N | W |

**Pattern:** EXPOSE's structural wins concentrate in axes 2-4, 7-8, 10-13 (attribution, signed artifacts, self-host, dual audience, $0 floor, research, LLM transparency, supply chain, ATT&CK). Structural losses concentrate in axis 5 (FedRAMP authorization, where Cortex Xpanse holds the strongest position) and axis 9 (out-of-the-box CTEM-vendor adapters, correctly out of scope per ADR-004 but a procurement-conversation friction point). EXPOSE wins on architectural and integrity dimensions; loses on integration polish and authorized-managed-service maturity.

---

## 10. Strategic recommendations

1. **Lead with the four-property conjunction, not feature parity.** EXPOSE's defensible position is the conjunction of (a) continuous artifact, (b) attribution rigor, (c) cryptographic signing, (d) federal-deployable open-source substrate. No incumbent delivers all four. Marketing should anchor here rather than feature-by-feature comparison, where EXPOSE will lose on enrichment depth (Mandiant), data depth (Censys), remediation automation (Cortex), and cloud-native depth (Wiz).

2. **Avoid the FedRAMP-authorized framing war against Cortex Xpanse.** Cortex Xpanse holds FedRAMP High and EXPOSE will not dislodge it from managed-service federal evaluations where FedRAMP High is a hard requirement. The right framing is the **self-host alternative** — agencies that want to operate within their own authorization boundary, prefer open-source over inherited vendor authorization, or want the commercial-modular path rather than the platform-bundle path. Lead with self-host architectural credibility, not authorization head-to-head.

3. **Treat EXPOSE Research as long-term marketing infrastructure.** Almost no commercial EASI vendor publishes reference datasets. The academic-credibility-to-federal-credibility-to-commercial-credibility loop compounds over years. Sponsor an academic conference paper or two before public launch. Treat the eval harness epic as marketing infrastructure, not a side artifact. (Reinforces persona-analysis recommendation 2.)

4. **Per-persona sales motions matter more than per-vendor sales decks.** The three personas have different objections and different competitive matchups: red teamer vs. SpiderFoot / Bishop Fox; researcher vs. Censys / OSS recon; security director vs. Mandiant / Defender / Cortex. A single deck addressing all three loses all three. Build separate motions; the per-persona recap in §8 is the starting scaffold.

5. **Foreground supply-chain integrity in non-federal sales too.** Cosign signatures, SLSA L2+ attestations, and SBOMs serve EO 14028, NSM-22, and the broader supply-chain-security movement that extends well beyond federal. Commercial vendor questionnaires in financial services, healthcare, and critical infrastructure increasingly require this. The signed-artifact story compounds beyond FedRAMP.

6. **Dual-audience design is real but needs careful sales separation.** Defensive CTEM buyers are unsettled by the red-team angle; red-team buyers are unsettled by compliance-heavy framing. The three-layer pitch in `positioning.md` §5 already handles this — preserve the technical-buyer pitch for security architects and the strategic-buyer pitch for boards and federal program managers. **Do not collapse the two pitches into one slide deck.** The red team angle is a moat in capability and a friction point in defensive-buyer sales. Acknowledge that and separate the motions.

---

## 11. Open questions for follow-on work

- **CTEM platform adapter ecosystem** (Splunk, Sentinel, Chronicle, Cortex XSIAM, XSOAR). Out of scope for v1 per ADR-004; becomes a competitive question when the production-hardening epic adds the authenticated HTTPS API.
- **Pricing decision tree for commercial modules.** When does a customer need Core only vs. Core + Threat Context vs. Core + Identity Surface vs. all three? Persona analysis recommendation 5 already flagged this.
- **Federal sponsoring-agency relationship.** ADR-010 makes FedRAMP authorization conditional on a sponsoring agency. The competitive position against Cortex Xpanse strengthens materially once that relationship exists.
- **Analyst-relations strategy** for Gartner, Forrester, IDC. None of the major EASM Magic Quadrants currently include open-source-substrate vendors; EXPOSE's category fit is non-obvious. Worth a separate session.
- **Reference customers for the dual-audience claim.** A documented red team consultancy reference and a documented federal-self-host reference would dramatically strengthen the dual-audience positioning. Both are post-implementation milestones.

---

## 12. Recommended follow-on work

- **Session C (module specifications):** Recorded Future ASI is the relevant Threat Context comparison; SpiderFoot HX and Maltego with paid transforms are the relevant Identity Surface comparisons.
- **Session E (framework annotation):** Per-collector ATT&CK Reconnaissance annotation is a competitive differentiator no commercial EASM vendor matches. Make it visible in marketing materials and the canonical artifact.
- **Session G (Federal Customer Deployment Guide):** Upstream of any confident federal sales conversation against Cortex Xpanse. Prioritize.
- **Discrete go-to-market session** (not currently in the queue): per-persona sales decks, RFP response templates, Gartner/Forrester analyst-relations brief.

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

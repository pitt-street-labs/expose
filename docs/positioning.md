# FF6K — Positioning

**Status:** Locked — strategic foundation
**Date:** 2026-05-09
**Working codename:** FF6K (public name to be selected in subsequent session)

This document captures the locked strategic positioning for FF6K following the design conversations of 2026-05-09. It is the foundation document that subsequent specifications, marketing materials, and roadmap decisions reference.

## 1. The niche

FF6K occupies a specific, defensible niche within the External Attack Surface Intelligence (EASI) category:

> **Continuous, attributed, cryptographically signed external attack surface intelligence — engineered for both defensive Continuous Threat Exposure Management (CTEM) workflows and authorized red team operations — with a federal-deployable open-source substrate and a research-grade dataset offering, designed to produce structured input for downstream high-capability AI security analysis under appropriate safeguards.**

Each clause of this positioning cuts out a defined competitor or category. Together they define a niche that no incumbent currently occupies cleanly.

### 1.1 Niche-defining clauses, individually examined

**Continuous.** FF6K is not a point-in-time recon tool. It is a daily-cadence (or faster, where infrastructure permits) intelligence pipeline that produces deltable artifacts across years. This cuts out Recon-NG, theHarvester, Maltego, manual SpiderFoot OSS — point-in-time tools that produce snapshots without continuity.

**Attributed (with confidence tiers and provenance).** FF6K's defining technical contribution is rigorous attribution: every claim about an asset's ownership carries a confidence tier (`confirmed`, `high`, `medium`, `requires_review`) and a full evidence chain back to the collector observation that justified it. This cuts out Shodan and Censys raw feeds — they are data sources without organizational attribution as a first-class concept. It also cuts out most "data lake" EASI products that emphasize volume over defensible attribution.

**Cryptographically signed.** Every artifact FF6K produces is cosign-signed with full provenance attestations. No major incumbent in the EASM/EASI space produces tamper-evident, cryptographically signed deliverables. This is genuinely novel and aligns with FedRAMP-ready architecture, supply-chain integrity standards (SLSA, in-toto), and the broader software supply chain security movement (Executive Order 14028, NSM-22). This cuts out essentially everyone in the commercial EASM space.

**Engineered for both defensive CTEM AND authorized red team operations.** Most commercial EASM tools (Mandiant ASM, Microsoft Defender EASM, CrowdStrike Falcon Surface, Tenable ASM, Wiz EASM) are positioned purely for defensive use. Most offensive recon tooling (SpiderFoot, Recon-NG, Amass) is positioned purely for offensive use and produces outputs that are unsigned, ephemeral, and difficult to integrate with CTEM workflows. FF6K's dual-audience design is unusual and reflects a deliberate architectural choice — the artifact contract is identical for both audiences, with authorization scope and ethics layer determining what each operator does with the output.

**Federal-deployable open-source substrate.** Apache 2.0 engine, FedRAMP-ready architecture (per ADR-010), federal customers can self-host within their own authorization boundary and integrate FF6K artifacts into their own continuous monitoring program. This cuts out commercial-only SaaS products that require federal customers to inherit the vendor's authorization or wait for a vendor's authorization to mature.

**Research-grade dataset offering.** FF6K Research will publish reference datasets, schemas, and example graphs that the cybersecurity research community can use without operating the pipeline themselves. Almost no one in the commercial EASI space publishes reference datasets. Researchers either pay for commercial APIs (Censys, Shodan) or build their own. This is a credibility-building move for academic engagement, federal-research adoption, and the broader scientific contribution the project intends.

**Designed to produce structured input for downstream high-capability AI security analysis.** The two-environment architecture (Environment 1 = FF6K deterministic engine; Environment 2 = downstream LLM-driven analysis under appropriate safeguards) is genuinely unusual in the security tooling landscape. No commercial EASM vendor has architected for high-capability autonomous LLM downstream consumption with air-gapped handoff and signed inputs. This is a moat that strengthens as Mythos-class capabilities reach broader research and operational access.

### 1.2 What this niche is NOT

Equally important — FF6K is *not*:

- A vulnerability scanner. Nessus, OpenVAS, Qualys, Tenable.io are vulnerability management tools that operate against authenticated assets. FF6K observes external surface and attributes it; it does not enumerate CVEs against authenticated systems.
- An exploitation framework. Metasploit, Cobalt Strike, Nuclei (in some configurations) are post-discovery offensive tools. FF6K produces leads; it does not exploit them.
- A Cyber Threat Intelligence (CTI) platform. Recorded Future, Mandiant Threat Intelligence, CrowdStrike Falcon Intelligence are threat-actor and adversary-tracking platforms. FF6K Threat Context (the commercial module) consumes CTI to enrich attribution, but the core engine is not a CTI product.
- A CAASM (Cyber Asset Attack Surface Management) tool. CAASM products like JupiterOne, Axonius, runZero focus on internal asset inventory across cloud and on-prem. FF6K is external-surface-only.
- A bot-detection or anti-fraud platform. PerimeterX/HUMAN Security, Akamai Bot Manager, Cloudflare Bot Management protect web apps from automated abuse. Different category entirely.

## 2. The MITRE ATT&CK anchor

FF6K is anchored in **Reconnaissance (Tactic TA0043)** — the first tactic in the MITRE ATT&CK Enterprise matrix and the first phase of both the Lockheed Martin Cyber Kill Chain and the Unified Kill Chain. This is the only ATT&CK tactic that occurs entirely *before* an adversary has touched target infrastructure, which makes it the natural domain for a defensive tool that produces input for CTEM workflows.

### 2.1 ATT&CK Reconnaissance technique coverage

Every collector and attribution rule in FF6K is annotated against specific ATT&CK Reconnaissance techniques:

| ATT&CK Technique | FF6K Coverage |
|---|---|
| T1595 — Active Scanning | Tier 3 active probing collectors (DNS resolution, TLS handshake, HTTP fingerprinting) |
| T1595.001 — Scanning IP Blocks | Cloud provider IP range manifest collectors |
| T1595.002 — Vulnerability Scanning | Out of scope for FF6K Core (defensive use case) |
| T1595.003 — Wordlist Scanning | Out of scope for FF6K Core (defensive use case) |
| T1592 — Gather Victim Host Information | HTTP fingerprinting, banner collection, TLS certificate analysis |
| T1592.001 — Hardware | Out of scope (limited public observability) |
| T1592.002 — Software | Tech stack inference (Wappalyzer rules, header analysis, LLM enrichment) |
| T1592.003 — Firmware | Out of scope (limited public observability) |
| T1592.004 — Client Configurations | Limited coverage via TLS fingerprinting |
| T1589 — Gather Victim Identity Information | WHOIS/RDAP collectors, registrant pivots |
| T1589.001 — Credentials | Out of scope (FF6K does not handle leaked credentials in Core) |
| T1589.002 — Email Addresses | WHOIS contact data (with PII handling per ETHICS.md) |
| T1589.003 — Employee Names | Identity Surface module only (commercial, separate ethics surface) |
| T1590 — Gather Victim Network Information | DNS, BGP, ASN collectors; cohabitation analysis |
| T1591 — Gather Victim Org Information | Organizational attribution rules, registrant pivots, cloud account attribution |
| T1593 — Search Open Websites/Domains | CT log collectors, passive DNS, search-engine-style queries |
| T1594 — Search Victim-Owned Websites | Limited coverage (Tier 3, attribution-gated) |
| T1597 — Search Closed Sources | Threat Context module (commercial, dark-web sources) |

Every artifact FF6K produces carries the ATT&CK technique IDs that contributed to its attribution decision. Auditors, federal customers, and analysts can trace any FF6K finding back to a specific ATT&CK technique.

### 2.2 Why Reconnaissance is the right anchor and not "phases 1 and 2"

The earlier framing of "phases 1 and 2 of MITRE ATT&CK" conflated Reconnaissance (TA0043) with Resource Development (TA0042). After the design discussion of 2026-05-09, the position is:

- **Reconnaissance (TA0043)** is the primary anchor for FF6K Core (the open-source engine). This is where the product's deterministic, attribution-focused capability lives.
- **Resource Development (TA0042)** monitoring — detecting adversary infrastructure being prepared against the operator (typosquats, staging infrastructure, leaked credentials in markets, dark-web indicators) — is the domain of FF6K Threat Context (commercial module). It is adjacent to but architecturally separate from Core.

This separation is not arbitrary. The two tactics have fundamentally different data sources, different ethics surfaces, different threat models, and different competitive landscapes. Bundling them into one product creates a "we do everything" pitch that is harder to defend technically and harder to position commercially.

### 2.3 Other framework alignment

FF6K's framework annotation extends beyond ATT&CK to the frameworks federal and enterprise customers use to evaluate security tools:

- **NIST Cybersecurity Framework 2.0** — primary alignment with the **Identify** function (ID.AM Asset Management, ID.RA Risk Assessment).
- **NIST SP 800-53 Rev 5** — controls primarily in CA (Assessment, Authorization, and Monitoring), CM (Configuration Management), RA (Risk Assessment), and SI (System and Information Integrity) families.
- **NIST AI Risk Management Framework** — applicable to LLM enrichment subsystem (Govern, Map, Measure, Manage functions).
- **CIS Critical Security Controls v8** — primary alignment with Control 1 (Inventory and Control of Enterprise Assets), Control 2 (Software Inventory).
- **OWASP Application Security Verification Standard (ASVS) 4.0** — internal API surface compliance.
- **OWASP AI Security Verification Standard (AISVS)** — LLM provider integration compliance.
- **CSA Cloud Controls Matrix (CCM) v4** — cloud-deployment alignment.
- **MITRE D3FEND** — defensive countermeasure mapping (counterpart to ATT&CK).

The framework annotation work itself is a subsequent session deliverable. This positioning document establishes that the alignment will exist; the detail follows.

## 3. The competitive cut

FF6K's competitive positioning is best understood by what each clause of the niche cuts out. Three layers:

### 3.1 Direct competitors (commercial EASM/EASI category)

| Vendor | Positioning vs. FF6K |
|---|---|
| Microsoft Defender EASM (formerly RiskIQ) | Commercial SaaS, Microsoft ecosystem-tied, no open-source substrate, no signed artifacts, defensive-only |
| Mandiant Advantage ASM (Google Cloud) | Commercial SaaS, FedRAMP-authorized, no open-source substrate, defensive-focused, no AI-enriched attribution architecture |
| Censys ASM | Commercial SaaS, data-source pivot from Censys raw, strong data depth, no signed artifacts, defensive-focused |
| CrowdStrike Falcon Surface | Commercial SaaS, integrated with broader Falcon platform, no open-source substrate, defensive-only |
| Tenable Attack Surface Management | Commercial SaaS, integrated with Tenable vulnerability management, no open-source substrate, defensive-focused |
| Palo Alto Cortex Xpanse | Commercial SaaS, deep enterprise integration, no open-source substrate, defensive-focused |
| Wiz EASM | Cloud-native focus (excellent), commercial SaaS, no signed artifacts, defensive-only |
| Detectify EASM | Commercial SaaS, web-application focus, no open-source substrate |
| Bishop Fox CAST | Hybrid service-and-tool, manual analyst integration, not a pure product |
| IBM Randori | Commercial SaaS, attack-emulation focus, no open-source substrate |
| SecurityScorecard ASI | Commercial SaaS, ratings-platform-tied, no signed artifacts, defensive-focused |
| Recorded Future ASI | Commercial SaaS, threat-intelligence-tied, no open-source substrate, no signed artifacts |
| ZeroFox | Commercial SaaS, brand-protection-focused, no open-source substrate |

Common pattern: all are commercial SaaS, all are defensive-focused, none produce cryptographically signed artifacts, none have open-source substrates that federal customers can self-host. FF6K's differentiation against this category is structural, not feature-incremental.

### 3.2 Open-source recon tooling (different category, adjacent)

| Tool | Positioning vs. FF6K |
|---|---|
| SpiderFoot OSS / SpiderFoot HX | Closest analog. Point-in-time recon, broad data source coverage, no signed artifacts, no FedRAMP-ready architecture, no continuous attribution model. HX is commercial SaaS. |
| Recon-NG | Modular recon framework, point-in-time, no continuous mode, no signed artifacts, manual workflows |
| OWASP Amass | DNS-focused subdomain enumeration, point-in-time, excellent for what it does, narrower scope |
| theHarvester | Email/subdomain harvesting, point-in-time, narrow scope |
| Maltego | Graph-visualization tool with paid transforms, manual workflow, no continuous operation |
| Shodan / Censys (raw) | Data sources, not products. FF6K consumes these via collector adapters. |

These are tools FF6K's open-source engine competes with on capability but is differentiated from on operational model (continuous vs. point-in-time), output discipline (signed artifacts vs. ad-hoc reports), and architectural posture (FedRAMP-ready vs. researcher-tool).

### 3.3 CTI and CAASM (different categories, occasional overlap)

| Tool | Positioning vs. FF6K |
|---|---|
| Recorded Future Intelligence Cloud | CTI platform, FF6K Threat Context will consume CTI feeds; not a direct competitor |
| Mandiant Threat Intelligence | CTI platform, similar relationship |
| JupiterOne / Axonius / runZero (CAASM) | Internal asset inventory, different category from external surface |

These products are integration partners or upstream data sources, not competitors.

## 4. The federal procurement framing

Per ADR-010, FF6K is FedRAMP-ready by design without pursuing FedRAMP authorization for the open-source engine itself. The federal-procurement framing is:

**For federal agencies wanting to use FF6K Core:** self-host the open-source Apache 2.0 engine within your existing authorization boundary. FF6K Core's architecture (FIPS 140-3 validated cryptography, NIST 800-53 control alignment, audit logging to AU-family standards, FedRAMP-aligned configuration patterns) is built so that integration into an agency's existing ATO is feasible. The Federal Customer Deployment Guide (subsequent deliverable) documents exactly which controls FF6K satisfies, which require agency-side implementation, and what evidence the engine produces for continuous monitoring.

**For federal agencies wanting managed service:** the future Korlogos commercial SaaS offering will pursue FedRAMP authorization (Moderate baseline, Agency ATO sponsorship pathway preferred). Authorization is a roadmap-future business decision, not a v1 deliverable. The architectural readiness in v1 makes future authorization significantly cheaper than greenfield FedRAMP work.

This dual-path approach mirrors successful patterns in the federal cybersecurity space: agencies can adopt the open-source tool immediately within their own ATOs, and migrate to the FedRAMP-authorized commercial offering when operational scale justifies managed service. CISA, NSA, and DHS all have precedent for this pattern with other tools.

### 4.1 What the open-source engine offers federal customers

- Self-hostable software the agency operates within its own authorization boundary
- FIPS 140-3 validated cryptography in all modes (TLS, signing, hashing, key management)
- Audit logging compliant with NIST 800-53 AU-family controls
- Supply-chain integrity evidence (SBOMs, cosign signatures, SLSA Level 2+ attestations) for the agency's own continuous monitoring
- Documented control mapping showing which NIST 800-53 controls FF6K satisfies, partially satisfies, or requires agency-side implementation
- Continuous monitoring outputs in formats compatible with CDM (Continuous Diagnostics and Mitigation) ingestion patterns

### 4.2 What the commercial Korlogos offering will eventually offer (roadmap-future)

- FedRAMP Moderate authorization (target)
- Korlogos-managed deployment with full operational responsibility
- StateRAMP and CMMC pathways considered
- Threat Context and Identity Surface modules with their own commercial licenses
- Federal-customer-specific support, integration assistance, and continuous monitoring participation
- Federal-customer-curated rule packs

## 5. The narrative pitch (in three layers)

Different audiences need different framings. The positioning supports three layers, each appropriate for its audience.

### 5.1 The casual-conversation pitch (humorous, accurate enough)

> "It's the tool that lets you map an organization's external attack surface continuously, with attribution you can defend, in a signed artifact your downstream tools can trust. We took the work that a team of skilled-but-junior operators would do over three days with Kali and made it run in hours with AI assist — and made the output something a federal agency or a Fortune 500 CISO can actually rely on."

This is the elevator-pitch version. It lands the speed/automation point and gestures at the rigor.

### 5.2 The technical-buyer pitch

> "FF6K is an open-source External Attack Surface Intelligence platform that produces continuous, attributed, cryptographically signed artifacts from public data sources. Unlike commercial EASM tools, it's federal-deployable and designed for both defensive CTEM and authorized red team workflows. The architecture is FedRAMP-ready by design — federal agencies self-host within their own authorization boundary and integrate the artifacts into their continuous monitoring. The two-environment design separates the deterministic discovery substrate from downstream high-capability AI analysis, which lets you pair this with research-grade LLM tooling under your own safety controls."

This is for security architects, federal CISOs, technical evaluation conversations.

### 5.3 The strategic-buyer pitch

> "The category leaders in attack surface management are commercial SaaS — they require federal customers to wait for vendor authorization, they don't produce auditable signed artifacts, and they're architecturally locked to defensive-only use. FF6K is the federal-deployable open-source alternative with cryptographic integrity built in, designed to interoperate with both your CTEM workflows and your authorized red team operations, with a research-grade public dataset that supports academic and government cybersecurity research. The commercial offering follows the open-source engine — federal customers can adopt the tool today and grow into managed service when the operational scale justifies it."

This is for board-level conversations, federal program manager discussions, strategic partnership evaluations.

## 6. The product structure

Per ADR-009, FF6K is structured as an open-core engine plus separate proprietary commercial modules and a research dataset offering:

- **FF6K Core** (open-source, Apache 2.0) — the engine. EASI substrate. Self-hostable. FedRAMP-ready by design. Produces signed JSON graph artifacts.
- **FF6K Threat Context** (commercial, separate license) — APT targeting profiles, dark-web IoAc/IoI/IoP enrichment, historical point-in-time enrichment, MITRE ATT&CK Resource Development tactic monitoring. Consumes Core artifacts, produces enriched artifacts.
- **FF6K Identity Surface** (commercial, separate license, higher ethics bar) — WHOIS-personnel and authorized social-media tangential targets, scope-gated, off by default.
- **FF6K Research** (open dataset, separate licensing for the data) — reference graph datasets, schemas, benchmarks for academic and federal-research use. Published periodically. The published datasets are sourced from public observations of operator-authorized research targets, not from customer deployments.

This structure preserves Apache 2.0 community engagement for Core while protecting commercial value in the modules. See ADR-009 for full rationale.

## 7. What this positioning enables

This positioning is the foundation for several subsequent work streams that can now run in parallel:

- **Competitive analysis (deeper).** Detailed technical comparison against SpiderFoot HX, Mandiant ASM, Censys ASM, Microsoft Defender EASM. Subsequent session.
- **Module specifications.** SPEC.md, ETHICS.md, threat models, schemas for FF6K Threat Context and FF6K Identity Surface. Subsequent session.
- **Novel AI-leverage roadmap.** Beyond the three commercialization ideas already discussed, the additional AI capabilities that strengthen the moat. Subsequent session.
- **Framework annotation deep-dive.** Mapping every FF6K capability against MITRE ATT&CK, NIST CSF, NIST SP 800-53, OWASP ASVS/AISVS, CIS Controls. Subsequent session.
- **Secure Development Lifecycle Plan (SDLP).** The pre-implementation security posture document. Subsequent session.
- **Federal Customer Deployment Guide.** The integration document for federal agencies self-hosting FF6K Core within their ATOs. Subsequent session.
- **Public name selection.** The naming session, conducted with positioning locked. Subsequent session.

Each subsequent session has a clear scope, a stable foundation to build on, and produces an artifact that can be developed by an agent team in parallel with others.

## 8. What this positioning rules out (so we don't drift later)

- We do not pivot to vulnerability scanning. We produce leads; vulnerability scanning is a different category.
- We do not pivot to active exploitation. FF6K never exploits, never validates vulnerabilities through exploitation, never delivers exploitation toolchains.
- We do not pivot to internal asset inventory. CAASM is a different category and FF6K does not extend inside the operator's network.
- We do not pivot to defensive-only positioning. The dual-audience design (defensive CTEM + authorized red team) is a deliberate strategic choice and a moat.
- We do not pursue FedRAMP authorization for the open-source engine. The architecture is ready; authorization is for the future commercial offering only.
- We do not bundle Resource Development monitoring into Core. Threat Context is a separate commercial module.
- We do not abandon the two-environment design. Environment 1 produces structured input; Environment 2 (out of scope for this codebase) consumes for narrative analysis under appropriate safeguards.

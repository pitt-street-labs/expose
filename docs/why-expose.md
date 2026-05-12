# Why EXPOSE?

The External Attack Surface Management (EASM) category is mature. Mandiant, Censys, Microsoft, CrowdStrike, Palo Alto, and a dozen others sell products that discover your internet-facing assets and tell you what is exposed. They work. Many of them work well.

So why build another one?

Because none of them deliver the combination of properties that matters. EXPOSE exists to close that gap -- not by out-featuring incumbents on any single dimension, but by delivering a conjunction of capabilities no incumbent offers together.

---

## What makes EXPOSE different

### 1. Attribution intelligence -- not just asset discovery

Most EASM tools produce asset inventories: lists of IPs, domains, and certificates associated with an organization. An analyst receives "we found these things" and then spends hours manually attributing each one, correlating WHOIS records, certificate chains, DNS resolution, and organizational knowledge to decide what actually belongs to the target.

EXPOSE automates this work with a structured attribution engine:

- **12 attribution predicates** evaluated in recursive AND/OR/NOT condition trees against the observation graph
- **Confidence tiers** (`confirmed` >= 0.95, `high` >= 0.75, `medium` >= 0.50, `requires_review`) with numeric scores on every claim
- **Full evidence chains** -- every attribution decision traces back to the specific collector observation and rule that produced it
- **Declarative rule packs** -- attribution logic is defined as JSON Schema-validated data files, not buried in code. Auditors, compliance officers, and researchers can inspect exactly how every decision was made
- **Configurable organizational profiles** -- cloud-first, conservative, government-aligned rule packs tailor attribution behavior to the operating environment

When a red team operator says "this asset is in scope," the evidence chain is right there. When a CISO presents external surface to a board, every claim is defensible. When a federal auditor asks how an attribution decision was reached, the answer is a data file and a provenance record.

No commercial EASM vendor exposes programmatic, auditable attribution logic with per-claim provenance chains.

### 2. SOC threat package -- bridging EASM to security operations

When EXPOSE discovers target-owned assets that appear on DNS blocklists, have degraded trust indicators, show infrastructure shifts, or exhibit compromise patterns, it does not just flag them in a dashboard. It packages them as **actionable Indicators of Compromise (IoCs) and Indicators of Attack (IoAs)** for SOC teams to hunt internally.

- **Output formats:** STIX 2.1 bundles, MISP events, CSV with SIEM field mapping, JSON IoC feed
- **SIEM push integration** via Splunk HEC, Microsoft Sentinel, and Google Chronicle adapters -- findings flow directly into the SOC's existing tooling
- **LLM-generated hunt recommendations** (Environment 2): what internal logs to search, what network patterns to look for, suggested Splunk SPL / KQL / Chronicle YARA-L queries tailored to the specific finding
- **Automated triage context** -- each IoC carries the attribution confidence, the discovery timeline, and the evidence chain so the SOC analyst can prioritize without re-investigating

Today, bridging EASM findings into SOC workflows requires manual analyst effort -- exporting from the EASM tool, reformatting for the SIEM, writing hunt queries by hand. EXPOSE eliminates that gap. No competitor does this natively.

### 3. Two-environment architecture -- deterministic engine plus LLM analysis

Every competitor that uses AI treats it as a black box. You send your data to their cloud, their model runs, you get a result you cannot inspect, reproduce, or cost-control.

EXPOSE separates concerns into two environments:

**Environment 1 (this platform)** is the deterministic discovery and attribution engine. Given the same seeds, the same rule pack, and the same configuration, it produces the same canonical artifact. Every decision is auditable and reproducible. This matters for regulators who need to trace the decision chain, federal customers who require deterministic systems, and legal teams who need to defend attribution decisions.

**Environment 2** is a separate downstream system that consumes EXPOSE's signed artifacts for high-capability LLM-driven analysis -- threat assessment, hunt recommendation generation, strategic reporting. The separation is architectural, not incidental.

Within Environment 1, EXPOSE's `SafeLLMClient` provides bounded LLM enrichment with full operator control:

- **Four provider adapters** -- Anthropic, OpenAI, Gemini, and local Ollama (fully offline, never leaves your network)
- **Operator sees every prompt** and every response
- **Per-run cost ceilings** enforced by the client
- **Structured-output validation** against JSON schemas before any LLM output enters the artifact
- **Per-call audit logging** for compliance evidence

The AI enriches; it does not decide. The deterministic engine decides. Competitors either have no LLM integration or mix it in opaquely with no operator visibility.

### 4. Federal-ready architecture

Federal agencies face a specific version of the EASM problem: they need continuous external surface monitoring, but commercial SaaS tools require either inheriting the vendor's FedRAMP authorization or waiting years for one to mature. Meanwhile, the agency's external surface is expanding daily.

EXPOSE offers an alternative path. Self-host the Apache 2.0 engine within your existing authorization boundary:

- **FIPS 140-3 validated cryptography** in all modes -- all crypto operations route through a centralized `fips_adapter`, never raw `hashlib` or `secrets`
- **NIST SP 800-53 control alignment** with documented mapping per control family (AU-2/AU-3 audit logging, CA-7 continuous monitoring, RA-5 vulnerability scanning, SI-family system integrity)
- **Air-gap artifact consumption** -- the engine requires internet egress for collection, but produced artifacts can be transported to air-gapped environments for downstream analysis
- **Ed25519/ECDSA artifact signing** with content-addressed evidence storage and provenance chains satisfying EO 14028 and NSM-22 supply-chain integrity requirements
- **CDM-compatible output** -- structured JSON artifacts with stable schemas feed directly into agency Continuous Diagnostics and Mitigation programs
- **Append-only, retention-aware audit logging** producing the continuous evidence stream federal continuous monitoring requires

This represents 12-18 months of compliance engineering that competitors would need to replicate. Agencies deploy EXPOSE Core inside their existing High ATO without waiting for a vendor authorization cycle.

### 5. Open-core with commercial modules

The EXPOSE engine is Apache 2.0 licensed. The engine, schemas, rule packs, and eval datasets are open source. Community-contributed rule packs improve attribution accuracy for everyone, creating a network effect.

Commercial modules extend the platform for enterprise and federal buyers:

| Module | Capability |
|---|---|
| **EXPOSE Threat Context** | Adversary-infrastructure monitoring (MITRE ATT&CK Resource Development, TA0042), dark web indicators, threat actor profiling, vertical-specific threat landscape |
| **EXPOSE Identity Surface** | M&A-aware asset discovery via registrant pivot analysis, organizational graph construction, fuzzy registrant matching -- finds assets that acquired companies forgot about |
| **SOC Threat Package** | STIX 2.1 / MISP packaging, SIEM push adapters, LLM hunt recommendations |
| **CISO Strategic Report** | Executive-level reporting with sector threat landscape, threat actor profiling, attraction assessment, and ranked likely targets |

The open core drives adoption. The commercial modules drive revenue. The community rule packs drive accuracy. Each reinforces the others.

### 6. 40 collectors with MITRE ATT&CK mapping

EXPOSE ships 40 built-in collectors across three sensitivity tiers, each annotated with the specific MITRE ATT&CK Reconnaissance (TA0043) techniques it exercises. Federal customers and auditors trace any finding to a specific technique.

**Tier 1 -- Passive, Broad** (no target contact): Certificate Transparency (crt.sh, Certstream, Censys CT, Certspotter), RDAP/WHOIS, BGP/ASN (Hurricane Electric, RIPEstat, Team Cymru), cloud IP range manifests (AWS/Azure/GCP), email authentication (SPF/DKIM/DMARC), GitHub organization enumeration, DNS blacklist reputation, passive DNS history (SecurityTrails, VirusTotal), M&A subsidiary discovery, OTX/AlienVault, Common Crawl, Wikipedia edit monitoring, paste site monitoring, mail header analysis, git commit email extraction.

**Tier 2 -- Passive, Targeted** (queries about specific entities already in the graph): favicon hashing, reverse PTR lookup, WAF/CDN detection and origin-IP discovery, internet-wide scan databases (Shodan, Censys, BinaryEdge), screenshot vision analysis, cloud storage exposure, security.txt and robots.txt parsing, SIP discovery, Wayback Machine.

**Tier 3 -- Active, Attribution-Gated** (sends packets to target infrastructure): active DNS resolution, TLS handshake with JARM fingerprinting, HTTP fingerprinting, TCP port surface enumeration, subdomain brute-force, DNS zone transfer, DNS CHAOS queries, WAF origin discovery.

Tier 3 dispatch is centrally gated by the attribution engine -- an active collector can only fire against entities with `confirmed` or `high` attribution confidence, or explicit authorization scope membership. This is enforced by the dispatcher, not by individual collectors.

### 7. Cryptographically signed artifacts

Every artifact EXPOSE produces is signed with Ed25519 or ECDSA P-256, with SLSA-aligned provenance attestations and FIPS SHA-256 content hashing. The artifact is tamper-evident. Downstream consumers -- your SIEM, your auditors, your client in a red team engagement -- can verify integrity offline without trusting the producing infrastructure.

No major commercial EASM vendor produces signed deliverables. In a post-EO 14028 world where supply-chain integrity is a federal procurement requirement, this is not a nice-to-have.

---

## Own your data

SaaS EASM products hold your attack surface data in their cloud. You query their API. You export their reports. If you cancel, your historical attack surface intelligence -- years of delta data showing how your perimeter evolved -- stays behind a paywall or disappears entirely.

EXPOSE produces portable artifacts. Signed JSON files you own, store wherever you want, and verify offline. Your attack surface history is yours. Feed it into Splunk, Sentinel, Chronicle, a Jupyter notebook, or a filing cabinet. The artifact is the deliverable, not the subscription.

---

## Dual-audience design

Most EASM tools are built for one audience: the defensive security team running a continuous monitoring program. Red team operators use different tools -- SpiderFoot, Recon-NG, Amass, manual correlation. The two audiences produce different outputs in different formats with different levels of rigor, and then spend hours reconciling when the engagement report lands.

EXPOSE serves both. The same engine, the same artifact contract, the same attribution model. The difference is authorization scope, not tooling. A defensive team runs EXPOSE against their own organization for CTEM. A red team runs it against an authorized target for engagement scoping. Both get the same signed artifact with the same evidence chains. When the red team delivers findings and the blue team triages them, they are working from the same data structure. The reconciliation gap disappears.

This is a deliberate architectural choice, not an afterthought. The scope matcher enforces authorization boundaries. The ethics layer detects misuse patterns. The artifact does not change shape depending on who runs it.

---

## Comparison with the market

The EASM market is large ($1.5B+ as of 2026, growing ~25% YoY) and consolidating through acquisition. Palo Alto acquired Expanse (~$800M). Microsoft acquired RiskIQ (~$500M). CrowdStrike acquired Reposify. Intel 471 acquired SpiderFoot. IBM acquired Randori. The pattern: large platform vendors absorbing EASM point solutions to bundle with their existing stack.

EXPOSE occupies a different position -- the intersection of EASM, threat intelligence, and SOC automation -- a category that currently requires 2-3 separate tools.

| Capability | Censys ASM | Shodan Monitor | MS Defender EASM | Palo Alto Xpanse | Mandiant ASM | RiskIQ (legacy) | EXPOSE |
|---|---|---|---|---|---|---|---|
| **Attribution with provenance** | Proprietary | None | Proprietary | Proprietary | Proprietary | Proprietary | Open rule packs, per-claim evidence chains |
| **Confidence tiers** | Internal | None | Internal | Internal | Internal | Internal | 4 tiers, numeric scores, predicate vocabulary |
| **Signed artifacts** | No | No | No | No | No | No | Ed25519/ECDSA + SLSA provenance |
| **Self-host pathway** | No | No | No | No | No | No | Apache 2.0, deploy inside your ATO |
| **FIPS 140-3 architecture** | No | No | Partial (Azure) | Unknown | Unknown | No | Built in, all crypto via fips_adapter |
| **SOC threat packaging** | No | No | No | No | No | No | STIX 2.1, MISP, SIEM push adapters |
| **Dual audience (CTEM + red team)** | Defensive | Ad hoc | Defensive | Defensive | Defensive | Defensive | Structural (authorization scope model) |
| **Operator-controlled LLM** | No | No | No | No | No | No | Multi-provider, cost-capped, audited |
| **Open-source core** | No | No | No | No | No | No | Apache 2.0 |
| **Research datasets** | No | No | No | No | No | No | CC BY 4.0 reference graphs |
| **ATT&CK technique mapping** | No | Informal | No | No | No | No | Per-collector TA0043 annotation |
| **Pricing floor** | Enterprise | Freemium (limited) | $0.011/asset/day | Enterprise | Enterprise | Deprecated | $0 (Core) |

**Where EXPOSE does not compete:** EXPOSE is not a vulnerability scanner (Nessus, Qualys, Tenable), not an exploitation framework (Metasploit, Cobalt Strike), not a CAASM tool (JupiterOne, Axonius, runZero), and not a CTI platform (Recorded Future, Mandiant Threat Intelligence). It produces attributed leads about external surface. What you do with those leads is your workflow.

---

## The AI question, answered honestly

"AI-powered" is the most overused phrase in security marketing. Here is what EXPOSE actually does with AI, and what it does not.

**What AI does in EXPOSE:** Multi-provider LLM enrichment supplements deterministic analysis. When the rule engine identifies an asset but cannot confidently attribute it from structured data alone, the LLM enrichment layer provides a structured assessment. The operator sees the prompt. The operator sees the response. The operator controls which provider runs and how much it costs. The output is validated against a schema before it enters the artifact.

**What AI does not do in EXPOSE:** AI does not make scope decisions. AI does not determine attribution confidence tiers. AI does not sign artifacts. AI does not replace the deterministic engine. The engine is reproducible -- given the same inputs, it produces the same artifact. The AI enrichment is an optional layer that adds signal; it is not the decision-maker.

---

## For researchers

Almost no commercial EASM vendor publishes reference datasets. Researchers either pay for API access or build their own collection infrastructure. Reproducibility suffers. Attribution methodologies cannot be benchmarked against common baselines.

EXPOSE Research publishes reference graph datasets under CC BY 4.0, alongside the Apache 2.0 engine that produced them. The eval harness provides a framework for benchmarking attribution accuracy against curated datasets with known ground truth. If you are publishing a paper on attack surface attribution methodology, EXPOSE gives you a reproducible engine, open rule packs, and a reference dataset to cite.

---

## Getting started

EXPOSE is Apache 2.0 licensed. The engine, schemas, rule packs, and eval datasets are open source.

- Repository: [github.com/pitt-street-labs/expose](https://github.com/pitt-street-labs/expose)
- Specification: `docs/SPEC.md`
- Architecture decisions: `docs/adr/`
- Quickstart guide: `docs/quickstart.md`
- Example rule packs: `examples/rulepacks/`

Commercial modules (Threat Context, Identity Surface, SOC Package, CISO Report) and the managed-service offering are separately licensed and follow the open-source engine.

# Why EXPOSE?

The External Attack Surface Management (EASM) category is mature. Mandiant, Censys, Microsoft, CrowdStrike, Palo Alto, and a dozen others sell products that discover your internet-facing assets and tell you what is exposed. They work. Many of them work well.

So why build another one?

Because none of them deliver the four properties that matter simultaneously. EXPOSE exists to close that gap.

---

## The four-property conjunction

EXPOSE's value is not any single feature. It is the conjunction of four properties that no incumbent delivers together:

**1. Cryptographically signed artifacts.** Every artifact EXPOSE produces is cosign-signed with SLSA provenance attestations. The artifact is tamper-evident. Downstream consumers -- your SIEM, your auditors, your client in a red team engagement -- can verify integrity offline without trusting the producing infrastructure. No major commercial EASM vendor produces signed deliverables. In a post-EO 14028 world where supply-chain integrity is a federal procurement requirement, this is not a nice-to-have.

**2. Attribution rigor with provenance.** EXPOSE does not just discover assets. It attributes them -- and every attribution carries a confidence tier (`confirmed`, `high`, `medium`, `requires_review`) with a full evidence chain back to the collector observation and rule that produced it. When a red team operator says "this asset is in scope," the evidence chain is right there. When a security director presents external surface to a board, every claim is defensible. Most EASM tools produce lists of discovered assets. EXPOSE produces claims with evidence.

**3. Operator-controlled AI.** Every competitor that uses AI treats it as a black box. You send your data to their cloud, their model runs, you get a result you cannot inspect, reproduce, or cost-control. EXPOSE's `SafeLLMClient` lets you choose the provider (Anthropic, OpenAI, Gemini, or a local Ollama instance that never leaves your network), see every prompt, set a per-run cost ceiling, and validate every output against the structured-output schema. The AI enriches; it does not decide. The deterministic engine decides. You control the AI, not the other way around.

**4. Federal-deployable open core.** The engine is Apache 2.0. Federal agencies self-host EXPOSE Core within their existing authorization boundary. The architecture is FedRAMP-ready by design -- FIPS 140-3 cryptography, NIST 800-53 control mapping, AU-family audit logging -- so integration into an agency's ATO is a configuration exercise, not a re-architecture. No waiting for a vendor's FedRAMP authorization. No inheriting a vendor's security posture. The commercial managed-service offering follows separately for agencies that want it.

Any one of these properties is useful. The conjunction is rare. As of this writing, no incumbent in the EASM category delivers all four.

---

## Own your data

SaaS EASM products hold your attack surface data in their cloud. You query their API. You export their reports. If you cancel, your historical attack surface intelligence -- years of delta data showing how your perimeter evolved -- stays behind a paywall or disappears entirely.

EXPOSE produces portable artifacts. Signed JSON files you own, store wherever you want, and verify offline. Your attack surface history is yours. You can feed it into Splunk, Sentinel, Chronicle, a Jupyter notebook, or a filing cabinet. The artifact is the deliverable, not the subscription.

---

## Dual-audience design

Most EASM tools are built for one audience: the defensive security team running a continuous monitoring program. Red team operators use different tools -- SpiderFoot, Recon-NG, Amass, manual correlation. The two audiences produce different outputs in different formats with different levels of rigor, and then spend hours reconciling when the engagement report lands.

EXPOSE serves both. The same engine, the same artifact contract, the same attribution model. The difference is authorization scope, not tooling. A defensive team runs EXPOSE against their own organization for CTEM. A red team runs it against an authorized target for engagement scoping. Both get the same signed artifact with the same evidence chains. When the red team delivers findings and the blue team triages them, they are working from the same data structure. The reconciliation gap disappears.

This is a deliberate architectural choice, not an afterthought. The scope matcher enforces authorization boundaries. The ethics layer detects misuse patterns. The artifact does not change shape depending on who runs it.

---

## Where EXPOSE fits (and where it does not)

EXPOSE is anchored in MITRE ATT&CK Reconnaissance (TA0043) -- the first tactic in the Enterprise matrix, the phase that occurs entirely before an adversary touches target infrastructure. Every collector and attribution rule is annotated against specific ATT&CK Reconnaissance techniques. Auditors and federal customers can trace any finding to a specific technique.

What EXPOSE is not:

- **Not a vulnerability scanner.** EXPOSE produces leads about your external surface. It does not enumerate CVEs against authenticated systems. Nessus, Qualys, and Tenable.io are different tools for a different job.
- **Not an exploitation framework.** EXPOSE never exploits, never validates vulnerabilities through exploitation, never delivers offensive payloads. Metasploit and Cobalt Strike are post-discovery tools. EXPOSE is pre-discovery intelligence.
- **Not a CAASM tool.** JupiterOne, Axonius, and runZero do internal asset inventory. EXPOSE is external-surface-only.
- **Not a CTI platform.** Recorded Future and Mandiant Threat Intelligence track adversary activity. EXPOSE's commercial Threat Context module consumes CTI feeds to enrich attribution, but the core engine is not a threat-intelligence product.

---

## The AI question, answered honestly

"AI-powered" is the most overused phrase in security marketing. Here is what EXPOSE actually does with AI, and what it does not.

**What AI does in EXPOSE:** Multi-provider LLM enrichment supplements deterministic analysis. When the rule engine identifies an asset but cannot confidently attribute it from structured data alone, the LLM enrichment layer provides a structured assessment. The operator sees the prompt. The operator sees the response. The operator controls which provider runs and how much it costs. The output is validated against a schema before it enters the artifact.

**What AI does not do in EXPOSE:** AI does not make scope decisions. AI does not determine attribution confidence tiers. AI does not sign artifacts. AI does not replace the deterministic engine. The engine is reproducible -- given the same inputs, it produces the same artifact. The AI enrichment is an optional layer that adds signal; it is not the decision-maker.

**The two-environment architecture:** EXPOSE (Environment 1) produces deterministic, signed artifacts. Downstream high-capability AI analysis (Environment 2) is a separate system that consumes those artifacts under its own safety controls. EXPOSE is designed to produce structured input for AI-driven security analysis without being that AI system itself. This separation is architectural, not incidental.

---

## For federal customers

Federal agencies face a specific version of the EASM problem: they need continuous external surface monitoring, but commercial SaaS tools require either inheriting the vendor's FedRAMP authorization or waiting years for one to mature. Meanwhile, the agency's external surface is expanding daily.

EXPOSE offers an alternative path. Self-host the Apache 2.0 engine within your existing authorization boundary. The architecture was designed from day one for federal deployment:

- FIPS 140-3 validated cryptography in all modes
- NIST 800-53 control mapping documented per control family
- AU-family audit logging for continuous monitoring evidence
- Supply-chain integrity evidence (SBOMs, cosign signatures, SLSA attestations)
- CDM-compatible output formats
- No vendor cloud dependency for the open-source engine

The commercial managed-service offering, when it arrives, will pursue FedRAMP Moderate authorization. But agencies do not need to wait. The self-host path is available now.

---

## For researchers

Almost no commercial EASM vendor publishes reference datasets. Researchers either pay for API access or build their own collection infrastructure. Reproducibility suffers. Attribution methodologies cannot be benchmarked against common baselines.

EXPOSE Research will publish reference graph datasets under CC BY 4.0, alongside the Apache 2.0 engine that produced them. The eval harness provides a framework for benchmarking attribution accuracy against curated datasets with known ground truth. If you are publishing a paper on attack surface attribution methodology, EXPOSE gives you a reproducible engine, open rule packs, and a reference dataset to cite.

---

## Getting started

EXPOSE is Apache 2.0 licensed. The engine, schemas, rule packs, and eval datasets are open source.

- Repository: [github.com/pitt-street-labs/expose](https://github.com/pitt-street-labs/expose)
- Specification: `docs/SPEC.md`
- Architecture decisions: `docs/adr/`
- Example rule packs: `examples/rulepacks/`

Commercial modules (Threat Context, Identity Surface) and the managed-service offering are separately licensed and follow the open-source engine.

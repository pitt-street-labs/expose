# EXPOSE — Three-Persona Strategy Review

**Status:** Advisory — not locked. Open for revision in subsequent sessions.
**Date:** 2026-05-09
**Author context:** AI-assisted synthesis from the locked spec-phase artifacts (SPEC.md, all 10 ADRs, positioning.md, ETHICS.md). Produced in response to a project-lead request for a strategy review across three named personas.
**Public name:** EXPOSE (selected 2026-05-10 in Session H) / **Internal codename:** FF6K

This document analyses how EXPOSE sells, operates, and serves three named personas — red teamer, threat researcher, corporate security director — and identifies one missing audience plus seven strategic recommendations. It is intended to inform Session B (competitive analysis), Session C (module specifications), and the eventual go-to-market workstream. It does **not** replace those sessions; it surfaces structural questions and assets the project lead can use to scope them.

This is advisory analysis, not locked architecture. Treat it as input to subsequent work, not as a foundation document on the level of `positioning.md` or the ADRs.

---

## 1. The Red Teamer

**Who.** Senior pentest operator at a boutique consultancy (Bishop Fox-style) or in-house red team at a Fortune 500 / federal contractor. Carries a Burp Suite Pro license and a Cobalt Strike CK; has opinions about Censys vs. Shodan; defends scope decisions in client review.

| Dimension | Detail |
|---|---|
| **Sells on** | Speed (hours instead of days of manual correlation); attribution rigor with confidence tiers and evidence chains for defensible "this is in scope" decisions in client review; reproducible signed artifact for client deliverables; continuous mode for long engagements; authorized-use posture for legal cover |
| **Operates as** | Per-client tenant with engagement scope mapped to `authorization_scope`; daily cron during active engagements, manual burst pre-engagement; pulls artifact, hands to Burp scope / Nuclei templates / manual workflow downstream; some self-host on consultancy infra, some will buy Korlogos managed-service when it lands |
| **Use cases** | Pre-engagement scope confirmation (1-day burst); continuous CTEM-as-a-service for retainer clients; long-engagement weekly delta; M&A due-diligence on acquisition targets; bug bounty work where the program scope is the authorization scope |
| **Verdict** | Right audience for the senior, professional end of the red team market. Wrong audience for the speed-and-exploit crowd. |

**Risks for this audience.**

- The "produces leads, never exploits" boundary (per ADR-008 explicit non-goals) is correct positioning but means red teamers need a separate stack for post-discovery work — friction.
- The medium-mode `authorization_scope` enforcement warns but does not block. Aggressive operators will silence those warnings. ETHICS.md acknowledges this; it is intent-shaping, not enforcement.
- The "12-year-old-with-Kali" elevator pitch (mentioned in `positioning.md` §5.1) lands the speed point in casual conversation but signals the wrong audience to executive buyers. Recommend dropping it from external materials. The problem-statement scaffold already flags this concern.
- The default `$5/run` LLM cost ceiling is fine for daily defensive operations but tight for high-volume red team batches. The Ollama path mitigates this for cost-bound operators.

---

## 2. The Threat Researcher

**Who.** Security researcher at a CTI firm, academic security lab, federal-research lab (MITRE FFRDCs), or vendor research team. Publishes papers, builds datasets, benchmarks tools, teaches graduate-level cybersecurity seminars. Lives in Jupyter notebooks and Maltego graphs.

| Dimension | Detail |
|---|---|
| **Sells on** | **EXPOSE Research dataset offering (CC BY 4.0) is the headline** — almost no one in the EASM category publishes reference datasets. Reproducible deterministic artifact generation; provenance chain on every claim; Apache 2.0 means friction-free academic adoption; eval harness (Phase 2 deliverable) is exactly what attribution-methodology papers need. |
| **Operates as** | Self-hosted on lab compute or research cloud; seeds drawn from own institutional infrastructure, partnered research domains, or synthetic targets; local Ollama for cost discipline; downstream dataset publication is a separate workflow under the operator's control. |
| **Use cases** | Attribution-accuracy methodology research; EASM tool benchmarking (EXPOSE eval datasets become the benchmark the broader community adopts); reproducible reference architecture for security papers; ML training data; graduate-level cybersecurity course labs. |
| **Verdict** | Yes — and this is the most strategically underleveraged piece of the project. |

**Risks and notes for this audience.**

- Research adoption is slow (years to show up in citations) but compounds. A citation in a top-tier conference paper is worth a lot of federal-research credibility, which compounds into federal commercial credibility.
- Threat researchers at *competitor* firms (Mandiant, Recorded Future, Censys research arm) are a tricky audience because their employer sells competing products. The clean audience: academic researchers, federal-research labs, vendor researchers at non-EASM firms.
- The Threat Context module's adversary-infrastructure monitoring (MITRE ATT&CK Resource Development tactic per ADR-009) is exactly what threat researchers care about deeply — natural commercial upgrade path from academic Core to enterprise Threat Context when those researchers move to industry roles.
- Dataset curation effort is real ongoing work (tracked in the `eval-harness` epic). Underinvesting there breaks the Research credibility play.

---

## 3. The Corporate Security Director

**Who.** CISO or VP of Security at a Fortune 1000 / regulated industry / federal contractor / municipal-state government. Buys tools, does not operate them. Reports to a board, manages a security program budget, owns continuous-monitoring evidence streams.

| Dimension | Detail |
|---|---|
| **Sells on** | **FedRAMP-ready posture is the headline** for federal-adjacent buyers; self-hostable open-source addresses vendor lock-in fatigue; signed artifacts plus AU-family audit-log discipline answer the "prove it" requirement; $0 software cost on Core; modular commercial upgrade path; integrates into existing CTEM rather than replacing the stack. |
| **Operates as** | The *security team* operates it; the director procures. Likely deployment: cloud inside the existing AuthZ boundary, or self-hosted on internal Kubernetes. Procurement: Core via internal sponsorship + open-source approval process; commercial modules through standard vendor procurement cycles. Integration: artifacts feed into Splunk / Sentinel / Chronicle SIEM and are referenced in continuous-monitoring evidence. |
| **Use cases** | Board-level external surface visibility; pre/post-M&A surface assessment; subsidiary visibility via multi-tenant deployments; federal ATO continuous-monitoring evidence; NIST Cybersecurity Framework Identify function; NIST 800-53 RA-5 (vulnerability scanning) and CA-7 (continuous monitoring) evidence. |
| **Verdict** | Yes for federal-adjacent and regulated industries. Partial for general enterprise. Wrong for SMB. |

**Risks for this audience.**

- "Open-source means we have to operate it" is friction for risk-averse buyers. The absence of a Korlogos managed-service offering until ADR-010's "future commercial" milestone leaves a gap that competitors fill (Mandiant Advantage ASM, Microsoft Defender EASM, Censys ASM).
- Frequent confusion point: **"FedRAMP-ready" is not "FedRAMP-authorized."** Buyers will hear "ready" and think they have nothing to do. The Federal Customer Deployment Guide (Session G) is upstream of any confident federal sales conversation; without it, the FedRAMP-ready claim does not land defensibly.
- The dual-audience framing (defensive CTEM + authorized red team) may unsettle compliance-minded buyers. The strategic-buyer pitch in `positioning.md` §5.3 already downplays the red team angle for them — this is the right call; preserve it.
- Incumbents have polish, integration libraries, and support contracts. EXPOSE wins on cost, FedRAMP-readiness, openness, and signed-artifact rigor; loses on out-of-the-box CTEM-vendor adapters (correctly out-of-scope per ADR-004 but a frequent procurement-conversation friction point).

---

## Cross-persona comparison

| Dimension | Red Teamer | Threat Researcher | Security Director |
|---|---|---|---|
| Buyer? | Sometimes (consultancy procurement) | Rarely (academic budget) | **Yes** (program budget) |
| Operator? | **Yes** (hands-on) | Yes (researcher-engineer) | No (delegates) |
| Open-source matters? | Yes (extends, modifies) | Yes (research methodology) | Yes (no vendor lock-in) but secondary |
| FedRAMP matters? | No | Slightly | **Yes — primary motivator** |
| Signed artifacts matter? | Yes (deliverables) | Yes (reproducibility) | Yes (audit) |
| Research dataset matters? | No | **Yes — primary motivator** | Slightly (training data) |
| Threat Context module fits? | Yes (commercial upgrade) | Yes (research) | Yes (commercial upgrade) |
| Identity Surface module fits? | **Yes — primary for some** | Slightly (PII research ethics) | Cautious (compliance flag) |
| Managed-service interest? | Maybe (consultancy infra) | No | **Yes (eventual upgrade)** |
| LLM cost sensitivity | High | High (academic budget) | Low (enterprise budget) |
| Sales cycle | 3-6 months | n/a (adoption-driven) | 6-18 months commercial; 18-24 months federal |

---

## Missing audience: the Federal CDM / Continuous-Monitoring Engineer

The three personas above are mostly right, but there is a fourth worth surfacing because they pair with the Security Director persona for federal sales:

**The Federal CDM Engineer.** The person inside an agency who ingests EXPOSE artifacts into the agency's Continuous Diagnostics and Mitigation program, the agency SIEM, the RMF continuous-monitoring evidence stream. The positioning targets federal *buyers* (CISOs and contracting officers) but the *daily user* is this person.

They care about:

- JSON schema stability across releases (NIST 800-53 evidence pipelines are intolerant of breaking changes)
- Audit log fidelity (AU-family compliance, per ADR-010)
- Integration with CDM tooling (RVA tools, ADE feeds, agency SIEM)
- Performance at federal-agency scale (a single DOD service has more attack surface than most Fortune 500s)

This is the *user* persona that pairs with the Security Director *buyer* persona for federal sales. Worth distinguishing in Session G's Federal Customer Deployment Guide.

---

## Strategic recommendations

1. **Dual-audience GTM is a strategic asset but needs separate sales motions.** Do not collapse defensive CTEM and red team into a single pitch deck. Different reference customers, different conferences (Black Hat / DEF CON for red team; RSA / Gartner Security Summit for defensive CISOs), different language registers. The three-layer pitch in `positioning.md` already handles this — preserve it.

2. **EXPOSE Research is the most underleveraged piece of the structure.** Almost no commercial EASM publishes research datasets. This is the credibility wedge for academic adoption, which compounds into federal-research credibility, which compounds into federal commercial sales. Treat Research as marketing infrastructure with its own budget and roadmap, not as a side artifact. Consider sponsoring an academic conference paper or two before public launch.

3. **Identity Surface module needs its own GTM and ethics conversation.** Different buyer (red team lead, not CISO), different ethics surface (personnel reconnaissance), different procurement. Compliance-minded enterprise buyers will be cautious. Probably warrants a session distinct from Session C's general module specification — perhaps "Session C.5: Identity Surface go-to-market" — to design that specific motion.

4. **The Federal Customer Deployment Guide (Session G) is upstream of confident federal sales.** Selling "FedRAMP-ready" without the deployment guide leaves federal buyers asking "ok, how do I actually use this in my ATO?" with no defensible answer. Consider re-prioritizing Session G earlier in the parallel sequence than its current "parallel after E" position.

5. **Document a packaging and pricing decision tree** before commercial conversations begin. When does a customer need Core only? Core + Threat Context? Core + Identity Surface? All three? Research dataset access? Federal customers especially need a documented bundle-pricing pattern for RFP responses. ADR-009 says federal RFPs may require negotiated bundle pricing — this is the document that supports those negotiations.

6. **Drop the "12-year-old-with-Kali" framing from external materials.** Lands the speed point in casual conversation; signals the wrong audience to executive buyers. Keep it for internal speed-of-execution discussions only. The problem-statement scaffold (§Notes for the project lead) already flags this; reinforce in any draft README rewrites and post-Session-H rename pass.

7. **Add Federal CDM Engineer as a documented user persona** in the eventual Federal Customer Deployment Guide (Session G). Distinguish buyer persona (CISO / contracting officer) from operator persona (CDM engineer / continuous-monitoring lead).

---

## Right-audience verdict in one line

The three personas are mostly right. The strongest fit is **Security Director at a federal-adjacent or regulated organization**. The most underleveraged is **Threat Researcher**. The trickiest go-to-market is **Red Teamer**, because the dual-audience design needs careful sales separation that the current materials handle but easily lose.

---

## Recommended follow-on work

- Session B (competitive analysis): use this document as input. The competitor matrix in `positioning.md` §3 is a starting point; persona-by-persona competitor positioning is the next layer.
- Session C (module specifications): use the Identity Surface persona-fit notes (§3 verdict + recommendation 3) as scope-shaping input.
- Session F (SDLP): the Federal CDM Engineer persona affects audit-log requirements; surface that in SDLP scope.
- Session G (Federal Customer Deployment Guide): incorporate the buyer/user persona distinction (Security Director / CDM Engineer) as a documented section.
- A discrete "go-to-market session" not currently in the queue: address packaging, pricing decision tree, and dual-audience sales separation. May warrant its own session timeslot post-Session-G.

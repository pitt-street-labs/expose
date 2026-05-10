# EXPOSE — Problem Statement

**Status:** Scaffold awaiting researcher-journey framing from project lead
**Public name:** EXPOSE (selected 2026-05-10 in Session H)
**Internal codename:** FF6K

This document captures the problem EXPOSE solves, framed around the cybersecurity-researcher journey of the project lead. It is the foundational narrative document — the "why does this exist" answer — that drives README content, marketing positioning, and federal procurement narrative.

The structure below is a scaffold. Each section has placeholder questions and prompts that the project lead populates with their own framing and language. The result should be 1500-2500 words, readable by both technical and non-technical audiences, that authentically reflects the project lead's perspective on the gap EXPOSE fills.

---

## 1. The practitioner experience

*Two to four paragraphs answering: what is the lived experience of being a cybersecurity practitioner — specifically a cloud cybersecurity architect doing CTEM, red team support, and municipal infrastructure work — that creates the gap EXPOSE fills?*

*Anchor questions to consider:*
- *What did you find frustrating or inadequate about existing tools when doing real client engagements (NYC DOT, Koi deployments, etc.)?*
- *What recurring tasks did you find yourself doing manually that should have been automatable?*
- *Where did existing commercial tools fail you, and how did that shape your view of what was missing?*
- *What did you notice about the gap between offensive recon tooling and defensive CTEM tooling?*

[Placeholder for researcher-journey narrative — 400-600 words]

---

## 2. The specific gap EXPOSE addresses

*One to two paragraphs naming, concretely, what EXPOSE does that existing tools do not. This section is technical and specific, not abstract.*

*Reference points to draw on:*
- *Continuous attribution with cryptographic provenance — no incumbent does this*
- *Dual-audience design (defensive CTEM + authorized red team) — most tools are one-or-the-other*
- *Federal-deployable open-source substrate — most commercial EASM is SaaS-only*
- *Two-environment architecture supporting downstream high-capability AI analysis — genuinely novel*
- *Research-grade dataset offering — almost no commercial EASM publishes datasets*

[Placeholder for gap-naming — 300-400 words]

---

## 3. Why the existing market does not solve this

*One to two paragraphs explaining why incumbents have not built this — not just what they fail to do, but why their structural incentives or origins prevent them from filling this gap.*

*Reference points:*
- *Commercial EASM vendors are SaaS-only by business model; they have no incentive to produce federal-deployable open-source*
- *Open-source recon tools (SpiderFoot, Recon-NG, Amass) are point-in-time research tools; they were not built for continuous CTEM operation*
- *The dual-audience design requires architectural commitment most vendors won't make because it complicates GTM*
- *The two-environment AI architecture requires deliberate safety-first thinking that the commercial market hasn't priced yet*

[Placeholder for market-gap analysis — 300-400 words]

---

## 4. The researcher-journey framing

*One to two paragraphs in your own voice connecting the problem to your trajectory as a researcher. This is the section that distinguishes EXPOSE from a generic vendor pitch — it grounds the project in a specific person's professional journey rather than a market opportunity.*

*Anchor questions to consider:*
- *What specific clients, deployments, or projects shaped your view of what was needed?*
- *What did the ARC project teach you about preparedness-oriented thinking that applies to commercial cybersecurity?*
- *How does your work on municipal IoT, cloud security frameworks, and AI security inform what EXPOSE must be?*
- *Why does the federal trajectory matter to you specifically?*

[Placeholder for researcher-journey framing — 300-400 words]

---

## 5. The pragmatic outcome

*One paragraph naming concretely what EXPOSE enables that was not previously possible. Not abstract benefits — specific outcomes a practitioner experiences.*

*Reference points:*
- *A team can generate a defensible, signed, attributed external surface artifact for an enterprise in hours instead of days*
- *Federal agencies can self-host the tool within their ATO without waiting for vendor authorization*
- *Researchers can use published reference datasets to study attack surface attribution methodology without operating the pipeline themselves*
- *Authorized red team operations have a structured artifact contract for handing leads to Mythos-class analysis under appropriate safeguards*
- *The 12-year-old-with-Kali pitch lands here, with rigor: yes, the speed comparison is real; yes, the rigor is the difference*

[Placeholder for outcome statement — 200-300 words]

---

## 6. What EXPOSE is not

*One paragraph reaffirming the boundaries from positioning.md, in your own voice, so that buyers and adopters who read this document understand what they are not getting.*

*Reference points:*
- *Not a vulnerability scanner*
- *Not an exploitation framework*
- *Not a CAASM internal-asset tool*
- *Not a CTI platform (though it integrates with CTI)*
- *Not a defensive-only product (dual-audience by design)*
- *Not a magic wand — it produces leads and structured intelligence, not finished work*

[Placeholder for boundary statement — 150-250 words]

---

## Notes for the project lead

When you populate this scaffold:

1. **Write in your own voice.** This document is most effective when it sounds like the practitioner who built it, not a marketing department. First-person is acceptable in section 4. The other sections can use first-person plural ("we built EXPOSE because...") or descriptive prose.

2. **Be specific.** "Frustration with existing tools" is not specific. "The third time I had to manually correlate a Censys query against three passive DNS providers and a registrar pivot to attribute one cloud asset for a NYC DOT vendor assessment, I started thinking about what this should look like as a continuous pipeline" is specific. Specificity is what makes this document credible.

3. **Avoid marketing register.** Phrases like "revolutionary," "game-changing," "industry-leading" cheapen the document. Plain language is better.

4. **Connect to FedRAMP and federal trajectory honestly.** The federal angle is real but should not feel bolted on. If the federal trajectory grew from your municipal critical-infrastructure work, say that. If it grew from observing how poorly federal agencies are served by commercial SaaS-only EASM, say that.

5. **Keep it honest about limitations.** The research-grade dataset offering, the dual-audience design, the two-environment architecture — these are genuine differentiators. Other claims (e.g., "this replaces an entire SOC team") would be overclaiming. Honest framing is more credible.

6. **The 12-year-old-with-Kali pitch.** This humorous framing is fine in a casual conversation but should not appear in this document as the central pitch. It is mentioned in section 5 as one outcome among others. The serious framing — defensible attribution, signed artifacts, federal-deployable architecture — is the load-bearing pitch.

When you are ready to populate this, you can either:
- Edit this file directly, replacing each `[Placeholder]` block with your prose
- Provide rough notes against each section, and the next session can polish them into prose
- Dictate or write it in conversation, and the next session captures it

There is no rush. The problem statement is foundational, but it is not blocking — the parallelization sessions (competitive analysis, module specs, framework annotation, SDLP) can proceed without it. The problem statement becomes important when README content, marketing materials, and federal procurement narrative are produced.

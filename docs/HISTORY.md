# EXPOSE — Project History

This document captures the lineage and development history of the EXPOSE project, including its codename history (FatFinger6000 → FF6K → EXPOSE) and the strategic decisions that shaped its early specification.

## Public name: EXPOSE (selected 2026-05-10)

The public name **EXPOSE** (EXtended Perimeter Ontology Security Evaluation) was selected in Session H on 2026-05-10. Preliminary EASM/security-tooling conflict check found no major-product conflicts; formal trademark search in USPTO security classes (9, 38, 42) is deferred to pre-publication review per the consent gate. The mechanical rename pass propagated EXPOSE across all public-facing and spec artifacts on the same day; HISTORY.md, HANDOFF.md, and `init-and-push-to-gitea.sh` are preserved verbatim as historical / genesis records.

All four product surfaces share the EXPOSE prefix per ADR-009: **EXPOSE Core** (Apache 2.0), **EXPOSE Threat Context** (proprietary), **EXPOSE Identity Surface** (proprietary), **EXPOSE Research** (CC BY 4.0 datasets).

## Codename: FF6K (preserved)

The internal working codename for this project is **FF6K**, shortened from the original conversational codename **FatFinger6000**. The name originated as a deliberate counterpoint to high-capability frontier AI tooling: where Mythos-class capabilities represent the open-ended, narrative-reasoning frontier of AI security analysis, FatFinger6000 represented the deterministic, dependable, structured substrate that produces input for that analysis. The humor of the name was always in tension with the rigor of the engineering — the joke was that the most boring possible tool name applied to a genuinely sophisticated piece of infrastructure.

The decision to use FF6K (rather than the full FatFinger6000) as the working codename through specification phase was made on 2026-05-09 to:
1. Shorten references in working artifacts and code comments
2. Provide a transition point toward the eventual public name
3. Preserve the lineage joke for those who get the reference, without putting it at the front of federal procurement conversations

Per the original convention, **FF6K continues as the internal codename** in development artifacts, internal communications, and historical references throughout the project's lifetime. **EXPOSE is used in all public-facing and customer-facing artifacts.** The Gitea repository remains at `pitt-street-labs/ff6k` (internal codename); a renamed-to-`expose` Gitea repo is a separate decision deferred to pre-publication review.

## Specification phase timeline

**2026-05-09 — Specification design session.**

A multi-turn collaborative design session produced the foundational specification for FF6K, including:
- Eight architectural decisions (ADRs 1-8) covering implementation language, graph storage, deployment posture, output artifact, LLM integration, repository and licensing, multi-tenancy, and authorized use
- Comprehensive SPEC.md
- JSON Schema files for canonical artifact, manifest, and rule pack formats
- Example rule pack
- Glossary
- Initial governance documents (README, SECURITY.md, ETHICS.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, LICENSE pointer)
- Six deferred-issues backlogs covering deployment-portability, production-hardening, llm-quality, eval-harness, repo-governance, multi-tenancy, and authorized-use epics

**2026-05-09 — Strategic foundation session (this document set).**

A subsequent design conversation locked the strategic positioning and produced two additional ADRs:
- **ADR-009: Commercial structure** — open-core engine plus three proprietary commercial modules plus a separate research dataset offering
- **ADR-010: FedRAMP-ready posture** — architectural readiness in v1, authorization-deferred for the open-source engine, authorization-targeted for the future commercial managed-service offering

The strategic foundation session also clarified the niche positioning and the MITRE ATT&CK Reconnaissance anchor (with Resource Development as a separate commercial module rather than bundled into Core), produced `docs/positioning.md` as the foundational positioning document, and created the problem statement scaffold.

## Naming history

| Stage | Name |
|---|---|
| Original codename | FatFinger6000 |
| Specification phase codename | FF6K (preserved as internal codename per above) |
| Heliograph candidate (rejected after sanity check) | Heliograph — found multiple AI-tooling product conflicts |
| PERIM candidate (rejected after sanity check) | PERIM — found "perimeter" framing conceptually misaligned with Zero Trust direction |
| EASI candidate (rejected after evaluation) | EASI — too descriptive of the category, not distinctive as a brand |
| Public name selected (Session H, 2026-05-10) | **EXPOSE** (EXtended Perimeter Ontology Security Evaluation) — preliminary EASM/security-tooling conflict check clean; formal trademark search deferred to pre-publication review |

## Strategic decisions locked

The following decisions are locked as foundation for all subsequent work:

1. **Apache 2.0 engine, separate commercial license for proprietary modules** (ADR-006, extended by ADR-009)
2. **Three commercial modules: Threat Context, Identity Surface, with separate Research dataset offering** (ADR-009)
3. **FedRAMP-ready by design, authorization-deferred for open-source engine, authorization-targeted for future commercial offering** (ADR-010)
4. **MITRE ATT&CK Reconnaissance (TA0043) as primary anchor; Resource Development (TA0042) as commercial-module-only scope** (positioning.md)
5. **Two-environment architecture preserved: Environment 1 deterministic engine, Environment 2 downstream LLM analysis under appropriate safeguards** (SPEC.md, preserved across all subsequent decisions)
6. **Continuous, attributed, signed, AI-enriched, dual-audience, research-dataset-publishing as the niche definition** (positioning.md)

## Subsequent sessions queued

Per the parallelization plan, the following work streams can now proceed in parallel against this strategic foundation:

- Session B: Competitive analysis (deeper technical comparison vs. SpiderFoot HX, Mandiant ASM, Censys ASM, Microsoft Defender EASM, others)
- Session C: Module specifications for Threat Context and Identity Surface (separate SPECs, ETHICS, threat models, schemas)
- Session D: Novel AI-leverage roadmap (additional capabilities beyond the three commercialization ideas already discussed)
- Session E: Framework annotation deep-dive (MITRE ATT&CK, NIST CSF 2.0, NIST SP 800-53, OWASP ASVS/AISVS, CIS Controls)
- Session F: Secure Development Lifecycle Plan (SDLP) — pre-implementation security posture document
- Session G: Federal Customer Deployment Guide (integration guide for federal agencies self-hosting FF6K Core within their ATOs)
- Session H: Public name selection (with positioning locked)

Each session has clear scope, stable foundation, and produces an artifact that agent teams can develop in parallel.

## Consent gate

As of the date of this document, **no FF6K artifact has been pushed to GitHub.com or any public host.** All artifacts remain in the project lead's lab environment for inspection and selective publication. The consent gate remains in force until the project lead explicitly authorizes public publication.

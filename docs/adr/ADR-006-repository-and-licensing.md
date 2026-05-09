# ADR-006: Repository and licensing

**Status:** Accepted
**Date:** 2026-05-09
**Decision-makers:** Korlogos / Pitt Street Labs

## Context

FatFinger6000 will be developed as a real GitHub project, not throwaway code. The licensing posture affects what contributions can be accepted, how the project is positioned in the security tooling community, and what commercial protection Korlogos has against forks.

Specific considerations:

- Korlogos has built brand recognition in cloud and municipal cybersecurity. A well-built public tool reinforces that brand.
- The work product has client-engagement-specific elements (rule packs tuned to specific organizations) that should not be public.
- Operators in the security community generally prefer OSI-approved licenses; source-available licenses get less community engagement.
- The tool's category (EASM/CTEM intelligence) has commercial vendors (Tenable, Wiz, Microsoft Defender EASM, others). A permissive license means competitors can fork.
- Apache 2.0 specifically provides patent grant protection that MIT does not.

## Decision

**Apache 2.0 license for the engine, in a public GitHub repository named `fatfinger6000`.**

**Separate private repository for client-specific rule packs**, named `fatfinger6000-rulepacks` (or per-client variants). Rule packs are consumed as deployment-time data, not built into the engine.

The split:

- **`fatfinger6000`** (public, Apache 2.0): the engine, schemas, collector framework, attribution rule engine, LLM provider abstractions, JSON artifact format, infrastructure code, documentation. Includes example rule packs sufficient to demonstrate the engine end-to-end.
- **`fatfinger6000-rulepacks`** (private, all rights reserved): client-specific seeds, attribution rules tuned for specific engagements, sensitive collector configurations, internal eval datasets that contain real client surface data.

Public repository governance:

- README, SECURITY.md, ETHICS.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md (Contributor Covenant 2.1).
- DCO sign-off for contributions (per `Signed-off-by:` in commit messages, enforced by DCO bot).
- Security disclosure policy via private GitHub Security Advisory.
- Quarterly review cadence for ETHICS.md and SECURITY.md positioning.
- Trademark posture deferred until project visibility justifies the legal work.

## Consequences

**Positive:**

- Brand visibility for Korlogos in the security tooling community.
- OSI-approved license maximizes community engagement and contribution.
- Apache 2.0 patent grant protects contributors and downstream users.
- Engine improvements from the community benefit all operators.
- Client-specific work stays private; competitors cannot fork engagement-specific intelligence.
- Standard governance practices (DCO, SECURITY.md, Code of Conduct) signal professionalism.
- Migration path to other licenses (BUSL, ELv2) preserved if commercial pressure changes the calculus.

**Negative:**

- Competitors can fork the engine. Acceptable risk because the value of FatFinger6000 is *applied* — operational competence, integration with red team operations, attribution rule tuning for specific clients. Forking the code does not transfer those.
- External contribution management has ongoing cost (PR review, issue triage, community moderation).
- Trademark protection is not granted by the license; "FatFinger6000" can be used by forks unless trademark is registered. Deferred concern.
- Sophisticated buyers in security reviews will scrutinize the public engine (supply chain, dependencies, build provenance). This is a reason to invest in image signing, SBOMs, and SLSA provenance from day one — already required by Decision 3.

## Alternatives considered

**Source-available license (BUSL-1.1, PolyForm Strict, ELv2).** Public repo, code visible, commercial use restricted by license terms. Rejected for v1 because:
- Not OSI-approved; security tooling community tends toward strict OSS preferences.
- Community contribution dynamics are weaker ("why contribute if I can't use commercially").
- BUSL has time-bound conversion to permissive license (typically 4 years), so the project becomes truly OSS eventually anyway.
- For FatFinger6000's category, competitors can build similar tools without forking; the protection BUSL provides is modest.

Migration path preserved if commercial pressure changes — Apache 2.0 to BUSL is a license bump, but accepting future contributions under BUSL after they were submitted under Apache 2.0 requires CLA or contributor permission.

**Internal Korlogos project, private repo, no external license.** Maximum control, no community management overhead. Rejected because:
- No brand visibility benefit.
- No external feedback or contribution.
- Harder to demonstrate technical capability to clients evaluating Korlogos's work.
- Wastes the chance to contribute back to a security community Korlogos benefits from.

**Public repo, no license declared.** Visible code, legally unusable. Rejected as actively hostile to anyone who finds it useful and the worst of all worlds.

**Single repo, everything public including rule packs.** Maximum transparency, but client-specific rule packs would expose engagement-specific attribution logic. Rejected because the dual-repo split serves both transparency (engine is public) and client confidentiality (rule packs are private).

## When to revisit

Trigger conditions for license or governance change:

- **Significant commercial competitive threat.** A well-funded vendor forks FatFinger6000 and ships a commercial product. Move to source-available is an option; cost is community goodwill.
- **A specific client requires a commercial license guarantee.** Apache 2.0 already permits commercial use; this is unlikely to trigger a change unless the client wants exclusive provisions.
- **External adoption justifies trademark registration.** When the name has visible market presence, register the trademark.

The dual-repo structure is durable. Engine-public, rule-packs-private is the right pattern for security tooling and unlikely to need revisiting.

## References

- Decision recorded in design conversation 2026-05-09.
- Five deferred-issues in the repo-governance epic. See `docs/issues-backlog.md`.
- Project name "FatFinger6000" chosen as deliberate counterpoint to Mythos — this codebase is the deterministic, dependable, boring substrate; Mythos-class capability lives in Environment 2.

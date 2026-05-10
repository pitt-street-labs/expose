# Ethics and Intended Use

EXPOSE is an external attack surface intelligence pipeline. It is genuinely capable — it attributes external assets to organizations, identifies cloud resources, fingerprints tech stacks, scores leads for red team prioritization. This document establishes how we intend it to be used and what we explicitly do not want it used for.

We cannot prevent misuse. The project is open source under Apache 2.0, and anyone with a clone can run it. What we can do is be clear about intent, be deliberate about defaults, and be honest about capability.

## Intended use

EXPOSE is designed for:

**Defensive Continuous Threat Exposure Management (CTEM).** Security teams mapping their own organization's external attack surface for prioritization and response. Producing structured input for CTEM platforms, vulnerability management programs, and security posture dashboards.

**Authorized red team operations.** Supporting engagements with explicit scope contracts where the operator is authorized to enumerate and analyze the target organization's external surface.

**Own-perimeter mapping.** Internal security operations within organizations where the operator has standing authorization to assess.

**Educational and research use.** Studying EASM techniques, attribution methodology, and CTEM workflows. Authors of academic papers, training materials, and blog posts are welcome to use the tool for these purposes within ethical research norms.

## Explicit non-goals

The following are out of scope for EXPOSE — not deferred, not future-work, but deliberately not part of the project:

**Active exploitation, vulnerability validation, or post-discovery offensive action.** EXPOSE produces leads. Exploitation toolchains (Nuclei, Metasploit, manual red team operations) are different categories. We will not add exploitation modules to this project.

**PII enrichment beyond public records.** Registrant emails, contact names, and similar fields disclosed in WHOIS/RDAP and certificate registration are PII but are publicly disclosed. The pipeline treats them as such. We will not add enrichment with private data sources, paid identity-resolution services, or social-graph correlation.

**Adversarial use against third parties.** The intended user is a security team mapping their own organization's surface or supporting authorized red team operations. The runtime warns when collection or attribution operates outside the configured authorization scope. Operators who ignore those warnings to enumerate organizations they are not authorized to assess are operating outside the project's intent.

**Open-ended narrative reasoning, exploit hypothesis generation, red team briefing prose.** These belong in a separate downstream environment (Environment 2 in our architecture) where high-capability LLM tooling has its own safety controls. EXPOSE produces structured input for those workflows, not narrative output.

**Real-time surveillance, stalking, or monitoring of individuals.** The project enumerates organizational infrastructure, not people. Attempting to use it to track individuals' online presence violates the project's intent.

## Capability disclosure

In plain language, what EXPOSE does:

1. Takes operator-provided seeds (organization name, brand strings, known apex domains, cloud account IDs).
2. Queries public data sources (Certificate Transparency logs, passive DNS providers, ASN/BGP databases, internet-wide scan datasets, cloud provider IP range manifests).
3. Performs active reconnaissance (DNS resolution, TLS handshakes, HTTP fingerprinting) against assets attributed to the operator's organization with high confidence.
4. Applies declarative rules to attribute observed assets to the operator's organization with confidence tiers.
5. Optionally uses bounded LLM enrichment to sanity-check ambiguous attributions, infer tech stacks, and classify noise.
6. Produces a signed JSON artifact summarizing the attributed external surface.

What it does *not* do:

- Exploit vulnerabilities.
- Enrich with private data sources.
- Generate offensive narrative content.
- Track individuals.
- Bypass authentication or access controls on target systems.

## Adversary-controlled inputs

Some of the data EXPOSE collects comes from sources adversaries can influence — certificate Subject Alternative Names, HTTP banners, DNS TXT records, WHOIS organization fields. We treat all such content as untrusted. The pipeline's sanitization layer (Stage 3 in `docs/SPEC.md`) is a security property, not just code quality.

LLM prompts wrap collected content in explicit `<external_observation>` tags with system-prompt instructions to treat enclosed content as data, not instructions. This is a defense-in-depth pattern — adversaries who plant prompt-injection-style payloads in cert SANs see their content rendered as data within marked sections; they do not get to issue instructions to the LLM.

## Authorization-scope posture

EXPOSE supports per-tenant authorization scope configuration. The default enforcement mode is **medium** — collection that operates outside the configured scope produces warnings flagged in the artifact, but is not blocked. The medium default makes scope a first-class concept the operator must engage with while not breaking legitimate workflows where external authorization exists outside the engine's view.

Stricter enforcement (`hard` mode) is available for deployments where blocking out-of-scope active collection is appropriate — regulated industries, scope-contracted customer engagements, conservative defensive deployments.

Soft enforcement (`soft` mode) is available for deployments where the operator accepts full responsibility and wants only audit logging.

Whichever mode is configured, the operator is responsible for ensuring collection operates within their actual authorization. The engine cannot verify that authorization; it only enforces what the operator declares.

## Two-environment design

EXPOSE deliberately operates as **Environment 1** — the deterministic discovery and bounded structured-output enrichment pipeline. **Environment 2** — separate, downstream, where operators perform open-ended narrative analysis using high-capability LLM tooling — is out of scope for this codebase.

This separation is deliberate. It preserves the air-gap discipline appropriate for high-capability autonomous LLM tooling, keeps Environment 1's safety properties simple to audit, and isolates the domains of concern: Environment 1 is "what is reachable that belongs to us"; Environment 2 is "what does an operator do about it."

Whatever tooling Environment 2 uses — Project Glasswing access, internal red team tooling, future GA frontier models, locally-hosted models — is the operator's decision under whatever safeguards their access program requires. EXPOSE has no opinion about Environment 2 implementation; we coordinate at the artifact contract boundary only.

## What we ask of operators

If you deploy EXPOSE:

- Run it only against assets you are authorized to analyze.
- Configure authorization scope explicitly per tenant; don't leave it empty.
- Treat the artifact's `outside_authorized_scope_summary` as actionable; investigate non-zero counts.
- Honor the medium-mode warnings; if you need broader scope, extend the scope explicitly with documented authorization.
- Keep collector and LLM credentials in a real secrets backend, not in plaintext config.
- Verify artifact signatures before trusting downstream consumption.

## What we ask of contributors

If you contribute to EXPOSE:

- Don't add exploitation modules. Lead-finding, not exploitation.
- Don't add features that primarily enable surveillance of individuals or unauthorized reconnaissance against third parties.
- Don't add features that bypass the sanitization or authorization-scope layers.
- Discuss controversial features in an issue before opening a pull request.
- Read CONTRIBUTING.md and the Code of Conduct.

We reserve the right to decline contributions that conflict with the project's intent as documented here.

## Maintenance and review

This document is reviewed quarterly. Changes are tracked in git history. Material updates are noted in release notes.

### Trigger events for ad-hoc review

In addition to the quarterly cadence, an ad-hoc review of this document is initiated when any of the following occurs:

- **Material capability additions.** New collectors, new enrichment modes, new artifact fields, or expansion of active-collection scope (e.g., new probe types, new providers) that change what EXPOSE can observe or infer about a target.
- **External guidance changes.** Updates to NIST CSF, NIST AI RMF, FedRAMP control baselines, the MITRE ATT&CK Reconnaissance (TA0043) tactic (new techniques, sub-techniques, or technique deprecations), or other authoritative frameworks EXPOSE aligns to.
- **Security disclosures.** Any vulnerability report (per `SECURITY.md`) whose remediation involves changing what data is collected, retained, or how authorization scope is enforced.
- **User-reported misuse patterns.** Reports received via `conduct@korlogos.com` or issue tracker that surface new misuse vectors not anticipated by the current document.
- **ADR-008 scope-model changes.** Any modification to the authorization-scope model (default mode, scope schema, enforcement semantics) defined in ADR-008.

For each trigger event: an ad-hoc ETHICS review is initiated; the outcome (no change, clarification, or substantive amendment) is documented in the next release notes; substantive amendments to intent, non-goals, or scope posture also receive a corresponding ADR amendment so the architectural rationale is preserved alongside this document.

If you believe EXPOSE is being used in ways that conflict with this document, you can:

- Open a GitHub issue (for general concerns or policy discussions).
- Email `conduct@korlogos.com` (for specific incidents that should be handled privately).
- Report to the GitHub Security team if the misuse involves the GitHub platform itself.

## Last reviewed

This document was last reviewed on **2026-05-09** at project specification completion.

Next review: **2026-08-09**.

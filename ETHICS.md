# Ethics and Intended Use

EXPOSE is an external attack surface intelligence pipeline. It attributes external assets to organizations, identifies cloud resources, fingerprints tech stacks, and scores leads for red team prioritization. This document establishes how we intend it to be used and what we explicitly do not want it used for.

We cannot prevent misuse. The project is open source under Apache 2.0, and anyone with a clone can run it. What we can do is be clear about intent, be deliberate about defaults, and be honest about capability.

## Intended Use

EXPOSE is designed for:

**Defensive Continuous Threat Exposure Management (CTEM).** Security teams mapping their own organization's external attack surface for prioritization and response. Producing structured input for CTEM platforms, vulnerability management programs, and security posture dashboards.

**Authorized red team operations.** Supporting engagements with explicit scope contracts where the operator is authorized to enumerate and analyze the target organization's external surface.

**Own-perimeter mapping.** Internal security operations within organizations where the operator has standing authorization to assess.

**Educational and research use.** Studying EASM techniques, attribution methodology, and CTEM workflows. Authors of academic papers, training materials, and blog posts are welcome to use the tool for these purposes within ethical research norms.

## Explicit Non-Goals

The following are out of scope for EXPOSE -- not deferred, not future-work, but deliberately excluded:

**Active exploitation, vulnerability validation, or post-discovery offensive action.** EXPOSE produces leads. Exploitation toolchains (Nuclei, Metasploit, manual red team operations) are different categories. We will not add exploitation modules to this project.

**PII enrichment beyond public records.** Registrant emails, contact names, and similar fields disclosed in WHOIS/RDAP and certificate registration are PII but are publicly disclosed. The pipeline treats them as such. We will not add enrichment with private data sources, paid identity-resolution services, or social-graph correlation.

**Adversarial use against third parties.** The intended user is a security team mapping their own organization's surface or supporting authorized red team operations. The runtime warns when collection or attribution operates outside the configured authorization scope. Operators who ignore those warnings to enumerate organizations they are not authorized to assess are operating outside the project's intent.

**Open-ended narrative reasoning, exploit hypothesis generation, red team briefing prose.** These belong in a separate downstream environment (Environment 2 in our architecture) where high-capability LLM tooling has its own safety controls. EXPOSE produces structured input for those workflows, not narrative output.

**Real-time surveillance, stalking, or monitoring of individuals.** The project enumerates organizational infrastructure, not people. Attempting to use it to track individuals' online presence violates the project's intent.

## Capability Disclosure

In plain language, what EXPOSE does:

1. Takes operator-provided seeds (organization name, brand strings, known apex domains, cloud account IDs).
2. Queries public data sources (Certificate Transparency logs, passive DNS providers, ASN/BGP databases, internet-wide scan datasets, cloud provider IP range manifests).
3. Performs active reconnaissance (DNS resolution, TLS handshakes, HTTP fingerprinting) against assets attributed to the operator's organization with high confidence.
4. Applies declarative rules to attribute observed assets to the operator's organization with confidence tiers.
5. Optionally uses bounded LLM enrichment to sanity-check ambiguous attributions, infer tech stacks, and classify noise.
6. Produces a signed JSON artifact summarizing the attributed external surface.

What it does not do: exploit vulnerabilities, enrich with private data sources, generate offensive narrative content, track individuals, or bypass authentication or access controls on target systems.

## Three-Tier Collector Model

The collector architecture enforces ethical boundaries through tiered access controls:

| Tier | Activity | Target Interaction | Gating |
|------|----------|-------------------|--------|
| **Tier 1 -- Passive** | Certificate Transparency logs, cloud IP range manifests, BGP/ASN data | None. No packets sent to target infrastructure. | Ungated. |
| **Tier 2 -- Semi-passive** | WHOIS/RDAP queries, passive DNS lookups, internet-wide scan dataset queries | Queries go to third-party databases, not the target. | Requires valid authorization scope configuration. |
| **Tier 3 -- Active** | DNS resolution, TLS handshakes, HTTP fingerprinting | Direct interaction with target infrastructure. | Requires attribution confidence above configurable threshold AND the asset must fall within the operator's declared authorization scope. |

Tier 3 is where ethical risk concentrates. The attribution gating requirement means EXPOSE will not actively probe infrastructure unless it has already established, through passive and semi-passive means, that the asset likely belongs to the operator's organization. This prevents accidental or careless probing of unrelated third-party infrastructure.

## Authorization-Scope Posture

EXPOSE supports per-tenant authorization scope configuration with three enforcement modes:

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Hard** | Out-of-scope active collection is blocked. | Regulated industries, scope-contracted engagements, conservative deployments. |
| **Medium** (default) | Out-of-scope collection produces warnings flagged in the artifact. | General defensive use. Makes scope a first-class concept without breaking legitimate workflows. |
| **Soft** | Audit logging only. | Operators accepting full responsibility for scope compliance. |

Whichever mode is configured, the operator is responsible for ensuring collection operates within their actual authorization. The engine cannot verify that authorization; it only enforces what the operator declares.

## Misuse Detection

EXPOSE includes an advisory misuse detection system that monitors collection patterns for indicators of unauthorized use:

- Collection targeting assets with zero attribution to the configured tenant.
- Abnormally broad seed configurations inconsistent with single-organization mapping.
- Repeated scope-violation warnings that are never addressed.

When misuse indicators are detected, the system generates advisory warnings in the run artifact. These are informational -- the system does not phone home or report to any external party. The warnings exist to help operators and their compliance teams audit their own use.

## Privacy and Compliance

**GDPR and CCPA compliance is built into the pipeline.** The compliance module provides:

- **Data export.** Operators can export all data associated with a tenant in a portable format, supporting data subject access requests.
- **Data deletion.** Operators can purge all data associated with a tenant, supporting right-to-erasure requests.
- **Retention policies.** Configurable per-tenant retention windows ensure data is not kept longer than operationally necessary.
- **PII sanitization.** The sanitization layer strips or redacts PII from collected data before graph insertion, with configurable aggressiveness.

EXPOSE processes only publicly available information. It does not collect private communications, authentication credentials, personal browsing data, or non-public personal information.

## Two-Environment Design

EXPOSE deliberately operates as **Environment 1** -- the deterministic discovery and bounded structured-output enrichment pipeline. **Environment 2** -- separate, downstream, where operators perform open-ended narrative analysis using high-capability LLM tooling -- is out of scope for this codebase.

This separation is deliberate. It preserves the air-gap discipline appropriate for high-capability autonomous LLM tooling, keeps Environment 1's safety properties simple to audit, and isolates the domains of concern: Environment 1 answers "what is reachable that belongs to us"; Environment 2 addresses "what does an operator do about it."

Whatever tooling Environment 2 uses is the operator's decision under whatever safeguards their access program requires. EXPOSE coordinates at the artifact contract boundary only.

## Adversary-Controlled Inputs

Some of the data EXPOSE collects comes from sources adversaries can influence -- certificate Subject Alternative Names, HTTP banners, DNS TXT records, WHOIS organization fields. We treat all such content as untrusted. The pipeline's sanitization layer is a security property, not just code quality.

LLM prompts wrap collected content in explicit `<external_observation>` tags with system-prompt instructions to treat enclosed content as data, not instructions. This is a defense-in-depth pattern against prompt injection via adversary-controlled infrastructure fields.

## What We Ask of Operators

If you deploy EXPOSE:

- Run it only against assets you are authorized to analyze.
- Configure authorization scope explicitly per tenant; do not leave it empty.
- Treat the artifact's `outside_authorized_scope_summary` as actionable; investigate non-zero counts.
- Honor scope warnings; if you need broader scope, extend it explicitly with documented authorization.
- Keep collector and LLM credentials in a real secrets backend, not in plaintext config.
- Verify artifact signatures before trusting downstream consumption.

## What We Ask of Contributors

If you contribute to EXPOSE:

- Do not add exploitation modules. Lead-finding, not exploitation.
- Do not add features that primarily enable surveillance of individuals or unauthorized reconnaissance against third parties.
- Do not add features that bypass the sanitization or authorization-scope layers.
- Discuss controversial features in an issue before opening a pull request.
- Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

We reserve the right to decline contributions that conflict with the project's intent as documented here.

## Maintenance and Review

This document is reviewed quarterly. Changes are tracked in git history. Material updates are noted in release notes.

### Trigger Events for Ad-Hoc Review

In addition to the quarterly cadence, an ad-hoc review is initiated when any of the following occurs:

- **Material capability additions.** New collectors, enrichment modes, artifact fields, or expansion of active-collection scope that change what EXPOSE can observe or infer about a target.
- **External guidance changes.** Updates to NIST CSF, NIST AI RMF, FedRAMP control baselines, the MITRE ATT&CK Reconnaissance (TA0043) tactic, or other authoritative frameworks EXPOSE aligns to.
- **Security disclosures.** Any vulnerability report (per `SECURITY.md`) whose remediation involves changing what data is collected, retained, or how authorization scope is enforced.
- **User-reported misuse patterns.** Reports received via `conduct@korlogos.com` or the issue tracker that surface new misuse vectors not anticipated by this document.
- **Scope-model changes.** Any modification to the authorization-scope model (default mode, scope schema, enforcement semantics).

For each trigger event, the outcome (no change, clarification, or substantive amendment) is documented in the next release notes. Substantive amendments to intent, non-goals, or scope posture also receive a corresponding ADR amendment so the architectural rationale is preserved alongside this document.

## Anonymized Egress

EXPOSE supports routing active scanner traffic through anonymizing infrastructure
(SOCKS5 proxies, Tor circuits) via configurable egress profiles. When anonymized
egress is active, scan artifacts record `egress_anonymized: true` in their
provenance metadata so downstream consumers know the scan origin was masked.

This capability exists to serve legitimate use cases:
- Geographic distribution testing
- IP-reputation impact assessment
- Authorized adversary emulation (red team)
- Research scenarios (censorship, CDN behavior)

Operators are responsible for ensuring anonymized egress complies with their
organization's policies and applicable law. The EXPOSE Core engine documents
the capability honestly; it does not encourage or facilitate unauthorized use.

## Reporting Concerns

If you believe EXPOSE is being used in ways that conflict with this document:

- Open a [GitHub issue](https://github.com/pitt-street-labs/expose/issues) for general concerns or policy discussions.
- Email `conduct@korlogos.com` for specific incidents that should be handled privately.
- Report to the GitHub Security team if the misuse involves the GitHub platform itself.

## Last Reviewed

This document is reviewed at each major release and updated as needed.

Next scheduled review: at v1.0 release.

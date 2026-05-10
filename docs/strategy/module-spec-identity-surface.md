# EXPOSE Identity Surface — Module Specification

**Status:** Draft — Session C deliverable. Subject to revision in Session F (SDLP), Session G (Federal Customer Deployment Guide), and an explicitly-recommended external ethics review (§16) before any public availability of the module. Not locked at the level of the SPEC.md or the ADRs, and held to a higher revision-discipline bar than other strategy documents.
**Date:** 2026-05-10
**Author context:** AI-assisted synthesis grounded in the locked spec-phase artifacts (SPEC.md, ADR-008, ADR-009, ADR-010, positioning.md), Session E framework annotation, persona-analysis.md §3 verdict on Identity Surface and Recommendation 3, and current (May 2026) public guidance on GDPR Article 6 legitimate-interest doctrine, the CCPA/CPRA Delete Request and Opt-Out Platform (DROP, operative 2026-01-01 per California Privacy Protection Agency), the hiQ Labs v. LinkedIn outcome, EU AI Act high-risk system enforcement (operative 2026-08-02), and FedRAMP CA-8(2) red-team rules-of-engagement requirements.
**Public name:** EXPOSE Identity Surface (per ADR-009 prefix convention) / **Internal codename:** FF6K Identity Surface
**Source files cited:** `docs/SPEC.md`, `docs/positioning.md`, `docs/adr/ADR-008-authorized-use-and-ethics.md`, `docs/adr/ADR-009-commercial-structure.md`, `docs/adr/ADR-010-fedramp-ready-posture.md`, `docs/strategy/framework-annotation.md`, `docs/strategy/persona-analysis.md`, `docs/strategy/module-spec-threat-context.md`, `schemas/canonical-artifact-v1.json`.

---

## ETHICS NOTE — read before any other section

**EXPOSE Identity Surface is the highest-ethics-surface module in the EXPOSE product line.** It correlates personnel data — names, roles, organizational relationships, public-profile attributes of individuals — that exist as humans, not as infrastructure. Misuse of this module's outputs is capable of materially harming specific individuals.

This specification is deliberately more conservative, more cautious, and more guardrail-heavy than the EXPOSE Core spec or the EXPOSE Threat Context module spec. Where a tradeoff exists between operational utility and individual safety, this spec resolves it in favor of individual safety. Readers expecting a parallel structure to Threat Context will find Identity Surface narrower in scope, more restrictive in defaults, and more demanding in activation prerequisites. That is intentional and load-bearing — not an editorial oversight.

**The module is off by default at every layer.** Per ADR-009 §"FF6K Identity Surface", per persona-analysis.md §3 verdict, and per the explicit decision recorded in this spec's §11, the module requires explicit per-tenant activation gated by: a written scope contract documenting an authorized red-team engagement; GDPR-aware data-subject-rights infrastructure; a signed operator attestation; and Korlogos-side activation review. None of those gates are perfunctory. Any of them can refuse activation.

**Korlogos commits to refusing customer requests** for module activation against journalists, activists, dissidents, minors, or non-consenting individuals. This is documented in the module's commercial EULA and is a contractual term, not a customer-service guideline. The module cannot prevent technical misuse by a determined operator who bypasses Korlogos-side controls (open-source modules cannot prevent technical misuse) but Korlogos refuses to participate in misuse and will not grant activation to operators whose stated use case is misuse.

**Recommendation §16: An external ethics review board should review this module's design and operational posture before the module enters public availability.** That recommendation is load-bearing. The module should not ship into commercial availability without that review.

---

## 1. Module overview

### 1.1 What EXPOSE Identity Surface is

EXPOSE Identity Surface is a separately-licensed proprietary module that consumes the canonical signed JSON artifact produced by EXPOSE Core (`schemas/canonical-artifact-v1.json`) and produces an enriched signed JSON artifact carrying personnel-graph correlation, WHOIS-personnel pivots beyond Core's WHOIS scope, and authorized-scope-gated public-profile observations from named social-media platforms.

The module's deliverable is the same kind of object Core's deliverable is: a deterministic, attributable, cryptographically signed JSON file with full provenance, suitable for the same Environment 2 handoff disciplines defined in SPEC.md §2.1. The artifact is the API; there is no live API contract, no streaming feed, no human-readable narrative output.

### 1.2 Why Identity Surface requires a higher ethics bar than other modules

Three structural reasons distinguish Identity Surface from Core and Threat Context:

- **The subjects are individuals, not infrastructure.** Core observes domains, IPs, certificates, services. Threat Context observes adversary infrastructure and threat-actor patterns. Identity Surface observes attributes of named individuals — even when those attributes are publicly disclosed by the individual themselves. Public disclosure does not equal consent to surveillance correlation, and the distinction between "publicly available" and "consented to be aggregated for use against me" is precisely where the privacy-and-surveillance literature and regulatory frameworks (GDPR, CCPA/CPRA, EU AI Act high-risk-system criteria) draw their hardest lines.
- **The harms are immediate and individual.** Misuse of Core's output drives bad scope decisions on infrastructure assessment. Misuse of Threat Context's output drives bad threat-actor attribution. Misuse of Identity Surface's output drives concrete harm to identifiable individuals: stalking enablement, doxxing, harassment campaigns, employment-targeting, political-targeting. The downstream-harm pathway is shorter and more direct.
- **The legal exposure is materially larger.** GDPR's Article 6 lawful-basis doctrine, CCPA's right-to-delete (and the new DROP — Delete Request and Opt-Out Platform — operative since 2026-01-01 with broker compliance required by 2026-08-01), other US state privacy laws, EEOC anti-discrimination law in employment contexts, federal-contractor PII handling rules, and the EU AI Act's prohibition on social-scoring systems all interact with personnel-data correlation in ways that Core's external-attack-surface scope and Threat Context's threat-intelligence scope do not trigger.

### 1.3 What the module produces (in the narrow scope it operates within)

For each target in the input Core artifact whose attribution tier is `confirmed` or `high` (the module deliberately does not enrich `medium` or `requires_review` tiers — §3.4), and where the operator's authorization scope explicitly enables Identity Surface enrichment for that target, the module produces a `identity_surface` block carrying:

- WHOIS-personnel correlation extending Core's WHOIS observations (registrant graph, historical registrant pivots).
- Authorized-scope-gated public-profile observations from named platforms (LinkedIn, Twitter/X, Mastodon, Bluesky), where the subject's profile is publicly accessible and the operator's scope contract explicitly authorizes red-team-relevant personnel reconnaissance.
- Personnel-graph attribution (organizational-hierarchy inference from public signals).

For every target where the module is configured but enrichment is suppressed (by per-target authorization scope, by data-subject erasure request, by ethical-review hold, by source-availability gap), the artifact records the suppression reason in `identity_surface.suppressed`. Operators must see the difference between "we looked and there was nothing in scope" and "we did not look."

---

## 2. Scope (deliberately narrow)

### 2.1 In scope

ADR-009 §"FF6K Identity Surface" defines three capability categories. This section expands each into concrete capability bundles with explicit constraints.

**WHOIS-personnel correlation beyond Core's WHOIS handling.** Core observes WHOIS contact emails as PII per ADR-008 §Layer 3 and treats them as publicly disclosed. The module extends this with:

- **Registrant-graph analysis.** Cross-reference registrant identifiers across the operator's attributed surface and across historical observations to infer registrant relationships (same individual registering multiple domains, same organization registering through multiple registrants). Output is a graph annotation; the module never asserts identity matches based on WHOIS alone — confidence tiers and `requires_review` flags are mandatory.
- **Historical registrant pivots.** Where historical WHOIS data is available (per Threat Context's historical partners or operator-uploaded historical data), the module follows registrant changes over time to surface relationships that current WHOIS hides.

**Authorized-scope-gated social-media tangential target discovery.** For platforms named explicitly in the operator's scope contract (LinkedIn, Twitter/X, Mastodon, Bluesky):

- **Profile correlation against operator-attributed surface.** Where a publicly-accessible profile names the operator's organization or domain (e.g., a LinkedIn profile naming the operator as the user's employer), the profile is correlated against the operator's surface. Profile attributes captured: display name, public role, public profile URL, public-profile-stated employer relationship.
- **Profile-graph correlation.** Where multiple correlated profiles are observed, organizational relationships among them (peer/manager/report inferred from public signals like "Reports to" sections, named project collaborations, public org-chart references) are surfaced.

**Personnel-graph attribution.** Combining the above, the module produces a personnel graph for the operator's organization composed of public-signal-derived nodes (individuals who have publicly disclosed their relationship to the operator) and inferred edges (organizational relationships inferred from public signals).

### 2.2 Constraints on scope (load-bearing)

These constraints are not aspirational. They define the module's operational scope and any expansion of them requires re-running the module's external ethics review (§16):

- **Operator's own organization only.** The module operates against the operator's organization as defined by the authorization scope. It does not operate against arbitrary third-party organizations even when those organizations appear in the operator's surface. Use against suppliers, customers, partners, or other third parties requires the third party's own scope contract or is refused.
- **Public-signal only.** The module never accesses non-public profiles, never authenticates as the operator's individuals to access non-public personnel directories, never exploits private-data leaks to enrich personnel records.
- **Confirmed/high attribution tier only.** The module operates only against targets the rule engine has attributed at `confirmed` or `high` tier. Lower-tier targets do not receive personnel enrichment; the per-individual harm potential of false positive attribution is too high.
- **Authorized red-team operations or operator-self-assessment only.** The module's outputs are intended for authorized red-team scope-confirmation and operator-self-assessment of personnel-related external surface. Other uses are out of scope and contractually prohibited (§4).

---

## 3. Explicit non-goals (load-bearing)

This section is structurally distinct from a "scope" section. It enumerates capabilities the module **will never have** and uses the module will **never serve**. Each non-goal is documented as a contractual term in the module's EULA, and Korlogos's activation review process for the module refuses activation requests whose stated use case implicates a non-goal.

### 3.1 Capabilities the module will never have

| Non-goal | Why |
|---|---|
| **Real-time individual surveillance.** No live tracking of individual location, activity, or communication. | Direct harm to individuals; falls into EU AI Act high-risk surveillance category; incompatible with daily-batch architecture per SPEC.md §1.2. |
| **Stalking enablement.** No capability designed to support tracking specific named individuals across platforms over time for individual-targeting purposes. | Direct harm to individuals; criminal-misuse risk dominates any defensive use case. |
| **Harassment-campaign enablement.** No capability designed to support coordinated targeting of specific individuals (mass-message generation, public-statement aggregation for amplification, identification of personal-to-individuals communication channels). | Direct harm to individuals; incompatible with intelligence-cycle ethics in §10. |
| **Doxxing-as-a-service.** No capability that aggregates personally-identifying information about non-public individuals into operator-consumable form, even when each individual data point is publicly disclosed. | The aggregation itself is the harm; the line between "public" and "private" data deteriorates as aggregation density grows. |
| **Unauthorized personnel tracking.** No capability that operates against personnel outside the operator's authorization scope, even when operator interest is plausibly legitimate. | The authorization-scope enforcement is the load-bearing distinction between authorized red-team work and adversarial reconnaissance. |
| **Re-identification of pseudonymous individuals.** No capability that links pseudonymous online identities (e.g., a Mastodon handle) to legal names where the individual has not voluntarily disclosed the linkage. | Re-identification is a category of harm in itself; pseudonymity protects journalists, activists, dissidents, abuse survivors, and many others. |
| **Real-time alerting on individual activity.** No capability that surfaces "person X just posted Y" to operators in operator-actionable time. | Real-time alerting on individual activity is surveillance-tool patterning; the daily-batch cadence is operationally sufficient for authorized red-team scope-confirmation. |
| **Behavioral-pattern inference.** No capability that infers individual behavioral patterns (typical posting times, mood inference, sentiment tracking) from public-profile observations. | Behavioral-pattern inference falls into EU AI Act high-risk categorization for the social-scoring prohibition. |
| **Cross-employer correlation.** No capability that correlates an individual's profile across past employers to construct a career history. | Career-history aggregation is precisely the data that EEOC anti-discrimination enforcement scrutinizes; the module refuses to produce an artifact that an employer could use as a pretextual screening input. |
| **Image-based identification.** No facial-recognition capability. No image-search capability. No reverse-image lookup against published profile photos. | EU AI Act explicitly prohibits real-time biometric identification; the module excludes the broader category to avoid any biometric-identification adjacency. |

### 3.2 Use cases the module will never serve

| Use case | Why |
|---|---|
| **Surveillance of journalists, activists, dissidents, or minors.** Use of the module to identify, track, correlate, or aggregate data about individuals in these categories. | Direct harm; categorical refusal regardless of operator request; Korlogos refuses activation for any operator whose stated or apparent use case implicates these categories. |
| **Use against non-consenting individuals.** Use of the module against individuals who have not consented to being subjects of personnel reconnaissance (which, under any consent-respecting framing, includes virtually all individuals not party to the operator's red-team scope contract). | Per the consent-respecting framing, the only legitimate subjects are those covered by the authorization scope's red-team contract; everyone else is out of scope. |
| **Political-targeting.** Use of the module to identify, target, or aggregate data about individuals for political campaigning, political opposition research, or political coercion. | Categorical refusal; falls into EU AI Act high-risk and into US state laws prohibiting some forms of political profiling. |
| **Advertising-targeting.** Use of the module to support advertising-targeting workflows. | The module is not a marketing-data product; the ethics surface and the customer expectations are completely incompatible with advertising-data-product norms. |
| **Employment-targeting / pretextual hiring screens.** Use of the module to screen prospective employees, support employment decisions, or aggregate career data for HR consumption. | EEOC anti-discrimination enforcement; categorical refusal regardless of operator HR-team request; HR-side data products are a different category entirely. |
| **Harassment / coordinated reputation attack.** Use of the module to support coordinated harassment, reputation-damage campaigns, or organized brigading. | Direct harm; criminal-misuse risk; categorical refusal. |
| **Personal-relationship aggregation.** Use of the module to surface personal relationships among individuals (family, romantic, friendship) that an individual has not explicitly published as such. | Direct privacy violation; categorical refusal. |
| **Use against operator's own employees in employment-related contexts.** Use of the module by an employer to surveil, evaluate, or surface data about the employer's own employees beyond the scope of an authorized red-team engagement. | EEOC enforcement; right-to-organize protections; basic employee-trust violation; categorical refusal — operator HR teams should procure legitimate HR data products. |

These non-goals are enforced contractually, not technically. The module's open-source posture is not the issue here (the module is proprietary), but no software can prevent a determined misuser. Korlogos's posture is to refuse activation, refuse renewal, and pursue contractual remedy when misuse is detected — and the module's operational design (audit logging, attestation requirements, kill-switch capability per §6.4) supports detection.

---

## 4. Threat model

This section is distinct from the threat models for Core (SPEC.md §3) and Threat Context (`module-spec-threat-context.md` §4). The Identity Surface threat model centers on adversaries who would misuse the module against individuals.

### 4.1 Adversaries and their goals

**Authoritarian or otherwise hostile actors who acquire commercial access and misuse it against journalists, activists, dissidents.** A foreign-government-aligned customer or front company acquires a Korlogos commercial license under pretext (e.g., posing as a security consultancy) and uses the module against civil-society subjects.

*Mitigation:* Customer-side activation review documented per-customer (§11.1), including KYC-equivalent verification of the operating organization's identity and stated red-team-engagement scope. Korlogos refuses activation when stated scope is implausible or when KYC verification surfaces hostile-actor signals. Quarterly re-review of activation; revocation pathway documented and operationally rehearsed.

**Operators who acquire legitimate access and misuse it against journalists / activists / dissidents / minors.** A legitimately-onboarded customer extends use of the module beyond their stated authorized red-team scope to surveillance use cases.

*Mitigation:* Per-target authorization scope enforced at module dispatch time (§6.3); audit log of every personnel-correlation operation tagged with the operator-asserted scope contract reference and target authorization-tier; Korlogos activation review periodically samples audit logs for scope-violation patterns; contractual right to revoke activation.

**Operators who use the module against their own employees in pretextual ways** (e.g., to screen for organizing activity, to surface protected-class information, to surveil whistleblowers).

*Mitigation:* Per-tenant ethics-attestation prohibits this use case (§7.4); audit log surfaces operator-employee-targeted operations distinctly so internal review can detect the pattern; contractual right to revoke activation; operator-side legal review required as part of activation.

**Operators who suffer credential compromise, where the attacker uses the operator's module access against the operator's own employees** (e.g., a ransomware actor who gains operator access uses the module to identify high-value individual targets within the operator's organization).

*Mitigation:* Operator-side attestation that the module is operated under the operator's IAM controls; audit-log streaming to operator's SIEM so abnormal-use patterns are detectable operator-side; cooling-period for high-rate personnel queries (rate-limit at the module dispatch layer that visibly slows mass-correlation operations and surfaces them in audit logs).

**State-actor compulsion (subpoena, NSL, foreign-jurisdiction equivalent) to disclose module-derived personnel data.** Korlogos receives legal compulsion to disclose specific operators' personnel-correlation outputs.

*Mitigation:* Korlogos's transparency report obligation documented in EULA; data-minimization at storage layer (the module retains derived correlation data with a short retention window — §7.6 — so legal-compulsion disclosure scope is bounded); operator notification of compulsion subject to legal-counsel guidance.

**Module artifact compromise to inject false personnel attributions.** An adversary tampers with the enriched artifact between Environment 1 and Environment 2 to inject false personnel attributions intended to drive operator decisions against specific named individuals.

*Mitigation:* Cosign signing of the enriched artifact (separate signing identity from Core's and from Threat Context's); the enriched artifact references Core's artifact by signed hash; signature verification on Environment 2 ingestion side documented in module SECURITY.md.

**Re-identification attacks against artifacts shared downstream.** An operator forwards the module's enriched artifact to a downstream consumer who uses it for re-identification attacks against pseudonymous data subjects.

*Mitigation:* The module's per-target enrichment includes only attributes the data subject has publicly disclosed in the form the module observes them; pseudonymous identifiers are stored as pseudonyms (no automatic pseudonym-to-real-name resolution); operator agreements prohibit downstream sharing of the enriched artifact outside the authorized red-team engagement boundary.

### 4.2 What the module explicitly does not defend against

The module does not defend against operator misuse that bypasses both the technical controls and the contractual controls. A determined operator who acquires the module under pretext, ignores the scope contract, and processes the module's outputs out-of-band can misuse the data. Open-source and proprietary modules alike face this; Korlogos's commitment is to make misuse contractually impermissible, technically detectable, and operationally consequential — not to make it physically impossible.

The module does not defend against compromise of the operator's host infrastructure. If the operator's environment is compromised, the attacker has access to whatever data the operator has. The module's data-minimization discipline (§7.6) limits the blast radius but does not eliminate it.

The module does not defend against the broader societal harm of personnel-data correlation existing as a category of capability. Korlogos believes the module's narrow-scope design with extensive guardrails serves authorized red-team operations more responsibly than the alternative of operators building ad-hoc personnel reconnaissance with no guardrails. The recommendation in §16 (external ethics review board) is partly a check on whether this belief continues to hold over time.

---

## 5. Authorized-use posture

This section is structurally analogous to ADR-008 §Layer 1/2/3 but materially stricter. Where Core's ADR-008 establishes that "the medium-mode default is informational; it warns but does not block" (§3.2 of ADR-008), Identity Surface's authorized-use posture is **block-by-default with explicit per-target scope enforcement**.

### 5.1 Authorization scope, additional attestation, scope-contract integration

Beyond Core's `authorization_scope` configuration (SPEC.md §10.1), Identity Surface activation requires an **identity surface authorization scope** with structurally-additional fields:

```yaml
identity_surface_authorization_scope:
  scope_contract_reference: <legal-document-id>
  scope_contract_title: <human-readable>
  scope_contract_effective_date: <date>
  scope_contract_expiry_date: <date>
  scope_contract_authorized_red_team_engagement: true   # must be true for activation
  authorized_subject_categories:
    - operator_personnel_in_authorized_red_team_scope
  prohibited_subject_categories:
    - journalists
    - activists
    - dissidents
    - minors
    - non_consenting_individuals
    - operators_own_employees_outside_red_team_scope
    - third_parties_outside_scope_contract
  data_subject_rights_infrastructure:
    erasure_request_endpoint: <url>
    erasure_request_email: <email>
    data_protection_officer_contact: <email>
    response_sla_days: <integer, max 30>
  jurisdiction_compliance_attestations:
    - jurisdiction: <ISO-country-code>
      gdpr_applicable: true | false
      ccpa_applicable: true | false
      operator_legal_review_id: <reference>
      operator_legal_review_date: <date>
  signed_operator_attestation:
    signer_name: <name>
    signer_role: <role; must be authorized signatory>
    signer_attestation_text: |
      <verbatim attestation text matching the EULA-required language>
    signature_method: gpg | pki | docusign
    signature_id: <signature-bundle-id>
    attestation_date: <date>
  korlogos_activation_review:
    reviewer: <korlogos-staff-id>
    review_date: <date>
    review_outcome: approved | conditional | refused
    conditions: []   # if conditional
    next_review_date: <date>   # mandatory quarterly recurrence
```

**Every field is required** for activation. Missing fields refuse activation. The module's activation API rejects scope-contract entries that lack any required field.

**Quarterly re-attestation.** Operator attestation re-execution and Korlogos activation re-review are required quarterly. Lapse of either re-attestation triggers automatic suspension of the module for that tenant.

### 5.2 Scope-contract integration requirements

The operator's scope contract referenced in `scope_contract_reference` must:

- Be a legitimate red-team engagement contract between the operator and the operator's contracting party (whether external client or internal-stakeholder approval).
- Identify the authorized red-team engagement and its scope, including scope of personnel-related reconnaissance.
- Document the contracting party's awareness that personnel-data correlation will occur.
- Include a documented data-handling agreement covering Identity Surface-derived data.
- Be available to Korlogos's activation review on request (in sanitized form sufficient to verify scope).

Operators whose engagements lack one of these elements are advised to obtain the missing element before requesting Identity Surface activation.

### 5.3 Hard mode by default for active personnel-correlation operations

ADR-008's `enforcement_mode` semantics carry forward for the module but the default differs: **the module's effective enforcement mode is `hard`** for any personnel-correlation operation, regardless of the tenant's Core-side `enforcement_mode` setting. There is no `soft` or `medium` mode for personnel correlation.

Concretely:

- Personnel correlation against any subject not explicitly within the `identity_surface_authorization_scope` is **refused at dispatch time**, not flagged in the artifact and continued.
- Active probing of social-media platforms is gated by the explicit `authorized_subject_categories` enumeration; categories not listed are refused.
- The artifact's `outside_authorized_scope_summary` field always shows zero for the module's operations (because operations outside scope are refused, not recorded in the artifact).

### 5.4 Ethical-review process for new collectors

Adding a new collector to Identity Surface requires an ethical review more stringent than Threat Context's collector review (`module-spec-threat-context.md` §5.4). The Identity Surface review additionally covers:

| Review dimension | Question |
|---|---|
| Subject-consent posture | Does the source provide reasonable opt-out for individuals who do not wish to be aggregated? Sources without opt-out posture are rejected. |
| Data-subject-rights compatibility | Does the source's terms of service preserve operator's ability to honor erasure requests against module-derived data? |
| Pseudonymity protection | Does the source require or strongly support pseudonymity? Sources whose users typically use real names (LinkedIn) versus sources where pseudonymity is the norm (Mastodon) are treated differently in collector design. |
| ToS-compliance | Does the source's terms of service permit the module's intended use? Per the hiQ Labs v. LinkedIn outcome (2022 settlement), even publicly-accessible data scraping can be enjoined under breach-of-contract claims when ToS prohibits scraping. The module obtains ToS-compliance review per source. |
| Jurisdiction sensitivity | Does access to this source from the module's deployment jurisdiction or operator's jurisdiction create exposure under local privacy law? |
| Third-party harm potential | Could this collector's existence as a module capability harm individuals beyond the operator's authorized scope? |

The review is documented in the source registry with an approving reviewer identity and a quarterly re-review cadence. New collectors require additional sign-off from Korlogos's ethics review process, and (per §16) ideally from the recommended external ethics review board once that board is established.

### 5.5 Kill-switch capability

The module has a **kill switch** at three levels:

- **Per-tenant kill switch.** Korlogos can administratively suspend a tenant's Identity Surface activation immediately, halting all in-flight operations and refusing new operations. Activation is suspended until re-review. Use cases: suspected misuse, lapsed re-attestation, contractual dispute, legal compulsion that warrants suspension for protection of subjects.
- **Per-collector kill switch.** Korlogos can administratively disable a specific collector for all tenants. Use cases: source-side ToS change, source-side ethical-posture change, legal-compulsion-driven removal.
- **Global module kill switch.** Korlogos can administratively disable the entire module for all tenants. Use cases: severe misuse pattern detected across multiple tenants, regulatory compulsion, internal ethics-review hold pending re-design.

Each kill-switch invocation generates a documented incident record reviewed at next ethics review cadence. The kill switch is operationally rehearsed quarterly (the rehearsal exercises the technical mechanism without affecting customer service except in genuine misuse scenarios).

---

## 6. ETHICS surface deep-dive

This section is materially more extensive than Core's ETHICS.md or Threat Context's ETHICS surface. The module's commitments here are operational, not aspirational — they are reflected in the module's architecture (§7), schema (§8), per-tenant configuration (§11), and EULA terms (§13).

### 6.1 GDPR / CCPA / state-privacy-law handling

The module is a personal-data processor in the GDPR sense and is subject to data-protection law in any jurisdiction where the operator processes personnel data through the module. Concrete commitments:

**Lawful basis for processing.** The module's intended lawful basis under GDPR Article 6 is **legitimate interest** (Article 6(1)(f)) for the operator's authorized cybersecurity-defensive purposes, with the three-part test (purpose, necessity, balancing) documented per-tenant as part of activation review. The operator carries the legitimate-interest assessment; Korlogos's documentation supports the operator's assessment but does not substitute for it. The European Data Protection Board's October 2024 Guidelines 1/2024 on legitimate-interest processing are the reference authority. UK ICO guidance similarly recognizes IT security as a potential legitimate-interest purpose, subject to the balancing test.

**Data-subject rights infrastructure.** The operator must operate a data-subject-rights infrastructure capable of receiving and processing GDPR Article 15 (access), Article 17 (erasure), Article 21 (objection) requests within statutory deadlines (30 days standard). The activation scope contract requires the operator to designate an erasure-request endpoint and a data protection officer contact (§5.1); these are propagated into the module's per-tenant configuration and are reflected in any data-subject documentation the operator publishes.

**Erasure request propagation.** When an operator receives a data-subject erasure request and the operator confirms the request applies to module-derived data, the operator submits the request to the module's per-tenant erasure API. The module deletes the relevant per-target enrichment from active artifacts within 24 hours (well below the 30-day statutory deadline) and from historical artifacts on the next regeneration cadence. Per Core's `delta_from_previous_run.removed.reason` enumeration (`tenant_data_subject_request`), the deletion is recorded as a structured event in subsequent artifacts.

**CCPA / CPRA right-to-delete and the DROP integration.** California's Delete Request and Opt-Out Platform went live 2026-01-01 (per California Privacy Protection Agency announcement), with broker compliance required from 2026-08-01. While Korlogos is not a registered data broker (the module operates per-customer, not as a broker selling lists), Korlogos's posture is to honor DROP-mediated deletion requests forwarded by operators serving California-resident data subjects and to design the module's data handling in DROP-aware ways even where direct broker registration does not apply. CCPA exceptions (§1798.105(d)) for security-incident detection are relied upon only where genuinely applicable; the module's broader operations are subject to the right-to-delete.

**Other state privacy laws.** Virginia (VCDPA), Colorado (CPA), Connecticut (CTDPA), Utah (UCPA), Texas (TDPSA), and other state laws have data-subject-rights infrastructure. The module's per-tenant erasure API is the unified intake; per-state nuances (verification standards, response timelines, exemption scopes) are operator-side compliance work.

**Federal contractor PII rules.** Per federal contracting requirements, federal contractor operators using the module must align module use with the contracting agency's PII handling and incident-reporting expectations. The module's per-tenant audit log is designed for federal-contractor-grade evidence retention.

### 6.2 Data-subject rights — concrete operational commitments

| Right | Commitment | Mechanism |
|---|---|---|
| Right of access (GDPR Art. 15) | Operator can request export of all module-derived data linked to a specified data subject within 30 days. | Per-tenant data-subject API; export format includes provenance and source attribution. |
| Right to erasure (GDPR Art. 17, CCPA §1798.105) | Module-derived data linked to the data subject is deleted within 24 hours of operator's confirmed erasure submission. | Per-tenant erasure API; deletion propagated into next-run artifacts; deletion is recorded as structured `tenant_data_subject_request` event per Core's `delta` schema. |
| Right to object (GDPR Art. 21) | Operator can flag specific data subjects as objected; subsequent runs do not enrich those subjects. | Per-tenant objection list maintained in the tenant configuration; module dispatch refuses operations against objected subjects. |
| Right to rectification (GDPR Art. 16) | Where module-derived data is incorrect, operator can submit a rectification flag; the corrected attribute appears in subsequent runs. | Per-tenant rectification API; corrections are themselves audit-logged. |
| Right to restrict processing (GDPR Art. 18) | Operator can flag specific subjects as restricted; module retains data but does not include in subsequent artifacts pending dispute resolution. | Per-tenant restriction API; restricted subjects appear in suppression-reason summary. |
| Right to data portability (GDPR Art. 20) | Per Art. 20's narrower scope (data the subject has provided), most module-derived data is not subject to portability. Where applicable, structured-export format provided. | Per-tenant data-subject API. |
| Right not to be subject to automated decision-making (GDPR Art. 22) | The module does not produce automated decisions about subjects; outputs are inputs to operator analyst review, not automated decisions. The module-EULA requires operator to maintain meaningful human review in any decision-pipeline. | Architectural; the module produces enrichment, not decisions. |

### 6.3 Retention limits

- **Active enrichment data.** Per-target identity-surface enrichment is retained for the period of the operator's active scope contract (typically the duration of the authorized red-team engagement). Default cap: 90 days, configurable per-tenant downward only.
- **Historical artifact retention.** Once an artifact is generated, the operator controls its retention as the operator's data. Korlogos retains its server-side copy for the standard tenant-retention window (90 days default, per-tenant configurable downward only — not upward without re-attestation).
- **Audit log retention.** Audit log data is retained for the federal-contractor-grade evidence period (3 years default), regardless of active-data retention. This is structurally distinct: data-subject erasure removes enrichment data but does not remove the audit-log fact that an enrichment event occurred. Audit-log retention is a security and compliance requirement, not a personnel-data record.
- **Evidence-store data.** Raw-source observations stored in the evidence-store have explicit per-source retention windows defined per ethical review (§5.4); typically 30 days for social-media observations, 90 days for WHOIS-historical observations.

### 6.4 Opt-out / right-to-erasure mechanisms (subject-direct path)

In addition to operator-mediated data-subject requests (§6.2), the module supports a subject-direct opt-out pathway:

- **Subject opt-out registry.** A globally-shared opt-out registry is maintained by Korlogos. Individuals who do not wish to be subjects of any operator's Identity Surface enrichment can submit themselves to the registry. The module's dispatch checks the registry before any per-individual enrichment operation; opted-out individuals receive `suppressed.reason: subject_opted_out` in the artifact.
- **Verification.** The opt-out registry verification uses minimal-PII signal (proof-of-identity-control on a public profile or domain) sufficient to prevent denial-of-service-style mass-opt-out abuse without burdening the subject with extensive identity disclosure.
- **Persistence.** Opt-out persists across operator changes; if a subject opts out today and a new operator activates the module tomorrow with a scope that would otherwise include that subject, the subject's opt-out is honored.
- **Public documentation.** The opt-out registry and process are publicly documented at a stable Korlogos URL so that any individual can find and use it without requiring operator mediation.

### 6.5 Audit-log requirements

Beyond Core's audit-log discipline (per `framework-annotation.md` §5.2 AU-family coverage), Identity Surface adds:

- **Per-individual-correlation event logging.** Every personnel-correlation operation generates a structured audit-log event with: target identifier, subject pseudonym (not real-name), authorization-scope reference, operator-staff identity (if logged via operator IAM), timestamp, outcome (correlated / suppressed / refused-out-of-scope).
- **Per-erasure-request event logging.** Every erasure-request submission, processing, and completion generates a structured audit-log event with subject pseudonym, request source (operator-mediated or subject-direct), submission timestamp, completion timestamp.
- **Per-attestation event logging.** Every operator attestation, attestation re-execution, and Korlogos activation review event is logged with reviewer identity, decision, conditions.
- **Korlogos-side aggregate audit visibility.** Korlogos's activation-review staff has read-only access to aggregate audit metrics across operator deployments to detect patterns indicating misuse (e.g., abnormally-high cross-tenant query rate, queries that look like one operator using the module against another operator's employees).

### 6.6 Prohibitions (categorical, EULA-codified)

These prohibitions are EULA terms; violation is grounds for license revocation. They restate non-goals from §3 in EULA-actionable form:

- Use against journalists, activists, dissidents, minors, or non-consenting individuals — categorically prohibited.
- Use for political-targeting (campaign work, opposition research, political coercion) — categorically prohibited.
- Use for advertising-targeting (marketing-data product role) — categorically prohibited.
- Use for employment-targeting (HR screening, employee-organizing surveillance, performance-management surveillance) — categorically prohibited.
- Use for harassment, coordinated reputation attacks, or organized brigading — categorically prohibited.
- Use against operator's own employees outside the scope of an authorized red-team engagement — categorically prohibited.
- Re-distribution of module-derived data to third parties outside the authorized red-team engagement boundary — prohibited without per-engagement Korlogos approval.

### 6.7 Third-party data-source ethical-review requirements

Every commercial data-source partnership the module integrates with is subject to a partnership-level ethical review that includes data-subject-rights compatibility (§6.2), pseudonymity protection (§5.4), and ToS-compliance (§5.4). Partnerships whose data practices conflict with these commitments are refused regardless of operational utility.

For social-media platforms specifically: the module's posture per the hiQ Labs v. LinkedIn settlement (2022) is to operate within each platform's terms of service as those terms exist at the time of operation. Platforms that prohibit scraping (LinkedIn enforces this; the 2022 settlement included a permanent injunction) require API-mediated access via the platform's authorized developer programs, where such programs exist and permit the module's intended use. Platforms whose ToS prohibits the module's intended use are refused as collectors regardless of technical feasibility.

---

## 7. Architecture

### 7.1 Separation from Core, separation from Threat Context

The module is a **separate codebase** in a **separate repository** (`github.com/korlogos/ff6k-identity-surface`, private per ADR-009 §"Repository structure"). It has **no source-code dependency on Core or Threat Context**. The module consumes Core's published artifact via the documented schema contract; it does not depend on Threat Context's enriched artifact for its operations (though the module can optionally consume Threat Context's enriched artifact to enrich personnel correlation with WHOIS-historical data, when the operator licenses both modules).

The module deploys as a **separate worker pool** in a **separate cluster** in a **separate cloud account** from Core and from Threat Context. The justification differs from Threat Context's:

- **Personnel-data isolation.** The module's data-store contains personnel data with elevated handling requirements; isolating the deployment ensures Core and Threat Context infrastructure remain free of personnel-data handling obligations.
- **Audit-boundary clarity.** Federal customer 3PAOs reviewing Identity Surface integration can scope their review to the module's deployment without touching Core's or Threat Context's deployments.
- **Blast-radius containment.** A compromise of the module's infrastructure must not pivot into Core or Threat Context infrastructure.
- **Kill-switch granularity.** The module's separate deployment supports the per-module kill switch (§5.5) without affecting Core or Threat Context operations.

### 7.2 Additional security controls

Beyond Core's security posture (per ADR-010 FedRAMP-ready architecture and `framework-annotation.md` §5):

- **Encryption-at-rest of personnel data with stricter key management.** Personnel data in the module's data-store is encrypted at rest using customer-controlled keys where the customer's deployment posture supports it (BYOK), with KMS audit-logging of every key-use event. Default deployment uses Korlogos-managed keys with separate key custody from Core's and Threat Context's keys.
- **Separate audit log with restricted admin access.** Identity Surface audit logs are written to a separate audit-log store with access controls that exclude general Korlogos engineering staff. Access requires elevated authorization analogous to financial-data access controls; access events are themselves audit-logged.
- **Restricted admin access to personnel data.** Korlogos staff with operational responsibility for the module's deployment are subject to elevated background-check requirements (analogous to federal-contractor cleared-personnel posture). The number of staff with such access is intentionally small.
- **No cross-tenant query capability for Korlogos staff.** Even Korlogos administrators do not have a cross-tenant query interface for personnel data; debugging access requires per-incident authorization with documented justification.
- **Data-store partitioning by tenant.** Per-tenant data-store partitioning is physical (separate database schemas or separate database instances per tenant for high-tier customers), not just logical.

### 7.3 Trust boundaries (extends Core's)

Beyond the trust boundaries defined in SPEC.md §2.3 and Threat Context (`module-spec-threat-context.md` §6.3):

**Untrusted third-party platform content → sanitized personnel observations** (between social-media platform ingest and module enrichment). Platform content is treated as adversary-controlled by default; sanitization for personnel-data content reuses Core's stage-3 discipline plus additional personnel-data-specific normalization (e.g., handling of unicode personal-name representations, length-capping of "About Me" text fields, suppression of bio text that contains injection-style payloads).

**Module's enrichment state → enriched artifact** (between graph state and artifact generation). The same deterministic-to-LLM-context discipline Core uses extends here; LLM enrichment in Identity Surface is bounded to the same structured-output, no-tool-access discipline, with the additional constraint that LLM prompts never include real-name personal identifiers — only pseudonymized identifiers that the post-processor maps back to artifact form.

**Subject-direct opt-out registry → module dispatch** (read-side trust boundary). The opt-out registry is read by every per-individual dispatch; integrity of the registry is operationally critical. Registry writes are audit-logged and rate-limited; reads use signed-batch verification.

### 7.4 LLM enrichment in Identity Surface

The module reuses Core's `LLMProvider` abstraction and `SafeLLMClient` wrapper (SPEC.md §8.4) with additional restrictions:

- **No personal-name input.** LLM prompts use pseudonymized identifiers; the prompt construction layer rejects real-name strings via a regex-and-known-name-list filter before prompt construction. Real-name resolution happens only post-LLM-output, on the module's deterministic side.
- **No biographical inference.** The LLM is not asked to infer biographical facts, behavioral patterns, demographic attributes, or any other personal attribute beyond what's strictly necessary for the structured output (e.g., tech-stack inference from a public role description).
- **No re-identification reasoning.** The LLM is never asked to correlate pseudonymous identifiers to real names; this work is deterministic when permitted at all and never performed by the LLM.
- **Stricter cost ceiling.** Default per-run cost ceiling for personnel-related LLM operations is $25 USD (lower than Threat Context's $50 default), reflecting both the smaller per-target operation set and the stricter discipline expected.

---

## 8. Schema additions (`canonical-identity-surface-v1`)

### 8.1 Top-level structure

The Identity Surface enriched artifact is, like Threat Context's, a documented superset of `canonical-artifact-v1.json`. It carries every field Core's artifact carries plus the additions below.

```
{
  "schema_version": "expose-identity-surface/v1",
  "core_artifact_ref": {
    "artifact_path": "...",
    "artifact_sha256": "...",
    "core_run_id": "..."
  },
  // ... all fields from canonical-artifact-v1.json ...
  "identity_surface_enrichment": {
    "module_version": "...",
    "rule_pack_version": "...",
    "enrichment_run_id": "...",
    "started_at": "...",
    "completed_at": "...",
    "scope_contract_reference": "...",
    "scope_contract_attestation_id": "...",
    "subject_categories_processed": ["operator_personnel_in_authorized_red_team_scope"],
    "subjects_opted_out_count": 0,
    "subjects_erased_this_run_count": 0,
    "subjects_objected_count": 0,
    "is_collector_health": {...}
  }
}
```

Each `Target` object in the enriched artifact's `targets` array carries an additional optional `identity_surface` block:

```
{
  "target_id": "...",
  // ... Core's Target fields ...
  "identity_surface": {
    "personnel_correlation": [...],
    "registrant_graph_observations": [...],
    "personnel_graph_summary": {
      "personnel_node_count": ...,
      "inferred_organizational_relationships_count": ...
    },
    "suppressed": null | {
      "reason": "subject_opted_out | data_subject_erasure | per_target_scope_disabled | source_unavailable | ethical_review_pending | tenant_jurisdiction_excluded | hard_mode_refused_out_of_scope",
      "details": "..."
    }
  }
}
```

### 8.2 Personnel correlation entry — redaction options

Each `personnel_correlation` entry has multiple representation modes determined by per-tenant configuration. The default mode is **maximum redaction**:

```
{
  "subject_pseudonym": "is-{tenant-scoped-pseudonym}",
  "subject_attributes": {
    "public_role_category": "engineering | sales | marketing | leadership | other",
    "publicly_stated_employer_relationship": "current | former | unspecified",
    "public_signal_corroboration_count": 1-N
  },
  "source_observations": [
    {
      "source_pseudonym": "platform_a | platform_b | whois | platform_c",
      "first_observed_at": "...",
      "last_observed_at": "...",
      "ethical_review_id": "..."
    }
  ],
  "evidence_refs": ["sha256:..."],
  "review_required": true | false
}
```

Per-tenant configuration can opt **upward** to a less-redacted representation only with explicit per-tenant attestation and only for tenants with a documented legitimate operational need. Opt-up modes:

- **`role_disclosure`** mode: `subject_attributes` includes specific role string (e.g., "Senior Software Engineer") rather than category.
- **`name_disclosure`** mode: `subject_pseudonym` is replaced by `subject_name` containing the publicly-disclosed name. This mode requires additional attestation and is incompatible with subjects who have opted into pseudonym-only treatment.

The default-redaction posture enforces minimum-disclosure as a structural property: even an operator who later decides to misuse the artifact gets fewer hooks to misuse if the artifact never carried real-name PII to begin with.

### 8.3 Registrant graph observations

```
{
  "registrant_pseudonym": "...",
  "observed_role": "registrant | admin_contact | tech_contact",
  "registration_count_within_scope": ...,
  "first_observed_at": "...",
  "last_observed_at": "...",
  "evidence_refs": ["sha256:..."],
  "review_required": true | false
}
```

Note: the module never resolves `registrant_pseudonym` to a name in the artifact even when the underlying WHOIS observation contains a name. Real-name resolution is operator-side workflow (operators consume the artifact, then perform whatever real-name resolution their authorized red-team scope permits) and does not happen inside the module.

### 8.4 Per-tenant raw-PII opt-in

Per ADR-009 §"FF6K Identity Surface" emphasis on the higher ethics bar, **the module's default posture is no raw PII in artifacts**. Operators may opt in per-tenant to raw-PII inclusion (e.g., real names rather than pseudonyms in the `personnel_correlation` block) only with:

- Explicit raw-PII attestation in the activation scope contract.
- Documented operational necessity (raw-PII inclusion is not the default for any common authorized red-team engagement; the necessity must be documented).
- Korlogos activation-review approval specifically for raw-PII opt-in.
- Quarterly re-attestation of continued raw-PII necessity.

Raw-PII opt-in is auditable per-tenant. Federal-contractor PII handling rules and operator-jurisdiction privacy law apply once raw PII enters the artifact; the operator's legal review owns the assessment.

### 8.5 Schema validation

The Identity Surface enriched-artifact schema is published in `schemas/canonical-identity-surface-v1.json` (in the private Identity Surface repository). The schema is structurally compatible with `canonical-artifact-v1.json`. The schema definition includes JSON Schema validation rules that enforce structural redaction (e.g., `subject_name` field is conditionally permitted only when the artifact's metadata records raw-PII opt-in attestation).

---

## 9. Collector matrix

Collectors in Identity Surface follow Core's pluggable-collector contract (SPEC.md §6.1) extended with the elevated ethical-review process (§5.4).

### 9.1 Personnel-data sources (public-only)

| Collector ID | Source | License Posture | Ethical-Review Status | Pseudonymity Posture |
|---|---|---|---|---|
| `is-whois-personnel` | Public WHOIS/RDAP | Public-record | Approved (quarterly review) | Real-name-typical |
| `is-linkedin-public` | LinkedIn Developer API (where partnership permits authorized red-team API use) | Per-platform license; subject to ToS | **Pending; v1 default off** | Real-name-typical |
| `is-twitter-public` | Twitter/X API (developer-tier compatible with red-team scope) | Per-platform license | **Pending; v1 default off** | Mixed (real and pseudonymous) |
| `is-mastodon-public` | Mastodon Federation API | Per-instance terms | Approved with per-instance care | Pseudonymous-typical |
| `is-bluesky-public` | Bluesky AT Protocol | Open-protocol-compatible | Approved | Mixed |
| `is-github-public` | GitHub public profile API | Standard GitHub terms; technical-staff often visibly disclose employer | Approved | Mixed |
| `is-orcid-public` | ORCID public researcher profile | Open | Approved | Real-name-typical |

Note on the LinkedIn / Twitter status: per the hiQ Labs v. LinkedIn 2022 settlement and the broader social-media ToS-enforcement landscape, scraping these platforms is contractually prohibited. The module's posture is to use only platform-authorized API access where it exists for the module's intended use. LinkedIn's API access tier suitable for red-team-scope-confirmation purposes is, as of May 2026, restricted; the module ships with the LinkedIn collector default-off pending confirmation that an approved API access path exists. The same posture applies to Twitter/X.

### 9.2 No-go collectors (categorical)

Several plausible collector ideas are excluded categorically from the module's roadmap:

| Excluded Collector | Why excluded |
|---|---|
| Facebook / Instagram personal profiles | Platform ToS prohibitions; high-noise / low-signal for authorized red-team scope confirmation; exposes the module to significant misuse pathway |
| TikTok personal profiles | Same as Facebook/Instagram plus jurisdictional sensitivity |
| Personal email harvesting | Categorically prohibited per non-goal §3.1 |
| Personal phone number aggregation | Categorically prohibited per non-goal §3.1 |
| Home-address resolution | Categorically prohibited per non-goal §3.1 |
| Personal-relationship inference (family / romantic) | Categorically prohibited per non-goal §3.2 |
| Image-based identification | Categorically prohibited per non-goal §3.1 |
| Voice-pattern identification | Categorically prohibited (analogous to image-based) |

These exclusions are documented in the module's collector-registry as permanent exclusions; adding any of them requires not only ethical review (§5.4) but also explicit external-ethics-review-board approval (§16) and Korlogos executive-leadership approval. They are intended to stay excluded.

### 9.3 Per-collector documentation requirements

Each collector's documentation in the source registry includes, beyond the standard collector documentation:

- The platform's data-subject-rights posture and how the module integrates with it.
- The platform's pseudonymity norms and how the collector treats them.
- The platform's ToS extract relevant to the module's intended use.
- The platform's relevant API documentation and the specific API-access tier the module uses.
- The ethical-review record, with reviewer identities and re-review schedule.

---

## 10. Per-tenant configuration

Identity Surface configuration is added as an additional block in tenant configuration. The module is **not enabled by default** for any tenant (per ADR-009 §"FF6K Identity Surface" explicit design); activation requires the activation-review process documented in §5.

```yaml
identity_surface:
  enabled: false   # default; explicit activation required
  license_id: <commercial-license-uuid>
  activation_attestation_bundle_id: <reference>

  identity_surface_authorization_scope:
    # ... see §5.1 for the full required structure ...

  capability_scope:
    whois_personnel_correlation: true | false
    registrant_graph_analysis: true | false
    historical_registrant_pivots: true | false
    social_media_correlation: true | false
    personnel_graph_inference: true | false

  social_media_platforms_enabled:
    linkedin: false   # default off pending API-access confirmation
    twitter_x: false   # default off pending API-access confirmation
    mastodon: true | false
    bluesky: true | false
    github: true | false
    orcid: true | false

  redaction_mode: maximum_redaction | role_disclosure | name_disclosure
    # default: maximum_redaction; opt-up requires additional attestation

  raw_pii_in_artifact:
    enabled: false   # default; opt-in requires additional attestation
    attestation_id: <reference if opted in>

  retention:
    active_enrichment_data_days: 90   # default; configurable downward only
    historical_artifact_days: 90   # default; configurable downward only
    audit_log_days: 1095   # 3 years default; not reducible

  data_subject_rights:
    erasure_endpoint: <url>
    objection_list_ref: <reference>
    rectification_endpoint: <url>

  korlogos_activation_review:
    last_review_date: <date>
    next_review_date: <date>
    reviewer: <korlogos-staff-id>
    decision: approved | conditional | refused
    conditions: []

  llm:
    cost_ceiling_usd_per_run: 25.00
    enrichment_policy: confirmed_high_tier_targets_only
```

The `enabled: false` default is structurally meaningful: it is not a placeholder. Activation is an event that requires explicit human review on both operator and Korlogos sides.

### 10.1 Activation prerequisites — single-sentence summary

For Korlogos to activate Identity Surface for a tenant, the operator must produce: a written scope contract documenting an authorized red-team engagement; documented data-subject-rights infrastructure; a signed operator attestation matching the EULA-required attestation language; a documented operator-side legal review for each applicable jurisdiction; and a designated data protection officer contact.

If any of these is absent, activation is refused. Korlogos's activation-review staff is not authorized to waive any of these requirements.

---

## 11. Activation policy (operationalizes ADR-009 §"off by default")

ADR-009 §"FF6K Identity Surface" states the module is "off by default; requires explicit per-tenant authorization scope acknowledgment with an additional attestation beyond Core's authorization scope". This section operationalizes that statement.

### 11.1 Activation review process

The Korlogos activation-review process for Identity Surface is structurally distinct from license-issuance. Acquiring a license to the module (commercial licensing) does not activate the module; activation is a separate event reviewed per-tenant.

Steps:

1. **License issued.** The operator obtains a commercial license to the module under the EULA.
2. **Activation request submitted.** The operator submits an activation request including the activation prerequisites (§10.1).
3. **Korlogos KYC-equivalent review.** Korlogos's activation-review staff verifies the operator's identity, organizational legitimacy, and stated red-team-engagement scope. Verification standards are documented internally; activation-review staff is not authorized to waive verification for any reason including customer service pressure or commercial pressure.
4. **Korlogos ethics review.** Korlogos's ethics-review staff (distinct from activation-review staff for separation-of-duties) reviews the stated use case for any non-goal implication (§3). Ethics review can refuse activation on its own authority.
5. **Per-jurisdiction legal review confirmation.** Korlogos confirms the operator-side legal review documentation for each applicable jurisdiction is present. Korlogos does not perform the operator's legal review; Korlogos confirms the operator has performed it.
6. **Activation effected.** If all gates clear, activation is effected with a documented activation-event audit-log entry.
7. **Quarterly re-review.** Activation re-review happens quarterly with simplified re-attestation; lapse triggers automatic suspension.

### 11.2 Refusals

Korlogos refuses activation in the following cases (non-exhaustive):

- The operator's stated use case implicates any non-goal in §3.
- The activation prerequisites in §10.1 are incomplete.
- KYC-equivalent review surfaces hostile-actor signals (front-company indicators, sanctioned-jurisdiction operator, public-record concerns about the operator's prior activity).
- The operator's stated authorized red-team engagement scope is implausible, missing essential detail, or appears constructed-after-the-fact to justify activation.
- The operator's data-subject-rights infrastructure is documented but appears non-functional (e.g., the erasure endpoint returns errors; the data protection officer contact is invalid).
- The operator-side legal review documentation is absent for an applicable jurisdiction.
- Operating-jurisdiction or operator-jurisdiction privacy law makes the module's operations implausibly compliant.
- The activation request appears to be testing the activation process rather than reflecting genuine intent to operate (probing the gates).

Refusals are documented; refused operators may resubmit after correcting deficiencies. Repeat refusals may trigger Korlogos to refuse the operator's commercial license entirely.

### 11.3 Suspensions and revocations

Activation may be suspended (temporary) or revoked (permanent) for:

- Lapse of quarterly re-attestation.
- Audit-log pattern indicating misuse.
- Operator complaint or external-third-party complaint surfacing misuse.
- Korlogos receipt of legal compulsion against the operator suggesting misuse.
- Korlogos's external ethics review (§16) recommending suspension or revocation.

Revocation is contractually permitted under the module's EULA. Operators can dispute revocation through the EULA's contractual-dispute process; Korlogos's authority to revoke is robust against commercial pressure.

---

## 12. Compliance considerations

This section enumerates regulatory frameworks that materially intersect with the module's operations. It does not constitute legal advice; per §10.1 each operator carries operator-side legal review for their applicable jurisdictions.

### 12.1 GDPR (EU + EEA + UK by extension)

- **Lawful basis.** Article 6(1)(f) legitimate interest for cybersecurity-defensive purposes is the intended basis; operator carries the three-part assessment (purpose, necessity, balancing) per EDPB Guidelines 1/2024 on legitimate interest.
- **Data-subject rights.** GDPR Articles 15 (access), 16 (rectification), 17 (erasure), 18 (restriction), 20 (portability), 21 (objection), 22 (automated decision-making) all apply.
- **Data protection impact assessment (DPIA).** Operators using the module on EU/EEA data subjects must conduct a DPIA per Article 35 — the module's nature triggers DPIA mandatory thresholds.
- **Data protection officer.** EU/EEA operators must designate a DPO per Article 37 thresholds; the module's per-tenant configuration captures DPO contact.
- **Cross-border transfer.** If the module's deployment processes EU/EEA personal data outside EU/EEA, Articles 44-50 apply (Standard Contractual Clauses, adequacy decisions, supplementary measures).

### 12.2 CCPA / CPRA (California) and other US state privacy laws

- **Right to delete.** California Civil Code §1798.105 right-to-delete applies to module-derived data about California residents.
- **DROP.** California's Delete Request and Opt-Out Platform (operative 2026-01-01 per California Privacy Protection Agency) is referenced for operators acting in roles that intersect with data-broker registration. While Korlogos itself is not a data broker (the module is not a data-list product), operators who use the module in ways that approach broker activity face their own DROP obligations.
- **VCDPA / CPA / CTDPA / UCPA / TDPSA.** Virginia, Colorado, Connecticut, Utah, Texas state laws all have data-subject-rights infrastructure interacting with the module. Per-state nuances are operator-side compliance.
- **Sensitive personal information.** CPRA's "sensitive personal information" category (precise geolocation, race, ethnicity, religion, mental/physical health, sexual orientation) is categorically excluded from the module's collected attributes (collectors are designed not to capture these).

### 12.3 Federal contractor PII rules

- Federal contractor operators using the module are subject to the contracting agency's PII-handling expectations, FedRAMP-aligned at agency option.
- Federal Information Security Management Act (FISMA) and Privacy Act of 1974 implications for federal-government contracting customers.
- Per ADR-010, the module's audit-log and integrity-evidence streams are designed for federal-contractor evidence retention.

### 12.4 EEOC anti-discrimination

- Use of the module to support employment decisions is prohibited (§3.2), reducing exposure under EEOC enforcement of Title VII (race, color, religion, sex, national origin), ADA (disability), ADEA (age 40+), GINA (genetic information).
- Even where employment-decision use is intended-prohibited, operators with HR-team activity must ensure operational separation between Identity Surface use (red-team work) and HR function.

### 12.5 EU AI Act high-risk classification

- The EU AI Act (Regulation (EU) 2024/1689) applies to AI systems including those used in the EU/EEA market.
- The module's LLM enrichment is a limited-AI-system use; the broader module is rule-based correlation, not AI in the AI Act's classification sense.
- The module's design explicitly avoids AI Act prohibited categories (no social-scoring system per §3.1 categorical exclusion of behavioral-pattern inference and cross-employer correlation; no real-time biometric identification per §3.1 image-identification exclusion).
- High-risk-system enforcement starts 2026-08-02 (per EU AI Act timeline); per-jurisdiction operator legal review covers enforcement implications.

### 12.6 Professional-norms compliance

- **Authorized red-team operations professional norms.** The module's intended use case sits within the SANS-aligned, OWASP-aligned authorized-penetration-testing community norms of scope contracts, rules of engagement, and explicit authorization.
- **OSINT community norms.** The OSINT (open-source intelligence) practitioner community has emerging norms on subject consent, harm-prevention, and source ethics that the module's design respects (§5.4 ethical review process, §6.4 subject opt-out registry).
- **Cybersecurity-research community norms.** Research-community norms on responsible disclosure, harm minimization, and subject consent are reflected in the module's design (§5.5 kill-switch capability, §16 external ethics review board recommendation).

---

## 13. Pricing model (high-level)

Detailed pricing is deferred to a discrete go-to-market session, with the additional discipline that pricing for Identity Surface is structurally distinct from Threat Context's pricing because the unit economics, the activation-review effort, and the per-customer compliance burden differ materially.

- **Separate license from Core and from Threat Context.** Operators pay a separate license fee for Identity Surface regardless of any other module licensing.
- **Stricter contractual terms.** The Identity Surface EULA includes the categorical prohibitions (§6.6) as contractual terms with revocation authority for Korlogos.
- **Per-tenant minimum spend.** Higher than Threat Context's per-tenant minimum, reflecting the activation-review burden, the compliance overhead, and the alignment-with-customer-scale expectation.
- **Per-engagement pricing alternative.** Some red-team consultancies prefer per-engagement pricing rather than annual subscription; a per-engagement pricing tier is anticipated for the boutique-consultancy customer segment.
- **Federal-customer pricing.** Federal customers with appropriate authorization may receive bundle pricing patterns; some federal agencies will explicitly bar this module per §14, in which case bundle pricing excludes Identity Surface entirely.
- **No usage-based pricing.** Identity Surface is not priced per personnel-record-correlated; usage-based pricing creates incentives misaligned with the module's responsible-use posture.

---

## 14. Federal-customer considerations

Federal customers have specific characteristics that affect Identity Surface adoption posture more so than for Core or Threat Context.

### 14.1 Some federal agencies will explicitly bar this module

Many federal agencies will, by policy, refuse to acquire personnel-correlation tooling regardless of the module's safeguards. Reasons include:

- **Privacy Act of 1974 implications.** Federal agencies operating Privacy-Act systems-of-records have prescribed handling for personnel data; introducing a personnel-data-correlation module into the agency environment may trigger SORN-revision requirements the agency declines to undertake.
- **Civil-liberties oversight policies.** Some agencies (notably those with civil-liberties offices like ODNI civil-liberties oversight, DHS CRCL) have policies that scrutinize personnel-data tools regardless of the operator's stated use.
- **Inspector general posture.** Agency IGs may scrutinize personnel-data acquisitions as audit-risk events.
- **Internal-affairs sensitivity.** The pattern-of-use of the module against agency personnel could be misread as internal-affairs surveillance even when the actual use is authorized red-team scope confirmation.
- **Federal employee union and labor-relations sensitivity.** Federal employee organizations may object to the deployment of personnel-correlation tooling in the workplace regardless of stated use.

The Federal Customer Deployment Guide (Session G) will document this categorically; some agencies' policies make Identity Surface adoption inappropriate. Pursuing Identity Surface sales into those agencies is wasted effort and potentially contractually fraught.

### 14.2 For agencies where adoption is plausible

The agencies plausibly compatible with Identity Surface adoption are typically those with:

- An explicit authorized red-team capability (USCYBERCOM red teams, certain DOE national-laboratory engagements, certain FFRDC engagements).
- Documented internal scope-contract discipline analogous to commercial red-team contracts.
- Civil-liberties-office sign-off processes that can review personnel-correlation tooling per-engagement.
- Operational scale justifying the personnel-correlation capability beyond ad-hoc methods.

For these agencies, the activation prerequisites in §10.1 still apply; agency-specific activation prerequisites may add additional gates.

### 14.3 ATT&CK / framework coverage delta

Per `framework-annotation.md` §2.1, T1589.003 (Employee Names) is marked "Out of scope for EXPOSE Core" with "Handled in commercial Identity Surface module per ADR-009". Activating Identity Surface fills this gap, with the caveat that the module's coverage is operationally narrower than the technique description (the module focuses on operator-attributed personnel only, not arbitrary victim personnel).

The module's NIST 800-53 control posture inherits Core's posture and adds:

| Control | Core Coverage | Identity Surface Extension |
|---|---|---|
| AC-3 (access enforcement) | Satisfies | Extends with per-target Identity Surface scope enforcement; categorically refuses out-of-scope dispatch |
| AU-2, AU-3, AU-12 (audit logging) | Satisfies | Extends with per-individual-correlation event logging, per-erasure-event logging, per-attestation-event logging |
| SC-28 (at-rest protection) | Satisfies | Extends with separate key custody, BYOK option, restricted-admin-access controls |
| SI-12 (information management and retention) | Satisfies | Extends with subject-direct opt-out registry, data-subject erasure, subject objection list |
| **Privacy Act controls** | N/A | Module-introduced consideration for federal customers |

### 14.4 Authorization-boundary considerations

Identity Surface, like Threat Context, deploys in a separate worker pool / cluster / cloud account from Core. Federal-customer deployment options are analogous to Threat Context's (`module-spec-threat-context.md` §11.1):

- **Self-host within agency boundary.** Operationally heavy; the agency must inherit the module's compliance burden into the agency's ATO, including personnel-data handling discipline.
- **Korlogos-managed.** Depends on the future Korlogos commercial offering's FedRAMP authorization (per ADR-010 Commitment 3) plus Korlogos's evolved capability to handle federal-customer personnel data.
- **Hybrid.** Generally not recommended for Identity Surface given the personnel-data-handling sensitivity.

---

## 15. Phase plan

Identity Surface's phase plan is **dependent on completion of the external ethics review board recommendation in §16** before any phase reaches commercial availability. Korlogos may execute the technical phases internally before the ethics-review-board recommendation closes, but commercial availability is gated on the ethics-review outcome.

### 15.1 Phase IS-0 — Foundation (4 weeks; can start in parallel with Threat Context Phase TC-0)

- Repository setup: private repository, commercial EULA with categorical prohibitions and revocation authority, SECURITY.md, ETHICS.md (separate from Core's and from Threat Context's), CONTRIBUTING.md.
- Activation-review process documented and operational (§5, §11).
- Subject-direct opt-out registry deployed (§6.4).
- Enriched-artifact schema: `schemas/canonical-identity-surface-v1.json` and JSON Schema validation.
- Module-side cosign signing identity provisioned with separate key custody; signing-key custody documented.
- Ethics-review process operational (§5.4).
- Cross-tenant isolation test suite extended for the module.

### 15.2 Phase IS-1 — WHOIS-personnel correlation (4 weeks)

This is the lowest-ethics-surface capability and ships first.

- WHOIS-personnel collector (`is-whois-personnel`) ingest and correlation.
- Registrant graph analysis.
- Historical registrant pivot collector (in coordination with Threat Context historical partners).
- Per-target `identity_surface.registrant_graph_observations` block in the enriched artifact.

### 15.3 Phase IS-2 — Pseudonymous-platform correlation (6 weeks)

The pseudonymous-typical platforms (Mastodon, Bluesky, GitHub, ORCID) ship before the real-name-typical platforms.

- Mastodon, Bluesky, GitHub, ORCID collectors operational.
- Per-target `identity_surface.personnel_correlation` block in the enriched artifact in maximum-redaction mode.
- Subject opt-out registry integrated into dispatch.

### 15.4 Phase IS-3 — Personnel-graph inference (4 weeks)

- Personnel-graph inference from corroborated multi-source public signals.
- Personnel-graph summary in the enriched artifact.
- LLM-assisted (bounded, structured-output) corroboration scoring.

### 15.5 Phase IS-4 — Real-name-typical platform integration (8 weeks; conditional on platform API access)

- LinkedIn collector — only if a platform-authorized API access path becomes available for the module's intended use.
- Twitter/X collector — same condition.
- If no platform-authorized access path is available within the phase window, this phase is deferred.

### 15.6 Phase IS-5 — External ethics review board engagement (concurrent; pre-commercial-availability gate)

- External ethics review board established per §16.
- Initial review of the module's design and operational posture.
- Review-recommendation incorporation before commercial availability.

### 15.7 Commercial availability gate

The module **does not enter commercial availability** until:

- Phases IS-0 through IS-3 complete.
- External ethics review board (Phase IS-5) issues an initial recommendation, and Korlogos has incorporated the recommendation into the module's design and operational posture.
- Korlogos's internal go-to-market readiness review confirms operational readiness for activation reviews at customer scale.

Phase IS-4 (real-name-typical platforms) can ship after commercial availability, conditional on platform-authorized API access.

### 15.8 Phase IS-6 — Ongoing

- Quarterly source-registry re-review.
- Quarterly per-tenant activation re-review.
- Quarterly external ethics review board review.
- Continuous data-subject-rights infrastructure operation.

---

## 16. Open questions — including the external ethics review board recommendation

These items are explicitly unresolved and shape future work. Several are load-bearing for the module's responsible operation.

| Question | Why it matters | Suggested resolution path |
|---|---|---|
| **External ethics review board.** Should the module establish an external ethics review board to vet the module's design and operations before public availability? | The module's ethics surface is materially larger than the rest of the EXPOSE product line. An external board provides independent scrutiny that Korlogos's internal review cannot fully substitute. The recommendation is to **establish the board before public availability**, not after. | **Recommended: establish board pre-commercial-availability.** Composition: 5-7 members with diversity across legal-academic / civil-liberties-org / red-team-practitioner / federal-government-civil-liberties / privacy-research / journalism perspectives. Quarterly review cadence; veto authority over new collectors and over per-jurisdiction expansion. Honoraria but not employment. Public board composition with charter publication. |
| **LinkedIn / Twitter API access pathway.** Is there a platform-authorized API access path for the module's intended use? | Without platform-authorized access, the real-name-typical-platform capabilities are deferred indefinitely. Per the hiQ Labs settlement and the broader social-media ToS-enforcement landscape, scraping is not a viable alternative. | Engage with each platform's developer-relations function; document the access posture; defer collectors absent platform-authorized access. |
| **Subject opt-out registry verification standard.** What is the appropriate verification standard for subject opt-out submissions to prevent denial-of-service-style mass opt-outs while preserving low subject burden? | Over-strong verification harms subject opt-out rate; under-strong verification permits abuse. | Implement DKIM-mediated email verification or similar low-burden verification; iterate based on operational experience. |
| **Per-jurisdiction sub-national granularity.** Should subject opt-out and operator activation-review carry sub-national jurisdiction granularity (US state, EU member state)? | Some state laws diverge materially from the federal-equivalent baseline (e.g., California's Delete Act and DROP). Operator activation-review may need to differentiate. | Initial v1: country-level for activation-review; US-state-level for CCPA / DROP integration. Expand if operator demand emerges. |
| **Korlogos-side activation-review staffing.** How is Korlogos's activation-review function staffed and incentivized to refuse activations that should be refused, against commercial-pressure incentives? | Activation-review function whose performance is measured on activation-rate is structurally incompatible with refusing activations. Need separation. | Activation-review staff reports outside commercial / sales reporting line; performance review on review-quality metrics, not approval-rate. Document explicitly in operational policy. |
| **Cross-tenant data leakage prevention.** Is logical multi-tenancy sufficient or does Identity Surface require physical multi-tenancy (separate database per tenant) by default? | The personnel-data context elevates cross-tenant leakage harm. | Recommend physical multi-tenancy by default for Identity Surface, deviating from Core's logical-by-default per ADR-007. Per-tenant database schema or per-tenant database instance for high-tier customers. |
| **Operator-side legal-review verification.** How does Korlogos confirm operator-side legal review documentation is genuine and current without itself becoming the operator's legal counsel? | Falsified legal-review documentation defeats the activation-review process. | Documented standards for legal-review evidence (counsel of record, jurisdiction-appropriate qualification); spot-check verification; refusal upon demonstrated falsification with permanent license-acquisition bar. |
| **Erasure cascade across coordinated module customers.** When a subject submits a direct opt-out, how does it cascade across multiple operators who may have already enriched the subject? | A subject who opts out today may have correlations in operator A's, B's, C's prior artifacts. The opt-out should propagate. | Direct opt-out propagates to all active operators within 24 hours and is reflected in the next per-operator artifact regeneration. Historical artifacts already in operator possession are subject to operator's data-handling agreement. |
| **EU AI Act high-risk system reclassification.** As EU AI Act enforcement matures (operative 2026-08-02), if the module is reclassified as high-risk by national-regulator interpretation, what is the response path? | High-risk-system reclassification triggers extensive AI Act compliance obligations (conformity assessment, post-market monitoring, fundamental-rights impact assessment). | Maintain monitoring of EU AI Act enforcement guidance; ready response plan to either invest in high-risk-system compliance or withdraw from EU jurisdiction; default position is investment over withdrawal. |
| **Federal Privacy Act SORN implications for federal customers.** What SORN implications does federal-customer activation create? | Federal customers may need to publish SORN updates; this is an agency-side burden but it affects the module's federal adoption pathway. | Document analysis in Federal Customer Deployment Guide (Session G); coordinate with each federal customer's privacy office during activation review. |
| **Operational detection of misuse patterns.** What audit-log patterns reliably indicate misuse, given the small per-tenant operation rate that is operationally appropriate for the module? | Misuse detection is the operational backstop to activation-review and contractual prohibition; needs to actually work. | Document pattern catalog with examples; iterate based on real-world incidents; surface high-signal patterns to Korlogos activation-review staff for per-tenant follow-up. |
| **Sunset / wind-down policy.** If the module proves to be fundamentally incompatible with responsible operation despite the guardrails, what is the wind-down policy? | The module's posture is to err toward more guardrails; the limiting case of "the guardrails are insufficient" should have a defined response. | Documented wind-down policy: revoke all activations within 90 days with subject-data-erasure cascade; cease commercial availability; preserve audit-log evidence per legal-retention requirements. The wind-down policy is a forcing function — its existence makes "we'll figure it out if it goes wrong" not the answer. |

---

## 17. Document maintenance

This is a working specification, held to a higher revision-discipline bar than other strategy documents in this project's `docs/strategy/` directory.

Triggers for revision:

- Each phase completion (IS-0 through IS-6).
- Each external ethics review board cycle (initial + quarterly).
- Each ADR revision affecting the module (ADR-008, ADR-009, ADR-010 in particular).
- Material legal-landscape changes (GDPR enforcement evolution, CCPA / DROP enforcement evolution, state-privacy-law expansion, EU AI Act high-risk-system reclassification, federal Privacy Act guidance, EEOC guidance on AI-mediated employment decisions).
- Material change to a referenced platform's terms of service or API access.
- Discovery of any operational misuse pattern not anticipated by this spec.
- New collector additions to the registry.
- New jurisdiction expansion (operator jurisdiction or operating jurisdiction).

Revision cadence: **monthly review** during Phase IS-0 through IS-3; quarterly thereafter, with immediate revision on any external-ethics-review-board recommendation, any operational-misuse-pattern discovery, or any material legal-landscape change.

This higher cadence is deliberate. The module's ethics surface and legal-landscape exposure are dynamic in ways the rest of the EXPOSE product surface is not.

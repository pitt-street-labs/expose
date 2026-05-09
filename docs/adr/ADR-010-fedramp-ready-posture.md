# ADR-010: FedRAMP-ready posture

**Status:** Accepted
**Date:** 2026-05-09
**Decision-makers:** Korlogos / Pitt Street Labs

## Context

The 2026-05-09 design conversation locked the commitment that FF6K will be **FedRAMP-ready by design**, and subsequently clarified what this means in practice through a careful research review of FedRAMP authorization boundary policy.

Key findings from that review:

1. FedRAMP's authorization boundary is defined by where federal data is stored, processed, or transmitted. A tool that observes only publicly available, internet-facing data about federal systems — running outside any federal authorization boundary — is not, by virtue of that observation alone, processing federal data in the FedRAMP sense.

2. CISA Binding Operational Directive 23-01 explicitly recommends federal agencies use third-party EASM solutions for attack surface visibility. Tools observing federal systems from outside agency boundaries are not categorically required to hold their own FedRAMP authorization for that observational use case.

3. The deployment model matters more than the architectural model for FedRAMP applicability. An open-source tool a federal agency self-hosts within their existing authorization boundary inherits the agency's ATO and does not require independent FedRAMP authorization. A commercial SaaS that stores federal customer configuration, scope, or output artifacts on vendor infrastructure does require FedRAMP authorization, regardless of whether the underlying observation is of public data.

4. FedRAMP authorization is expensive ($500K-$2M for Moderate authorization cycle, plus comparable engineering investment, plus $200K-$500K/year continuous monitoring) and slow (18-24 months to ATO for Moderate). This investment only makes sense when justified by federal-customer demand and operational scale.

The strategic question is therefore not "should FF6K be FedRAMP authorized" but "what FedRAMP posture should FF6K take that serves federal customers without requiring authorization investment that the v1 project cannot support."

## Decision

**FedRAMP-ready by design at the architecture level. Authorization-deferred for the open-source engine. Authorization-targeted for the future commercial managed-service offering.**

Three concrete commitments:

### Commitment 1: Architectural readiness in v1

Every architectural decision in v1 is made with FedRAMP Moderate baseline in mind, even though formal authorization is not pursued. This means:

- **FIPS 140-3 validated cryptography everywhere.** TLS, signing operations, hashing, key management, password storage, all use FIPS-validated implementations from day one. Specific stack choices: the `cryptography` Python library in FIPS mode, AWS-LC bindings, or BoringSSL bindings — never the default Python `hashlib` or `secrets` modules in non-FIPS mode. Cosign in FIPS-validated mode for artifact signing. Postgres with FIPS-mode OpenSSL. This is enforced at build time and verified in CI.

- **Audit logging compliant with NIST 800-53 AU-family controls.** Specifically AU-2 (event logging), AU-3 (content of audit records), AU-6 (audit review), AU-9 (protection of audit information), AU-11 (audit record retention), AU-12 (audit generation). Audit logs are tamper-evident (signed, append-only or write-once), timestamped to authoritative time sources, and retained for FedRAMP-specified durations.

- **Identity and access management aligned with NIST SP 800-63 and FedRAMP MFA requirements.** Multi-factor authentication mandatory for administrative access. Session management per AC-12 (session termination), CC-related controls. Role-based access control with documented role boundaries. The admin API has PIV/CAC support paths even if v1 lab doesn't activate them.

- **Configuration management aligned with CM-family controls.** Infrastructure-as-code (Helm, Terraform), version-controlled, with documented change management processes. CM-3 (configuration change control), CM-6 (configuration settings), CM-8 (information system component inventory).

- **Vulnerability management with FedRAMP-aligned scan cadences.** Weekly authenticated vulnerability scans of FF6K infrastructure components. Specific remediation SLAs (30 days for high-severity, 90 days for moderate). Scanner output formats compatible with FedRAMP continuous monitoring submission patterns.

- **Continuous monitoring with FedRAMP-aligned telemetry.** OpenTelemetry as the substrate, with output formats and content compatible with FedRAMP Continuous Monitoring program submissions, CDM (Continuous Diagnostics and Mitigation) ingestion, and agency-side SIEM integration.

- **Boundary clarity in design documentation.** System architecture documents explicitly identify what would be inside an FF6K authorization boundary, what would be external connected services, and what data flows would cross those boundaries. This is documented in v1 even though FF6K is not authorized in v1 — it's the foundation any future authorization would build on.

- **Supply-chain integrity at SLSA Level 2 (target Level 3).** SBOMs via syft, container images signed with cosign keyless via GitHub Actions OIDC, build provenance attestations. This is a FedRAMP requirement and a federal-customer expectation.

### Commitment 2: Authorization-deferred for the open-source engine

The Apache 2.0 FF6K Core engine itself does not pursue FedRAMP authorization. The engine is software, not a service. Federal customers wanting to use FF6K Core deploy it within their own authorization boundary and inherit the engine into their own ATO. This matches the established pattern for federal use of open-source security tools (Nessus open-source variants, OpenVAS, federal forks of various security tools).

What this means in practice:

- No SSP is written for the open-source engine. The engine is not a "system" in the FedRAMP sense; it's software.
- No 3PAO assessment is conducted for the open-source engine.
- No JAB or Agency ATO is pursued for the open-source engine.
- The engine produces evidence (SBOMs, control mapping, audit logs) that *supports* an agency's ATO process when that agency self-hosts the engine.
- The Federal Customer Deployment Guide (subsequent deliverable) documents exactly which NIST 800-53 controls FF6K satisfies, which it partially satisfies, and which require agency-side implementation. This is the integration document federal customers use to incorporate FF6K into their existing ATOs.

### Commitment 3: Authorization-targeted for the future commercial offering

The future Korlogos commercial managed-service offering of FF6K (per ADR-009) is the candidate for FedRAMP authorization. This is a roadmap-future business decision, not a v1 commitment. Specifically:

- Target tier: **FedRAMP Moderate**. This is appropriate for SaaS processing external attack surface observations of federal agency systems. Federal Information Processing Standards (FIPS) 199 categorization is moderate confidentiality, moderate integrity, moderate availability for the data types involved.
- Authorization pathway preference: **Agency Authorization** (sponsored by a specific federal agency) rather than JAB Provisional Authorization. Agency Authorization is faster, less expensive, and more directly tied to actual customer need.
- Trigger condition: a sponsoring federal agency relationship plus operational scale justifying the $500K-$2M authorization investment plus $200K-$500K/year continuous monitoring. This is a future business milestone, not a v1 deliverable.
- StateRAMP and CMMC pathways considered as follow-on once initial FedRAMP Moderate authorization is achieved.
- FedRAMP High is considered for future expansion if customer demand emerges; not a near-term target.

## Consequences

**Positive:**

- v1 budget is preserved. The $500K-$2M authorization cost is deferred to when business case justifies it, not borne by the open-source project.
- Federal-customer credibility from day one. "FedRAMP-ready by design" is a defensible claim backed by architectural evidence (FIPS crypto, control mapping, supply-chain integrity), even before formal authorization.
- Federal agencies can adopt FF6K Core today by self-hosting within their own ATOs. They are not waiting for vendor authorization to mature.
- The architectural posture benefits non-federal deployments too. FIPS-validated crypto, audit logging discipline, supply-chain integrity, and continuous monitoring patterns are best practices regardless of FedRAMP context.
- The future commercial authorization pursuit is significantly cheaper because the architecture is built right from day one, rather than retrofitting controls after the fact.
- The dual-path approach (self-host Core + future commercial SaaS) is a proven pattern for federal cybersecurity tools and creates a natural customer-progression model.

**Negative:**

- Architectural overhead in v1 is real. FIPS crypto integration, audit logging discipline, supply-chain attestation pipeline all add engineering effort. Estimate 30-50% more engineering time on relevant components than a non-FedRAMP-ready implementation.
- Specific tooling choices are constrained. We cannot use the easiest Python crypto path; we must use FIPS-validated alternatives. We cannot use the easiest audit logging path; we must structure logs per AU-family controls.
- Documentation discipline is high. The Federal Customer Deployment Guide is itself a substantial document, and it must accurately reflect what the engine does — meaning the documentation must be maintained alongside the codebase.
- Federal-customer adoption depends on the agency doing the integration work. Self-hosting is not zero-effort; it requires agency-side investment in deployment, configuration, and ATO integration. Some agencies will prefer to wait for the commercial managed-service offering.
- The FedRAMP-ready claim must be defensible. We cannot make this claim and then have a federal customer's 3PAO discover that, e.g., we use a non-FIPS Python `hashlib` call somewhere. The architectural commitment must be enforced rigorously, with CI gates, audit trails, and explicit verification.

## Alternatives considered

**Active FedRAMP authorization pursuit from v1.** Same architectural posture but also actively pursue Agency ATO for v1. Rejected because the $500K-$2M authorization investment is not justified by demonstrated federal-customer demand at the v1 stage, and authorization without a sponsoring agency relationship is operationally infeasible.

**No FedRAMP commitment at all.** Rejected because federal markets are explicitly part of the strategic plan and "FedRAMP-ready" is a credibility marker that distinguishes FF6K from competitors. Removing this commitment would reduce federal-buyer interest and would cost more to retrofit later than to build in now.

**FedRAMP authorization for the open-source engine itself.** Rejected because (a) the engine is software, not a service, and FedRAMP authorizes services; (b) authorization without a Korlogos-managed deployment is operationally meaningless — federal agencies self-host and inherit the engine into their own ATOs regardless of any FedRAMP designation FF6K might claim; (c) the cost is unjustifiable for an open-source project.

**StateRAMP-first or CMMC-first pursuit.** Both StateRAMP and CMMC inherit heavily from FedRAMP control families. Pursuing one of them first is a possible alternative path. Rejected because FedRAMP is the broader-applicability target; StateRAMP and CMMC are follow-ons once FedRAMP Moderate is achieved.

**Pursue FedRAMP Tailored.** FedRAMP Tailored is a lower-cost program for low-impact SaaS. Rejected for the future commercial offering because Tailored covers only specific use cases (typically internal-facing federal collaboration tools, not external-observation tools) and FF6K's data flows likely require Moderate baseline anyway.

## When to revisit

Trigger conditions for evolving this posture:

- **Sponsoring federal agency relationship emerges.** When a specific agency offers to sponsor an Agency ATO for FF6K commercial managed-service offering, FedRAMP pursuit timeline accelerates.
- **Commercial customer demand reaches operational scale justifying authorization.** Multiple federal customers asking for managed service rather than self-host create the business case.
- **Architectural drift from FedRAMP-ready posture.** If maintenance of FIPS crypto, audit logging, and other readiness commitments becomes expensive in ways unforeseen, the posture may need adjustment. Currently no expectation of drift.
- **FedRAMP program changes.** FedRAMP itself has been evolving rapidly (RFC-0004 boundary policy, RFC-0005 Minimum Assessment Scope, ongoing modernization). Material changes to FedRAMP policy may shift what "ready" means.

## Federal-customer integration evidence

When the Federal Customer Deployment Guide is produced (subsequent deliverable), it will document FF6K Core's contribution to federal customer ATOs across the following NIST 800-53 control families:

- **AC** (Access Control) — FF6K satisfies AC-2, AC-3, AC-6, partially satisfies AC-7, AC-11, AC-12; agency must implement AC-1 (policy) and AC-22 (publicly accessible content) per their environment.
- **AU** (Audit and Accountability) — FF6K satisfies AU-2, AU-3, AU-9, AU-12; partially satisfies AU-6, AU-11; agency must implement AU-1.
- **CA** (Assessment, Authorization, and Monitoring) — FF6K provides evidence for CA-7 (continuous monitoring); agency must implement CA-1, CA-2, CA-5, CA-6.
- **CM** (Configuration Management) — FF6K satisfies CM-2, CM-3, CM-6, CM-8; agency must implement CM-1, CM-4, CM-7.
- **CP** (Contingency Planning) — agency-implemented; FF6K provides supporting documentation.
- **IA** (Identification and Authentication) — FF6K satisfies IA-2, IA-5, IA-8 with appropriate configuration; agency must implement IA-1.
- **IR** (Incident Response) — agency-implemented; FF6K provides relevant audit logs.
- **RA** (Risk Assessment) — FF6K's output is itself input to agency RA-3 (risk assessment); FF6K satisfies RA-5 (vulnerability scanning) for the FF6K deployment itself.
- **SA** (System and Services Acquisition) — FF6K provides SBOMs (SA-12 supply chain risk management).
- **SC** (System and Communications Protection) — FF6K satisfies SC-8 (transmission confidentiality and integrity) via TLS 1.3 with FIPS validation, SC-12, SC-13 (cryptographic protection), SC-28 (protection of information at rest).
- **SI** (System and Information Integrity) — FF6K satisfies SI-2, SI-3, SI-4 within the deployment; agency must implement SI-1.

This control mapping is preliminary; the Federal Customer Deployment Guide will produce the complete, verified mapping with specific implementation evidence per control.

## References

- ADR-009: Commercial structure (referenced for the federal-customer adoption pathway)
- `docs/positioning.md` for the federal procurement framing
- FedRAMP RFC-0004 (Boundary Policy) and RFC-0005 (Minimum Assessment Scope) — authoritative FedRAMP boundary guidance
- NIST SP 800-53 Rev 5 — control catalog
- NIST SP 800-37 Rev 2 — Risk Management Framework
- CISA BOD 23-01 — federal asset visibility and vulnerability detection (precedent for external EASM use)
- Executive Order 14028, NSM-22 — software supply chain security context
- Subsequent deliverable: `docs/federal-customer-deployment-guide.md`

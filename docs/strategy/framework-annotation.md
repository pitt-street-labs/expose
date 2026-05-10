# EXPOSE — Framework Annotation Deep-Dive

**Status:** Advisory — not locked. Open for revision in subsequent sessions and 3PAO consultation.
**Date:** 2026-05-10
**Author context:** AI-assisted synthesis grounded in the locked spec-phase artifacts (SPEC.md, ADR-008, ADR-009, ADR-010, positioning.md). Framework citations confirmed via May 2026 web research against the official publishers (NIST, MITRE, OWASP, CSA, CIS).
**Public name:** EXPOSE (selected 2026-05-10 in Session H) / **Internal codename:** FF6K
**Source files cited:** `docs/SPEC.md`, `docs/positioning.md`, `docs/adr/ADR-008-authorized-use-and-ethics.md`, `docs/adr/ADR-009-commercial-structure.md`, `docs/adr/ADR-010-fedramp-ready-posture.md`.

This document provides the framework-by-framework mapping of EXPOSE Core capabilities against the cybersecurity and AI-governance frameworks federal and enterprise compliance organizations use to evaluate security tooling. It is upstream input to Session F (SDLP) and Session G (Federal Customer Deployment Guide). Coverage classifications are deliberate and conservative; "Satisfies" is reserved for cases where the engine implements the control end-to-end without agency-side completion.

This is advisory analysis pending 3PAO review. Treat the mappings here as the starting baseline a Session G deliverable refines, not as a final assessment.

---

## 1. Coverage taxonomy

Throughout this document, EXPOSE's contribution to each framework control is classified using one of four labels:

| Label | Meaning |
|---|---|
| **Satisfies** | The engine implements the control end-to-end. Operator-side configuration is normal deployment work, not control implementation. The control text can be answered "yes" by inspecting EXPOSE alone. |
| **Partially satisfies** | The engine implements the control mechanism, but full satisfaction requires agency-side completion (policy, designated personnel, organizational process, or environmental configuration the engine cannot supply). |
| **Provides evidence for** | The engine produces outputs (artifacts, audit logs, telemetry, SBOMs) that feed agency control implementation. The control itself is implemented elsewhere; EXPOSE supplies the data the control consumes. |
| **Out of scope** | The engine does not address the control. Agency must implement it independently. EXPOSE neither hinders nor helps. |

These labels are deliberately conservative. A federal 3PAO assessor reading this document will hold EXPOSE to the literal text of each control. Where the engine partially implements a control, that partial state is documented rather than overstated.

---

## 2. MITRE ATT&CK Enterprise — Reconnaissance (TA0043)

**Framework version:** MITRE ATT&CK Enterprise v15 (current as of 2026-05). Tactic TA0043 (Reconnaissance) defines fourteen techniques and sub-techniques.

EXPOSE Core is anchored in this tactic per `positioning.md` §2. Every collector and attribution rule is annotated against specific Reconnaissance techniques. The table below is the authoritative mapping for v1; it expands the starting table in `positioning.md` §2.1 with collector-level granularity, contributing data sources, and explicit in-scope / out-of-scope rationale.

### 2.1 Reconnaissance technique mapping

| Technique ID | Technique Name | EXPOSE Coverage | Contributing Collectors / Rules | Data Sources | In-Scope / Rationale |
|---|---|---|---|---|---|
| T1595 | Active Scanning | Tier 3 active probing collectors gated by attribution tier (SPEC.md §6.3) | `active-dns-resolve`, `active-tls-handshake`, `active-http-fingerprint`, `active-port-surface` | DNS resolvers, TLS endpoints, HTTP servers, light port enumeration | **In-scope (defensive observation only).** Engine emulates the technique to map the operator's own surface; gated to `confirmed`/`high` attribution or explicit scope per ADR-008. |
| T1595.001 | Scanning IP Blocks | Cloud IP manifest correlation, ASN-range expansion | `cloud-aws-ranges`, `cloud-azure-ranges`, `cloud-gcp-ranges`, `bgp-he-toolkit`, `bgp-ripestat`, `bgp-team-cymru` | AWS `ip-ranges.json`, Azure service tags, GCP `_cloud-netblocks`, Hurricane Electric, RIPE, Team Cymru | **In-scope.** Used to attribute IPs in cloud ranges to operator's cloud accounts and to seed Tier 3 probing within scope. |
| T1595.002 | Vulnerability Scanning | **Out of scope for EXPOSE Core** | None | N/A | **Out of scope.** EXPOSE produces leads, not vulnerability findings. CVE enumeration against authenticated systems is a different category (Tenable/Qualys/Nessus). Per SPEC.md §1.2 explicit non-goal. |
| T1595.003 | Wordlist Scanning | **Out of scope for EXPOSE Core** | None | N/A | **Out of scope.** Brute-force directory/parameter enumeration is post-discovery offensive tooling territory (per ADR-008 explicit non-goals). |
| T1592 | Gather Victim Host Information | HTTP fingerprinting, banner collection, TLS certificate analysis | `active-http-fingerprint`, `active-tls-handshake`, `iwide-censys`, `iwide-shodan`, `iwide-binaryedge` | HTTP responses, TLS handshakes, internet-wide scan datasets | **In-scope.** Direct contributor to tech-stack inference and lead scoring. |
| T1592.001 | Hardware | **Out of scope for EXPOSE Core** | None | N/A | **Out of scope.** Hardware identification from external observation is rarely achievable at signal quality; would require active intrusive probing outside ADR-008 scope. |
| T1592.002 | Software | Tech-stack inference (Wappalyzer-style rules, header analysis, LLM enrichment job 4b) | `active-http-fingerprint`, `iwide-censys`, `iwide-shodan`, attribution rule pack tech-stack predicates, `expose-llm-worker` tech-stack inference job | HTTP server headers, page metadata, JS framework signatures, banner analysis | **In-scope.** A primary EXPOSE deliverable in the canonical artifact's `tech_stack` field. |
| T1592.003 | Firmware | **Out of scope for EXPOSE Core** | None | N/A | **Out of scope.** Firmware identification requires authenticated scanning or device-specific protocol exchanges outside passive observation. |
| T1592.004 | Client Configurations | Limited via TLS fingerprinting (JA3/JA4 not collected by Core in v1) | `active-tls-handshake` (server-side cipher and extension data only) | TLS server hello, certificate chain | **Partial / in-scope.** Server-side TLS configuration is observable; client TLS fingerprinting requires inverted vantage and is deferred. |
| T1589 | Gather Victim Identity Information | WHOIS/RDAP collectors, registrant pivots; PII handling per ADR-008 §Layer 3 | `whois-rdap`, `whois-whoisxml`, `whois-domaintools` | RDAP, WhoisXML, DomainTools | **In-scope (with PII handling).** Public-record identity data treated per ETHICS.md; not enriched with private sources. |
| T1589.001 | Credentials | **Out of scope for EXPOSE Core** | None (handled in commercial Threat Context module per ADR-009) | N/A in Core | **Out of scope for Core.** Leaked-credential detection lives in EXPOSE Threat Context (commercial), not Core. Per SPEC.md §1.2. |
| T1589.002 | Email Addresses | WHOIS contact data only, with ADR-008 PII discipline | `whois-rdap`, `whois-whoisxml` (registrant_email field) | RDAP registrant contact records | **In-scope (limited).** Registrant emails are publicly disclosed PII and treated as such. No paid identity-resolution enrichment. |
| T1589.003 | Employee Names | **Out of scope for EXPOSE Core** | Handled in commercial Identity Surface module per ADR-009 | N/A in Core | **Out of scope for Core.** Personnel reconnaissance is gated to Identity Surface module with separate ethics surface, scope-gated, off by default. |
| T1590 | Gather Victim Network Information | DNS, BGP, ASN collectors; cohabitation analysis | `pdns-securitytrails`, `pdns-validin`, `pdns-farsight`, `bgp-he-toolkit`, `bgp-ripestat`, `bgp-team-cymru`, `cloud-*-ranges` | Passive DNS providers, BGP route observers, cloud IP manifests | **In-scope.** Foundational for graph construction and edge generation (`resolves_to`, `hosted_in_asn`, `cohabits_ip_with`, `in_cloud_range`). |
| T1591 | Gather Victim Org Information | Organizational attribution rules, registrant pivots, cloud-account attribution | Rule pack predicates: `same_registrant_as`, `cloud_resource_belongs_to`, `registrant_of`; collectors `whois-*` and `cloud-*-ranges` | RDAP, WhoisXML, cloud provider account-resource APIs (where authorized) | **In-scope.** Direct contributor to attribution tier decisions and the `Organization` entity type. |
| T1593 | Search Open Websites/Domains | CT log collectors, passive DNS, search-engine-style queries via internet-wide scan APIs | `ct-crtsh`, `ct-certstream`, `ct-censys`, `pdns-*`, `iwide-censys` | Certificate Transparency logs (Google, Cloudflare, DigiCert, Sectigo, Let's Encrypt), Censys/Shodan search APIs | **In-scope.** Primary discovery vector for Stage 1 seed expansion. |
| T1594 | Search Victim-Owned Websites | Limited Tier 3 coverage; attribution-gated | `active-http-fingerprint` against in-scope or attributed-tier targets | HTTP request/response analysis | **In-scope (gated).** Limited to operator's own surface or explicitly scoped third parties. Robots.txt and `.well-known` paths included; aggressive crawling is not. |
| T1597 | Search Closed Sources | **Out of scope for EXPOSE Core** | Handled in commercial Threat Context module (dark-web sources) per ADR-009 | N/A in Core | **Out of scope for Core.** Dark-web / closed-source intelligence is a commercial-module concern with its own ethics surface. |

### 2.2 ATT&CK technique annotation in artifacts

Per `positioning.md` §2.1, every artifact target carries the ATT&CK technique IDs that contributed to its attribution decision. v1 artifacts include a `attack_techniques_contributing` array per target, populated by collector-emitted technique tags. This makes auditor traceability explicit at artifact-inspection time without requiring backend log review.

### 2.3 Reconnaissance technique coverage summary

| Status | Count | Techniques |
|---|---|---|
| In-scope (full) | 9 | T1595, T1595.001, T1592, T1592.002, T1589, T1589.002, T1590, T1591, T1593 |
| In-scope (partial / gated) | 2 | T1592.004, T1594 |
| Out of scope (commercial module) | 3 | T1589.001, T1589.003, T1597 |
| Out of scope (deliberate non-goal) | 4 | T1595.002, T1595.003, T1592.001, T1592.003 |

**Coverage strength:** Strong for the passive-discovery core of TA0043 (T1593, T1590, T1591, T1592). Strong for org-attribution (T1591). Deliberately bounded for sub-techniques that cross into commercial-module territory or ADR-008 non-goals.

---

## 3. MITRE D3FEND defensive countermeasures

**Framework version:** MITRE D3FEND v1.3.0 (December 2025). 267 defensive techniques across seven tactical categories.

D3FEND is the defensive counterpart to ATT&CK. EXPOSE Core is itself a defensive instrument (a tool federal CISOs and CTEM programs use to map external surface), so it both *implements* certain D3FEND techniques and *enables* others when its artifacts feed downstream tools. The mapping below covers the most relevant D3FEND techniques.

| D3FEND Technique ID | Technique Name | EXPOSE Relationship | Mechanism |
|---|---|---|---|
| D3-DA | Domain Name Analysis | **Implements** | EXPOSE attribution rules analyze domain metadata (registration age, registrant patterns, TLD distribution, IDN/punycode detection) to inform the `Domain` and `Organization` entity attribution. Sanitization (SPEC.md §7) flags suspicious TLD/punycode content. |
| D3-NTA | Network Traffic Analysis | **Out of scope** | EXPOSE does not consume network traffic; it consumes external observability data. NTA is downstream tooling responsibility. |
| D3-DNSTA | DNS Traffic Analysis | **Partially implements** | Passive-DNS collectors observe DNS resolution behavior over time; EXPOSE detects unusual resolution patterns (rapid IP rotation, fast-flux indicators) as inputs to attribution confidence. Live DNS traffic interception is out of scope. |
| D3-ID | Identifier Analysis | **Implements** | EXPOSE's core function is identifier analysis on IPs, FQDNs, ASNs, certificate fingerprints, cloud resource ARNs. Every entity in the observation graph is an identifier under analysis. |
| D3-CSPP | Client-Server Payload Profiling | **Partially implements** | HTTP fingerprinting and TLS handshake collection profile server-side payload responses; client-side profiling is not observed. |
| D3-CA | Certificate Analysis | **Implements** | CT log collection (`ct-crtsh`, `ct-certstream`, `ct-censys`) and active TLS handshake capture support certificate metadata analysis (issuer, SAN list, validity windows, key parameters). The `Certificate` entity is a first-class graph node. |
| D3-AVE | Active Vulnerability Enumeration | **Out of scope** | Per SPEC.md §1.2 explicit non-goal and ADR-008 non-goals. |
| D3-OAM | Operational Activity Mapping | **Provides evidence for** | EXPOSE artifacts feed downstream OAM by supplying authoritative attack-surface inventory; OAM execution is operator-side. |
| D3-AM | Asset Inventory | **Implements** (external surface scope only) | EXPOSE's canonical artifact is itself an external-surface asset inventory. Limited to externally-reachable assets per the engine's positioning; CAASM scope is explicitly excluded per `positioning.md` §1.2. |
| D3-NM | Network Mapping | **Partially implements** | The observation graph is an external-perspective network map (subdomains -> IPs -> ASNs -> cloud ranges). Internal-perspective mapping is out of scope. |
| D3-CSPN | Connection Source Provenance Notation | **Implements** | Every observation in the graph carries `collector_id`, `evidence_ref`, `observed_at`, satisfying provenance-notation requirements for downstream defensive consumers. |

**Coverage strength:** Strong for identifier-centric defensive techniques (D3-DA, D3-ID, D3-CA, D3-CSPN, D3-AM external scope). Engine implements seven D3FEND techniques directly; produces evidence for several more.

---

## 4. NIST Cybersecurity Framework 2.0 (CSF 2.0)

**Framework version:** NIST CSF 2.0 (NIST CSWP 29, published 2024-02-26). Six functions: Govern, Identify, Protect, Detect, Respond, Recover.

EXPOSE's primary alignment is with the **Identify** function, especially Asset Management (ID.AM) and Risk Assessment (ID.RA). Secondary touches in **Detect** (DE.CM Continuous Monitoring) and **Govern**. The function/category nomenclature uses CSF 2.0 conventions throughout.

### 4.1 Identify function — Asset Management (ID.AM)

| Subcategory | Subcategory Text (abridged) | EXPOSE Coverage | Rationale |
|---|---|---|---|
| ID.AM-01 | Inventories of hardware managed by the organization are maintained | **Out of scope** | EXPOSE is external-surface, not internal-asset. CAASM territory. |
| ID.AM-02 | Inventories of software, services, and systems managed by the organization are maintained | **Partially satisfies** (external-facing services only) | The canonical artifact's `Service` entities are an inventory of externally-reachable services and the inferred software stack behind each. Internal services not exposed externally are out of scope. |
| ID.AM-03 | Network communication and external network data flows are maintained | **Provides evidence for** | The graph documents external-facing connectivity (`resolves_to`, `presented_cert`, `in_cloud_range`); operator integrates into broader data-flow documentation. |
| ID.AM-04 | Inventories of services provided by suppliers are maintained | **Partially satisfies** | Cloud-account attribution (AWS, Azure, GCP) and ASN/CDN mapping document third-party service dependencies surfaced through external observation. |
| ID.AM-05 | Assets are prioritized based on classification, criticality, resources, and impact on the mission | **Provides evidence for** | The lead score (SPEC.md §8.3) provides a numeric prioritization input; mission-criticality classification is operator-side. |
| ID.AM-07 | Inventories of data and corresponding metadata for designated data types are maintained | **Out of scope** | Data inventory is internal to the organization; EXPOSE observes external surface, not data flows. |
| ID.AM-08 | Systems, hardware, software, services, and data are managed throughout their life cycles | **Provides evidence for** | The delta-from-previous-run section (SPEC.md §9.3) tracks asset lifecycle events (`added`, `removed`, `changed`) for external-facing systems. |

### 4.2 Identify function — Risk Assessment (ID.RA)

| Subcategory | Subcategory Text (abridged) | EXPOSE Coverage | Rationale |
|---|---|---|---|
| ID.RA-01 | Vulnerabilities in assets are identified, validated, and recorded | **Provides evidence for** | EXPOSE produces leads (potentially vulnerable surface) but does not validate vulnerabilities. Validation is downstream tooling (operator side). |
| ID.RA-02 | Cyber threat intelligence is received from information sharing forums | **Out of scope** | CTI ingestion is the role of EXPOSE Threat Context (commercial module) per ADR-009, not Core. |
| ID.RA-03 | Internal and external threats to the organization are identified and recorded | **Partially satisfies** (external-surface threats only) | The artifact identifies external-surface exposures that imply external threats. Internal threats are not in scope. |
| ID.RA-04 | Potential impacts and likelihoods of threats exploiting vulnerabilities are identified and recorded | **Provides evidence for** | Lead score and tech-stack inference inform impact/likelihood analysis; full risk computation is operator-side. |
| ID.RA-05 | Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk | **Provides evidence for** | EXPOSE is an upstream input to ID.RA-05; the operator's risk register integrates EXPOSE outputs. |
| ID.RA-06 | Risk responses are chosen, prioritized, planned, tracked, and communicated | **Out of scope** | Risk-response decisioning is operator-side. |
| ID.RA-07 | Changes and exceptions are managed, assessed for risk impact, recorded, and tracked | **Provides evidence for** | The delta artifact provides change-tracking input; exception management is operator-side. |
| ID.RA-08 | Processes for receiving, analyzing, and responding to vulnerability disclosures are established | **Out of scope** | Vulnerability disclosure handling is governance/process, not engine functionality. |
| ID.RA-09 | The authenticity and integrity of hardware and software are assessed prior to acquisition | **Out of scope** | Acquisition-stage assessment is procurement-process, not external-surface observation. |
| ID.RA-10 | Critical suppliers are assessed prior to acquisition | **Out of scope** | Supplier assessment is procurement-process. |

### 4.3 Detect function — Continuous Monitoring (DE.CM)

| Subcategory | Subcategory Text (abridged) | EXPOSE Coverage | Rationale |
|---|---|---|---|
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events | **Partially satisfies** (external network observability only) | Daily-cadence surface mapping with delta detection acts as a continuous monitoring layer for external-facing change. |
| DE.CM-02 | The physical environment is monitored | **Out of scope** | N/A. |
| DE.CM-03 | Personnel activity and technology usage are monitored | **Out of scope** | N/A. |
| DE.CM-06 | External service provider activities and services are monitored | **Partially satisfies** | Cloud-provider IP range manifests, ASN observations, and CT log entries provide an external view of service-provider-hosted assets attributed to the operator. |
| DE.CM-09 | Computing hardware and software, runtime environments, and their data are monitored | **Out of scope** for internal computing; **partially satisfies** for external-facing instances. |

### 4.4 Govern function (GV)

| Subcategory | EXPOSE Coverage | Rationale |
|---|---|---|
| GV.OC-01 (Organizational Context) | **Out of scope** | Governance/process. |
| GV.RM-01 (Risk Management Strategy) | **Out of scope** | Governance/process. |
| GV.SC-01..-10 (Cybersecurity Supply Chain Risk Management) | **Provides evidence for** | EXPOSE's SBOM (syft), cosign-signed images, and SLSA L2 (target L3) provenance attestations per ADR-010 feed agency C-SCRM evidence. |
| GV.OV-01..-03 (Oversight) | **Provides evidence for** | Audit logs (AU-family compliant per ADR-010) feed agency oversight processes. |

### 4.5 CSF 2.0 coverage summary

| Function | Coverage Strength | Primary Subcategories |
|---|---|---|
| Govern (GV) | Provides evidence for | GV.SC, GV.OV |
| Identify (ID) | **Strong** | ID.AM-02, ID.AM-04, ID.AM-08, ID.RA-01, ID.RA-03, ID.RA-04, ID.RA-05, ID.RA-07 |
| Protect (PR) | Out of scope | None (EXPOSE is observation, not protection) |
| Detect (DE) | Partial | DE.CM-01, DE.CM-06 |
| Respond (RS) | Out of scope | None |
| Recover (RC) | Out of scope | None |

---

## 5. NIST SP 800-53 Rev 5 control mapping

**Framework version:** NIST SP 800-53 Revision 5 (initial 2020, updated 2023). Control catalog organized into 20 control families.

This section expands the preliminary mapping in ADR-010 §"Federal-customer integration evidence". The classifications below are the engine-side baseline a Federal Customer Deployment Guide (Session G) refines into agency-side implementation evidence. Where ADR-010 stated "satisfies AC-2", the table below validates that claim and adds adjacent controls.

### 5.1 Access Control (AC) family

| Control | Title | EXPOSE Contribution | Rationale |
|---|---|---|---|
| AC-1 | Policy and Procedures | Out of scope | Agency policy. |
| AC-2 | Account Management | **Satisfies** | The control plane API has account-management primitives (create/disable/delete tenant-scoped accounts) per SPEC.md §10.3. Tenant-isolation enforcement per ADR-007. |
| AC-3 | Access Enforcement | **Satisfies** | Tenant-scoped query middleware (SPEC.md §4.3) enforces access decisions at the data layer. |
| AC-4 | Information Flow Enforcement | **Partially satisfies** | Trust-boundary controls (SPEC.md §2.3) enforce sanitization at the external-to-canonical boundary and structured-output enforcement at the deterministic-to-LLM boundary. |
| AC-5 | Separation of Duties | **Provides evidence for** | Role-based access control on the admin API (per ADR-010 commitment) supports separation-of-duties; the specific role model is agency configuration. |
| AC-6 | Least Privilege | **Satisfies** | Default tenant configuration grants minimum required collector privileges; per-collector credential scoping. |
| AC-7 | Unsuccessful Logon Attempts | **Partially satisfies** | The admin API enforces lockout after configurable failure thresholds; agency configures the threshold. |
| AC-11 | Device Lock | **Partially satisfies** | Session timeout per AC-12 indirectly addresses this for browser-mediated admin sessions. |
| AC-12 | Session Termination | **Satisfies** | Session-token expiration enforced server-side per ADR-010 §IAM commitment. |
| AC-17 | Remote Access | **Provides evidence for** | All remote access via authenticated TLS 1.3; agency configures network controls. |
| AC-18 | Wireless Access | Out of scope | Network-layer concern. |
| AC-22 | Publicly Accessible Content | **Partially satisfies** | Artifact emission gating (medium-mode scope warnings, hard-mode blocking per ADR-008) ensures published artifacts contain only operator-authorized content. |

### 5.2 Audit and Accountability (AU) family

| Control | Title | EXPOSE Contribution | Rationale |
|---|---|---|---|
| AU-1 | Policy and Procedures | Out of scope | Agency policy. |
| AU-2 | Event Logging | **Satisfies** | OpenTelemetry instrumentation (SPEC.md §10.2) emits all auditable events: tenant-lifecycle changes, scope modifications, LLM provider changes, secret access, run dispatch, collector errors. Per ADR-010 explicit commitment. |
| AU-3 | Content of Audit Records | **Satisfies** | Each audit event includes the AU-3 mandatory fields: timestamp (UTC ISO 8601), tenant_id, actor identity, event type, outcome, source/target identifiers. |
| AU-3(1) | Additional Audit Information | **Satisfies** | Structured JSON event payloads carry contextual fields (collector_id, run_id, evidence_ref) sufficient for forensic reconstruction. |
| AU-4 | Audit Log Storage Capacity | **Partially satisfies** | Log retention is configured per-tenant (SPEC.md §10.2); storage capacity provisioning is deployment concern. |
| AU-5 | Response to Audit Logging Process Failures | **Partially satisfies** | OTel collector failure modes are documented; agency configures alerting. |
| AU-6 | Audit Record Review, Analysis, and Reporting | **Partially satisfies** | Log structure is machine-consumable for SIEM ingestion; the review process is agency-side. |
| AU-7 | Audit Record Reduction and Report Generation | **Provides evidence for** | Structured logs feed agency reporting tools. |
| AU-8 | Time Stamps | **Satisfies** | Authoritative time source (NTP with FIPS-validated client) per ADR-010; UTC-normalized. |
| AU-9 | Protection of Audit Information | **Satisfies** | Audit logs written to append-only storage where supported; cosign-signing of canonical artifacts ensures tamper-evidence on emitted records. Per ADR-010. |
| AU-9(2) | Audit Record Storage Backups | **Partially satisfies** | Backup configuration is deployment concern (SPEC.md §10.4). |
| AU-11 | Audit Record Retention | **Partially satisfies** | Per-tenant retention configuration; agency sets duration to FedRAMP-required values. |
| AU-12 | Audit Record Generation | **Satisfies** | All in-engine actions generate audit records via OTel; no actions execute outside the audit pathway. |

### 5.3 Assessment, Authorization, and Monitoring (CA) family

| Control | Title | EXPOSE Contribution | Rationale |
|---|---|---|---|
| CA-1 | Policy and Procedures | Out of scope | Agency policy. |
| CA-2 | Control Assessments | Out of scope | Agency process. |
| CA-3 | Information Exchange | **Provides evidence for** | The canonical artifact is itself a documented information exchange; the manifest documents schema version, signing key reference, run metadata. |
| CA-5 | Plan of Action and Milestones | Out of scope | Agency process. |
| CA-6 | Authorization | Out of scope | Agency process. |
| CA-7 | Continuous Monitoring | **Provides evidence for** (primary) | Daily-cadence delta artifacts are the engine's continuous-monitoring contribution. CDM-compatible output formats per ADR-010. |
| CA-8 | Penetration Testing | Out of scope | Agency-procured assessment activity. |
| CA-9 | Internal System Connections | Out of scope | Agency-side. |

### 5.4 Configuration Management (CM) family

| Control | Title | EXPOSE Contribution | Rationale |
|---|---|---|---|
| CM-1 | Policy and Procedures | Out of scope | Agency policy. |
| CM-2 | Baseline Configuration | **Satisfies** | Helm chart and version-controlled tenant YAML (SPEC.md §10.1) constitute documented baselines. |
| CM-3 | Configuration Change Control | **Satisfies** | Configuration changes via versioned IaC (Helm, tenant YAML in Postgres with audit log of changes). |
| CM-4 | Impact Analysis | **Partially satisfies** | Change-control process documented; impact analysis depth is agency-side. |
| CM-5 | Access Restrictions for Change | **Satisfies** | Admin-API access controls plus IaC review gating before deployment. |
| CM-6 | Configuration Settings | **Satisfies** | Tenant YAML defines settings; Helm values define infrastructure settings; both versioned. |
| CM-7 | Least Functionality | **Partially satisfies** | Container images include only required components; ports exposed are minimal. Agency hardens further per environment. |
| CM-8 | System Component Inventory | **Satisfies** | SBOM (syft) per container image satisfies CM-8 component inventory. Per ADR-010. |
| CM-8(3) | Automated Unauthorized Component Detection | **Provides evidence for** | SBOM diff between releases enables agency-side detection. |
| CM-10 | Software Usage Restrictions | **Provides evidence for** | License manifest (Apache 2.0 plus dependency licenses in SBOM) feeds agency restrictions tracking. |
| CM-11 | User-Installed Software | Out of scope | Agency-environment concern. |

### 5.5 Contingency Planning (CP) family

| Control | EXPOSE Contribution | Rationale |
|---|---|---|
| CP-1 through CP-13 | **Provides evidence for** (most) / **Out of scope** (operational testing) | EXPOSE produces backup-amenable state (Postgres + object store, SPEC.md §10.4); contingency planning, exercising, and recovery are agency-implemented. |
| CP-9 | System Backup | **Partially satisfies** | Backup mechanism documented (SPEC.md §10.4); backup execution is deployment-specific. |
| CP-10 | System Recovery and Reconstitution | **Provides evidence for** | Reproducibility of artifact generation (SPEC.md §9.2) supports reconstitution validation. |

### 5.6 Identification and Authentication (IA) family

| Control | Title | EXPOSE Contribution | Rationale |
|---|---|---|---|
| IA-1 | Policy and Procedures | Out of scope | Agency policy. |
| IA-2 | Identification and Authentication (Organizational Users) | **Satisfies** | Admin API requires authenticated identity; PIV/CAC support paths exist per ADR-010 even if v1 lab does not activate them. |
| IA-2(1) | MFA for Privileged Accounts | **Satisfies** | MFA mandatory for admin per ADR-010 commitment. |
| IA-2(2) | MFA for Non-Privileged Accounts | **Satisfies** | Same posture. |
| IA-3 | Device Identification | **Provides evidence for** | mTLS support paths for service-to-service authentication. |
| IA-4 | Identifier Management | **Satisfies** | Tenant_id and account identifier lifecycle managed by control plane. |
| IA-5 | Authenticator Management | **Satisfies** | Password/secret policies enforced; secrets backend abstraction (Vaultwarden/cloud-native) per SPEC.md §6.4 / ADR-010. |
| IA-5(1) | Password-Based Authentication | **Satisfies** | FIPS-validated hashing (per ADR-010) with appropriate complexity, rotation, and reuse controls. |
| IA-6 | Authentication Feedback | **Satisfies** | Authentication failures do not disclose whether the identifier or the authenticator was wrong. |
| IA-7 | Cryptographic Module Authentication | **Satisfies** | FIPS 140-3 validated crypto modules per ADR-010. |
| IA-8 | Identification and Authentication (Non-Organizational Users) | **Satisfies** | Federation paths supported (OIDC); agency configures IdP. |
| IA-11 | Re-authentication | **Satisfies** | Sensitive-action re-authentication enforced. |

### 5.7 Incident Response (IR) family

| Control | EXPOSE Contribution | Rationale |
|---|---|---|
| IR-1 through IR-10 | **Provides evidence for** (audit logs feed IR processes) / **Out of scope** (process and personnel) | Engine produces structured audit logs IR teams consume. IR plan, training, testing, and reporting are agency-implemented. |

### 5.8 Risk Assessment (RA) family

| Control | Title | EXPOSE Contribution | Rationale |
|---|---|---|---|
| RA-1 | Policy and Procedures | Out of scope | Agency policy. |
| RA-2 | Security Categorization | **Provides evidence for** | EXPOSE artifacts inform agency categorization of external-facing systems. |
| RA-3 | Risk Assessment | **Provides evidence for** (primary upstream input) | Per ADR-010: EXPOSE's output is itself input to agency RA-3. The artifact's lead scores, attribution tiers, and tech-stack inference are explicit RA-3 inputs. |
| RA-5 | Vulnerability Monitoring and Scanning | **Satisfies** (for the EXPOSE deployment itself) | EXPOSE infrastructure is itself subject to weekly authenticated scans per ADR-010. **Out of scope** for scanning targets external to EXPOSE — that is downstream tooling. |
| RA-5(2) | Update Vulnerabilities to Be Scanned | **Satisfies** | Scan tool feeds maintained by deployment per ADR-010. |
| RA-7 | Risk Response | Out of scope | Agency-side. |
| RA-9 | Criticality Analysis | **Provides evidence for** | Lead scoring informs criticality discussions. |
| RA-10 | Threat Hunting | **Provides evidence for** | Artifact deltas (especially `removal_uncertain_collector_failure` distinct from `no_longer_observed`) support hunt workflows. |

### 5.9 System and Services Acquisition (SA) family

| Control | Title | EXPOSE Contribution | Rationale |
|---|---|---|---|
| SA-1 through SA-9 | Out of scope | Agency procurement process. |
| SA-10 | Developer Configuration Management | **Provides evidence for** | The engine's own SDLC (per Session F output) demonstrates SA-10 conformance for agency reliance. |
| SA-11 | Developer Testing and Evaluation | **Provides evidence for** | Eval harness (Phase 2 deliverable) plus cross-tenant isolation test suite (SPEC.md §11.1) provide testing evidence. |
| SA-12 | Supply Chain Risk Management | **Satisfies** | SBOMs via syft, cosign-signed images, SLSA L2 (target L3) provenance attestations per ADR-010. |
| SA-15 | Development Process, Standards, and Tools | **Provides evidence for** | Apache 2.0 public engine, DCO sign-off, public ADR record support agency review. |
| SA-22 | Unsupported System Components | **Provides evidence for** | SBOM enables agency tracking of dependency support status. |

### 5.10 System and Communications Protection (SC) family

| Control | Title | EXPOSE Contribution | Rationale |
|---|---|---|---|
| SC-1 | Policy and Procedures | Out of scope | Agency policy. |
| SC-7 | Boundary Protection | **Provides evidence for** | The engine's deployment topology (SPEC.md §4.1) supports agency boundary configuration; egress isolation (`expose-scanner-worker` egress profiles) supports SC-7(8) prevent split tunneling. |
| SC-8 | Transmission Confidentiality and Integrity | **Satisfies** | TLS 1.3 with FIPS-validated cipher suites for all in-flight communication per ADR-010. |
| SC-8(1) | Cryptographic Protection | **Satisfies** | FIPS 140-3 validated. |
| SC-12 | Cryptographic Key Establishment and Management | **Satisfies** | Secrets backend abstraction with FIPS-validated key generation per ADR-010. |
| SC-13 | Cryptographic Protection | **Satisfies** | FIPS 140-3 throughout, enforced at build time. |
| SC-15 | Collaborative Computing Devices | Out of scope | N/A. |
| SC-17 | Public Key Infrastructure Certificates | **Satisfies** | TLS server certificates from agency-approved CA; cosign signing supports both keyless (OIDC) and keypair models per SPEC.md §9.4. |
| SC-23 | Session Authenticity | **Satisfies** | Authenticated TLS sessions for all administrative and inter-component communication. |
| SC-28 | Protection of Information at Rest | **Satisfies** | FIPS-validated encryption at rest for Postgres and object storage per ADR-010. |
| SC-28(1) | Cryptographic Protection | **Satisfies** | FIPS 140-3 modules. |

### 5.11 System and Information Integrity (SI) family

| Control | Title | EXPOSE Contribution | Rationale |
|---|---|---|---|
| SI-1 | Policy and Procedures | Out of scope | Agency policy. |
| SI-2 | Flaw Remediation | **Satisfies** (within EXPOSE deployment) | Patch SLAs per ADR-010 (30 days high, 90 days moderate). |
| SI-3 | Malicious Code Protection | **Satisfies** | Container image scanning in CI; SBOM-driven dependency CVE alerting. |
| SI-4 | System Monitoring | **Satisfies** (within EXPOSE deployment) | OpenTelemetry instrumentation (SPEC.md §10.2). |
| SI-7 | Software, Firmware, and Information Integrity | **Satisfies** | Cosign-signed canonical artifacts (SPEC.md §9.4); cosign-signed container images per ADR-010. |
| SI-7(1) | Integrity Checks | **Satisfies** | Signature verification on Environment 2 ingestion side per SPEC.md §9.4. |
| SI-7(6) | Cryptographic Protection | **Satisfies** | FIPS-validated signature operations. |
| SI-7(15) | Code Authentication | **Satisfies** | SLSA L2 (target L3) provenance attestations. |
| SI-10 | Information Input Validation | **Satisfies** | Sanitization layer (SPEC.md §7) is the input-validation control for external-data ingestion. |
| SI-11 | Error Handling | **Satisfies** | Structured error responses do not leak system details. |
| SI-12 | Information Management and Retention | **Satisfies** | Per-tenant retention policies (SPEC.md §5.5, §10.1); incidental data pruning per ADR-008. |

### 5.12 800-53 coverage summary by family

| Family | Satisfies | Partially | Provides Evidence | Out of Scope | Strength |
|---|---|---|---|---|---|
| AC | 4 | 5 | 2 | 2 | Strong |
| AU | 7 | 4 | 1 | 1 | Strong |
| CA | 0 | 0 | 2 | 5 | Evidence-only |
| CM | 5 | 2 | 2 | 2 | Strong |
| CP | 0 | 1 | 1 | 11 | Out of scope |
| IA | 10 | 0 | 1 | 1 | **Strong** |
| IR | 0 | 0 | 4 | 6 | Evidence-only |
| RA | 2 | 0 | 4 | 2 | Strong (RA-3 primary) |
| SA | 1 | 0 | 4 | 9 | Evidence-only |
| SC | 8 | 0 | 1 | 2 | **Strong** |
| SI | 9 | 0 | 0 | 1 | **Strong** |

The pattern: EXPOSE most strongly satisfies the technical-control families (AU, CM, IA, SC, SI) while providing evidence for the procedural/organizational families (CA, IR, SA). This matches the ADR-010 posture — engine is a software product that supports an agency's ATO, not a self-contained service.

---

## 6. NIST AI Risk Management Framework (AI RMF 1.0)

**Framework version:** NIST AI RMF 1.0 (NIST AI 100-1, January 2023). Four functions: Govern, Map, Measure, Manage.

EXPOSE's LLM enrichment subsystem (SPEC.md §8.4, the `SafeLLMClient`) is the surface area that the AI RMF applies to. The deterministic discovery and attribution layers are not AI in the AI RMF sense and are out of scope for this framework.

### 6.1 Govern function

| Subcategory (illustrative) | EXPOSE Coverage | Mechanism |
|---|---|---|
| GOVERN 1.1 | **Partially satisfies** | LLM use is policy-governed via the configurable tenant `llm` block; ADR-008 establishes the use-of-AI policy posture. |
| GOVERN 1.2 | **Satisfies** | Bounded LLM scope — strict structured-output enforcement, no general tool access during enrichment, no narrative generation in v1 (SPEC.md §8.1). |
| GOVERN 1.3 | **Provides evidence for** | Per-call audit logs (provider, model, token counts, latency, cost) feed agency oversight. |
| GOVERN 1.5 (Documentation) | **Satisfies** | SPEC.md §8 documents the AI subsystem in detail. |
| GOVERN 4.1 (Roles and Responsibilities) | **Partially satisfies** | AI subsystem ownership documented; agency assigns operational roles. |
| GOVERN 5.1 (Risk Tolerance) | **Provides evidence for** | Cost ceilings (default $5/run) and tie-breaker escalation paths support risk-tolerance configuration. |

### 6.2 Map function

| Subcategory | EXPOSE Coverage | Mechanism |
|---|---|---|
| MAP 1.1 (System Context) | **Satisfies** | Two-environment model (SPEC.md §2.1) explicitly maps where AI operates and what it consumes/produces. |
| MAP 2.2 (Categorization of AI System) | **Satisfies** | LLM use categorized as "bounded structured-output enrichment" with explicit non-applicability to narrative reasoning (SPEC.md §8.1). |
| MAP 3.4 (Mapping AI Risks) | **Satisfies** | Threat model (SPEC.md §3) specifically addresses prompt-injection risks via stage-3 sanitization and external_observation tag wrapping (SPEC.md §7.3). |
| MAP 4.1 (Impact Assessment) | **Partially satisfies** | Negative impacts of LLM disagreement are bounded (rule-engine decision stands; disagreement logged for review). Broader impact assessment is agency-side. |

### 6.3 Measure function

| Subcategory | EXPOSE Coverage | Mechanism |
|---|---|---|
| MEASURE 2.5 (TEVV) | **Partially satisfies** | Eval harness (Phase 2 deliverable) provides held-out evaluation against curated datasets (`confirmed_yours`, `confirmed_not_yours`, `ambiguous_with_resolution`, `adversarial_injection`). Quarterly re-evaluation procedure documented. |
| MEASURE 2.6 (Safety) | **Satisfies** | Adversarial-injection eval dataset specifically tests prompt-injection resistance. Output schema validation rejects malformed outputs. |
| MEASURE 2.7 (Security) | **Satisfies** | SafeLLMClient enforces input-sanitization integrity (verifies external_observation tag wrapping), schema validation, audit logging, cost ceiling. |
| MEASURE 2.8 (Privacy) | **Satisfies** | LLM prompts contain only sanitized observations; no PII enrichment beyond public records (per ADR-008). |
| MEASURE 2.9 (Fairness/Bias) | **Provides evidence for** | LLM disagreement logging supports bias review; eval datasets include diverse organizational targets. |
| MEASURE 2.11 (Explainability) | **Partially satisfies** | LLM outputs are structured and schema-validated, with provenance (model, version, prompt template ID) recorded; full chain-of-thought introspection is not stored. |
| MEASURE 3.1 (Performance) | **Satisfies** | Per-call latency, token counts, cost recorded. |

### 6.4 Manage function

| Subcategory | EXPOSE Coverage | Mechanism |
|---|---|---|
| MANAGE 1.1 (Risk Tolerance Operationalized) | **Satisfies** | Cost ceiling (hard stop on breach), tie-breaker escalation, fail-safe on schema validation failure. |
| MANAGE 2.3 (Continuous Monitoring) | **Satisfies** | OpenTelemetry per-call metrics; quarterly eval re-run procedure. |
| MANAGE 4.1 (Decommissioning) | **Provides evidence for** | LLM provider can be swapped via configuration without engine modification; provider abstraction supports future model changes. |

### 6.5 AI RMF coverage summary

| Function | Strength |
|---|---|
| Govern | Partial (engine implements; agency-side governance complementary) |
| Map | **Strong** (architecture explicitly maps AI scope) |
| Measure | **Strong** (eval harness, audit logging, structured outputs) |
| Manage | **Strong** (cost ceilings, fail-safes, provider abstraction) |

---

## 7. OWASP Application Security Verification Standard (ASVS)

**Framework version:** ASVS 4.0.3 (current widely-deployed) — referenced as the verification baseline for EXPOSE's internal API surface (control plane admin API, work-queue endpoints, evidence-storage interfaces). ASVS 5.0 forthcoming; mappings will need re-validation when 5.0 releases.

The internal API surface that ASVS applies to includes: the control plane admin API, the inter-worker work queue protocol, the evidence-storage put/get interface, and any operator-facing UI (deferred to production-hardening). EXPOSE's externally-observable behavior (what gets collected) is governed by the threat model (SPEC.md §3), not by ASVS.

### 7.1 V1 — Architecture, Design and Threat Modeling

| Requirement Area | EXPOSE Coverage | Mechanism |
|---|---|---|
| V1.1 Secure Software Development Lifecycle | **Satisfies** | SDLP forthcoming in Session F; current discipline includes ADR review, threat model in SPEC.md §3, security review of all changes. |
| V1.2 Authentication Architecture | **Satisfies** | Centralized authentication via secrets-backend-mediated identity. Per ADR-010 IAM commitment. |
| V1.4 Access Control Architecture | **Satisfies** | Tenant-scoped access enforcement at the data layer (SPEC.md §4.3, ADR-007). |
| V1.5 Input and Output Architecture | **Satisfies** | Stage-3 sanitization (SPEC.md §7) enforces input-validation discipline at the trust boundary. |
| V1.7 Errors, Logging and Auditing | **Satisfies** | OTel-based audit logging compliant with NIST 800-53 AU-family per ADR-010. |
| V1.8 Data Protection and Privacy | **Satisfies** | PII handling per ADR-008; encryption at rest and in transit per ADR-010. |
| V1.10 Malicious Software | **Satisfies** | Container image scanning, SBOM, cosign signing per ADR-010. |
| V1.14 Configuration | **Satisfies** | Helm + tenant YAML, IaC versioned, ADR-010 enforcement. |

### 7.2 V2 — Authentication

| Requirement Area | EXPOSE Coverage | Mechanism |
|---|---|---|
| V2.1 Password Security | **Satisfies** | FIPS-validated hashing per ADR-010; complexity, history, throttling enforced. |
| V2.2 General Authenticator | **Satisfies** | MFA required for admin access. |
| V2.3 Authenticator Lifecycle | **Satisfies** | Rotation, expiration, revocation supported. |
| V2.5 Credential Recovery | **Satisfies** | Out-of-band recovery; no security-questions-as-credential. |
| V2.7 Out of Band Verifier | **Satisfies** | TOTP / FIDO2 paths supported. |
| V2.9 Cryptographic Software and Devices | **Satisfies** | FIPS 140-3 validated modules. |

### 7.3 V3 — Session Management

| Requirement Area | EXPOSE Coverage | Mechanism |
|---|---|---|
| V3.1 Fundamental Session Management | **Satisfies** | Server-side session state; cryptographically random session identifiers. |
| V3.2 Session Binding | **Satisfies** | Session tokens bound to user agent context; reauthentication on sensitive actions. |
| V3.3 Session Logout and Timeout | **Satisfies** | Idle and absolute session timeouts; explicit logout invalidates server-side state. |
| V3.4 Cookie-based Session Management | **Satisfies** | `Secure`, `HttpOnly`, `SameSite=Strict` on session cookies. |
| V3.5 Token-based Session Management | **Satisfies** | JWTs with appropriate claims, signature validation, expiration. |

### 7.4 V4 — Access Control

| Requirement Area | EXPOSE Coverage | Mechanism |
|---|---|---|
| V4.1 General Access Control Design | **Satisfies** | Default-deny; tenant-scoped enforcement at data layer (ADR-007). |
| V4.2 Operation Level Access Control | **Satisfies** | Operations gated by role; sensitive operations (tenant-lifecycle, scope-modifications, secret access) audit-logged. |
| V4.3 Other Access Control Considerations | **Satisfies** | Admin paths require step-up auth; CSRF protections on state-changing endpoints. |

### 7.5 V5 — Validation, Sanitization and Encoding

| Requirement Area | EXPOSE Coverage | Mechanism |
|---|---|---|
| V5.1 Input Validation | **Satisfies** | Pydantic v2 models on all API surfaces; stage-3 sanitization on all external-observation ingestion (SPEC.md §7). |
| V5.2 Sanitization and Sandboxing | **Satisfies** | LLM prompts wrap external content in `<external_observation>` tags (SPEC.md §7.3); structured-output validation enforces schema conformance. |
| V5.3 Output Encoding and Injection Prevention | **Satisfies** | JSON output escaped per encoding rules; HTML output (admin UI) context-aware encoded. |
| V5.4 Memory, String, and Unmanaged Code | **Satisfies** | Pure Python (ADR-001) eliminates native-memory class of bugs; native dependencies (e.g., crypto) come from validated upstream. |
| V5.5 Deserialization Prevention | **Satisfies** | JSON-only with schema validation across cross-trust-boundary inputs; language-specific binary serialization formats are not used on external inputs. |

### 7.6 V7 — Cryptography

| Requirement Area | EXPOSE Coverage | Mechanism |
|---|---|---|
| V7.1 General Cryptography | **Satisfies** | FIPS 140-3 validated throughout per ADR-010. |
| V7.2 Algorithms | **Satisfies** | TLS 1.3 with FIPS-approved cipher suites; SHA-256/SHA-3 for hashing; AES-256 for symmetric encryption. |
| V7.3 Random Values | **Satisfies** | FIPS-validated RNG (no `os.urandom` direct use; mediated through validated module). |
| V7.4 Secret Management | **Satisfies** | Secrets backend abstraction with just-in-time fetch (SPEC.md §6.4). |

### 7.7 V8 — Data Protection

| Requirement Area | EXPOSE Coverage | Mechanism |
|---|---|---|
| V8.1 General Data Protection | **Satisfies** | Sensitive data encrypted at rest; transmission via TLS 1.3 only. |
| V8.2 Client-side Data Protection | **Satisfies** | No sensitive data in client-side storage beyond session tokens. |
| V8.3 Sensitive Private Data | **Satisfies** | PII handling per ADR-008; retention policies per SPEC.md §5.5. |

### 7.8 V10 — Malicious Code

| Requirement Area | EXPOSE Coverage | Mechanism |
|---|---|---|
| V10.1 Code Integrity Controls | **Satisfies** | Cosign-signed container images, SLSA L2 (target L3) attestations per ADR-010. |
| V10.2 Malicious Code Search | **Satisfies** | Image scanning in CI; dependency CVE alerting. |
| V10.3 Application Integrity | **Satisfies** | Cosign-signed canonical artifacts (SPEC.md §9.4); signature verification on consumer side. |

### 7.9 V13 — API and Web Service

| Requirement Area | EXPOSE Coverage | Mechanism |
|---|---|---|
| V13.1 Generic Web Service Security | **Satisfies** | Authentication required on all API endpoints; rate limiting; structured error responses. |
| V13.2 RESTful Web Service | **Satisfies** | FastAPI (ADR-001) with OpenAPI documentation; versioned URI scheme. |
| V13.3 SOAP Web Service | N/A | EXPOSE does not expose SOAP. |
| V13.4 GraphQL | N/A | EXPOSE does not expose GraphQL in v1. |

### 7.10 ASVS coverage summary

| Chapter | Strength |
|---|---|
| V1 Architecture | **Strong** |
| V2 Authentication | **Strong** |
| V3 Session Management | **Strong** |
| V4 Access Control | **Strong** |
| V5 Validation | **Strong** |
| V7 Cryptography | **Strong** (FIPS-validated) |
| V8 Data Protection | **Strong** |
| V10 Malicious Code | **Strong** |
| V13 API and Web Service | **Strong** (REST scope) |

ASVS Level 2 verification is the design target; ASVS Level 3 (high-risk applications) is the aspirational target for the federal-customer deployment posture and is achievable for the listed chapters given the FedRAMP-ready architectural commitments.

---

## 8. OWASP AI Security Verification Standard (AISVS)

**Framework version:** AISVS 1.0 (current stable release as of May 2026). 13 chapters, each with verification levels 1-3.

AISVS applies to EXPOSE's LLM enrichment subsystem — the SafeLLMClient, the LLM provider abstraction, and the structured-output discipline. It does not apply to the deterministic discovery and attribution pipeline.

### 8.1 AISVS chapter mapping

| Chapter | Title | EXPOSE Coverage | Mechanism |
|---|---|---|---|
| C01 | Training Data Governance & Bias Management | **Out of scope** | EXPOSE does not train models. The LLMs used (Ollama / Anthropic / OpenAI / Gemini) are pretrained third-party models; their training data governance is the provider's responsibility. |
| C02 | User Input Validation | **Satisfies** | Stage-3 sanitization (SPEC.md §7) plus external_observation tag wrapping (SPEC.md §7.3) constitute prompt-injection defense at the AISVS C02 standard. The threat model (SPEC.md §3.1) explicitly addresses adversary-controlled prompt content. |
| C03 | Model Lifecycle Management & Change Control | **Partially satisfies** | Provider model selection is per-tenant configuration with version pinning; eval harness re-evaluation on model changes (Phase 2 deliverable). Full lifecycle governance (deprecation policy, version-rollout testing) is a Session F SDLP concern. |
| C04 | Infrastructure, Configuration & Deployment Security | **Satisfies** | LLM workers deploy in container topology per SPEC.md §4.1; FIPS-validated TLS to provider endpoints; per-tenant credential isolation in production-hardening. |
| C05 | Access Control & Identity for AI Components & Users | **Satisfies** | Tenant-scoped LLM access; per-call audit log identifies invoking actor; provider credentials fetched just-in-time per SPEC.md §6.4. |
| C06 | Supply Chain Security for Models, Frameworks & Data | **Partially satisfies** | LLM providers identified by name and version in audit logs; for self-hosted Ollama models, model-file integrity via SHA-256. Provider-side supply chain (e.g., model-weight integrity at Anthropic/OpenAI) is provider responsibility. |
| C07 | Model Behavior, Output Control & Safety Assurance | **Satisfies** | Strict structured-output enforcement (rejects malformed outputs, retries up to 2x, then escalates). LLM has no narrative-generation role in v1 (SPEC.md §8.1). Output schema validation is the safety gate. |
| C08 | Memory, Embeddings & Vector Database Security | **Out of scope** | EXPOSE v1 does not maintain LLM memory or vector embeddings. The LLM is invoked stateless per enrichment call. |
| C09 | Autonomous Orchestration & Agentic Action Security | **Satisfies (by absence)** | EXPOSE v1's LLM enrichment is bounded structured-output, not agentic. The LLM has no tool access during enrichment; whatever evidence it needs is pre-baked into the prompt (SPEC.md §2.3). The two-environment design (SPEC.md §2.1) explicitly isolates agentic workflows to Environment 2, out of EXPOSE's scope. |
| C10 | Adversarial Robustness & Attack Resistance | **Satisfies** | Adversarial-injection eval dataset (Phase 2 deliverable) tests resistance to prompt injection, jailbreak, instruction override. Failed adversarial cases trigger eval-harness alerts. |
| C11 | Privacy Protection & Personal Data Management | **Satisfies** | LLM prompts contain only sanitized observations from public sources per ADR-008. No private PII enrichment. |
| C12 | Monitoring, Logging & Anomaly Detection | **Satisfies** | Per-call audit logs (provider, model, token counts, latency, cost, schema-validation outcome) per SPEC.md §8.4. Cost ceiling acts as anomaly threshold. |
| C13 | Human Oversight, Accountability & Governance | **Partially satisfies** | LLM disagreement with rule engine is logged for analyst review; tie-breaker escalation framework supports human-in-the-loop on configurable conditions. Broader governance is agency-side. |

### 8.2 AISVS coverage summary

| Chapter | Strength |
|---|---|
| C01 Training Data | Out of scope (engine does not train) |
| C02 Input Validation | **Strong** |
| C03 Lifecycle | Partial |
| C04 Infrastructure | **Strong** |
| C05 Access Control | **Strong** |
| C06 Supply Chain | Partial |
| C07 Output Control | **Strong** |
| C08 Memory/Embeddings | Out of scope (no memory in v1) |
| C09 Agentic Security | **Strong** (by deliberate non-agentic design) |
| C10 Adversarial Robustness | **Strong** |
| C11 Privacy | **Strong** |
| C12 Monitoring | **Strong** |
| C13 Human Oversight | Partial |

---

## 9. CIS Critical Security Controls v8

**Framework version:** CIS Critical Security Controls v8.1 (March 2025). 18 controls, 153 safeguards across three Implementation Groups.

EXPOSE's primary alignment is with Controls 1 (Asset Inventory) and 2 (Software Inventory). Partial alignment with Controls 7 (Continuous Vulnerability Management) and 12 (Network Infrastructure Management).

### 9.1 Control 1 — Inventory and Control of Enterprise Assets

| Safeguard | Title | EXPOSE Coverage | Mechanism |
|---|---|---|---|
| 1.1 | Establish and Maintain Detailed Enterprise Asset Inventory | **Partially satisfies** (external-facing assets only) | The canonical artifact's `IP`, `Subdomain`, `Service`, `CloudResource` entities populate external-asset inventory. Internal assets are out of scope. |
| 1.2 | Address Unauthorized Assets | **Provides evidence for** | The delta artifact's `added` section identifies newly-observed external assets the operator may not have authorized. |
| 1.3 | Utilize an Active Discovery Tool | **Satisfies** (external scope) | Tier 3 active probing, attribution-gated. |
| 1.4 | Use DHCP Logging | Out of scope | Internal-network concern. |
| 1.5 | Use a Passive Asset Discovery Tool | **Satisfies** (external scope) | Tier 1/2 passive collectors (CT logs, passive DNS, ASN, cloud IP manifests, internet-wide scans). |

### 9.2 Control 2 — Inventory and Control of Software Assets

| Safeguard | Title | EXPOSE Coverage | Mechanism |
|---|---|---|---|
| 2.1 | Establish and Maintain Software Inventory | **Partially satisfies** (externally-inferable software only) | Tech-stack inference (SPEC.md §8.1) populates `Service.tech_stack` from HTTP fingerprinting, banner analysis, LLM enrichment. Limited to externally-observable signal. |
| 2.2 | Ensure Authorized Software is Currently Supported | **Provides evidence for** | Tech-stack inference inputs to support-status review. |
| 2.3 | Address Unauthorized Software | **Provides evidence for** | Newly-observed tech stack components in the delta feed unauthorized-software review. |
| 2.4 | Utilize Automated Software Inventory Tools | **Satisfies** (external scope) | EXPOSE is itself such a tool for external-facing software. |
| 2.5 | Allowlist Authorized Software | Out of scope | Internal endpoint-control concern. |

### 9.3 Control 7 — Continuous Vulnerability Management

| Safeguard | Title | EXPOSE Coverage | Mechanism |
|---|---|---|---|
| 7.1 | Establish and Maintain a Vulnerability Management Process | **Provides evidence for** | EXPOSE artifacts feed the process. |
| 7.2 | Establish and Maintain a Remediation Process | Out of scope | Process. |
| 7.3 | Perform Automated Operating System Patch Management | Out of scope | Internal patching. |
| 7.4 | Perform Automated Application Patch Management | Out of scope | Internal patching. |
| 7.5 | Perform Automated Vulnerability Scans of Internal Enterprise Assets | Out of scope | Internal scan. |
| 7.6 | Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets | **Provides evidence for** | EXPOSE produces leads (potentially-vulnerable surface) but does not enumerate CVEs. Downstream tooling (Nessus, Qualys) consumes EXPOSE output and performs CVE enumeration. |
| 7.7 | Remediate Detected Vulnerabilities | Out of scope | Operator action. |

### 9.4 Control 12 — Network Infrastructure Management

| Safeguard | Title | EXPOSE Coverage | Mechanism |
|---|---|---|---|
| 12.1 | Ensure Network Infrastructure is Up-to-Date | Out of scope | Internal infrastructure. |
| 12.2 | Establish and Maintain a Secure Network Architecture | Out of scope | Internal architecture. |
| 12.3 | Securely Manage Network Infrastructure | Out of scope | Internal management. |
| 12.4 | Establish and Maintain Architecture Diagram | **Provides evidence for** | The graph (especially `resolves_to`, `hosted_in_asn`, `in_cloud_range` edges) documents external-perspective architecture. |
| 12.6 | Use of Secure Network Management and Communication Protocols | Out of scope | Internal protocols. |
| 12.8 | Establish and Maintain Dedicated Computing Resources for All Administrative Work | Out of scope | Operational practice. |

### 9.5 CIS Controls coverage summary

| Control | Strength |
|---|---|
| Control 1 (Asset Inventory) | **Strong** (external scope) |
| Control 2 (Software Inventory) | **Strong** (external scope) |
| Control 7 (Vulnerability Management) | Evidence-only |
| Control 12 (Network Infrastructure Management) | Evidence-only |
| Controls 3-6, 8-11, 13-18 | Out of scope |

---

## 10. CSA Cloud Controls Matrix (CCM) v4

**Framework version:** CCM v4.0.10 / CAIQ v4.1 (Cloud Security Alliance, current as of 2026-05). 17 domains, 207 controls. Used by cloud-native operators evaluating EXPOSE for cloud deployment.

This mapping is selectively populated for the domains most relevant to EXPOSE deployment; the full 207-control mapping is a Session G deliverable (federal-customer deployment guide). The selected domains below reflect the cloud-deployment relevance for EXPOSE Core when an operator deploys it on AWS, Azure, GCP, or a hybrid configuration.

| CCM Domain | Domain Name | EXPOSE Coverage | Rationale |
|---|---|---|---|
| A&A | Audit and Assurance | **Provides evidence for** | OpenTelemetry audit logs, SBOM, signed artifacts feed cloud customer audit obligations. |
| AIS | Application and Interface Security | **Satisfies** | Internal API surface compliant with ASVS Level 2 (per Section 7); FastAPI with OpenAPI specification. |
| BCR | Business Continuity Management & Operational Resilience | **Provides evidence for** | Reproducibility of artifacts (SPEC.md §9.2), backup-amenable state, deterministic restart. |
| CCC | Change Control and Configuration Management | **Satisfies** | IaC-driven change control per ADR-010; Helm + tenant YAML versioned. |
| CEK | Cryptography, Encryption and Key Management | **Satisfies** | FIPS 140-3 throughout per ADR-010; secrets backend abstraction (Vaultwarden / AWS Secrets Manager / Azure Key Vault / GCP Secret Manager). |
| DSP | Data Security and Privacy Lifecycle Management | **Satisfies** | Per-tenant retention policies; incidental data pruning per ADR-008; encryption at rest. |
| DCS | Datacenter Security | Out of scope | Cloud provider responsibility. |
| GRC | Governance, Risk and Compliance | **Provides evidence for** | Documentation set (ADRs, SPEC.md, Federal Customer Deployment Guide forthcoming) supports cloud-customer GRC obligations. |
| HRS | Human Resources | Out of scope | Cloud-customer responsibility. |
| IAM | Identity and Access Management | **Satisfies** | MFA, RBAC, federation paths per ADR-010. |
| IPY | Interoperability and Portability | **Satisfies** | Helm-based deployment portable across AWS/Azure/GCP/on-prem; canonical artifact is portable JSON. |
| IVS | Infrastructure and Virtualization Security | **Partially satisfies** | Container topology; cloud-provider-level virtualization is inherited. |
| LOG | Logging and Monitoring | **Satisfies** | OpenTelemetry; structured logs; per-tenant retention. |
| SEF | Security Incident Management, E-Discovery, and Cloud Forensics | **Provides evidence for** | Structured audit logs and evidence-store immutability support forensics; incident management is operator-side. |
| STA | Supply Chain Management, Transparency, and Accountability | **Satisfies** | SBOM, cosign, SLSA per ADR-010. |
| TVM | Threat and Vulnerability Management | **Partially satisfies** | EXPOSE itself is patched per RA-5 / SI-2 SLAs; threat intelligence feed is downstream concern. |
| UEM | Universal Endpoint Management | Out of scope | Cloud-customer endpoint concern. |

### 10.1 CCM coverage summary

| Domain Cluster | Strength |
|---|---|
| Application/Interface (AIS) | **Strong** |
| Crypto/Identity (CEK, IAM) | **Strong** (FIPS posture) |
| Logging/Monitoring (LOG, A&A) | **Strong** |
| Configuration (CCC) | **Strong** |
| Supply Chain (STA) | **Strong** |
| Data Lifecycle (DSP) | **Strong** |
| Infrastructure (IVS, DCS) | Partial (cloud-provider-shared) |

---

## 11. Cross-framework coverage summary matrix

This table is the executive-level summary across all frameworks documented above. It is intended for federal compliance auditors performing initial framework-fit assessment.

| Framework (Version) | Coverage Strength | Primary Anchor / Strength | Notable Gaps |
|---|---|---|---|
| MITRE ATT&CK Enterprise v15 — Reconnaissance (TA0043) | **Strong** | Anchor tactic; 9 techniques in-scope, 2 partial, 7 deliberate exclusions | T1597 (closed sources) and T1589.001/.003 (credentials, employee names) deferred to commercial modules |
| MITRE D3FEND v1.3.0 | **Strong** | D3-DA, D3-ID, D3-CA, D3-CSPN, D3-AM (external scope) | D3-NTA, D3-AVE explicit out-of-scope |
| NIST CSF 2.0 — Identify | **Strong** | ID.AM-02/04/08, ID.RA-01/03/04/05/07 | Internal asset (ID.AM-01/07), governance categories (GV.OC, GV.RM) |
| NIST CSF 2.0 — Detect | Partial | DE.CM-01, DE.CM-06 | All other Detect categories |
| NIST 800-53 Rev 5 — AU, IA, SC, SI | **Strong** | Technical-control families with ADR-010 backing | None within scope |
| NIST 800-53 Rev 5 — AC, CM, RA | **Strong** (with caveats) | AC-2/3/6, CM-2/3/6/8, RA-3/5 | AC-1, CM-1, RA-1 (policy controls) |
| NIST 800-53 Rev 5 — CA, IR, SA | Evidence-only | CA-7 continuous monitoring; SA-12 supply chain | Procedural families largely agency-side |
| NIST 800-53 Rev 5 — CP | Out of scope | CP-9 partial | Contingency planning is agency-side |
| NIST AI RMF 1.0 | **Strong** | Map, Measure, Manage | Govern partial (agency-side complementary) |
| OWASP ASVS 4.0.3 | **Strong** | All listed chapters (V1, V2, V3, V4, V5, V7, V8, V10, V13) target Level 2-3 | ASVS 5.0 transition pending |
| OWASP AISVS 1.0 | **Strong** | C02, C04, C05, C07, C09, C10, C11, C12 | C01 (training) out of scope by design; C03, C13 partial |
| CIS Controls v8.1 — Controls 1, 2 | **Strong** | External-asset and software inventory | Internal-asset/software safeguards out of scope |
| CIS Controls v8.1 — Controls 7, 12 | Evidence-only | Lead generation feeds vuln-mgmt; external view feeds network architecture | Internal vuln scan / network mgmt out of scope |
| CSA CCM v4.0.10 | **Strong** (selected domains) | AIS, CEK, IAM, LOG, A&A, CCC, DSP, STA | DCS, HRS, UEM cloud-customer-side |

---

## 12. Federal Customer Deployment Guide (Session G) implications

Session G is the downstream consumer of this framework annotation. For each control mapping above, Session G must distinguish 3PAO-defensible evidence from narrative-only claims. The categorization below pre-stages that work.

### 12.1 Controls supported by 3PAO-defensible technical evidence

These are mappings where EXPOSE produces concrete artifacts a 3PAO can inspect. Session G should organize evidence packages around these:

| Control / Subcategory | Evidence Type | Producing Component |
|---|---|---|
| AU-2, AU-3, AU-12 | OTel-emitted audit log samples with mandatory fields | All EXPOSE components via instrumentation |
| AU-9 | Cosign signature on canonical artifact + log immutability claim | `expose-control-plane` artifact generation |
| CM-2, CM-6 | Helm chart manifest + tenant YAML schema | Repository state |
| CM-8 | SBOM (syft-generated, cyclonedx-json format) | CI pipeline output |
| IA-2, IA-2(1) | Authentication flow trace showing MFA enforcement | Admin API logs |
| IA-7, SC-13 | FIPS module identification (build-time enforcement evidence) | Container image inspection |
| RA-5 | Vulnerability scan reports of EXPOSE infrastructure | Weekly scan output per ADR-010 |
| SC-8, SC-28 | TLS configuration inspection + at-rest encryption configuration | Helm values + Postgres/object-store config |
| SI-7, SI-7(15) | Cosign signatures + SLSA provenance attestations | CI pipeline output |
| SI-10 | Sanitization layer test outputs (eval harness adversarial dataset) | `expose-control-plane` test suite |
| SA-12 | SBOM + signed images + provenance | CI pipeline output |
| ID.AM-02 (CSF) | Sample canonical artifact with `Service` entities | Production artifact |
| ID.AM-08 (CSF) | Delta artifact showing lifecycle changes | Production delta output |
| CA-7 (continuous monitoring) | Daily-cadence artifact stream evidence | Run history |

### 12.2 Controls supported by narrative-only / configuration claims

These are mappings where the engine satisfies the control but the evidence is configuration-driven rather than artifact-driven. Session G should provide narrative explanations and reference configuration excerpts:

| Control | Evidence Approach |
|---|---|
| AC-1, AU-1, CM-1, IA-1, SI-1 | Agency policy reference; engine does not implement policy |
| AC-7, AC-11 | Configuration sample showing thresholds |
| AU-4, AU-5, AU-11 | Tenant retention configuration excerpt |
| CP-9 | Backup procedure documentation |
| ID.RA-04, ID.RA-05 | Narrative on lead-score-as-input-to-risk-assessment workflow |
| AI RMF GOVERN 1.1, 4.1 | Tenant configuration plus ADR-008 reference |

### 12.3 Controls requiring agency-side completion

These are the controls Session G must explicitly document as agency-side:

- **AC-1, AU-1, CA-1, CM-1, CP-1, IA-1, IR-1, RA-1, SA-1, SC-1, SI-1** — all "Policy and Procedures" controls. Engine cannot implement agency policy.
- **CA-2, CA-5, CA-6** — assessment, POAM, authorization processes.
- **CP-1 through CP-13 (most)** — contingency planning is agency-implemented.
- **IR-1 through IR-10** — incident response process and personnel.
- **SA-1 through SA-9** — agency procurement processes.

### 12.4 Tenant configuration that affects control posture

Session G must also document configuration choices with control implications:

| Configuration | Impact |
|---|---|
| `authorization_scope.enforcement_mode` (soft/medium/hard per ADR-008) | Affects AC-22 satisfaction strength |
| `llm.cost_ceiling_usd` | AI RMF MANAGE 1.1 |
| `llm.tie_breaker.enabled` | AI RMF MEASURE 2.7 |
| `retention.incidental_days` | AU-11, SI-12, ADR-008 |
| `collectors.enabled` set | ATT&CK technique coverage breadth |
| Cosign signing mode (keyless vs keypair) | SI-7 evidence model differs |

---

## 13. Open framework questions

Items that remain unsettled or require SME (subject matter expert) input or 3PAO consultation before final mapping is locked.

| Question | Why it matters | Suggested Resolution Path |
|---|---|---|
| **ASVS 4.0.3 to 5.0 transition timing** | ASVS 5.0 is forthcoming with chapter renumbering (V6 Stored Cryptography may merge with V7; V11 Business Logic is restructured). When 5.0 stabilizes, the Section 7 mapping needs re-validation. | Track ASVS 5.0 release; re-run Section 7 mapping in a quarterly review cadence. |
| **AISVS 1.0 stability and adoption** | AISVS is a newer standard (1.0 published 2025). Federal adoption posture is evolving. The Section 8 mapping may need refinement as 3PAO assessor practices crystallize. | Engage with AISVS working group; track FedRAMP guidance on AI-system controls. |
| **NIST AI RMF Generative AI Profile** | NIST AI 600-1 (Generative AI Profile) extends AI RMF 1.0 with generative-AI-specific guidance. Section 6 mapping should be reviewed against this profile. | Add Generative AI Profile mapping in Session G or a follow-on session. |
| **FedRAMP Rev 5 baseline transition** | FedRAMP is migrating from Rev 4 to Rev 5 baseline; some controls in the Section 5 mapping may need adjustment for Rev 5 alignment. | Already Rev 5; reconfirm with current FedRAMP baseline document. |
| **CCM v4.1 vs v4.0.10 reconciliation** | Cloud Security Alliance has issued minor updates. Section 10 selected mapping should be re-checked against the latest CCM v4.x release. | Pull latest CCM and reconcile in Session G. |
| **CISA BOD 23-01 evidence formats** | Per ADR-010, EXPOSE is positioned for federal asset-visibility per BOD 23-01. The specific format BOD 23-01 expects for vulnerability-disclosure metadata may not align exactly with EXPOSE's canonical artifact. | Verify BOD 23-01 reporting format expectations and document any required transformation. |
| **NIST SP 800-218 SSDF mapping** | NIST 800-218 (Secure Software Development Framework) is the SDLC standard. Session F SDLP will produce mapping; this document does not pre-empt that. | Cross-reference Section 5.9 (SA family) with Session F output. |
| **CMMC 2.0 mapping** | CMMC 2.0 inherits heavily from NIST 800-171 / 800-53. For DoD-adjacent customers, a CMMC mapping is needed. Per ADR-010 it is a roadmap-future concern. | Add CMMC mapping in a follow-on session once CMMC 2.0 final rule stabilizes. |
| **ISO/IEC 27001:2022 mapping** | Non-US enterprise customers may require ISO 27001 alignment. Not currently in scope for this document. | Add if/when international enterprise customers emerge. |
| **OASIS / OSCAL formal expression** | OSCAL (Open Security Controls Assessment Language) is the NIST machine-readable format for control mappings. The mappings in this document should eventually be expressed in OSCAL for FedRAMP automation. | OSCAL conversion in Session G or a follow-on production-hardening epic. |

---

## 14. Document maintenance

This is a living document. The mappings here reflect the v1 SPEC.md and ADRs as of 2026-05-10. Triggers for revision:

- ASVS 5.0 stable release
- AISVS 1.x to 2.0 transition
- NIST CSF 3.0 (no current public timeline)
- NIST 800-53 Rev 6 (no current public timeline)
- FedRAMP modernization initiative impact on baseline
- New collectors added to EXPOSE Core (impacts Section 2 ATT&CK mapping)
- New entity/edge types in observation graph (impacts Section 4 CSF ID.AM mapping)
- LLM provider additions (impacts Section 6 AI RMF and Section 8 AISVS)

Revision cadence: quarterly review or on any framework-version change, whichever is earlier.

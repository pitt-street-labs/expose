# EXPOSE Use Cases

Concrete scenarios showing how EXPOSE operates in practice. Each describes the operator, the problem, and how EXPOSE's architecture addresses it.

---

## 1. Red team engagement -- signed scope confirmation

### The operator

A senior penetration tester at a boutique security consultancy. The client is a mid-market financial services company with a complex cloud footprint spanning AWS and Azure, several acquired subsidiaries, and no authoritative inventory of their internet-facing assets.

### The problem

The first three days of every engagement are spent on manual reconnaissance -- correlating Censys results, passive DNS, WHOIS records, and Certificate Transparency logs in spreadsheets and ad-hoc scripts. The output is a scope document that the operator defends in a client review meeting. If the scope is wrong -- too broad and the operator touches assets outside authorization, too narrow and real exposure goes unexamined -- the engagement is compromised. The evidence behind scope decisions lives in browser history and analyst notes.

### How EXPOSE addresses it

The operator creates a tenant in EXPOSE with the client's organization name, known apex domains, and brand strings as seeds. The authorization scope is configured to match the Rules of Engagement. EXPOSE runs a single burst scan:

- **14 collectors** enumerate the external surface from CT logs, DNS, WHOIS/RDAP, BGP/ASN data, cloud IP range manifests, TLS certificates, HTTP fingerprinting, email authentication records, and GitHub organization data
- **Attribution engine** classifies every discovered asset into confidence tiers (`confirmed`, `high`, `medium`, `requires_review`) with full evidence chains -- the operator can show the client exactly why each asset was considered in-scope
- **Scope matcher** flags assets that fall outside the authorization boundary, generating warnings the operator reviews before proceeding
- The output is a **signed canonical artifact** -- a cosign-signed JSON file the operator delivers to the client as engagement evidence

In the client review meeting, the operator opens the artifact and walks through the attribution tiers. A domain attributed as `confirmed` has a direct WHOIS match to the client organization. A domain attributed as `medium` was found via CT log correlation and registrant name pivot -- the evidence chain shows why. The client confirms or rejects each attribution. The signed artifact becomes part of the engagement record.

For retainer engagements, EXPOSE runs on a daily schedule. Weekly delta reports show what changed in the client's external surface since the last scan -- new subdomains, expired certificates, infrastructure moves between cloud providers. The red team and the client's defensive team work from the same artifact format.

---

## 2. Enterprise CTEM program -- continuous surface monitoring

### The operator

A security director at a Fortune 500 manufacturing company with operations in 40 countries, 200+ subsidiaries, and a history of acquisitions that left orphaned infrastructure scattered across cloud providers and legacy hosting.

### The problem

The quarterly attack surface review is a manual exercise. An analyst pulls reports from the current EASM vendor (SaaS, defensive-only), correlates with internal asset inventory, and produces a slide deck. By the time the deck reaches the board, the data is weeks old. Shadow IT, subsidiary infrastructure, and post-acquisition assets slip through. The EASM vendor holds the historical data -- if the contract ends, years of surface evolution data disappear.

### How EXPOSE addresses it

EXPOSE runs on a daily schedule across the organization's full seed set -- all known apex domains, brand strings, subsidiary names, and cloud account identifiers. Each run produces a signed artifact and a delta against the previous run.

**Daily operations:**

- The artifact lands in the security team's artifact store (S3-compatible object storage within the company's own infrastructure)
- Delta computation highlights what changed: new assets discovered, assets that disappeared, attribution confidence changes, new technology fingerprints detected
- The SIEM integration (Splunk adapter) ingests the structured artifact, creating alerts for new `high` or `confirmed` assets that were not in the previous day's artifact
- The security team triages new discoveries during their daily standup

**Quarterly board reporting:**

- The security director queries the artifact history to show surface evolution over the quarter -- how many internet-facing assets were discovered, how many were remediated, how attribution confidence trended
- Every claim in the report traces back to a signed artifact with a provenance chain the audit team can verify independently
- The data lives in the company's own storage, not a vendor's cloud

**Post-acquisition integration:**

- When the company acquires a subsidiary, the security team adds the subsidiary's known domains and brand strings as new seeds
- The first scan produces a baseline of the subsidiary's external surface
- Subsequent daily scans track how the subsidiary's infrastructure is integrated or decommissioned
- Multi-tenant isolation ensures subsidiary data is scoped appropriately

**Cost control:**

- LLM enrichment runs against a local Ollama instance for routine daily scans, keeping per-run costs near zero
- High-confidence commercial LLM enrichment (Anthropic or OpenAI) is reserved for quarterly deep-analysis runs where the richer model output justifies the cost
- The operator sets per-run cost ceilings; EXPOSE enforces them

---

## 3. Academic research -- reproducible attribution benchmarking

### The operator

A PhD candidate at a university security research lab studying attribution accuracy in external attack surface management. The dissertation proposes a novel graph-based attribution methodology and needs to benchmark it against existing approaches using a common dataset.

### The problem

There is no standard benchmark for EASM attribution accuracy. Commercial vendors do not publish their attribution logic or reference datasets. Censys claims ">95% attribution accuracy" but the methodology and test set are proprietary. Academic papers on attack surface attribution each build their own collection infrastructure, making cross-study comparison impossible. Reproducibility is aspirational.

### How EXPOSE addresses it

**Building the benchmark:**

- The researcher deploys EXPOSE Core (Apache 2.0) on university compute infrastructure
- EXPOSE's eval harness provides a framework for running attribution against curated datasets with known ground truth -- the `confirmed_yours` and `confirmed_not_yours` datasets establish baseline precision and recall
- The researcher extends the eval harness with their novel attribution methodology, implemented as a custom rule pack
- Both the baseline EXPOSE methodology and the novel methodology run against the same dataset, producing comparable metrics

**Publishing reproducible results:**

- The EXPOSE engine is open source; reviewers can run the same version against the same dataset
- Rule packs are declarative JSON -- the novel methodology is fully specified in a file, not buried in code
- The deterministic engine guarantees that given the same inputs and rules, the same artifact is produced
- The signed artifact provides integrity evidence that the published results match the actual engine output
- Reference datasets from EXPOSE Research (CC BY 4.0) are citable and available to other researchers

**Extending the work:**

- Other researchers at different institutions can fork the engine, add their own rule packs, and run against the same reference datasets
- The eval harness metrics (precision, recall, F1 against ground-truth attribution) become the common vocabulary for the subfield
- Graduate students in the lab use EXPOSE as a teaching tool for cybersecurity courses -- the pipeline architecture, collector framework, and attribution model are documented and extensible

The dissertation cites the EXPOSE engine version, the rule pack hash, and the reference dataset version. A reviewer in a different country can reproduce the results without building collection infrastructure from scratch.

---

## 4. Federal agency self-host -- operating within the ATO boundary

### The operator

An information security team at a civilian federal agency operating under a NIST 800-53 Moderate baseline. The agency has an existing Authorization to Operate (ATO) for its cloud infrastructure and needs continuous external surface monitoring as part of its CDM (Continuous Diagnostics and Mitigation) program.

### The problem

Commercial EASM vendors are SaaS. Adopting them means either inheriting the vendor's FedRAMP authorization (if they have one) or sponsoring the vendor through the authorization process (18-24 months and significant agency effort). The agency's external surface is expanding now -- new cloud workloads, contractor-managed infrastructure, inter-agency integrations. The CISO cannot wait two years for a vendor authorization to mature.

Meanwhile, the agency's CDM program requires continuous monitoring evidence that feeds into the agency SIEM and is auditable against NIST 800-53 controls. Point-in-time recon tools do not produce the structured, continuous evidence stream the CDM program needs.

### How EXPOSE addresses it

**Deployment within the ATO boundary:**

- The agency deploys EXPOSE Core on its existing authorized Kubernetes infrastructure (cloud or on-premise)
- FIPS 140-3 validated cryptography is used in all modes -- TLS for API communication, SHA-256 for content hashing, cosign for artifact signing
- The Helm chart deploys with NetworkPolicy and PodSecurity hardening aligned to the agency's existing security baseline
- No data leaves the agency's authorization boundary except collector egress to allowlisted public data sources (CT logs, DNS resolvers, RDAP registries)

**NIST 800-53 control satisfaction:**

- **AU-family (Audit):** Structured audit logging captures every pipeline action, collector invocation, and attribution decision in a format compatible with the agency's SIEM
- **CA-7 (Continuous Monitoring):** Daily signed artifacts provide the continuous evidence stream the CDM program requires
- **RA-5 (Vulnerability and Monitoring Scanning):** EXPOSE's external surface discovery complements the agency's internal vulnerability scanning (Nessus/Tenable) -- different scope, complementary evidence
- **SI-family (System and Information Integrity):** Cosign-signed artifacts with SLSA attestations and SBOMs satisfy supply-chain integrity requirements per EO 14028 and NSM-22
- A documented control mapping shows which controls EXPOSE satisfies, which it partially satisfies, and which require agency-side implementation

**CDM integration:**

- Signed artifacts are ingested into the agency's CDM tooling via the structured JSON schema
- Delta computation between daily runs produces change reports compatible with the agency's existing alerting workflow
- The artifact schema is stable across releases -- the agency's ingestion pipeline does not break on engine updates

**Operational independence:**

- The agency operates EXPOSE without vendor involvement for the open-source engine
- LLM enrichment runs against a local Ollama instance within the agency network -- no data is sent to external AI providers
- When the commercial Korlogos managed-service offering achieves FedRAMP Moderate authorization, the agency can migrate to managed service or continue self-hosting -- the artifact format is identical either way
- Historical artifacts remain in the agency's own storage regardless of any future vendor relationship

The agency's CISO reports to the CIO that continuous external surface monitoring is operational within the existing ATO, using open-source software the agency controls, producing signed evidence the CDM program can ingest, without waiting for a vendor authorization cycle.

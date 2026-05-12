# EXPOSE Use Cases

Concrete scenarios showing how EXPOSE operates in practice. Each describes the operator, the problem, how EXPOSE's architecture addresses it, and the specific features and commands involved.

---

## 1. SOC Analyst -- triage, hunt, and respond

### The operator

A Tier 2 SOC analyst at a mid-market financial services company. Works in Splunk, maintains detection rules, and triages escalated alerts. Familiar with STIX/TAXII and MISP but spends most of the day in the SIEM console.

### The problem

The organization's EASM tool produces weekly asset discovery reports as PDFs and CSV exports. When a new external asset appears -- a forgotten staging server, a subsidiary's unmonitored domain -- the analyst has to manually determine whether it represents a threat, cross-reference it against blocklists, check if the IP appears in existing SIEM data, and write hunt queries by hand. The gap between "EASM found something" and "SOC is hunting for it" is measured in days.

### How EXPOSE addresses it

**Daily triage workflow:**

1. EXPOSE runs nightly against the organization's seed set. The SOC threat package module identifies assets with degraded trust indicators -- DNS blocklist hits, certificate authority changes, hosting migrations, or new port exposure.

2. Findings push automatically to Splunk via the HEC adapter:

```bash
# Configure SIEM push for the tenant
curl -X PUT http://expose:8090/api/v1/tenants/{tenant_id}/config \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "siem_integration": {
      "provider": "splunk",
      "hec_url": "https://splunk.corp:8088/services/collector",
      "hec_token": "configured-via-secrets-backend",
      "index": "expose_findings",
      "enabled": true
    }
  }'
```

3. The analyst sees new EXPOSE findings as Splunk alerts, each carrying attribution confidence, the discovery timeline, and the evidence chain. A `confirmed` attribution at 0.97 confidence with a WHOIS registrant match gets a different priority than a `medium` at 0.52 from a CT log SAN correlation.

**IoC import and internal hunt:**

4. When a finding warrants investigation, the analyst exports the SOC threat package as a STIX 2.1 bundle:

```bash
# Export STIX bundle for a specific run
expose run export --run-id $RUN_ID --format stix21 --output findings.stix.json

# Or via API
curl http://expose:8090/api/v1/runs/{run_id}/export?format=stix21 \
  -H "Authorization: Bearer $TOKEN" -o findings.stix.json
```

5. The STIX bundle contains structured IoCs (IP addresses, domains, certificate fingerprints) with sighting relationships back to the EXPOSE observations. The analyst imports them into MISP or feeds them directly into Splunk's threat intelligence framework.

6. For findings with LLM enrichment (Environment 2), the SOC threat package includes suggested hunt queries:

```
# Example LLM-generated hunt recommendation (from E2 analysis)
# Finding: staging.acme-corp.com resolving to non-corporate IP (AS13335)
# Suggested Splunk query:
index=proxy sourcetype=web_proxy dest_ip="104.21.x.x"
| stats count by src_ip, dest_ip, uri_path
| where count > 5

# Suggested KQL (Sentinel):
CommonSecurityLog
| where DestinationIP == "104.21.x.x"
| summarize count() by SourceIP, RequestURL
```

**Features used:** SOC threat package, SIEM push adapters (Splunk HEC, Sentinel, Chronicle), STIX 2.1 export, MISP event generation, attribution confidence tiers, delta computation, DNS blocklist collector (`dns-blacklist`), trust degradation detection.

---

## 2. CISO -- executive attack surface reporting

### The operator

A CISO at a Fortune 1000 manufacturing company with operations in 40 countries, 200+ subsidiaries, and a history of acquisitions that left orphaned infrastructure scattered across cloud providers and legacy hosting. Reports to the board quarterly. Manages a $15M security program budget.

### The problem

The quarterly attack surface review is a manual exercise. An analyst pulls reports from the current EASM vendor, correlates with internal asset inventory, and produces a slide deck. By the time the deck reaches the board, the data is weeks old. The CISO cannot answer "how has our attack surface changed since last quarter?" with data -- only with anecdotes. M&A due diligence relies on the acquiring company's self-reported asset inventory, which is always incomplete.

### How EXPOSE addresses it

**Continuous surface monitoring:**

1. EXPOSE runs daily across the organization's full seed set. The security team configures seeds for all known apex domains, brand strings, subsidiary names, and cloud account identifiers:

```bash
# Add seeds for the parent organization and subsidiaries
expose run start acme-corp.com --tenant $TENANT_ID
expose run start acme-subsidiary.de --tenant $TENANT_ID
expose run start "Acme Corporation" --seed-type organization --tenant $TENANT_ID
```

2. Each run produces a signed artifact and a delta against the previous run. The artifact lands in the company's own object storage -- not a vendor's cloud.

**Executive attack surface report (CISO Strategic Report module):**

3. The CISO Strategic Report module generates automated executive-level reporting:

```bash
# Generate quarterly executive report
curl -X POST http://expose:8090/api/v1/reports/ciso \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "tenant_id": "'$TENANT_ID'",
    "period": "2026-Q1",
    "include_sector_analysis": true,
    "include_threat_actors": true,
    "include_attraction_assessment": true
  }'
```

The report includes:
- Attack surface evolution over the quarter (new assets discovered, assets remediated, attribution confidence trends)
- Sector-specific threat landscape (which threat groups target manufacturing, their TTPs, motivation)
- Attraction assessment (what makes this organization interesting to attackers based on exposed surface)
- Ranked likely targets based on lead scores and threat intelligence correlation
- Every claim traced to a signed artifact with a provenance chain the audit team verifies independently

**M&A due diligence:**

4. When the company evaluates an acquisition target, the security team creates a new tenant scoped to the target's known domains:

```bash
# Create tenant for acquisition target
curl -X POST http://expose:8090/api/v1/tenants \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Project Atlas - Target Corp",
    "authorization_scope": {
      "domains": ["targetcorp.com", "targetcorp.io"],
      "organizations": ["Target Corporation"]
    }
  }'

# Run initial discovery
expose run start targetcorp.com --tenant $TARGET_TENANT_ID
```

5. The Identity Surface module discovers assets the target may not know about -- subsidiary domains found via registrant pivot analysis, infrastructure from prior acquisitions, orphaned cloud resources:

```bash
# Enable identity surface expansion
curl -X PUT http://expose:8090/api/v1/tenants/$TARGET_TENANT_ID/config \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "modules": {
      "identity_surface": {
        "enabled": true,
        "registrant_pivot": true,
        "org_graph": true,
        "fuzzy_matching_threshold": 0.8
      }
    }
  }'
```

6. The baseline scan quantifies the target's external exposure before the deal closes. Post-acquisition, daily scans track integration and decommissioning progress.

**Features used:** CISO Strategic Report module, Identity Surface module (registrant pivot, org graph, fuzzy matching), multi-tenant isolation, delta computation, artifact history queries, LLM-driven sector analysis, signed artifact provenance, daily scheduling.

---

## 3. Penetration Tester -- external recon and scope validation

### The operator

A senior penetration tester at a boutique security consultancy. The client is a mid-market financial services company with a complex cloud footprint spanning AWS and Azure, several acquired subsidiaries, and no authoritative inventory of their internet-facing assets.

### The problem

The first three days of every engagement are spent on manual reconnaissance -- correlating Censys results, passive DNS, WHOIS records, and Certificate Transparency logs in spreadsheets and ad-hoc scripts. The output is a scope document the operator defends in a client review meeting. If the scope is wrong -- too broad and the operator touches assets outside authorization, too narrow and real exposure goes unexamined -- the engagement is compromised.

### How EXPOSE addresses it

**Pre-engagement scope confirmation:**

1. The operator creates a tenant scoped to the client's Rules of Engagement:

```bash
# Create engagement tenant
curl -X POST http://expose:8090/api/v1/tenants \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Engagement: ACME Financial Q2 2026",
    "authorization_scope": {
      "domains": ["acmefinancial.com", "acme-fin.io"],
      "cidrs": ["198.51.100.0/24"],
      "organizations": ["ACME Financial Services LLC"]
    }
  }'
```

2. EXPOSE runs a burst scan using all tiers. Tier 3 (active) collectors fire only against entities with `confirmed` or `high` attribution, or those explicitly listed in the authorization scope:

```bash
# Burst scan with all tiers enabled
expose run start acmefinancial.com \
  --tenant $ENGAGEMENT_TENANT \
  --tiers 1,2,3 \
  --rule-pack examples/rulepacks/cloud-first.json
```

3. The attribution engine classifies every discovered asset into confidence tiers with full evidence chains. In the client review meeting, the operator walks through the artifact:

```bash
# View attribution summary
expose run results $RUN_ID --format table --min-confidence 0.5

# Export the signed artifact for client delivery
expose run export --run-id $RUN_ID --format json --sign --output scope-artifact.json
```

A domain attributed as `confirmed` (0.97) has a direct WHOIS registrant match. A domain at `medium` (0.62) was found via CT log SAN correlation and registrant name pivot -- the evidence chain shows exactly why. The client confirms or rejects each attribution. The signed artifact becomes part of the engagement record.

**WAF origin discovery:**

4. During the engagement, the operator uses the WAF origin discovery collector to find the real IP behind CDN-protected assets:

```bash
# Enable WAF origin discovery for confirmed assets
curl -X PUT http://expose:8090/api/v1/tenants/$ENGAGEMENT_TENANT/config \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "collectors": {
      "enabled": ["waf-origin-discovery", "waf-detection"]
    }
  }'
```

**Continuous engagement mode:**

5. For retainer engagements, EXPOSE runs on a daily schedule. Weekly delta reports show what changed -- new subdomains, expired certificates, infrastructure moves between cloud providers:

```bash
# Schedule daily scans
curl -X POST http://expose:8090/api/v1/scheduler \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "tenant_id": "'$ENGAGEMENT_TENANT'",
    "schedule": "0 2 * * *",
    "tiers": [1, 2, 3]
  }'

# View deltas
expose run delta --run-id $LATEST_RUN --previous $PREVIOUS_RUN
```

The red team and the client's defensive team work from the same artifact format. When findings are delivered, both sides reference the same data structure. The reconciliation gap disappears.

**Features used:** Authorization scope enforcement (medium/hard modes), burst scan mode, attribution confidence tiers with evidence chains, signed artifact export, WAF origin discovery (`waf-origin-discovery`, `waf-detection`), delta computation, cloud-first rule pack, daily scheduling, scope refusal event logging.

---

## 4. MSSP -- multi-tenant scanning and automated reporting

### The operator

A managed security services provider serving 40 mid-market clients across financial services, healthcare, and manufacturing verticals. Each client has a different security maturity level, different compliance requirements, and a different budget. The MSSP's value proposition is continuous monitoring and quarterly reporting at a price point below what an in-house security team would cost.

### The problem

The MSSP currently operates three separate tools for external surface monitoring, vulnerability assessment, and reporting. Client onboarding takes two weeks of manual configuration. Quarterly reports are assembled by hand from CSV exports. When a client asks "what changed since last month?" the answer requires an analyst to diff two spreadsheets. Per-client licensing on the current EASM vendor scales linearly and is consuming margin.

### How EXPOSE addresses it

**Multi-tenant architecture:**

1. Each client is a separate EXPOSE tenant with isolated data, authorization scope, and configuration. Onboarding is an API call:

```bash
# Onboard new client
curl -X POST http://expose:8090/api/v1/tenants \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Client: Midwest Manufacturing Co",
    "authorization_scope": {
      "domains": ["midwest-mfg.com", "midwestmanufacturing.net"],
      "organizations": ["Midwest Manufacturing Company"]
    },
    "config": {
      "collectors": {
        "enabled": ["ct-crtsh", "rdap-whois", "cloud-ranges", "bgp-ripestat",
                     "spf-dkim-dmarc", "favicon-hash", "active-dns-resolve",
                     "active-tls-handshake", "active-http-fingerprint",
                     "dns-blacklist", "waf-detection"]
      },
      "rule_pack": "examples/rulepacks/conservative.json",
      "schedule": "0 3 * * *"
    }
  }'
```

2. All 40 clients run on a single EXPOSE deployment with tenant-scoped data isolation. The MSSP's infrastructure cost is the compute to run one platform, not 40 per-client licenses.

**Automated reporting:**

3. Monthly and quarterly reports generate automatically from artifact history:

```bash
# Generate monthly report for a client
curl -X POST http://expose:8090/api/v1/reports/ciso \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "tenant_id": "'$CLIENT_TENANT'",
    "period": "2026-04",
    "include_sector_analysis": true,
    "include_delta_summary": true
  }'
```

4. Delta computation is built into every run. "What changed since last month?" is a query, not a manual diff:

```bash
# Monthly delta summary via API
curl http://expose:8090/api/v1/runs/delta?tenant_id=$CLIENT_TENANT\
  &from_date=2026-04-01&to_date=2026-04-30 \
  -H "Authorization: Bearer $TOKEN"
```

**SLA monitoring:**

5. The MSSP tracks scan coverage and freshness across all clients via the admin API:

```bash
# Check scan freshness across all tenants
curl http://expose:8090/api/v1/admin/tenants/health \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Response includes last scan time, entity count, attribution distribution, and alert counts per tenant. Clients whose scans are more than 24 hours stale trigger an internal SLA alert.

**Cost control:**

6. LLM enrichment costs are controlled per tenant. High-value clients use commercial providers (Anthropic, Gemini) for deeper analysis. Budget-conscious clients use local Ollama:

```bash
# Configure per-tenant LLM settings
curl -X PUT http://expose:8090/api/v1/tenants/$CLIENT_TENANT/config \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "llm_enabled": true,
    "llm_provider": "ollama",
    "llm_model": "llama3.2",
    "llm_cost_ceiling_per_run": 0.0
  }'
```

**Features used:** Multi-tenant isolation, tenant-scoped configuration, daily scheduling across tenants, delta computation, CISO Strategic Report module, admin health API, per-tenant LLM cost ceilings, per-tenant quota enforcement, conservative rule pack, SIEM push adapters for client SOCs.

---

## 5. Compliance Officer -- audit trail and evidence management

### The operator

A compliance officer at a federal contractor operating under NIST 800-53 Moderate baseline and CMMC Level 2. Responsible for continuous monitoring evidence, RMF (Risk Management Framework) package maintenance, and annual audit preparation. Reports to the CISO and coordinates with the agency's ISSM (Information System Security Manager).

### The problem

The organization's continuous monitoring program requires evidence that external surface scanning is performed regularly, that findings are documented with provenance, and that the evidence chain is tamper-evident and auditable. The current EASM vendor provides weekly PDF reports with no cryptographic integrity, no machine-readable provenance, and no mapping to NIST control families. During the last audit, the assessor asked "how do you know this report hasn't been modified?" and the compliance officer could not answer definitively.

### How EXPOSE addresses it

**NIST 800-53 control satisfaction:**

1. EXPOSE's architecture maps directly to specific control families:

| Control | Requirement | How EXPOSE satisfies it |
|---|---|---|
| **AU-2** (Audit Events) | Define auditable events | Structured audit logging captures every pipeline action, collector invocation, and attribution decision |
| **AU-3** (Content of Audit Records) | Sufficient detail for reconstruction | Each audit event includes timestamp, actor, action, target, outcome, and correlation ID |
| **CA-7** (Continuous Monitoring) | Ongoing security status assessment | Daily signed artifacts provide the continuous evidence stream |
| **RA-5** (Vulnerability Monitoring and Scanning) | Regular external surface scanning | 40 collectors provide comprehensive external surface discovery on a configurable schedule |
| **SI-7** (Software, Firmware, and Information Integrity) | Integrity verification | Cosign-signed artifacts with SLSA provenance and FIPS SHA-256 content hashing |

2. Every artifact is signed and content-addressed:

```bash
# Verify artifact integrity offline
cosign verify-blob --key expose-cosign.pub \
  --signature canonical-artifact.json.sig \
  canonical-artifact.json

# Verify content hash
sha256sum canonical-artifact.json
# Compare against manifest.json content_hash field
```

**Evidence storage with provenance:**

3. The compliance officer configures evidence storage to retain artifacts per the organization's retention policy:

```bash
# Configure retention policy
curl -X PUT http://expose:8090/api/v1/tenants/$TENANT_ID/config \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "storage": {
      "evidence_retention_days": 2555,
      "artifact_retention_days": 2555,
      "content_addressed": true
    }
  }'
```

4. Every artifact carries a provenance chain: the engine version, the rule pack hash, the collector set, the seed configuration, and the timestamp. An assessor can reconstruct exactly how any finding was produced:

```bash
# Query provenance for a specific finding
curl http://expose:8090/api/v1/provenance/{finding_id} \
  -H "Authorization: Bearer $TOKEN"
```

Response includes the collector that produced the observation, the rule that attributed it, the confidence calculation, and the signed artifact that contains it.

**Audit preparation:**

5. Before an annual assessment, the compliance officer exports the full audit log for the assessment period:

```bash
# Export audit log for assessment period
curl http://expose:8090/api/v1/audit/export \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "from_date": "2025-05-01",
    "to_date": "2026-04-30",
    "format": "json",
    "include_provenance": true
  }'
```

6. The audit log is append-only and retention-aware. The assessor sees a continuous record of scanning activity, attribution decisions, and artifact generation -- not a collection of PDFs assembled the week before the audit.

**FIPS compliance:**

7. All cryptographic operations route through the centralized `fips_adapter`. The compliance officer can demonstrate that no raw `hashlib` or `secrets` calls exist in the codebase -- all crypto is FIPS 140-3 validated:

```bash
# FIPS compliance check (CI gate)
python -m expose.crypto.fips_adapter --verify
```

**Features used:** FIPS 140-3 cryptography (fips_adapter), append-only audit logging (AU-2/AU-3), cosign artifact signing with SLSA provenance, content-addressed evidence storage, NIST 800-53 control mapping, retention policy configuration, provenance chain queries, audit log export, SBOM generation.

---

## 6. DevSecOps Engineer -- CI/CD integration and scheduled scanning

### The operator

A DevSecOps engineer at a SaaS company with 200 microservices across three cloud providers. Maintains the CI/CD pipeline (GitHub Actions), operates the security toolchain (SAST, DAST, SCA), and is responsible for ensuring that infrastructure changes do not introduce new external exposure.

### The problem

The security team runs the EASM tool manually once a month. Infrastructure changes -- new subdomains, new cloud services, new API endpoints -- deploy continuously via CI/CD but are not reflected in the attack surface inventory until the next manual scan. When a developer spins up a staging environment with a public IP and no WAF, the security team finds out weeks later. There is no gate in the deployment pipeline that checks whether a change introduces new external exposure.

### How EXPOSE addresses it

**CI/CD integration via the eval harness:**

1. The eval harness provides a programmatic interface for running EXPOSE scans as part of the deployment pipeline. A GitHub Actions workflow triggers a scan after infrastructure deployment:

```yaml
# .github/workflows/expose-scan.yml
name: EXPOSE Attack Surface Check
on:
  push:
    branches: [main]
    paths:
      - 'terraform/**'
      - 'k8s/**'
      - 'dns/**'

jobs:
  expose-scan:
    runs-on: self-hosted
    steps:
      - name: Run EXPOSE scan
        run: |
          expose run start ${{ vars.PRIMARY_DOMAIN }} \
            --tenant ${{ secrets.EXPOSE_TENANT_ID }} \
            --tiers 1,2 \
            --output artifact.json \
            --format json

      - name: Check for new exposure
        run: |
          expose run delta \
            --run-id $(jq -r '.run_id' artifact.json) \
            --previous latest \
            --fail-on-new-high-confidence
```

2. The `--fail-on-new-high-confidence` flag exits non-zero if the scan discovers new assets with `confirmed` or `high` attribution confidence that were not present in the previous run. This gates the deployment pipeline -- a PR that introduces unexpected external exposure does not merge without security review.

**Scheduled scanning with alerting:**

3. Daily scans run on a cron schedule via the EXPOSE scheduler:

```bash
# Configure daily scan with alerting
curl -X POST http://expose:8090/api/v1/scheduler \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "tenant_id": "'$TENANT_ID'",
    "schedule": "0 4 * * *",
    "tiers": [1, 2, 3],
    "alert_on_delta": true,
    "alert_webhook": "https://hooks.slack.com/services/T.../B.../xxx"
  }'
```

4. When the daily scan detects changes, a webhook fires with a structured delta summary. The DevSecOps engineer triages in Slack and escalates to the development team if the change was unintentional.

**Artifact signing in the supply chain:**

5. EXPOSE artifacts are signed with the same Ed25519 keys used for the organization's software supply-chain integrity:

```bash
# Generate signing keypair
cosign generate-key-pair --output-key-prefix expose

# Configure artifact signing
curl -X PUT http://expose:8090/api/v1/tenants/$TENANT_ID/config \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "signing": {
      "enabled": true,
      "algorithm": "ed25519",
      "key_path": "/secrets/expose-cosign.key"
    }
  }'
```

6. Signed artifacts feed into the organization's SLSA provenance chain. The security team can prove that a specific scan produced a specific artifact at a specific time with a specific configuration -- the same integrity guarantee they apply to software builds.

**Infrastructure-as-code integration:**

7. When Terraform or Kubernetes manifests change DNS records, the DevSecOps engineer uses EXPOSE's seed management to keep the scan scope current:

```bash
# Sync seeds from Terraform state
terraform show -json | jq -r '.values.root_module.resources[]
  | select(.type == "aws_route53_record")
  | .values.name' | while read domain; do
    curl -X POST http://expose:8090/api/v1/tenants/$TENANT_ID/seeds \
      -H "Authorization: Bearer $TOKEN" \
      -d "{\"value\": \"$domain\", \"type\": \"domain\"}"
done
```

**Features used:** Eval harness (CI/CD integration), `--fail-on-new-high-confidence` pipeline gate, daily scheduling with webhook alerting, delta computation, Ed25519 artifact signing with SLSA provenance, seed management API, structured JSON artifact output, cosign verification.

---

## 7. Academic researcher -- reproducible attribution benchmarking

### The operator

A PhD candidate at a university security research lab studying attribution accuracy in external attack surface management. The dissertation proposes a novel graph-based attribution methodology and needs to benchmark it against existing approaches using a common dataset.

### The problem

There is no standard benchmark for EASM attribution accuracy. Commercial vendors do not publish their attribution logic or reference datasets. Censys claims ">95% attribution accuracy" but the methodology and test set are proprietary. Academic papers on attack surface attribution each build their own collection infrastructure, making cross-study comparison impossible. Reproducibility is aspirational.

### How EXPOSE addresses it

**Building the benchmark:**

1. The researcher deploys EXPOSE Core (Apache 2.0) on university compute infrastructure:

```bash
git clone https://github.com/pitt-street-labs/expose.git
cd expose
uv pip install -e ".[all]"
```

2. The eval harness provides a framework for running attribution against curated datasets with known ground truth:

```bash
# Run eval against reference datasets
expose eval run \
  --dataset examples/eval-datasets/confirmed_yours.json \
  --dataset examples/eval-datasets/confirmed_not_yours.json \
  --dataset examples/eval-datasets/ambiguous.json \
  --dataset examples/eval-datasets/adversarial.json \
  --rule-pack examples/rulepacks/example-baseline.json \
  --output results.json
```

3. The researcher implements their novel attribution methodology as a custom rule pack and runs both approaches against the same dataset:

```bash
# Run novel methodology against same datasets
expose eval run \
  --dataset examples/eval-datasets/confirmed_yours.json \
  --dataset examples/eval-datasets/confirmed_not_yours.json \
  --rule-pack research/novel-graph-attribution.json \
  --output novel-results.json

# Compare precision, recall, F1
expose eval compare results.json novel-results.json --format table
```

**Publishing reproducible results:**

4. The deterministic engine guarantees that given the same inputs and rules, the same artifact is produced. The researcher's paper cites:
   - The EXPOSE engine version (`expose --version`)
   - The rule pack file hash
   - The reference dataset version (CC BY 4.0 from EXPOSE Research)

5. A reviewer in a different country can reproduce the results without building collection infrastructure from scratch:

```bash
git checkout v0.2.0
expose eval run --dataset ... --rule-pack ... --output reviewer-results.json
# Deterministic output matches published results
```

**Features used:** Eval harness (runner, datasets, CLI), reference datasets (CC BY 4.0), declarative rule packs (JSON Schema-validated), deterministic artifact generation, Apache 2.0 license, custom collector extension API.

---

## 8. Federal agency -- self-host within the ATO boundary

### The operator

An information security team at a civilian federal agency operating under a NIST 800-53 Moderate baseline. The agency has an existing Authorization to Operate (ATO) for its cloud infrastructure and needs continuous external surface monitoring as part of its CDM (Continuous Diagnostics and Mitigation) program.

### The problem

Commercial EASM vendors are SaaS. Adopting them means either inheriting the vendor's FedRAMP authorization (if they have one) or sponsoring the vendor through the authorization process (18-24 months and significant agency effort). The agency's external surface is expanding now -- new cloud workloads, contractor-managed infrastructure, inter-agency integrations. The CISO cannot wait two years for a vendor authorization to mature.

### How EXPOSE addresses it

**Deployment within the ATO boundary:**

1. The agency deploys EXPOSE Core on its existing authorized Kubernetes infrastructure:

```bash
# Deploy via Helm with federal-hardened values
helm install expose deploy/helm-chart/ \
  -f deploy/helm-chart/values-federal.yaml \
  --set fips.enabled=true \
  --set networkPolicy.enabled=true \
  --set podSecurity.enforce=restricted
```

2. No data leaves the agency's authorization boundary except collector egress to allowlisted public data sources (CT logs, DNS resolvers, RDAP registries). The egress allowlist is documented and auditable:

```bash
# View egress allowlist
expose config show-egress-allowlist
```

3. LLM enrichment runs against a local Ollama instance within the agency network -- no data is sent to external AI providers:

```bash
# Configure local-only LLM
curl -X PUT http://expose:8090/api/v1/tenants/$TENANT_ID/config \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "llm_enabled": true,
    "llm_provider": "ollama",
    "llm_model": "llama3.2",
    "llm_cost_ceiling_per_run": 0.0
  }'
```

**CDM integration:**

4. Signed artifacts are ingested into the agency's CDM tooling via the structured JSON schema. The artifact schema is stable across releases -- the agency's ingestion pipeline does not break on engine updates:

```bash
# Validate artifact against schema
expose artifact validate canonical-artifact.json \
  --schema schemas/canonical-artifact-v1.json
```

5. Delta computation between daily runs produces change reports compatible with the agency's existing alerting workflow.

**Operational independence:**

6. The agency operates EXPOSE without vendor involvement. Historical artifacts remain in the agency's own storage regardless of any future vendor relationship. When the commercial managed-service offering achieves FedRAMP Moderate authorization, the agency can migrate or continue self-hosting -- the artifact format is identical either way.

**Features used:** Helm chart (NetworkPolicy + PodSecurity hardened), FIPS 140-3 cryptography, NIST 800-53 control mapping, AU-family audit logging, cosign artifact signing with SLSA provenance, CDM-compatible JSON output, local Ollama LLM (air-gap compatible), egress allowlist, content-addressed evidence storage, stable JSON schema contract.

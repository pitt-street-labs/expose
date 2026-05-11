# EXPOSE Example Outputs

Example output artifacts from an EXPOSE scan of `acme-corp.com`. These files
represent the actual data structures produced by the EXPOSE pipeline and API.

All examples use the same fictional tenant (`Acme Corp`, tenant ID
`f47ac10b-58cc-4372-a567-0e02b2c3d479`) and a single scan run to maintain
consistency across artifacts.

## Files

| File | Description | Schema Source |
|------|-------------|---------------|
| `scan-report-example.json` | Full canonical artifact with 18 entities, attribution tiers, exposure data, tech stack, cloud resources, lead scores, provenance chains, collector health, and delta tracking | `schemas/canonical-artifact-v1.json` / `src/expose/types/canonical.py` |
| `findings-example.json` | Top 10 prioritized findings sorted by risk score (92 to 12), with signal breakdowns and justifications | `src/expose/api/findings.py` |
| `provenance-example.json` | Complete provenance chain for `staging.acme-corp.com` -- 4 collector observations, 2 rule applications, 3 entity relationships | `src/expose/api/provenance.py` |
| `graph-example.json` | Entity relationship graph with 12 nodes and 15 edges for D3 force-directed rendering | `src/expose/api/graph.py` |
| `audit-log-example.jsonl` | 8 NIST AU-2/AU-3 compliant audit entries (NDJSON) covering the full run lifecycle | `src/expose/observability/audit_schema.py` |
| `eval-report-example.json` | Eval harness output with 4 dataset categories, per-category P/R/F1, confusion matrix, 87% overall accuracy | `src/expose/eval/runner.py` |
| `siem-splunk-example.json` | 3 Splunk HEC events demonstrating CIM field mapping for DNS, Network Traffic, and Finding sourcetypes | `src/expose/integrations/splunk.py` |

## Scan Report Entity Breakdown

The `scan-report-example.json` artifact contains 18 entities with the following
attribution distribution:

| Attribution Tier | Count | Examples |
|------------------|-------|----------|
| Confirmed | 5 | `acme-corp.com`, `staging.acme-corp.com`, `admin.acme-corp.com`, `api.acme-corp.com`, `www.acme-corp.com` |
| High | 4 | `203.0.113.10`, `203.0.113.42`, `mail.acme-corp.com`, `vpn.acme-corp.com` |
| Medium | 3 | `dev.acme-corp.com`, `blog.acme-corp.com`, `status.acme-corp.com` |
| Requires Review | 6 | `198.51.100.25`, `203.0.113.50`, `arn:aws:s3:::acme-corp-public-assets`, `ns1.acmedns.net`, `ns2.acmedns.net`, `198.51.100.7` |

## Findings Priority Breakdown

| Tier | Score Range | Count |
|------|-------------|-------|
| Critical | 85-92 | 2 |
| High | 63-74 | 3 |
| Medium | 41-48 | 2 |
| Low | 12-28 | 3 |

## Usage

These files can be used for:

- **UI development** -- load as mock API responses for frontend work
- **Integration testing** -- validate parsers and consumers against realistic data
- **Documentation** -- reference in user guides and API documentation
- **Sales demos** -- show realistic output without running live scans
- **SIEM validation** -- test Splunk/Sentinel/Chronicle ingestion pipelines

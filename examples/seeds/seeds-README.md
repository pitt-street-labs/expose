# Example seeds — when to use each

This directory contains four example seed files for distinct deployment scenarios. Drop the contents of one into the `seeds:` block of your `tenant-config.yaml` (copied from `examples/tenant-config.yaml.template`) and edit values for your environment.

Seeds bootstrap the seed-expansion stage (`docs/SPEC.md` §2.2 Stage 1). They are the entry points the engine uses to discover the rest of your external surface; they are not the entire surface itself. More seeds = more recall, more cost, more incidental data. Choose the smallest seed set that anchors discovery in your real organizational footprint.

## When to use which

| Example file | Use when you are... | Pair with scope |
|--------------|---------------------|-----------------|
| `acme-corporate.yaml` | A Fortune-500-style enterprise with multiple apex domains, multiple cloud accounts across providers, brand variants in WHOIS, possibly an acquired-entity inheritance footprint. | `examples/scope/medium-default.yaml` |
| `municipal-agency.yaml` | A small municipal IT shop, one primary domain, mostly vendor-hosted services, a small directly-managed cloud footprint. | `examples/scope/medium-default.yaml` or `hard-mode-regulated.yaml` |
| `consulting-engagement.yaml` | A boutique red team running a per-client engagement tenant with a scope contract you must defend in client review. | `examples/scope/hard-mode-regulated.yaml` |
| `research-test-bed.yaml` | A researcher evaluating attribution methodology against operator-owned synthetic targets and publishing reproducible datasets. | `examples/scope/soft-mode-research.yaml` |

## Seed type reference

The three seed types in v1:

| Type | Purpose | Notes |
|------|---------|-------|
| `domain` | Apex domain entry point | Subdomains under it are discovered; do not seed individual subdomains unless you are scope-restricted. |
| `organization` | Free-text registrant string for WHOIS / RDAP pivots | List legal-entity name variants; WHOIS data is inconsistent across registrars. |
| `cloud_account` | AWS account ID, Azure subscription ID, GCP project ID | Cloud-account-authoritative observations are the strongest attribution signal in the engine. |

## What seeds are not

- **Not a complete surface inventory.** The engine discovers from seeds; it does not require you to list every asset.
- **Not unauthorized reconnaissance fuel.** Never seed third-party organizations under a "what would EXPOSE do?" pretext. Authorization scope (`examples/scope/`) plus seeds together define what you are authorized to attribute.
- **Not where to put one-off subdomains you want included.** Use the apex domain seed; the discovery stage finds subdomains. If you must constrain to a specific subdomain (rare), use the scope's `apex_domains` list and `exclusions` together.

## See also

- `examples/tenant-config.yaml.template` — the full tenant-config schema with seeds embedded.
- `examples/scope/` — example authorization-scope shapes for the matching scenarios.
- `docs/operator-quickstart.md` — operator quickstart with seed configuration in context.
- `docs/SPEC.md` §2.2 — seed-expansion stage in the pipeline.
- `docs/adr/ADR-008-authorized-use-and-ethics.md` — the relationship between seeds, scope, and authorization.

# Example authorization-scope shapes — when to use each enforcement mode

This directory contains three example scope files, one per supported enforcement mode. Drop the contents of one into the `authorization_scope:` block of your `tenant-config.yaml` (copied from `examples/tenant-config.yaml.template`) and edit values for your environment.

Authorization scope is the operator's declared boundary of what EXPOSE may attribute to this tenant. It is the central mechanism behind the project's authorized-use posture (see `docs/adr/ADR-008-authorized-use-and-ethics.md`). Choosing the right enforcement mode is a decision you make per tenant; getting it right is more important than getting any other configuration field right.

## Enforcement-mode summary

| Mode | Behavior | Use when |
|------|----------|----------|
| **`soft`** | Scope mismatches logged to audit log only. No artifact annotations. Active probing is not scope-gated (still attribution-tier-gated). | Research / methodology scenarios with operator-owned synthetic targets, internal evaluation against your own infrastructure. |
| **`medium`** | Scope mismatches flagged in `outside_authorized_scope_summary` (top-level) and `outside_authorized_scope` review reason (per-target). No blocking. | **v1 default. Recommended starting posture for most defensive CTEM deployments.** |
| **`hard`** | Active probing refuses out-of-scope assets unless they are `confirmed`/`high` tier. Passive collection remains broad. Refusals are recorded in `collector_health`. | Regulated-industry deployments, scope-contracted engagements, demonstrable-scope-discipline reference deployments. |

## When to use which

| Example file | Use when you are running... | Pair with seeds |
|--------------|-----------------------------|-----------------|
| `medium-default.yaml` | A typical enterprise / municipal / corporate CTEM tenant. The vast majority of deployments. | `examples/seeds/acme-corporate.yaml` or `municipal-agency.yaml` |
| `hard-mode-regulated.yaml` | A scope-contracted engagement (boutique red team), a regulated-industry deployment (financial / healthcare / defense), or any deployment where you must demonstrate active-probing scope discipline. | `examples/seeds/consulting-engagement.yaml` |
| `soft-mode-research.yaml` | A research scenario with operator-owned synthetic targets, where artifact-level scope annotations would interfere with the dataset under study. | `examples/seeds/research-test-bed.yaml` |

## What every scope shape contains

| Field | Purpose |
|-------|---------|
| `enforcement_mode` | One of `soft`, `medium`, `hard`. |
| `apex_domains` | The apex domains you authorize attribution for. Subdomains inherit. |
| `cloud_accounts` | Provider + account/subscription/project IDs. The strongest attribution signal in the engine. |
| `registrant_patterns` | Free-text patterns matched against WHOIS/RDAP registrant fields. Use legal-entity-name variants. |
| `asn_ranges` | ASNs you own/operate. Empty for cloud-only orgs. |
| `exclusions` | Specific assets that look like they should be in scope but are not yours. Override broader inclusion. |

## What scope is not

- **Not a substitute for the seeds list.** Seeds bootstrap discovery; scope authorizes attribution. They overlap but they do different things — see `examples/seeds/seeds-README.md`.
- **Not a vulnerability scope.** EXPOSE produces leads, not vulnerabilities; "scope" here is which assets the engine may attribute to you, not which assets a downstream scanner should test.
- **Not the only mechanism preventing misuse.** Hard mode is the strongest in-engine enforcement, but the project cannot prevent misuse by an operator with administrative control. ETHICS.md frames intent; scope mode shapes runtime behavior.

## Migration between modes

| From | To | Effect on next run |
|------|-----|--------------------|
| `medium` → `hard` | Recommended after a clean review showing zero unexpected scope warnings | Active probing refuses out-of-scope; previously-probed-but-out-of-scope assets stop being actively probed (passive collection continues) |
| `hard` → `medium` | After review tightens the scope contract enough that hard refusals become rare | Active probing resumes for previously-refused targets; review `outside_authorized_scope_summary` carefully |
| `medium` → `soft` | Only for research; rarely correct otherwise | Per-target scope annotations stop appearing; downstream consumers lose the per-target signal |
| `soft` → `medium` or `hard` | Anytime you graduate research into operational use | Artifact gains scope annotations; review and adjust scope before downstream consumers see the change |

Scope changes appear in the artifact's `scope_version` field (per `schemas/canonical-artifact-v1.json`) and produce structured `removed` deltas with reason `scope_changed_now_outside` for assets newly excluded.

## See also

- `examples/tenant-config.yaml.template` — the full tenant-config schema with scope embedded.
- `examples/seeds/` — example seed shapes for the matching scenarios.
- `docs/operator-quickstart.md` §6 "Update tenant authorization scope" — operations runbook for scope changes.
- `docs/adr/ADR-008-authorized-use-and-ethics.md` §"Layer 2" — the design rationale behind the three modes.
- `docs/SPEC.md` §10.1 — the formal scope schema.

# FatFinger6000

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status: Pre-release](https://img.shields.io/badge/status-pre--release-yellow.svg)](#status)

Continuous external attack surface intelligence pipeline. Produces signed JSON artifacts suitable for downstream Continuous Threat Exposure Management (CTEM) workflows and red team lead review.

**Status:** Pre-release. Specification complete (see [`docs/SPEC.md`](docs/SPEC.md)). Phase 1 implementation in progress. Not yet recommended for production use.

## What it does

Bootstraps from minimal seeds — organization name, brand strings, known apex domains — and progressively expands the attributed external attack surface through public data sources (Certificate Transparency logs, passive DNS, ASN/BGP data, internet-wide scan datasets, cloud provider IP range manifests). Produces:

- A canonical, attributable, well-typed JSON record per discovered target.
- Full provenance — every claim traceable to the collector, observation, and rule that produced it.
- Attribution confidence tiers (`confirmed`, `high`, `medium`, `requires_review`) so consumers can filter by trust level.
- Tech-stack fingerprinting and exposure indicators contributing to a numeric lead score.
- Deterministic generation — reproducibility from inputs.
- Cosign-signed integrity for offline verification by downstream consumers.

## Intended use

FatFinger6000 is designed for:

- **Defensive CTEM workflows** — security teams mapping their own organization's external surface for prioritization and response.
- **Authorized red team operations** — supporting engagements with explicit scope contracts.
- **Own-perimeter mapping** — internal security operations within organizations the operator works for or with explicit authorization.

It is **not** designed for and **not intended to be used for**:

- Active exploitation, vulnerability validation, or post-discovery offensive action.
- Adversarial reconnaissance against third parties without authorization.
- PII enrichment beyond public records.
- Open-ended narrative reasoning, exploit hypothesis generation, or red team briefing prose (these belong in a separate downstream environment).

See [`ETHICS.md`](ETHICS.md) for the full intended-use posture.

## Two-environment model

FatFinger6000 is **Environment 1** in a deliberate two-environment design:

- **Environment 1 (this codebase)** — deterministic discovery and bounded structured-output enrichment. Produces signed JSON artifacts.
- **Environment 2 (separate, downstream)** — open-ended LLM-driven narrative analysis, possibly using high-capability models under appropriate safeguards. Out of scope for this codebase.

Artifacts cross from Environment 1 to Environment 2 via manual transfer with cosign signature verification. This separation keeps Environment 1's safety properties simple to audit and isolates concerns appropriately.

## Architecture overview

```
seeds (operator)
    ↓
[Stage 1: Seed Expansion]                 deterministic, no LLM
    ↓
seed graph
    ↓
[Stage 2: Collection]                     passive + active
    ↓
raw observations
    ↓
[Stage 3: Sanitization & Normalization]   trust boundary
    ↓
observation graph (canonical)
    ↓
[Stage 4a: Rule-Based Attribution]        deterministic
    ↓
attributed candidates
    ↓
[Stage 4b: LLM Enrichment]                bounded structured-output
    ↓
enriched candidates
    ↓
[Stage 5: Artifact Generation]            canonical.json.gz + sig + manifest
```

See [`docs/SPEC.md`](docs/SPEC.md) for the full architecture.

## Documentation

- **[`docs/SPEC.md`](docs/SPEC.md)** — Full specification (architecture, threat model, observation graph, collectors, attribution engine, LLM integration, artifact format).
- **[`docs/adr/`](docs/adr/)** — Architecture Decision Records for the eight foundational design decisions.
- **[`docs/issues-backlog.md`](docs/issues-backlog.md)** — Consolidated deferred-issue backlog organized by epic.
- **[`docs/glossary.md`](docs/glossary.md)** — Term definitions.
- **[`schemas/`](schemas/)** — JSON Schema files (canonical artifact, manifest, rule pack).
- **[`examples/rulepacks/`](examples/rulepacks/)** — Example rule packs.
- **[`SECURITY.md`](SECURITY.md)** — Security disclosure policy.
- **[`ETHICS.md`](ETHICS.md)** — Intended use, non-goals, ethics posture.
- **[`CONTRIBUTING.md`](CONTRIBUTING.md)** — Contribution guidelines (DCO required).
- **[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)** — Contributor Covenant 2.1.

## Getting started

> **Pre-release:** the deployment instructions below describe the target user experience for v1 GA. Implementation is in Phase 1; not all components are functional yet.

```bash
# Clone the repository
git clone https://github.com/korlogos/fatfinger6000.git
cd fatfinger6000

# Configure your tenant (see docs/SPEC.md §10.1)
cp examples/tenant-config.yaml.template tenant-config.yaml
# Edit tenant-config.yaml with your seeds, scope, collector credentials

# Deploy via Helm chart (k3s lab deployment)
helm install fatfinger6000 ./deploy/helm-chart \
    --values tenant-config.yaml \
    --namespace fatfinger6000 --create-namespace

# Trigger a manual run
kubectl exec -n fatfinger6000 deploy/fatfinger6000-control-plane -- \
    fatfinger6000 run trigger --tenant default

# Retrieve the artifact (lab deployment)
kubectl exec -n fatfinger6000 deploy/fatfinger6000-control-plane -- \
    fatfinger6000 artifact list --tenant default

# Verify the artifact signature
cosign verify-blob --signature canonical.json.gz.sig canonical.json.gz \
    --certificate-identity-regexp '^https://github.com/korlogos/fatfinger6000/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Project structure

```
fatfinger6000/
├── docs/
│   ├── SPEC.md              # Main specification
│   ├── adr/                 # Architecture Decision Records
│   ├── issues-backlog.md    # Deferred issues by epic
│   └── glossary.md          # Term definitions
├── schemas/
│   ├── canonical-artifact-v1.json
│   ├── manifest-v1.json
│   └── rulepack-v1.json
├── examples/
│   └── rulepacks/           # Example rule packs
├── src/                     # Engine source code (in progress)
├── deploy/
│   └── helm-chart/          # Helm chart for Kubernetes deployment
├── tests/                   # Test suites
├── README.md
├── LICENSE                  # Apache 2.0
├── SECURITY.md
├── ETHICS.md
├── CONTRIBUTING.md
└── CODE_OF_CONDUCT.md
```

## Contributing

Contributions are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines. All commits require Developer Certificate of Origin sign-off (`Signed-off-by:` line in commits, enforced by DCO bot).

## License

Apache License 2.0. See [`LICENSE`](LICENSE) for full text.

The engine is open source. Client-specific rule packs and engagement-specific intelligence may live in separate private repositories under different terms.

## Maintainers

[Korlogos](https://korlogos.com) / [Pitt Street Labs](https://pittstreetlabs.com)

## Acknowledgements

FatFinger6000 builds on the work of:

- The [Sigstore](https://www.sigstore.dev/) project (cosign, Rekor, Fulcio).
- The [OpenTelemetry](https://opentelemetry.io/) project.
- The Certificate Transparency operators and contributors.
- The countless security researchers and tool authors whose work makes EASM tractable.

Project name: deliberate counterpoint to high-capability LLM frontier work — this codebase is the deterministic, dependable, boring substrate.

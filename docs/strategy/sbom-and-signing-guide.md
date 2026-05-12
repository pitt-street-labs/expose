# SBOM Generation and Container Image Signing Guide

> **Advisory -- not locked.** This document captures supply-chain security
> practices for EXPOSE container images. It is not part of the locked
> specification set (SPEC.md, ADRs, schemas). Updates do not require a
> dedicated session.

## 1. Why SBOM Matters for an EASI Platform

An External Attack Surface Intelligence platform inspects the supply chains
and exposed surfaces of its customers. It must hold itself to at least the
same standard it evaluates in others. A Software Bill of Materials (SBOM)
fulfills three obligations:

**Supply-chain integrity.** EXPOSE runs collectors that reach out to
third-party APIs, DNS resolvers, and certificate transparency logs. Every
dependency bundled into the container image is an attack surface. An SBOM
makes that surface enumerable and auditable.

**Regulatory alignment.** Executive Order 14028 (May 2021) requires SBOM
delivery for software sold to the US Government. FedRAMP Rev 5 maps this
requirement to SA-12 (Supply Chain Protection) and SI-7 (Software,
Firmware, and Information Integrity). NIST SP 800-218 (SSDF) tasks PW.4.1
and PW.4.4 require machine-readable dependency inventories.

**Vulnerability response.** When a new CVE drops in a transitive dependency
(e.g., a vulnerability in `cryptography` or `asyncpg`), an SBOM lets
operators instantly answer "are we affected?" without rebuilding the image
or inspecting the filesystem.

## 2. SBOM Generation with Syft

[Syft](https://github.com/anchore/syft) is the SBOM generator selected for
EXPOSE. It supports OCI images, filesystem paths, and archive files, and
emits both CycloneDX and SPDX formats.

### Installation

```bash
# Homebrew (macOS/Linux)
brew install syft

# Binary release (Linux amd64)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

### Generating SBOMs

The repository includes a convenience script at `scripts/generate-sbom.sh`:

```bash
# Default output directory: ./sbom/
./scripts/generate-sbom.sh expose:dev

# Custom output directory
./scripts/generate-sbom.sh ghcr.io/pitt-street-labs/expose:v1.0.0 dist/sbom
```

This produces two files:

| File | Format | Primary consumers |
|------|--------|-------------------|
| `expose-sbom.cdx.json` | CycloneDX 1.5 (JSON) | Dependency-Track, Grype, security scanners |
| `expose-sbom.spdx.json` | SPDX 2.3 (JSON) | Compliance tools, NTIA minimum-elements checkers |

**CycloneDX** is the preferred format for operational security tooling
because of its richer vulnerability-correlation metadata and native support
in Grype and Dependency-Track. **SPDX** is produced in parallel for
compliance scenarios where SPDX is the mandated format (e.g., certain
FedRAMP assessor requirements).

### Manual generation (without the script)

```bash
# CycloneDX
syft ghcr.io/pitt-street-labs/expose:v1.0.0 -o cyclonedx-json > expose-sbom.cdx.json

# SPDX
syft ghcr.io/pitt-street-labs/expose:v1.0.0 -o spdx-json > expose-sbom.spdx.json

# Human-readable table (quick inspection)
syft ghcr.io/pitt-street-labs/expose:v1.0.0 -o table
```

### What Syft captures from the EXPOSE image

The EXPOSE Dockerfile uses a multi-stage build (Python slim-bookworm base).
Syft catalogs:

- **Python packages** installed via uv into `/opt/venv` (including
  transitive dependencies)
- **Debian packages** from the `slim-bookworm` base layer (`libpq5`,
  `libssl3`, `ca-certificates`, `tini`)
- **OS-level metadata** (distro, kernel compatibility)

Because the builder stage is discarded, the runtime SBOM contains only the
packages actually shipped -- build-time dependencies (`build-essential`,
`libpq-dev`, `libssl-dev`) are excluded.

## 3. Container Image Signing with Cosign

Container signing ensures that the image a consumer pulls is the exact
image produced by the EXPOSE CI pipeline, not a tampered substitute.
EXPOSE uses [cosign](https://docs.sigstore.dev/cosign/overview/) from the
Sigstore project.

Full keypair setup instructions are in
[`deploy/cosign-keypair-setup.md`](../../deploy/cosign-keypair-setup.md).
This section summarizes the two signing modes.

### 3.1 Keypair mode (lab and pre-production)

Generate a keypair:

```bash
cosign generate-key-pair
```

Sign after build:

```bash
cosign sign --yes --key cosign.key ghcr.io/pitt-street-labs/expose:v1.0.0
```

Verify:

```bash
cosign verify --key cosign.pub ghcr.io/pitt-street-labs/expose:v1.0.0
```

The private key (`cosign.key`) is stored in the CI secret store, never in
source control. The public key (`cosign.pub`) is distributed with release
artifacts and committed to `deploy/`.

### 3.2 Keyless OIDC mode (production)

For production releases from GitHub Actions, cosign supports keyless
signing via Sigstore's Fulcio CA and Rekor transparency log:

```bash
cosign sign --yes ghcr.io/pitt-street-labs/expose:v1.0.0
```

In this mode:

- **Fulcio** issues a short-lived X.509 certificate bound to the GitHub
  Actions OIDC identity (repository, workflow, commit SHA).
- **Rekor** records the signature in an immutable transparency log, giving
  consumers a tamper-evident audit trail.
- Consumers verify with identity constraints instead of a public key file:

```bash
cosign verify \
  --certificate-identity-regexp "https://github.com/pitt-street-labs/expose/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/pitt-street-labs/expose:v1.0.0
```

Keyless signing is the target posture per ADR-004. It eliminates private
key management and binds every signature to a specific CI run, making
compromise of a single key insufficient to forge signatures.

## 4. SLSA Provenance

[SLSA](https://slsa.dev/) (Supply-chain Levels for Software Artifacts) is
a framework for evaluating build integrity. EXPOSE targets **SLSA Level 2**
for initial releases, with a path to Level 3.

### SLSA Level requirements

| Level | Requirement | EXPOSE status |
|-------|-------------|---------------|
| L1 | Build process is documented | Yes -- Dockerfile + CI workflow |
| L2 | Build service generates signed provenance | Target -- via `slsa-github-generator` |
| L3 | Build service is hardened (isolated, ephemeral) | Future -- requires GitHub-hosted or hardened runners |

### Generating provenance attestations

The
[slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator)
project provides reusable GitHub Actions workflows that produce SLSA
provenance attestations. For container images:

```yaml
# Provenance generation (runs after container-build)
- uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.1.0
  with:
    image: ghcr.io/pitt-street-labs/expose
    digest: ${{ steps.build.outputs.digest }}
  permissions:
    id-token: write
    contents: read
    actions: read
    packages: write
```

The provenance attestation is stored as an OCI artifact in the registry,
alongside the image and its cosign signature. It records:

- **Builder identity** (GitHub Actions, workflow file, runner environment)
- **Source reference** (repository, commit SHA, branch)
- **Build recipe** (Dockerfile path, build arguments, platform list)
- **Materials** (base image digest, dependency lock file hashes)

### Verifying provenance

Consumers verify provenance with the `slsa-verifier` CLI:

```bash
slsa-verifier verify-image \
  --source-uri github.com/pitt-street-labs/expose \
  --source-tag v1.0.0 \
  ghcr.io/pitt-street-labs/expose:v1.0.0
```

This checks that the image was built by the expected repository's CI
pipeline and has not been modified after build.

## 5. Verification Workflow

A consumer deploying an EXPOSE image should verify three things before
running it. Each check is independent and exits non-zero on failure.

### Step 1: Verify the image signature

```bash
# Keypair mode
cosign verify --key cosign.pub ghcr.io/pitt-street-labs/expose:v1.0.0

# Keyless mode
cosign verify \
  --certificate-identity-regexp "https://github.com/pitt-street-labs/expose/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/pitt-street-labs/expose:v1.0.0
```

**What this proves:** The image was signed by a holder of the EXPOSE
signing key (keypair mode) or by a GitHub Actions workflow in the
`pitt-street-labs/expose` repository (keyless mode).

### Step 2: Retrieve and inspect the SBOM

```bash
# Download the attached SBOM
cosign download sbom ghcr.io/pitt-street-labs/expose:v1.0.0 > expose-sbom.cdx.json

# Scan for known vulnerabilities
grype sbom:expose-sbom.cdx.json
```

**What this proves:** The image's dependency inventory is known, and each
component can be checked against vulnerability databases (NVD, OSV, GitHub
Advisory).

### Step 3: Verify SLSA provenance (when available)

```bash
slsa-verifier verify-image \
  --source-uri github.com/pitt-street-labs/expose \
  ghcr.io/pitt-street-labs/expose:v1.0.0
```

**What this proves:** The image was built by the expected CI pipeline from
the expected source repository, using an ephemeral build environment.

### Automated policy enforcement

For Kubernetes deployments, these checks can be enforced at admission time
using policy engines:

| Engine | What it enforces |
|--------|------------------|
| [Kyverno](https://kyverno.io/) | cosign signature verification, SBOM presence, image source |
| [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/) | Custom Rego policies for provenance and signature checks |
| [Sigstore Policy Controller](https://docs.sigstore.dev/policy-controller/overview/) | Native cosign verification as a Kubernetes admission webhook |

## 6. CI Integration Plan

The following steps show where SBOM generation, signing, and provenance
attestation fit into the existing `.github/workflows/ci.yml` pipeline.
These are documented here for planning -- the CI workflow itself is not
modified by this guide.

### Proposed additions to the `container-build` job

The `container-build` job already has the required permissions
(`id-token: write`, `packages: write`) and builds multi-arch images via
`docker/build-push-action`.

```yaml
# --- After the existing build-push-action step ---

# 1. Install supply-chain tools
- name: Install cosign
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  uses: sigstore/cosign-installer@v3

- name: Install syft
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  uses: anchore/sbom-action/download-syft@v0

# 2. Sign the image (keyless via GitHub OIDC)
- name: Sign container image
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  run: cosign sign --yes ghcr.io/pitt-street-labs/expose:${{ github.sha }}

# 3. Generate and attach SBOM
- name: Generate SBOM
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  run: |
    syft ghcr.io/pitt-street-labs/expose:${{ github.sha }} -o cyclonedx-json > expose-sbom.cdx.json
    cosign attach sbom --sbom expose-sbom.cdx.json ghcr.io/pitt-street-labs/expose:${{ github.sha }}

# 4. Upload SBOM as build artifact
- name: Upload SBOM artifact
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: expose-sbom.cdx.json
    retention-days: 90
```

### Proposed separate job for SLSA provenance

SLSA provenance generation uses a reusable workflow and runs as an
independent job after `container-build`:

```yaml
provenance:
  needs: [container-build]
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  permissions:
    id-token: write
    contents: read
    actions: read
    packages: write
  uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.1.0
  with:
    image: ghcr.io/pitt-street-labs/expose
    digest: ${{ needs.container-build.outputs.digest }}
```

### Gating logic

These steps only run on pushes to `main` (not on PRs), matching the
existing `container-build` behavior where PR builds verify buildability
with `push: false`. This ensures:

- PR builds are fast (no signing/SBOM overhead).
- Only images that pass all CI gates (lint, test, schema-sync, fips-gate,
  helm-lint) reach the signing step.
- Signing keys and OIDC tokens are never exposed to PR workflows from
  forks.

## 7. FedRAMP Alignment

SBOM generation and container signing directly satisfy several FedRAMP Rev
5 controls. The following table maps each practice to its controlling
requirement.

| FedRAMP Control | Title | How EXPOSE satisfies it |
|-----------------|-------|------------------------|
| **SA-12** | Supply Chain Protection | SBOM enumerates all components in the delivered image. CycloneDX + SPDX formats meet NTIA minimum elements. |
| **SA-12(1)** | Acquisition Strategies, Tools, and Methods | Syft is run in CI on every release build. SBOM is attached to the image as an OCI artifact for automated retrieval. |
| **SI-7** | Software, Firmware, and Information Integrity | Cosign signatures (keyless via Fulcio + Rekor) provide cryptographic proof that the image has not been modified after build. |
| **SI-7(1)** | Integrity Checks | Consumers run `cosign verify` before deployment. Kubernetes admission controllers (Kyverno, Sigstore Policy Controller) automate this check. |
| **SI-7(6)** | Cryptographic Protection | Cosign uses Sigstore's Fulcio CA for certificate issuance and Rekor for transparency logging. Keypair mode uses standard ECDSA P-256 keys. |
| **SI-7(15)** | Code Authentication | SLSA provenance attestations bind the image to a specific CI build from a specific source commit. `slsa-verifier` validates the chain. |
| **CM-7** | Least Functionality | The multi-stage Dockerfile discards build tools. The runtime image contains only the Python venv, application code, and minimal OS packages. SBOM makes this verifiable. |
| **CM-14** | Signed Components | All release images are signed before registry publication. Unsigned images are rejected by admission policy. |
| **AU-10** | Non-repudiation | Rekor transparency log entries provide tamper-evident, timestamped records of every signing event. Entries cannot be deleted or modified. |

### NIST SP 800-218 (SSDF) alignment

| SSDF Task | Description | EXPOSE practice |
|-----------|-------------|-----------------|
| **PW.4.1** | Acquire well-secured software components | SBOM enumerates all acquired components; Grype scans for known vulnerabilities. |
| **PW.4.4** | Verify acquired components have not been tampered with | Cosign signature verification on base images and dependencies. |
| **PS.3.1** | Archive and protect each software release | SBOM artifacts are stored in the OCI registry alongside the image with 90-day CI artifact retention. |
| **RV.1.1** | Identify vulnerabilities on an ongoing basis | SBOM enables continuous monitoring via Dependency-Track or `grype sbom:` scans. |

### EO 14028 compliance

Executive Order 14028 Section 4(e) requires SBOM delivery for all software
sold to the US Government. EXPOSE satisfies this by:

1. Generating SBOMs in both NTIA-recommended formats (CycloneDX, SPDX)
   with every release build.
2. Attaching the SBOM to the container image as an OCI artifact, making it
   retrievable via `cosign download sbom` without out-of-band distribution.
3. Including sufficient metadata to meet the NTIA "minimum elements for an
   SBOM": supplier name, component name, version, unique identifier,
   dependency relationships, author, and timestamp.

## Appendix A: Tool Version Matrix

| Tool | Minimum version | Purpose |
|------|-----------------|---------|
| [syft](https://github.com/anchore/syft) | v1.0.0 | SBOM generation (CycloneDX + SPDX) |
| [cosign](https://docs.sigstore.dev/cosign/overview/) | v2.0.0 | Image signing, SBOM attachment, verification |
| [grype](https://github.com/anchore/grype) | v0.79.0 | Vulnerability scanning against SBOMs |
| [slsa-verifier](https://github.com/slsa-framework/slsa-verifier) | v2.6.0 | SLSA provenance verification |
| [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator) | v2.1.0 | SLSA provenance attestation (CI reusable workflow) |

## Appendix B: Related Documents

- [`deploy/cosign-keypair-setup.md`](../../deploy/cosign-keypair-setup.md) --
  Detailed keypair generation and CI integration for cosign
- [`docs/SPEC.md`](../SPEC.md) Section 9 -- Security requirements
  (container hardening, signing, provenance)
- [ADR-004](../adr/ADR-004-multi-arch-container-builds.md) -- Multi-arch
  container build and signing decisions
- [`docs/strategy/sdlp.md`](sdlp.md) -- Secure Development Lifecycle
  Plan (covers SBOM as a release gate)

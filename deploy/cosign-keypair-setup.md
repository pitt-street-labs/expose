# Cosign Keypair Setup for EXPOSE Container Images

## Purpose

EXPOSE container images are signed with [cosign](https://docs.sigstore.dev/cosign/overview/)
to provide supply-chain integrity verification. Consumers can verify that a
pulled image was built by the EXPOSE CI pipeline and has not been tampered with
in transit or at rest.

Per ADR-004, production deployments use cosign keyless signing via GitHub Actions
OIDC. Internal or air-gapped lab deployments may run **unsigned** -- the Helm
chart's `image.verify` defaults to `false` and no signing infrastructure is
required for internal use.

This document covers keypair-based signing for environments that need image
verification but cannot use the keyless (OIDC) flow.

## Prerequisites

- **cosign** v2.x+ installed ([install guide](https://docs.sigstore.dev/cosign/system_config/installation/))
- Push access to the target container registry (e.g., `ghcr.io/korlogos`)
- A secure location for the private key (CI secret store or hardware token)

## Keypair Generation

Generate a password-protected keypair:

```bash
cosign generate-key-pair
```

This produces two files in the current directory:

| File | Purpose | Storage |
|------|---------|---------|
| `cosign.key` | Private key (encrypted with the password you provide) | CI secret store -- never commit to source control |
| `cosign.pub` | Public key (safe to distribute) | Commit to `deploy/` or publish alongside release artifacts |

Store the private key password in the same secret store as the key itself,
under a separate secret name (e.g., `COSIGN_PASSWORD`).

## Signing a Built Image

After a multi-arch build pushes a manifest to the registry:

```bash
cosign sign --key cosign.key ghcr.io/pitt-street-labs/expose:v1.0.0
```

cosign prompts for the private key password (or reads it from the
`COSIGN_PASSWORD` environment variable). The signature is stored as an OCI
artifact alongside the image in the registry -- no separate signature file
hosting is needed.

For multi-arch manifests, cosign signs the manifest list. All architecture
variants are covered by a single signature.

## Verification

Verify a signed image before deployment:

```bash
cosign verify --key cosign.pub ghcr.io/pitt-street-labs/expose:v1.0.0
```

A successful verification prints the signature payload and exits 0. A failed
verification exits non-zero -- the image should not be deployed.

To verify and display certificate/annotation details:

```bash
cosign verify --key cosign.pub ghcr.io/pitt-street-labs/expose:v1.0.0 | jq .
```

## CI Integration (GitHub Actions)

Add cosign signing as a post-build step in `.github/workflows/ci.yml`. The
`container-build` job already has the required permissions (`id-token: write`,
`packages: write`).

### Required secrets

| Secret | Value |
|--------|-------|
| `COSIGN_PRIVATE_KEY` | Contents of `cosign.key` |
| `COSIGN_PASSWORD` | Password used during `cosign generate-key-pair` |

### Workflow step (keypair mode)

Add after the `docker/build-push-action` step, gated on push-to-main:

```yaml
- name: Sign container image
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  uses: sigstore/cosign-installer@v3
- run: cosign sign --yes --key env://COSIGN_PRIVATE_KEY ghcr.io/pitt-street-labs/expose:${{ github.sha }}
  env:
    COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
    COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}
```

The `--yes` flag skips the interactive confirmation prompt in CI.

## Keyless Signing (Production -- Deferred)

For production releases published from GitHub Actions, cosign supports
OIDC-based keyless signing via Sigstore's Fulcio CA and Rekor transparency log.
This eliminates private key management entirely:

```yaml
- name: Sign container image (keyless)
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  uses: sigstore/cosign-installer@v3
- run: cosign sign --yes ghcr.io/pitt-street-labs/expose:${{ github.sha }}
```

With keyless signing:

- **Fulcio** issues a short-lived certificate bound to the GitHub Actions OIDC
  identity (repo, workflow, commit SHA).
- **Rekor** records the signature in an append-only transparency log for
  tamper-evident audit history.
- Verification uses `cosign verify --certificate-identity` and
  `--certificate-oidc-issuer` instead of a public key file.

Keyless signing is the target posture per ADR-004 but is deferred to the
production-hardening epic. The keypair flow above covers pre-production
environments that need verification without Sigstore infrastructure
dependencies.

## Lab Policy

Internal or air-gapped lab deployments do **not** use cosign signing.
Per ADR-004:

- Lab images are built and consumed locally; the threat model does not include
  registry tampering.
- The Helm chart's default values set image verification to disabled.
- The CI workflow builds multi-arch images with `push: false` -- images are
  verified as buildable but not published or signed.

Signing is activated when images are pushed to a shared registry (GHCR, ECR,
ACR) where multiple consumers pull from a centralized source.

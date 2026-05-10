# EXPOSE — Secure Development Lifecycle Plan (SDLP)

**Status:** Advisory — not locked. Open for revision in subsequent sessions and 3PAO consultation. This document defines the engineering process the EXPOSE codebase commits to follow; specific tooling choices remain implementation-tunable as long as the control objectives in this document are preserved.
**Date:** 2026-05-10
**Author context:** AI-assisted synthesis grounded in the locked spec-phase artifacts and the Session E framework annotation. Touchstones (NIST SP 800-218 SSDF, SLSA, Microsoft SDL, OWASP SAMM) confirmed against May 2026 publisher state. Where SSDF v1.1 (final, Feb 2022) and SSDF v1.2 (NIST CSRC initial public draft, December 2025; comment period closed January 30 2026) differ, this document targets v1.1 for current conformance and tracks v1.2 as the forward target.
**Public name:** EXPOSE (selected 2026-05-10 in Session H) / **Internal codename:** FF6K
**Source files cited:** `docs/SPEC.md`, `docs/strategy/framework-annotation.md`, `docs/adr/ADR-001-implementation-language.md`, `docs/adr/ADR-003-deployment-posture.md`, `docs/adr/ADR-004-output-artifact.md`, `docs/adr/ADR-005-llm-integration.md`, `docs/adr/ADR-006-repository-and-licensing.md`, `docs/adr/ADR-007-multi-tenancy.md`, `docs/adr/ADR-008-authorized-use-and-ethics.md`, `docs/adr/ADR-010-fedramp-ready-posture.md`, `docs/issues-backlog.md`, `ETHICS.md`, `CONTRIBUTING.md`, `SECURITY.md`.

This is the engineering-process document for EXPOSE Core. It describes how the engine is built, reviewed, tested, signed, released, and maintained — not how it is deployed (Session G covers deployment integration) and not what it does (SPEC.md covers behavior). Treat the practices below as the project's contract with federal customers, contributors, and 3PAO assessors who will inspect the SDLC alongside the runtime.

---

## 1. Scope and goals

### 1.1 What this document does

This SDLP commits the EXPOSE Core open-source project (Apache 2.0 engine repository per ADR-006) to a defined set of secure-development practices. It is the artifact a federal-customer 3PAO inspects when answering NIST 800-53 SA-15 (Development Process, Standards, and Tools) and NIST 800-218 SSDF practice questions, and it is the artifact a contributor reads when joining the project.

The SDLP scope:

- The public engine repository (`expose`, Apache 2.0) and all artifacts it produces — source code, schemas, container images, Helm charts, SBOMs, signed artifacts, attestations.
- Engineering practices for Korlogos / Pitt Street Labs maintainers and external contributors operating against the public repo.
- The CI/CD pipeline that gates merges and produces release artifacts.

The SDLP does not commit to:

- Customer deployment posture (Session G — Federal Customer Deployment Guide).
- Internal Korlogos commercial-module repositories beyond the requirement that they inherit at minimum the practices defined here when they consume the engine (ADR-009 commercial structure).
- The private `expose-rulepacks` repository's content; rule packs are data, not engine code, and have their own lighter governance documented in their repository.

### 1.2 Goals

| Goal | Mechanism | Reference |
|---|---|---|
| Defensible federal-customer posture | FedRAMP-ready architectural enforcement at build time, control mapping in `framework-annotation.md`, evidence pipeline that produces 3PAO-inspectable artifacts | ADR-010, framework-annotation.md §5, §12 |
| Supply-chain integrity | Signed images and artifacts, SBOMs, build provenance attestations, reproducibility investments | ADR-010, framework-annotation.md §5.10 (SI-7), §5.9 (SA-12) |
| Reviewable change control | DCO sign-off, branch protection, automated checks, reviewer requirements | ADR-006, CONTRIBUTING.md |
| Cross-tenant safety | Cross-tenant isolation tests as CI gate (`epic:multi-tenancy` / "Cross-tenant isolation testing" v1 deliverable) | ADR-007, SPEC.md §4.3, issues-backlog.md |
| Adversarial-input safety | Sanitization-layer tests, prompt-injection eval datasets, structured-output schema enforcement | SPEC.md §3.1, §7, ETHICS.md §"Adversary-controlled inputs" |
| Open contribution | Apache 2.0, DCO, public ADRs, public issue tracker | ADR-006, CONTRIBUTING.md |

### 1.3 Touchstones

The SDLP draws from four widely-recognized references. Where they diverge, this document calls out which target is normative for EXPOSE.

| Reference | Version | Use |
|---|---|---|
| NIST SP 800-218 Secure Software Development Framework (SSDF) | v1.1 (February 2022 final), v1.2 draft (NIST CSRC initial public draft December 2025; public comment period closed January 30 2026) | Normative for current conformance at v1.1; SDLP tracks v1.2 finalization for next-cycle update. Mapped in §17. |
| SLSA (Supply-chain Levels for Software Artifacts) | v1.0 build track (slsa.dev/spec/v1.0/levels), with v1.1 / v1.2 specifications visible at slsa.dev | Build L2 attained at v1 with documented Build L3 target. Mapped in §17. |
| Microsoft Security Development Lifecycle (SDL) | Public practices; current Microsoft SDL guidance | Reference for threat-modeling cadence, secure-design review patterns, and developer-training intent. |
| OWASP Software Assurance Maturity Model (SAMM) | v2 | Reference for cross-domain maturity self-assessment; SDLP target is SAMM Level 2 across Governance, Design, Implementation, Verification, Operations. |

Citations for the above: NIST CSRC pages for SP 800-218 r1 IPD (2025-12) and SP 800-218 final (2022-02); SLSA v1.0 specification at slsa.dev/spec/v1.0; Microsoft SDL practices documented at the Microsoft Security Development Lifecycle public site; OWASP SAMM v2 at owaspsamm.org.

---

## 2. Threat-modeling cadence

EXPOSE has a documented threat model in `SPEC.md` §3, identifying six adversary classes and the explicit non-defenses. The SDLP commits the threat model to be a living document, not a one-time deliverable.

### 2.1 STRIDE workflow per major change

Every change classified as **major** triggers a STRIDE pass before merge. Major changes are:

- New collector module (any Tier 1, 2, or 3 collector — particularly Tier 3 active probing).
- New attribution rule predicate or rule-pack format change.
- New LLM provider implementation or change to `SafeLLMClient` enforcement logic.
- Schema change to canonical artifact, manifest, or rule pack (`schemas/*.json`).
- Trust-boundary modification (sanitization layer, evidence-store API, work-queue protocol).
- New external-API integration (secrets backend, object store, telemetry sink).
- Change to multi-tenancy enforcement (query middleware, tenant-context propagation).
- Change to authentication, authorization, or session-management code.

For each major change, the PR description must include a STRIDE analysis section with the following structure:

| STRIDE Category | Threat in Context of Change | Mitigation | Residual Risk |
|---|---|---|---|
| Spoofing | (e.g., adversary spoofs collector source) | (e.g., signed evidence with collector_id binding) | (low / accepted / tracked-as-issue) |
| Tampering | | | |
| Repudiation | | | |
| Information Disclosure | | | |
| Denial of Service | | | |
| Elevation of Privilege | | | |

Reviewers verify the STRIDE table is complete and the mitigations are reflected in the diff. Empty rows are acceptable when a category genuinely does not apply (annotated "N/A — rationale: ..."), but blank cells without justification block merge.

### 2.2 Whole-system threat-model review cadence

Beyond per-change STRIDE, the SPEC.md §3 system-level threat model is re-reviewed:

- **Quarterly** — synchronized with the ETHICS.md and SECURITY.md review cadence (ADR-006, ETHICS.md §"Maintenance and review"). Driven by the maintainer team.
- **On every new collector tier or new entity/edge type** — because expansion of the collected data changes the adversary's payload-injection surface (ETHICS.md §"Adversary-controlled inputs").
- **On every LLM provider addition** — because each new provider is a new trust relationship and may have different structured-output guarantees, latency profiles, or cost ceilings.
- **On every authorization-scope mode change** (soft / medium / hard per ADR-008) — because enforcement-mode changes the misuse-resistance posture.

Threat-model revisions are PRs against `SPEC.md` §3, reviewed under the same gates as code, and noted in release notes.

### 2.3 Adversarial dataset coupling

The threat model couples to two test artifacts:

- The sanitization-layer adversarial test fixtures in `tests/sanitization/adversarial/` — known prompt-injection payloads, control-character injection, encoding tricks. Per SPEC.md §7. Required: each STRIDE pass that touches sanitization must extend or revise these fixtures.
- The Phase 2 LLM eval harness's `adversarial_injection` dataset (Phase 2 deliverable per SPEC.md §11.2). Per AI RMF MEASURE 2.6 in framework-annotation.md §6.3.

When a new STRIDE-class threat is identified in a major change, the corresponding adversarial fixture or eval case is required as part of the PR.

---

## 3. Secure-coding standards

### 3.1 Language and idiom

Per ADR-001, the implementation language is Python. The SDLP commits to:

| Standard | Rule | Verification |
|---|---|---|
| **Python version** | 3.12 minimum (3.13 supported); single supported major version range stated in `pyproject.toml`. | CI matrix runs the supported range. |
| **Style** | PEP 8 enforced via `ruff format`. Code that fails `ruff format --check` does not merge. | CI gate. |
| **Linting** | `ruff check` configured with strict rule set (security-relevant rules `S`, bug-bear `B`, anti-pattern `PL`, modernization `UP`). | CI gate. |
| **Type checking** | `mypy --strict` over `src/`. No untyped public functions. No `# type: ignore` without inline comment justifying. | CI gate. |
| **Pydantic** | All cross-trust-boundary inputs and outputs are Pydantic v2 models with strict validation (`model_config = ConfigDict(strict=True, extra='forbid')`). Per ADR-001. | Code review + CI schema-sync gate. |
| **Async I/O** | All I/O is async (asyncio + httpx). No blocking I/O in request handlers or job workers. | Code review; ruff-async lint rules. |
| **Logging** | Structured logging via OpenTelemetry. No bare `print()`. No string interpolation containing secrets. Per CONTRIBUTING.md §"Logging". | CI gate (lint rule); manual review for secret-leak risk. |
| **Comments** | Explain why, not what. Per CONTRIBUTING.md §"Comments". | Code review. |

### 3.2 Sanitization requirements (ETHICS.md / SPEC.md §7)

External content is **always** processed through the canonical sanitization pipeline before it reaches the observation graph or any LLM prompt. The SDLP enforces:

- All ingestion paths route through `expose.sanitize` (or its successor module). Direct path-around-sanitization writes to the graph fail code review; tests in `tests/sanitization/test_path_coverage.py` assert that all observation-construction code calls sanitization.
- The sanitization rules listed in SPEC.md §7.1 (control-character stripping, NFC normalization, length capping, suspicious-content flagging) are implemented as named sanitization functions with unit tests.
- LLM prompts wrap collected content in `<external_observation source="...">...</external_observation>` tags per SPEC.md §7.3. The prompt-construction code is centralized; ad-hoc string concatenation into LLM prompts is a code-review reject reason.

### 3.3 OWASP ASVS 4.0.3 alignment

Per framework-annotation.md §7, the engine internal API surface targets ASVS Level 2 verification with Level 3 aspirational for federal-customer deployments. The SDLP-side commitments per chapter:

| ASVS Chapter | SDLP Practice |
|---|---|
| V1 Architecture | Threat-model cadence (§2); design-review gate for major changes (§4). |
| V2 Authentication | Authentication-related changes auto-trigger the security-review skill / human security review (§5). |
| V3 Session | Session-handling code lives in a single module with elevated review requirements. |
| V4 Access Control | All endpoint handlers require explicit tenant-scope decoration (`@requires_tenant_context`); tests assert the decoration. |
| V5 Validation | Pydantic v2 strict mode (§3.1); sanitization (§3.2); JSON-only deserialization on cross-trust-boundary inputs. |
| V7 Cryptography | FIPS-mode enforcement (§8). |
| V8 Data Protection | Encryption-at-rest and TLS 1.3 enforcement at deployment (Helm chart defaults); secrets management (§9). |
| V10 Malicious Code | Image scanning, SBOM, signing (§7). |
| V13 API & Web Service | FastAPI with OpenAPI validation; rate limiting; structured error responses. |

### 3.4 Banned and required APIs

| Category | Banned | Required Alternative |
|---|---|---|
| Hashing in non-FIPS mode | `hashlib.md5`, `hashlib.sha1` (except non-security uses, e.g., evidence-store content addressing — must be annotated), default `hashlib` calls when FIPS validation is required | `cryptography.hazmat.primitives.hashes` via FIPS provider; `hashlib` with `usedforsecurity=False` flag for non-security uses |
| Symmetric crypto | `Crypto.*` (legacy pycrypto), `pycryptodome` unless from a FIPS-validated build | `cryptography` library in FIPS mode |
| Random | `random` module for security-relevant choices, `os.urandom` direct calls when FIPS validation is required | `secrets` module (which uses FIPS-validated provider in FIPS mode); `cryptography` RNG |
| TLS | TLS 1.0, TLS 1.1, weak cipher suites (RC4, 3DES, etc.) | TLS 1.3 with FIPS-approved cipher suites |
| Deserialization | Python binary serialization formats (the `p` module, `marshal`, `shelve`); `yaml.load` without `SafeLoader`; on any external-bound input | `json.loads` with Pydantic validation; `yaml.safe_load`; CBOR with schema |
| Subprocess | `shell=True` in `subprocess` calls without strict argument quoting | `subprocess.run` with list arguments; if shell required, document in code review |
| HTTP client | Bare `requests` / `urllib` (no async, no asyncio integration) | `httpx` async client; `aiohttp` acceptable in legacy code with migration ticket |
| LLM SDK | Direct provider SDK calls outside `LLMProvider` abstraction | `LLMProvider` interface (SPEC.md §8.4) wrapped by `SafeLLMClient` |
| File I/O on user-supplied paths | `open()` on unvalidated paths; `os.path.join` without canonicalization | `pathlib.Path` with explicit base-dir confinement; reject paths containing `..` |

A linter ruleset (`ruff` configuration plus a small custom checker for the project-specific rules) enforces the table at CI time. Violations require explicit justification comment plus reviewer sign-off.

---

## 4. Code review

### 4.1 DCO sign-off

Per ADR-006 and CONTRIBUTING.md §"Developer Certificate of Origin", every commit carries a `Signed-off-by:` trailer. The DCO bot enforces this on every PR. PRs without sign-off cannot merge. This is a hard CI gate, not a polite request.

For amended commits or rebases that drop sign-off, contributors use `git rebase --signoff main` or `git commit --amend -s --no-edit` per CONTRIBUTING.md §"Developer Certificate of Origin".

### 4.2 Branch protection

The `main` branch is protected with the following GitHub branch-protection rules:

- Require pull request before merging.
- Require at least one approving review from a Korlogos maintainer (CODEOWNERS-mediated).
- Require status checks to pass before merging — all CI gates listed in §13.
- Require branches to be up to date with main before merging (rebase or merge-commit at maintainer discretion).
- Require signed commits (cryptographic commit signing) is **encouraged** but not required for v1; the DCO sign-off is the canonical contributor identity. Cryptographic signing requirement is tracked as a future hardening item.
- Restrict who can push to `main` to maintainers (no direct pushes; merges via PR only).
- Require conversation resolution before merging.
- Block force-pushes; block deletions.
- Linear history preferred (squash or rebase merge); merge commits acceptable for substantive multi-commit features when commit history is intentional.

Tags follow the same protections — release tags are signed by the release engineer (cosign-signed tag, plus SemVer per CONTRIBUTING.md §"Releases" — see §14).

### 4.3 Reviewer requirements

| Change Class | Reviewers Required | Skills/Notes |
|---|---|---|
| Documentation only | 1 maintainer | Standard review. |
| Bug fix, non-security | 1 maintainer | Standard review. |
| New collector module (Tier 1 or 2) | 1 maintainer + 1 collector-domain reviewer | STRIDE pass per §2; collector-framework conformance check. |
| New collector module (Tier 3 active probing) | 1 maintainer + 1 collector-domain reviewer + 1 security-focused reviewer | Active-probing changes carry attribution-tier-gate verification. |
| Sanitization-layer change | 2 maintainers + adversarial-fixture extension | Per §2.3. |
| LLM provider or SafeLLMClient change | 2 maintainers + AI-RMF-aware reviewer | Eval-harness re-run required before merge. |
| Schema change (canonical artifact, manifest, rulepack) | 2 maintainers + schema-sync verification | See §5 "Automated checks: schema-sync". Major-version bump may be required. |
| Cryptography touch (`expose.crypto`, signing, hashing) | 2 maintainers + security-review skill | Banned-API check; FIPS-mode test re-run. |
| Authentication / session / authorization | 2 maintainers + security-review skill | ASVS V2/V3/V4 review. |
| Multi-tenancy enforcement (query middleware, context propagation) | 2 maintainers + cross-tenant-isolation test extension | Per ADR-007 and §12.1. |

Maintainer roster lives in `CODEOWNERS` and is reviewed quarterly.

### 4.4 Automated checks at PR time

Every PR runs the following checks (also listed in §13 as the CI pipeline):

| Check | Tool | Gate |
|---|---|---|
| DCO sign-off present on every commit | DCO bot | Hard fail |
| Lint clean | `ruff check` | Hard fail |
| Format clean | `ruff format --check` | Hard fail |
| Type-check clean | `mypy --strict src/` | Hard fail |
| Unit tests pass | `pytest tests/unit/` | Hard fail |
| Integration tests pass | `pytest tests/integration/` (against testcontainers Postgres) | Hard fail |
| Cross-tenant isolation tests pass | `pytest tests/multi_tenancy/` | **Hard fail — regardless of PR scope** per ADR-007 |
| Sanitization tests pass | `pytest tests/sanitization/` | Hard fail |
| Coverage threshold met | `pytest --cov` with thresholds per §12 | Hard fail |
| Schema sync verified | Custom checker (see below) | Hard fail |
| FIPS-mode crypto enforcement | Custom checker (banned-API per §3.4) | Hard fail |
| Dependency audit | `pip-audit` + OSV scanner | Hard fail on high-severity, soft-fail with override on medium/low |
| Container image build | Multi-arch (x86_64, arm64) via `docker buildx` | Hard fail |
| SBOM generation | `syft` produces SPDX or CycloneDX | Hard fail (must produce non-empty SBOM) |
| Container image scan | `trivy` or `grype` against built image | Hard fail on high-severity unfixed |

Schema-sync verification: Pydantic v2 models in `src/expose/schemas/` and the JSON Schema files in `schemas/*.json` describe the same shapes. The CI check generates the JSON Schema from the Pydantic models, diffs against the on-disk JSON Schema, and fails on mismatch. Schema changes require updating both sides in the same PR (per CONTRIBUTING.md §"Style and standards").

---

## 5. Dependency management

### 5.1 Lockfile policy

Dependencies are managed with `uv` (per ADR-001 §"Negative — Dependency management"). The SDLP commits to:

- `pyproject.toml` declares the abstract dependency set with PEP 440 version specifiers. Pinning style: lower-bound + compatible-release (`>=X.Y,<Z`) for libraries; exact pin (`==X.Y.Z`) for security-critical dependencies (cryptography, signing, auth).
- `uv.lock` is committed to the repository. Reproducible builds depend on this lock file.
- Lockfile updates happen via dedicated dependency-bump PRs, not bundled with feature work.
- Renovate (or equivalent) opens dependency-bump PRs weekly. Maintainers triage and merge based on §5.2 update policy.

### 5.2 Update policy

| Severity | Policy |
|---|---|
| Critical CVE in production runtime dependency | Patch within 7 days. Out-of-band release if necessary. |
| High CVE | Patch within 30 days. |
| Medium CVE | Patch within 90 days, batched into the next minor release. |
| Low CVE | Patch within 180 days, batched. |
| Security-irrelevant minor / patch | Weekly Renovate batch; reviewed and merged per maintainer cadence. |
| Major (breaking) updates | Each on its own PR; require migration notes; reviewed for compatibility implications. |

These match the SECURITY.md vulnerability-response SLAs (§10) and align with NIST 800-53 SI-2 (Flaw Remediation) per framework-annotation.md §5.11.

### 5.3 Vulnerability scanning

Two scanners run in CI on every PR and on a nightly schedule:

- `pip-audit` against the committed lockfile, using PyPI Advisory Database.
- OSV scanner against the lockfile, using the broader OSV.dev database.

Hard-fail thresholds: any unpatched **high or critical** vulnerability with a known fix blocks merge. Medium/low vulnerabilities are tracked as issues with the §5.2 SLA but do not block individual PRs.

For dependency vulnerabilities without a known fix (reported but unpatched upstream), the project documents the exposure in the `docs/security-bulletins/` directory and notifies federal customers via the SECURITY.md disclosure channel where impact is material.

### 5.4 SBOM generation

Per ADR-010 and framework-annotation.md §5.4 (CM-8) and §5.9 (SA-12):

- An SBOM in CycloneDX 1.5 format (preferred) and SPDX 2.3 format (fallback for tooling that requires it) is generated for every container image via `syft`.
- SBOMs are attached to every release as release-asset files.
- SBOMs include both Python dependency manifests and OS-package manifests for the base image (distroless or chainguard per ADR-003 commitment).
- The SBOM is reproducible: identical sources produce identical SBOMs (modulo timestamps documented in the manifest).

---

## 6. Supply-chain integrity

### 6.1 Container image signing

Per ADR-003 and ADR-010:

- Container images are signed via **cosign keyless** using GitHub Actions OIDC. The signing identity binds to the GitHub Actions workflow run that produced the image, providing cryptographic proof of build provenance.
- Signatures live in a separate sidecar (per cosign convention) co-located with the image in the registry.
- Verification commands published in SECURITY.md §"Verifying signed artifacts" allow consumers to verify with the certificate-identity-regexp pattern that pins to the official repo path.
- Lab deployments (per ADR-004 §9.4) may use cosign keypair signing as an alternative; production deployments use keyless via OIDC.

### 6.2 Canonical artifact signing

Artifacts produced by deployed EXPOSE instances (the `canonical.json.gz` files per SPEC.md §9) are also cosign-signed. The signing identity in production is tenant-scoped per the deployment (cosign keypair held by the deployment, or keyless via the deployment's OIDC issuer). Verification on the consumer side (Environment 2 ingestion) is documented per SPEC.md §9.4.

### 6.3 SLSA provenance

Per ADR-010 and framework-annotation.md §5.10 (SI-7(15)) and §5.9 (SA-12):

- v1 target: **SLSA Build Level 2** at slsa.dev/spec/v1.0/levels — builds run on a hosted platform (GitHub Actions) and the platform generates and signs the provenance.
- Roadmap target: **SLSA Build Level 3** — hardened build platform with strict isolation between build steps, non-falsifiable provenance, and non-relayed signing keys.
- Provenance attestations follow the SLSA v1.0 build-provenance format; in-toto attestation envelopes; signed with cosign keyless.
- Attestations are uploaded to the OCI registry alongside the images.
- The transparency-log entry (Rekor when keyless via OIDC) provides the auditable record per framework-annotation.md §5.10 (SC-17, SI-7).

### 6.4 Reproducible builds

Reproducibility is an investment, not a hard guarantee at v1. The SDLP commits:

- Container builds use pinned base images (digest-pinned) and pinned tool versions.
- Build steps documented in `Dockerfile` are deterministic; no network access during the final image-assembly stage beyond fetching pinned dependencies.
- Source-tarball releases include hash-pinned dependencies and instructions for rebuilding from source.
- The codebase tracks remaining sources of build non-determinism (timestamps, ordering of deps in lockfile resolution at upgrade time, container layer ordering) in `docs/security/build-reproducibility-status.md` and reduces them over time.
- Bit-for-bit reproducibility of artifact generation (separate from build reproducibility) is committed per SPEC.md §9.2 and is a runtime determinism property of the engine, not a build-time property.

### 6.5 Transparency log

Cosign keyless signing automatically produces a Rekor (sigstore transparency log) entry. The SDLP commits to:

- Not deleting Rekor entries (which is operationally enforced by the public Rekor instance).
- Not relying on a private transparency log that contributors cannot inspect.
- Documenting the Rekor entry IDs alongside release artifacts so consumers can independently verify the audit trail.

### 6.6 Multi-arch builds

Per ADR-003: multi-arch (x86_64 + arm64) from day one via `docker buildx`, published as multi-arch manifests. SBOM and signature generation cover both architectures.

---

## 7. Cryptography

### 7.1 FIPS 140-3 validated everywhere

Per ADR-010 §"Commitment 1: Architectural readiness in v1" and framework-annotation.md §5.10 (SC-13), §7.6 (V7 Cryptography), §5.6 (IA-7):

- All cryptographic operations in EXPOSE — TLS, signing, hashing for security purposes, key management, password hashing, randomness — use FIPS 140-3 validated implementations.
- The Python `cryptography` library is the canonical primitive provider, configured to use a FIPS-validated OpenSSL backend.
- Container images are built on a base image that ships FIPS-validated OpenSSL (chainguard or equivalent FIPS-mode distribution).
- Cosign is used in its FIPS-validated mode; signing operations use the FIPS-validated key types.
- Postgres deployments are configured with FIPS-mode OpenSSL; this is documented in the Helm chart defaults.

### 7.2 Allowed APIs

| Operation | Approved API |
|---|---|
| Hash (security) | `cryptography.hazmat.primitives.hashes.SHA256` (or SHA384, SHA512) via FIPS provider |
| Hash (non-security, e.g., evidence-store content addressing) | `hashlib.sha256(..., usedforsecurity=False)` — annotated; SHA-256 chosen for collision resistance even when not security-critical |
| Symmetric encryption | `cryptography.hazmat.primitives.ciphers` with AES-256-GCM |
| Asymmetric / signing | `cryptography.hazmat.primitives.asymmetric` (RSA-3072+, ECDSA P-256 / P-384, Ed25519 where FIPS approves) |
| Random | `secrets` module (FIPS-backed when interpreter is in FIPS mode); `cryptography` RNG for primitives |
| Password hashing | `argon2-cffi` (Argon2id) per OWASP guidance, with FIPS-validated underlying hash; alternative: `cryptography`-mediated PBKDF2-HMAC-SHA256 with appropriate iteration count |
| TLS | `httpx` / `aiohttp` configured to TLS 1.3 with FIPS cipher suites; certificate validation always on; system trust store unless mTLS configured |
| Signing (artifacts) | `cosign` (FIPS-validated build) |
| Signing (commits — encouraged) | GPG with FIPS-acceptable key type (RSA-3072+, Ed25519) |

### 7.3 Banned APIs

| Banned | Reason | Alternative |
|---|---|---|
| `hashlib.*` for security purposes in non-FIPS mode | Defaults to non-FIPS implementation in some Python builds | `cryptography.hazmat.primitives.hashes` |
| `pycrypto` (legacy) | Unmaintained; non-FIPS | `cryptography` |
| `pycryptodome` non-FIPS builds | Not FIPS-validated | `cryptography`; or pycryptodome FIPS-validated build with explicit approval |
| `random` module for any security-relevant choice | Mersenne Twister; not cryptographically secure | `secrets`; `cryptography` RNG |
| TLS 1.0, 1.1, 1.2 without FIPS cipher suites | Not FIPS-acceptable for federal posture | TLS 1.3 |
| RC4, 3DES, MD5, SHA-1 for security purposes | Cryptographically broken or deprecated | AES-256, SHA-256+ |
| `os.urandom` direct calls when FIPS validation is required | Default depends on platform crypto provider | `secrets`; `cryptography` RNG |
| Custom-rolled crypto | Always wrong | Use the validated library |

CI enforces banned-API rules via a custom checker (small Python AST visitor) plus `ruff` security-rule subset. Violations fail merge.

### 7.4 Build-time enforcement

The SDLP commits that FIPS enforcement is **build-time**, not runtime-only:

- The container image's base layer is FIPS-validated.
- A startup self-check in the EXPOSE entrypoint verifies the FIPS provider is active and refuses to start if it is not.
- A test in `tests/crypto/test_fips_mode.py` exercises the self-check and asserts the FIPS mode banner appears in startup logs.
- The CI job `fips-mode-check` runs the container image and verifies FIPS mode is on.

This protects against drift where someone introduces a non-FIPS dependency or build path; the image fails to start before any deployment can use it.

---

## 8. Secrets management

### 8.1 SecretsProvider abstraction

Per ADR-003 (and SPEC.md §6.4):

- All secrets (collector API keys, LLM provider credentials, database passwords, signing keys for keypair-mode cosign, OIDC client secrets, telemetry-backend tokens) are accessed through the `SecretsProvider` abstraction.
- v1 ships two implementations: Vaultwarden (ARC lab) and AWS Secrets Manager (cloud).
- HashiCorp Vault and Azure Key Vault implementations are deferred (issues-backlog.md "Secrets backend abstraction with non-Vaultwarden implementations").
- No secret is stored in the container image, in environment variables baked into the image, in Helm values that are not externalized to the secrets backend, in source control, or in build logs.

### 8.2 Just-in-time fetching

Per SPEC.md §6.4 and framework-annotation.md §5.10 (SC-12):

- Secrets are fetched from the backend per call (or per short-lived cache window, configurable). They are **not** held in long-lived application memory across the lifetime of a worker process.
- Cache TTLs are configurable; the default is short (60 seconds for collector API keys; longer for less-frequently-used credentials).
- Secrets are zeroed from memory after use where the language permits (Python's GC limits this, but explicit del + GC pressure on the bytes-bearing objects is the documented practice; for higher assurance, secrets stay in `bytearray` instances that can be explicitly zeroed).

### 8.3 Audit logging of secret access

Per framework-annotation.md §5.2 (AU-2, AU-3, AU-12) and SPEC.md §10.2:

- Every secret fetch from the SecretsProvider emits an audit-log event with: timestamp, tenant_id (if applicable), actor (service identity), secret reference (not the value), outcome.
- Sensitive operations are logged separately for compliance retention per SPEC.md §10.2.
- The audit log is the AU-9-protected log per §11.

### 8.4 Local development

For local development, secrets live in `.env.local` (gitignored) loaded by direnv or a similar mechanism. The SDLP commits that:

- `.env.local`, `.env.development`, and similar files are in `.gitignore`.
- A pre-commit hook scans for high-entropy strings and known secret patterns (using `gitleaks` or equivalent) and refuses commits that match.
- CI re-scans the diff with `gitleaks` (or equivalent) on every PR; any match fails the build.
- Test fixtures use clearly-fake secrets (`test_api_key_DO_NOT_USE`, etc.) that are pattern-matched by the secret scanner and exempted via baseline config.

---

## 9. Vulnerability disclosure and response

### 9.1 Disclosure channel

Per SECURITY.md §"Reporting a vulnerability":

- Preferred channel: **private security advisory** on the public repository (GitHub's Security Advisories feature, or the equivalent on the canonical hosting platform).
- Alternate channel: PGP-encrypted email to `security@korlogos.com`.
- Public GitHub issues for vulnerabilities are explicitly discouraged and silently triaged into private channels when they appear.

### 9.2 Severity classification

Per SECURITY.md §"Severity classification" — CVSS-aligned:

| Severity | Definition | Fix Target | Hard Maximum |
|---|---|---|---|
| Critical | Remote unauthenticated exploit producing data exfil, code execution, or tenant-boundary compromise | 30 days | 90 days (with public mitigation guidance during the window) |
| High | Authenticated exploit producing similar consequences; unauthenticated DoS against production | 30 days | 90 days |
| Medium | Exploit requiring local access or unusual conditions; non-secret information disclosure | 90 days | 180 days |
| Low | Best-practice deviations, hardening opportunities | 180 days or next minor release | 365 days |

These match the NIST 800-53 SI-2 SLAs in framework-annotation.md §5.11 (30 days high, 90 days moderate per the ADR-010 commitment). Where severity classification differs between EXPOSE's CVSS-aligned view and a federal-customer's risk-based assessment, the customer's view governs that customer's deployment; the project's view governs the upstream codebase.

### 9.3 Response timeline

Per SECURITY.md:

- Acknowledgment of report: within 72 hours.
- Initial triage and severity classification: within 7 days.
- Fix or mitigation per the severity table.

### 9.4 CVE process

- For vulnerabilities meeting the criteria, EXPOSE requests CVE assignment through GitHub's CNA (CVE Numbering Authority) program when the upstream is hosted there, or through MITRE-coordinated channels for off-GitHub disclosures.
- Released CVEs are linked from the GitHub Security Advisory and from the project's `docs/security-bulletins/` index.
- Reporters are credited (with their consent) in the advisory and in `SECURITY.md` §"Hall of fame".

### 9.5 Bug bounty

Per SECURITY.md §"Bug bounty": no bug bounty program in v1. Revisited when deployment scale and funding justify it.

### 9.6 Coordinated disclosure

Standard 14-day post-fix disclosure window unless reporter and maintainers agree otherwise (per SECURITY.md §"Coordinated disclosure"). Active-exploitation cases accelerate the timeline with mitigation guidance published before fix availability.

---

## 10. Audit logging

Per ADR-010 §"Commitment 1" and framework-annotation.md §5.2 (AU family — AU-2, AU-3, AU-9, AU-11, AU-12).

### 10.1 Events logged

EXPOSE emits audit-log events for:

| Event Class | Examples |
|---|---|
| Authentication / Authorization | Admin login (success, failure), MFA challenge, session creation, session termination, role change, failed authorization attempts |
| Tenant Lifecycle | Tenant create, configuration change, scope modification, suspension, deletion |
| Configuration Change | Collector enable/disable, rule pack version change, LLM provider change, retention policy change |
| Secret Access | Every fetch from SecretsProvider (timestamp, identity, secret-ref, outcome) |
| Run Lifecycle | Run dispatch, run completion, run failure, partial-run reasons |
| LLM Calls | Per-call: provider, model, input/output token counts, latency, cost estimate, schema-validation outcome (per SPEC.md §8.4) |
| Collector Outcomes | Collector success, failure, rate-limit, timeout |
| Artifact Generation | Artifact created, signed, written to storage |
| Trust-Boundary Crossings | Sanitization outcomes including suspicious-content flags; LLM disagreement events |
| Data Subject Requests | If/when production-hardening adds DSR handling |

### 10.2 Format

All audit events are structured JSON, emitted via OpenTelemetry, with the following mandatory fields per AU-3 (framework-annotation.md §5.2):

| Field | Type | Purpose |
|---|---|---|
| `timestamp` | ISO 8601 UTC | When the event occurred |
| `event_type` | enum | The class of event (one of the table above) |
| `tenant_id` | UUID (nullable for system-wide events) | Multi-tenancy context |
| `actor` | structured identity | User, service identity, or system; includes auth method |
| `outcome` | enum (`success` / `failure` / `error` / `denied`) | Result of the operation |
| `source` | structured | Originating component (e.g., `expose-control-plane`) |
| `target` | structured | Subject of the operation (e.g., entity ID, resource path) |
| `evidence_ref` | optional string | Pointer to evidence in object store |
| `correlation_id` | UUID | Trace correlation across distributed calls |
| `additional_context` | structured | Event-specific fields |

### 10.3 Tamper-evidence

Per ADR-010 and framework-annotation.md §5.2 (AU-9):

- Audit logs are written to **append-only** storage where the deployment provides one (cloud-native append-only log services; immutable object-storage buckets with deny-by-default delete IAM).
- Where append-only is not deployment-provided, audit logs are batched and the batch is **signed** by the EXPOSE instance using the same FIPS-validated signing key infrastructure as canonical artifacts. A tampered log batch fails signature verification.
- Audit-log streaming to an external SIEM (Splunk, Sentinel, Chronicle) is the deployment's responsibility; EXPOSE's role ends at OTel emission per SPEC.md §10.2.

### 10.4 Retention

Per framework-annotation.md §5.2 (AU-11) and SPEC.md §10.2:

- Audit-log retention is per-tenant configurable.
- Default retention (non-federal): 90 days hot, 365 days cold.
- FedRAMP-aligned retention (when configured): minimum 1 year for AU records, 3 years for compliance retention; deployment configures to its FedRAMP baseline.
- Retention configuration is itself audit-logged.

### 10.5 Access control

- Audit-log read access is privileged and itself audit-logged.
- Per-tenant logs are visible only to that tenant's authorized roles plus the deployment-operator role.
- Cross-tenant access (deployment operator) is logged separately for compliance retention.

---

## 11. Testing requirements

### 11.1 Cross-tenant isolation tests as CI gate

Per ADR-007 and the v1 deliverable "Cross-tenant isolation testing" in the multi-tenancy epic of `docs/issues-backlog.md`:

- Test suite at `tests/multi_tenancy/` exercises synthetic tenant_ids and asserts that tenant A cannot read tenant B's data via any API endpoint, that runs cannot reference cross-tenant data, that bearer tokens are tenant-scoped (when introduced), that database queries always scope by tenant_id, that caching keys include tenant_id, that background jobs preserve tenant context across async boundaries, and that audit logs are tenant-isolated.
- This test suite is a **hard CI gate, regardless of PR scope**. ADR-007 §"Consequences" makes this explicit: "CI fails on regressions in tenant isolation tests regardless of PR scope."
- New tests are added to this suite when a new entity / edge type, new API endpoint, or new background job is introduced.

### 11.2 Schema-sync tests

Per CONTRIBUTING.md §"Style and standards":

- A test in `tests/schemas/test_schema_sync.py` regenerates JSON Schemas from the Pydantic v2 models and asserts byte-for-byte equality with `schemas/*.json`.
- A second test in the same file asserts that example documents (e.g., `examples/rulepacks/example-baseline.json`) validate against the schemas.
- Schema changes require updating both the Pydantic models and the JSON Schema files in the same PR; the CI test catches divergence.

### 11.3 Integration tests against real Postgres

Per CONTRIBUTING.md §"Style and standards":

- Database tests use **real Postgres via testcontainers**, not SQLite or in-memory mocks.
- Integration tests cover: query construction with tenant context, recursive CTE traversals (per SPEC.md §5.1), Alembic migration up-and-down, observation-graph integrity under concurrent insert.
- Container-pinned Postgres version matches the production Postgres version range.

### 11.4 Eval harness for LLM enrichment (Phase 2)

Per SPEC.md §11.2 Sprint 13-14 and framework-annotation.md §6.3 (MEASURE 2.5, 2.6, 2.7) and §8.1 (AISVS C10):

- The eval harness ships in Phase 2 with held-out datasets: `confirmed_yours`, `confirmed_not_yours`, `ambiguous_with_resolution`, `adversarial_injection`.
- The eval harness has a CLI (`expose eval`) and emits structured metrics (precision, recall, F1, calibration, adversarial-resistance pass rate).
- Quarterly re-evaluation procedure: each quarter, the eval harness runs on the current LLM provider+model selections and the metrics are compared to baseline. Material regression triggers a STRIDE pass and possible model-pinning rollback.
- Adversarial-injection eval is a CI gate when LLM-provider or SafeLLMClient code is touched (§4.3).

### 11.5 Sanitization adversarial tests

Per §2.3 and SPEC.md §7:

- Test fixtures at `tests/sanitization/adversarial/` include known prompt-injection payloads, control-character injection, encoding tricks (homoglyph, IDN abuse, NFC bypass attempts).
- Every PR that touches sanitization extends or revises these fixtures.
- These tests are unit-test fast; not gated on LLM availability.

### 11.6 Coverage thresholds

| Module | Statement Coverage Threshold | Branch Coverage Threshold |
|---|---|---|
| `expose.sanitize` (security-critical) | 95% | 90% |
| `expose.crypto` (security-critical) | 95% | 90% |
| `expose.attribution` (rule engine) | 90% | 85% |
| `expose.collectors.*` | 80% | 75% |
| `expose.llm` (SafeLLMClient and providers) | 90% | 85% |
| `expose.api` (admin API handlers) | 85% | 80% |
| `expose.storage` (graph + object store interfaces) | 85% | 80% |
| Overall project | 85% | 80% |

Coverage is measured by `pytest-cov` and enforced by CI. PRs that drop coverage below threshold fail. Increasing coverage is encouraged; lowering threshold requires an ADR or maintainer-team decision.

### 11.7 Test taxonomy

- `tests/unit/` — fast (<1s each), no external dependencies, run on every commit during dev.
- `tests/integration/` — testcontainers Postgres / MinIO, no external network calls; mocked LLM providers via `respx`.
- `tests/multi_tenancy/` — cross-tenant isolation suite (§11.1).
- `tests/sanitization/` — sanitization adversarial fixtures (§11.5).
- `tests/schemas/` — schema-sync (§11.2).
- `tests/crypto/` — FIPS-mode self-checks and crypto API exercises (§7.4).
- `tests/eval/` — Phase 2 LLM eval harness fixtures (§11.4).

`pytest` markers gate optional / heavy tests; default `pytest` run executes the gating set.

---

## 12. CI/CD pipeline

### 12.1 GitHub Actions workflow shape

The CI/CD pipeline is implemented as GitHub Actions workflows in `.github/workflows/`. The shape is:

```
on: pull_request, push to main, release tag

ci.yml (PR + push):
    matrix: [python 3.12, python 3.13] x [linux/amd64, linux/arm64]
    jobs:
      - lint:        ruff check + ruff format --check
      - typecheck:   mypy --strict src/
      - test-unit:   pytest tests/unit/
      - test-integration:
                     pytest tests/integration/   (testcontainers)
      - test-multi-tenancy:
                     pytest tests/multi_tenancy/  (HARD GATE)
      - test-sanitization:
                     pytest tests/sanitization/
      - test-schemas:
                     pytest tests/schemas/
      - test-crypto:
                     pytest tests/crypto/
      - coverage:    pytest --cov; assert thresholds
      - dependency-audit:
                     pip-audit + osv-scanner against uv.lock
      - secret-scan:
                     gitleaks against diff
      - container-build:
                     docker buildx build --platform linux/amd64,linux/arm64
      - sbom:        syft -> CycloneDX + SPDX
      - container-scan:
                     trivy or grype against built image
      - fips-mode-check:
                     run image, verify FIPS provider active
      - dco:         (DCO bot enforces in PR check API)

release.yml (on release tag):
    [all of ci.yml] +
      - container-publish:
                     push multi-arch manifest to ghcr.io / internal registry
      - cosign-sign:
                     keyless via OIDC, attest to image
      - slsa-provenance:
                     in-toto attestation, signed via cosign keyless
      - sbom-attach: attach SBOM to release as asset
      - release-notes:
                     auto-generate from PR titles since previous tag

nightly.yml (schedule):
      - dependency-audit (re-run; new CVEs surface as issues)
      - eval-harness (Phase 2)
      - reproducible-build-check
```

### 12.2 Required checks for merge

Branch protection on `main` requires the following checks to pass before merge:

- DCO sign-off
- ci.yml::lint
- ci.yml::typecheck
- ci.yml::test-unit
- ci.yml::test-integration
- ci.yml::test-multi-tenancy (hard gate per ADR-007)
- ci.yml::test-sanitization
- ci.yml::test-schemas
- ci.yml::test-crypto
- ci.yml::coverage
- ci.yml::dependency-audit
- ci.yml::secret-scan
- ci.yml::container-build
- ci.yml::sbom
- ci.yml::container-scan
- ci.yml::fips-mode-check

### 12.3 Merge methods

- Squash merge by default for PRs with multi-commit feature work.
- Rebase merge for clean linear history when contributor commit history is intentional.
- Merge commit acceptable for substantive features where preserving the merge graph adds value.
- Force push to `main` is blocked by branch protection; `--force-with-lease` is acceptable on contributor branches before review.

### 12.4 Artifact provenance

Every release produces a complete provenance bundle attached to the GitHub release (or equivalent on the canonical host):

| Artifact | Format | Verification Tool |
|---|---|---|
| Container images | OCI manifests (multi-arch) | `cosign verify` per SECURITY.md |
| Image signatures | cosign signature sidecars | `cosign verify` |
| Image SBOMs | CycloneDX 1.5 + SPDX 2.3 | `syft cataloger`, `cyclonedx-cli` |
| SLSA build provenance | in-toto attestations, cosign-signed | `slsa-verifier` |
| Source tarball | git archive of the tag | `gpg --verify` against signed tag |
| Release-tag signature | GPG (or Sigstore) on the git tag | `git verify-tag` / `cosign verify-blob` |
| CHANGELOG, release notes | Markdown | Inspection |

---

## 13. Release management

### 13.1 SemVer

Per CONTRIBUTING.md §"Releases":

- **Major** (`X.0.0`): breaking schema changes (canonical artifact, manifest, rule pack), breaking config changes, removed APIs.
- **Minor** (`X.Y.0`): backward-compatible additions — new collectors, new attribution rule predicates, new optional artifact fields, new optional config fields.
- **Patch** (`X.Y.Z`): bug fixes, security fixes, documentation improvements with no behavior change.

Pre-release tags: `vX.Y.Z-rc.N`, `vX.Y.Z-beta.N`, `vX.Y.Z-alpha.N`.

### 13.2 Release notes

Each release ships with notes covering:

- New features (with issue references).
- Bug fixes (with issue references).
- Security advisories (with CVE IDs and severity).
- Breaking changes (with migration guidance).
- Schema version changes (with deprecation timeline if applicable).
- Dependency bumps with material security or behavior implications.
- Known issues at release time.

Release notes are generated semi-automatically from PR titles (Conventional Commits-adjacent style) and manually polished by the release engineer.

### 13.3 Signed tag requirements

- Release tags are GPG-signed (or Sigstore-signed) by the release engineer; `git verify-tag vX.Y.Z` validates.
- Cosign-signed release attestations bind the tag to the artifacts produced from that tag.
- Maintainer GPG key fingerprints are documented in `docs/security/release-keys.md` with rotation history.

### 13.4 Container tag conventions

| Tag | Meaning |
|---|---|
| `vX.Y.Z` | Immutable, signed, points to a specific release commit. |
| `vX.Y` | Floating; tracks the latest patch in the X.Y minor line. Re-pointed on each patch release. |
| `vX` | Floating; tracks the latest minor in the X major line. |
| `latest` | Floating; tracks the most recent stable release. Pre-releases do not update `latest`. |
| `edge` | Latest commit on `main`; not signed for production use; for testing only. |
| `vX.Y.Z-rc.N`, `vX.Y.Z-beta.N`, `vX.Y.Z-alpha.N` | Pre-release tags; signed; do not move floating tags. |

Federal customers and production deployments are documented to pin specifically to `vX.Y.Z` (immutable, signed) per Session G's deployment guidance, not to floating tags.

### 13.5 Schema versioning policy

- The canonical artifact, manifest, and rule pack schemas are versioned independently from the engine SemVer.
- Schema major-version changes (`canonical-artifact-v1.json` to `canonical-artifact-v2.json`) require an engine major-version bump.
- Schema minor changes (additive optional fields) require an engine minor-version bump.
- Schema deprecation policy: a deprecated field is announced in release notes, kept for at least one minor release, and removed only on a major-version bump.
- Federal customers (Session G) get longer deprecation timelines documented per the deployment guide.

### 13.6 Release cadence

- Patch releases on demand for security fixes (per SLAs in §9).
- Minor releases targeted monthly during active development; quarterly during steady-state.
- Major releases on infrequent schedule when breaking changes accumulate justifying coordinated migration.
- LTS designation is not committed in v1; tracked as a future commercial-offering concern.

---

## 14. Incident response

### 14.1 Vulnerability discovered post-release

When a vulnerability is reported privately (per §9.1) or discovered internally:

1. **Triage** — classify severity (§9.2), assign to a maintainer, open a private security advisory.
2. **Fix development** — branch from the impacted tag(s) into a security branch; develop fix; STRIDE-revisit the impacted area.
3. **Backport** — for actively-supported minor lines, backport the fix.
4. **Release** — patch release on the impacted minor line(s); coordinate disclosure (§9.6).
5. **Customer notification** — federal customers (Session G channel) notified per their notification SLA, with mitigation guidance if fix takes time.
6. **Postmortem** — documented in `docs/security/postmortems/` (private until disclosure window closes, then public).

### 14.2 Supply-chain compromise scenarios

Three scenarios documented and rehearsed:

| Scenario | Indicator | Response |
|---|---|---|
| Compromised dependency (malicious package version) | OSV alert, sudden behavior change, compromised maintainer reported | Pin to known-good prior version; release patch within 7 days; remove compromised version from all images; document in security bulletin. |
| Compromised CI / build platform | Cosign signature mismatch; transparency-log gap; unexpected GitHub Actions run | Halt releases; rotate cosign signing OIDC subject; rebuild from known-good source on alternate runner; coordinate with hosting platform incident response. |
| Compromised maintainer credentials | Unexpected commits, unauthorized publishes, anomalous Rekor entries | Revoke maintainer's GitHub access; force credential rotation; audit the affected period; coordinate disclosure if any malicious commits reached `main`. |

The incident-response runbook lives in `docs/security/incident-response.md` (private). The runbook is rehearsed annually (tabletop) per SAMM Operations practice.

### 14.3 Dependency-vulnerability triage workflow

For dependency CVEs surfaced by `pip-audit` / OSV scanner / nightly job:

1. **Classify impact** — does the vulnerable code path exist in EXPOSE's actual usage? Use SBOM + call-graph analysis.
2. **Decide action** —
   - If exposed: patch within §5.2 SLA.
   - If unexposed but theoretically reachable: patch within §5.2 SLA (reachability analysis is hard; default to patching).
   - If genuinely unreachable (e.g., dev-only dependency, unused submodule): document the rationale in `docs/security/cve-not-applicable.md` and patch on a non-urgent cadence.
3. **Document** — every CVE decision is recorded with rationale.

### 14.4 Active-exploitation response

Per SECURITY.md §"Coordinated disclosure": active in-the-wild exploitation accelerates disclosure with mitigation guidance published before fix availability. The decision to publish mitigation-before-fix is the maintainer team's, made in consultation with the reporter and any cooperating CERT/CSIRT.

---

## 15. Periodic review cadence

| Review | Cadence | Scope | Owner |
|---|---|---|---|
| ETHICS.md review | Quarterly (per ADR-006, ETHICS.md §"Maintenance and review") | Intended use, non-goals, capability disclosure | Maintainer team |
| SECURITY.md review | Quarterly (per ADR-006) | Disclosure policy, SLAs, scope | Maintainer team |
| SDLP review (this document) | Quarterly | Each section reviewed for currency vs. SSDF / SLSA / framework updates | Maintainer team |
| Whole-system threat model (SPEC.md §3) | Quarterly + on triggers in §2.2 | Adversary classes, mitigations, residual risks | Maintainer team |
| Dependency lockfile review | Weekly (Renovate cadence) | Open dependency-bump PRs | Maintainer team |
| CVE / OSV scan | Continuous (PR + nightly) | Lockfile vs. advisory databases | CI |
| Cross-tenant isolation tests | Continuous (PR) | Per ADR-007 | CI |
| LLM eval harness re-run (Phase 2) | Quarterly + on LLM provider/model change | Per AI RMF MEASURE per framework-annotation.md §6.3 | Maintainer team |
| External assessment | Annual (recommended) | Independent security review of the engine; not 3PAO unless commercial offering enters FedRAMP authorization (ADR-010) | Korlogos sponsorship |
| Release-key rotation | Annual or on indicator | Maintainer GPG keys, cosign OIDC subjects | Release engineer |

The annual external assessment is a **recommendation**, not a v1 commitment. It becomes a near-term commitment when (a) a federal customer relationship enters serious procurement, (b) the commercial managed-service offering is launched, or (c) project visibility justifies independent third-party review. Korlogos sponsors the assessment when triggered.

---

## 16. Mapping back to frameworks

This section cross-references the SDLP commitments to the framework controls inventoried in `framework-annotation.md`. Where a control is satisfied wholly by an SDLP practice rather than a runtime mechanism, this section is the canonical reference.

### 16.1 NIST SP 800-218 SSDF v1.1 mapping

| SSDF Practice | EXPOSE SDLP Implementation |
|---|---|
| **PO.1** Define Security Requirements | This document; ETHICS.md; SPEC.md §3 threat model. |
| **PO.2** Implement Roles and Responsibilities | CODEOWNERS; maintainer roster; reviewer requirements (§4.3). |
| **PO.3** Implement Supporting Toolchains | uv, ruff, mypy, pytest, syft, cosign, pip-audit, OSV scanner (§3, §5, §6). |
| **PO.4** Define Criteria for Software Security Checks | Coverage thresholds (§11.6); CI gates (§12.2); banned-API rules (§3.4, §7.3). |
| **PO.5** Implement and Maintain Secure Environments for SD | GitHub Actions hosted runners; FIPS-mode container base; OIDC for keyless signing (§6, §7). |
| **PS.1** Protect All Forms of Code | Branch protection; signed tags; signed images; signed artifacts (§4.2, §6, §13.3). |
| **PS.2** Provide a Mechanism for Verifying Software Release Integrity | Cosign + SLSA + SBOM + Rekor (§6). |
| **PS.3** Archive and Protect Each Software Release | Tag immutability; container-tag immutability for `vX.Y.Z` (§13.4). |
| **PW.1** Design Software to Meet Security Requirements and Mitigate Security Risks | STRIDE per change (§2.1); ASVS alignment (§3.3); design review for major changes. |
| **PW.2** Review the Software Design to Verify Compliance with Security Requirements and Risk Information | Reviewer requirements (§4.3); STRIDE table in PR (§2.1). |
| **PW.4** Reuse Existing, Well-Secured Software When Feasible | `cryptography` library; FastAPI; Pydantic; established Python ecosystem (ADR-001). |
| **PW.5** Create Source Code by Adhering to Secure Coding Practices | Secure-coding standards (§3); banned-API enforcement (§3.4, §7.3). |
| **PW.6** Configure the Compilation, Interpreter, and Build Processes to Improve Executable Security | FIPS-mode build (§7.4); reproducibility investments (§6.4). |
| **PW.7** Review and/or Analyze Human-Readable Code to Identify Vulnerabilities and Verify Compliance with Security Requirements | Code review (§4); ruff strict; mypy strict; security-focused reviewers for security-touching changes. |
| **PW.8** Test Executable Code to Identify Vulnerabilities and Verify Compliance with Security Requirements | Test taxonomy (§11.7); coverage thresholds (§11.6); adversarial fixtures (§11.5); eval harness Phase 2 (§11.4). |
| **PW.9** Configure Software to Have Secure Settings by Default | Helm chart defaults; tenant-config defaults; medium-mode enforcement default (ADR-008). |
| **RV.1** Identify and Confirm Vulnerabilities on an Ongoing Basis | Continuous CVE scanning (§5.3); private disclosure (§9). |
| **RV.2** Assess, Prioritize, and Remediate Vulnerabilities | Severity classification (§9.2); SLAs (§9.3); incident response (§14). |
| **RV.3** Analyze Vulnerabilities to Identify Their Root Causes | Postmortems (§14.1). |

### 16.2 SLSA v1.0 mapping

| SLSA Build Track Level | EXPOSE Status |
|---|---|
| Build L0 (no provenance) | Not applicable |
| Build L1 (provenance exists) | Satisfied — every release has provenance per §6.3 |
| **Build L2 (hosted platform, signed provenance) — v1 target** | Satisfied — GitHub Actions hosted runner with cosign keyless OIDC signing per §6.1, §6.3 |
| Build L3 (hardened build platform, isolated, non-falsifiable) — roadmap target | Tracked. Path: pinned digests for runner images; ephemeral isolated runners; provenance non-falsifiability via stricter OIDC scoping. |

### 16.3 NIST 800-53 Rev 5 controls (selected — cross-reference framework-annotation.md §5)

| Control | SDLP Section | Notes |
|---|---|---|
| AU-2, AU-3, AU-12 (Event Logging) | §10 | Audit-log structure and emission policy. |
| AU-9 (Protection of Audit Information) | §10.3 | Append-only / signed-batch tamper-evidence. |
| AU-11 (Audit Record Retention) | §10.4 | Per-tenant retention; FedRAMP defaults documented. |
| CM-2, CM-3, CM-6 (Configuration Management) | §13, §12 | Version-controlled IaC; release-management discipline. |
| CM-8 (Component Inventory) | §5.4 | SBOM generation. |
| IA-7, SC-13 (Cryptographic Module Authentication / Cryptographic Protection) | §7 | FIPS 140-3 enforcement at build time. |
| RA-5 (Vulnerability Monitoring and Scanning) | §5.3, §14.3 | Continuous CVE scanning of dependencies; for runtime infra Session G covers. |
| SA-10, SA-11, SA-12, SA-15 (Developer Configuration Management; Developer Testing; Supply Chain; Development Process) | §4, §11, §6, this document | The SDLP itself is the SA-15 evidence. |
| SI-2 (Flaw Remediation) | §5.2, §9.3 | SLAs aligned to ADR-010. |
| SI-7, SI-7(15) (Software Integrity, Code Authentication) | §6.1, §6.2, §6.3 | Cosign + SLSA. |
| SI-10 (Information Input Validation) | §3.2, §11.5 | Sanitization layer + adversarial fixtures. |

### 16.4 OWASP ASVS 4.0.3 chapters

Per framework-annotation.md §7 — V1 (Architecture), V2 (Authentication), V3 (Session), V4 (Access Control), V5 (Validation), V7 (Cryptography), V8 (Data Protection), V10 (Malicious Code), V13 (API & Web Service) all map to SDLP commitments per §3.3.

### 16.5 OWASP AISVS 1.0 chapters (LLM enrichment)

Per framework-annotation.md §8 — C02 (Input Validation), C03 (Lifecycle), C04 (Infrastructure), C05 (Access), C06 (Supply Chain), C07 (Output Control), C09 (Agentic Security — by absence), C10 (Adversarial), C11 (Privacy), C12 (Monitoring), C13 (Human Oversight) cross-reference §11.4 (eval harness), §3.2 (sanitization), §11.5 (adversarial), §10 (audit logging).

### 16.6 OWASP SAMM v2 maturity self-assessment target

| SAMM Business Function | SDLP Target Maturity | Evidence |
|---|---|---|
| Governance | Level 2 | This document; ETHICS.md; ADR record. |
| Design | Level 2 | Threat-modeling cadence (§2); design-review gate (§4.3). |
| Implementation | Level 2 | Secure-coding standards (§3); CI gates (§12). |
| Verification | Level 2 | Test taxonomy (§11); adversarial fixtures (§11.5); eval harness (§11.4 Phase 2). |
| Operations | Level 1 (v1) → Level 2 (production-hardening) | Incident response runbook (§14); release management (§13). Operations maturity is partly Session G's territory. |

---

## 17. Open questions and gaps for follow-on work

| Item | Why It Matters | Suggested Resolution |
|---|---|---|
| **SSDF v1.2 finalization** | NIST CSRC released the v1.2 initial public draft 2025-12 with public comment closing 2026-01-30. When v1.2 finalizes, the Section 16.1 mapping needs re-validation. | Track NIST CSRC publication; quarterly SDLP review (§15) catches the finalization. |
| **SLSA Build L3 path** | v1 target is L2; L3 is the federal-customer expectation for higher-assurance workloads. | File issues for hardened-runner adoption, ephemeral build-runner isolation, OIDC subject scoping. |
| **Reproducible builds at bit-for-bit level** | SLSA L4 and FedRAMP rigor benefit from full reproducibility. | Track in `docs/security/build-reproducibility-status.md` (§6.4); reduce sources of non-determinism over time. |
| **Cryptographic commit signing** | Currently encouraged not required (§4.2). Federal customers may expect required. | Decide at the Korlogos maintainer level; trigger when 3+ outside maintainers join or a federal customer requires it. |
| **SBOM-at-runtime** | The SBOM is build-time; runtime-component drift is not currently surfaced. | Future runtime SBOM exposure via admin API; tracked as production-hardening item. |
| **Independent annual security assessment** | Recommended in §15 but not committed. | Trigger on commercial offering or federal-procurement engagement; sponsor. |
| **Bug bounty program** | Deferred per SECURITY.md. Federal customers may expect. | Revisit when funding and deployment scale justify. |
| **Cryptographic module FIPS validation evidence** | EXPOSE relies on `cryptography` library FIPS-mode + base-image FIPS module. The evidence chain to a specific 140-3 certificate must be documented. | `docs/security/fips-modules.md` cataloging module name, certificate number, version. Session G consumes. |
| **Eval-harness public-dataset publication** | Framework-annotation.md §6.3 (MEASURE 2.5) and persona-analysis.md §2 ("Threat Researcher") both depend on eval-dataset publication. CC BY 4.0 datasets per ADR-009. | Phase 2 deliverable; coordinate with persona-analysis.md §"Recommendation 2" Research strategy. |
| **Federal CDM Engineer persona inputs to audit-log requirements** | Per persona-analysis.md §"Missing audience: the Federal CDM Engineer", the CDM persona affects audit-log fidelity expectations. | Revisit §10 audit-log fields when Session G drafts the deployment guide; CDM-specific schema may need additional fields. |
| **OSCAL expression of control mappings** | Per framework-annotation.md §13. Section 16 of this document is currently markdown; OSCAL automation benefits federal customers. | OSCAL conversion is a follow-on session; coordinate with Session G. |
| **CMMC and StateRAMP mappings** | Per framework-annotation.md §13 and ADR-010. Roadmap-future. | Track FedRAMP modernization; map when commercial offering enters CMMC/StateRAMP procurement. |
| **Pre-commit hook standardization for contributors** | DCO bot enforces in CI but contributors can still get surprised. | Ship a `pre-commit` configuration with sign-off helper, gitleaks, ruff, mypy in pre-commit cache. |
| **Long-term maintainer succession** | v1 has Korlogos maintainers. Federal customers may want continuity assurances. | Document maintainer succession policy in `docs/governance/`. Tracked as repo-governance concern. |
| **Schema-version deprecation timelines for federal customers** | §13.5 commits to a deprecation policy; federal customers may need longer windows. | Session G refines per-customer SLA. |

---

## 18. Document maintenance

This is a living document. The commitments here are the project's public contract; revisions are deliberate, reviewed, and noted in release notes when material.

**Last reviewed:** 2026-05-10 at SDLP first draft.
**Next review:** 2026-08-10 (quarterly cadence per §15).

Triggers for unscheduled revision:

- SSDF v1.2 finalization (§17).
- SLSA specification updates (current snapshot: v1.0 levels; v1.1 / v1.2 build-provenance specs visible at slsa.dev).
- Cosign or sigstore protocol changes that affect signing posture.
- New collector / entity / edge / LLM provider that materially changes the threat surface (§2.2).
- Federal customer 3PAO feedback that reveals gaps.
- Security incident postmortem identifying SDLP improvement.

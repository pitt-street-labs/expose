# Security Policy

This policy governs vulnerability reporting and response for EXPOSE. It is aligned with [`ETHICS.md`](ETHICS.md), which defines intended use, non-goals, and scope posture: security disclosures whose remediation changes what is collected, retained, or how authorization scope is enforced trigger an ad-hoc ETHICS review (see `ETHICS.md`).

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (dev) | Yes (current development) |
| < 0.1 | No |

Security fixes are applied to the current development branch only. Once EXPOSE reaches 1.0, this table will expand to cover LTS and maintenance release lines.

## Reporting a Vulnerability

If you discover a security vulnerability in EXPOSE, please report it privately. **Do not file public GitHub issues for security vulnerabilities.**

**Preferred:** [GitHub Security Advisory](https://github.com/pitt-street-labs/expose/security/advisories/new) (private, end-to-end).

**Alternate:** Email `security@korlogos.com` with GPG encryption preferred (key below).

### What to Include

- Description of the vulnerability and its impact.
- Steps to reproduce (proof-of-concept code, test scenarios, configuration excerpts).
- Affected version(s) and deployment context (container, bare-metal, Helm).
- Your severity estimate (CVSS score or qualitative assessment).
- Whether the vulnerability has been disclosed elsewhere.
- Your name and contact information for follow-up (or state that you prefer anonymity).

### Response SLA

| Severity | Target Fix | Maximum |
|----------|-----------|---------|
| Critical / High | 30 days | 90 days |
| Medium | 90 days | Best effort |
| Low | Next minor release | 180 days |

- **Initial acknowledgment:** within 48 hours of receipt.
- **Triage and severity classification:** within 5 business days.

These are targets. We will communicate proactively if a specific case will exceed them.

### Coordinated Disclosure

We follow a coordinated disclosure model with a **90-day disclosure window** from report acceptance. The reporter and maintainers may agree on a different timeline if circumstances warrant it.

After a fix is available:

- Public security advisory published on GitHub.
- CVE assigned via GitHub's CVE issuance program.
- Credit to the reporter unless they prefer anonymity.

If a vulnerability is being actively exploited in the wild, we will accelerate disclosure with mitigations.

### Reporter Credit

Reporters are credited by name (or handle) in the published advisory and in the [Hall of Fame](#hall-of-fame) section below, unless they request anonymity. We will confirm your preferred attribution before publication.

## Severity Classification

We use a CVSS-aligned classification:

| Level | Description |
|-------|-------------|
| **Critical** | Remote unauthenticated exploit producing data exfiltration, code execution, or tenant boundary compromise. |
| **High** | Authenticated exploit producing similar consequences, or unauthenticated denial of service against production deployments. |
| **Medium** | Exploit requiring local access or unusual conditions, or information disclosure of non-secret data. |
| **Low** | Best-practice deviations, hardening opportunities. |

## Security Scope

### In Scope

- **The EXPOSE engine** -- all source code in this repository.
- **Collector modules** -- both builtin collectors and the registered-plugin framework.
- **Pipeline orchestration and dispatch** -- the NATS JetStream broker, worker lifecycle, and run coordination.
- **Sanitization and canonicalization layer** -- input sanitization before graph insertion (SPEC Section 7).
- **Authentication and authorization** -- bearer token validation, tenant isolation enforcement, and scope gating.
- **Container images and supply chain** -- published images, cosign signatures, SBOMs, and build provenance.
- **Schemas and example rule packs** -- JSON Schema definitions and bundled examples.
- **Helm charts** -- deployment manifests published from this repository.

### Out of Scope

- **Environment 2 (downstream LLM analysis).** EXPOSE is Environment 1 only. Whatever tooling operators use for narrative analysis, red team briefing, or open-ended reasoning is outside our security boundary. See `ETHICS.md`.
- **Operator infrastructure.** Kubernetes cluster configuration, network policies, cloud IAM, host OS hardening, and similar deployment-environment concerns are the operator's responsibility.
- **Third-party collector API providers.** Vulnerabilities in Censys, Shodan, crt.sh, or other upstream data sources should be reported to those providers directly.
- **Customer-specific rule packs** that live in private repositories outside this codebase.
- **Social engineering of project maintainers.** Phishing, pretexting, or other social-engineering attacks targeting maintainers are not in scope.
- **Vulnerabilities in dependencies.** Report those upstream; we will update our pinned versions promptly. If a dependency vulnerability creates an exploitable path through EXPOSE, that is in scope.
- **Operator misconfigurations** -- unless caused by misleading defaults or unclear documentation in our code.

## Security Design Principles

**Tenant isolation enforced at every data path.** Entity, relationship, and run data are scoped by `tenant_id` at the repository layer. Cross-tenant queries are architecturally prevented, not just policy-gated.

**FIPS-validated cryptography only.** All hashing, fingerprinting, and signature operations use FIPS 140-2/3 validated algorithms. Non-FIPS primitives are banned by CI gate and test enforcement.

**External content always sanitized before graph insertion.** Data from adversary-controllable sources (certificate SANs, HTTP banners, DNS TXT records, WHOIS fields) passes through the sanitization layer before entering the observation graph.

**Three-tier collector model with attribution gating.** Passive collection (Tier 1) has no target interaction. Semi-passive collection (Tier 2) queries public databases. Active probing (Tier 3) is gated by attribution confidence thresholds within the operator's declared authorization scope -- preventing accidental probing of unrelated infrastructure.

**Container images signed with cosign.** Published images carry keyless cosign signatures and SLSA provenance attestations.

**Secrets never logged; credentials fetched just-in-time.** The secrets backend abstraction ensures credentials are retrieved at the point of use and never serialized to logs, artifacts, or diagnostic output.

## SBOM and Supply Chain

We publish SBOMs (SPDX format) for all container images via `syft`. Build provenance attestations target SLSA Level 2, with Level 3 as an ongoing improvement target.

SBOM generation is documented in `scripts/generate-sbom.sh`. Signing configuration is documented in `deploy/cosign-keypair-setup.md`.

## Verifying Signed Artifacts

Production artifacts (container images, releases) are signed via cosign keyless. To verify:

```bash
# Verify a container image
cosign verify ghcr.io/pitt-street-labs/expose:<tag> \
    --certificate-identity-regexp '^https://github.com/pitt-street-labs/expose/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Verify a canonical artifact
cosign verify-blob \
    --signature canonical.json.gz.sig \
    canonical.json.gz \
    --certificate-identity-regexp '^https://github.com/pitt-street-labs/expose/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Known Limitations

The following are known gaps in the current development state, tracked for resolution:

- **In-memory secrets backend is dev-only.** The `InMemoryBackend` stores credentials in process memory without encryption. Production deployments require a real secrets backend (Vault, KMS).
- **Bearer token authentication not yet implemented.** API authentication is planned for a future sprint. Current development builds have no authentication layer.
- **Rate limiting is per-collector, not global.** Each collector enforces its own rate limits. There is no fleet-level throttle across all collectors in a run. Operators deploying at scale should implement external rate limiting.

## Security Contacts

| Channel | Address |
|---------|---------|
| GitHub Security Advisories | [File a private advisory](https://github.com/pitt-street-labs/expose/security/advisories/new) |
| Email | `security@korlogos.com` |
| GPG key | Published with the first public release |

For conduct concerns related to EXPOSE's intended use, contact `conduct@korlogos.com` (see `ETHICS.md`).

## Bug Bounty

We do not currently offer a bug bounty program. We will revisit this when the project's deployment scale and funding justify it.

## Hall of Fame

Reporters credited here when they consent to public attribution:

(none yet -- project pre-release)

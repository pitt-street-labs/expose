# Security Policy

This policy governs vulnerability reporting and response for the EXPOSE engine. It is aligned with [`ETHICS.md`](ETHICS.md), which defines intended use, non-goals, and scope posture: security disclosures whose remediation changes what is collected, retained, or how authorization scope is enforced trigger an ad-hoc ETHICS review (see `ETHICS.md` § Trigger events for ad-hoc review).

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x (dev) | Yes (current development) |
| < 0.1 | No |

Security fixes are applied to the current development branch only. Once EXPOSE reaches 1.0, this table will expand to cover LTS and maintenance release lines.

## Reporting a vulnerability

If you discover a security vulnerability in EXPOSE, please report it privately. Do not file public GitHub issues for security vulnerabilities.

**Preferred channel:** GitHub Security Advisory at https://github.com/korlogos/expose/security/advisories/new (private).

**Alternate channel:** Email `security@korlogos.com` with GPG encryption preferred (see [Security contacts](#security-contacts) below).

### What to include

- Description of the vulnerability and its impact.
- Steps to reproduce (proof-of-concept code, test scenarios, configuration excerpts).
- Affected version(s) and deployment context (container, bare-metal, Helm).
- Your severity estimate (CVSS score or qualitative assessment).
- Whether the vulnerability has been disclosed elsewhere.
- Your name and contact information for follow-up (or state that you prefer anonymity).

### Response SLA

- **Initial acknowledgment:** within 48 hours of receipt.
- **Triage and severity classification:** within 5 business days.
- **Fix or mitigation:**
  - Critical/High severity: 30 days target, 90 days maximum.
  - Medium severity: 90 days target.
  - Low severity: 180 days or next minor release.

These are targets; we will communicate proactively if a specific case will exceed them.

### Coordinated disclosure

We follow a coordinated disclosure model with a **90-day disclosure window** from report acceptance. The reporter and maintainers may agree on a different timeline if circumstances warrant it.

After a fix is available:

- Public security advisory published on GitHub.
- CVE assigned via GitHub's CVE issuance program.
- Credit to the reporter unless they prefer anonymity.

If a vulnerability is being actively exploited in the wild, we will accelerate disclosure with mitigations.

### Reporter credit

Reporters are credited by name (or handle) in the published advisory and in the [Hall of fame](#hall-of-fame) section below, unless they request anonymity. We will confirm your preferred attribution before publication.

## Severity classification

We use a CVSS-aligned classification:

- **Critical** — remote unauthenticated exploit producing data exfiltration, code execution, or tenant boundary compromise.
- **High** — authenticated exploit producing similar consequences, or unauthenticated denial of service against production deployments.
- **Medium** — exploit requiring local access or unusual conditions, or information disclosure of non-secret data.
- **Low** — best-practice deviations, hardening opportunities.

## Security scope

### In scope

The following components are covered by this security policy:

- **The EXPOSE engine** — all source code in this repository.
- **Collector modules** — both builtin collectors and the registered-plugin framework (`src/expose/collectors/`).
- **Pipeline orchestration and dispatch** — the NATS JetStream broker, worker lifecycle, and run coordination (`src/expose/broker/`).
- **Sanitization and canonicalization layer** — input sanitization before graph insertion (SPEC §7, `src/expose/sanitization/`).
- **Authentication and authorization** — bearer token validation, tenant isolation enforcement, and scope gating when implemented (ADR-007, ADR-008).
- **Container images and supply chain** — published images, cosign signatures, SBOMs, and build provenance.
- **Schemas and example rule packs** — JSON Schema definitions (`schemas/`) and bundled examples (`examples/`).
- **Helm charts** — deployment manifests published from this repository (`deploy/helm-chart/`).

### Out of scope

- **Environment 2 (downstream LLM analysis).** EXPOSE is Environment 1 only. Whatever tooling operators use for narrative analysis, red team briefing, or open-ended reasoning is outside our security boundary. See `ETHICS.md` § Two-environment design.
- **Operator infrastructure.** Kubernetes cluster configuration, network policies, cloud IAM, host OS hardening, and similar deployment-environment concerns are the operator's responsibility.
- **Third-party collector API providers.** Vulnerabilities in Censys, Shodan, crt.sh, or other upstream data sources should be reported to those providers directly.
- **Customer-specific rule packs** that live in private repositories outside this codebase.
- **Social engineering of project maintainers.** Phishing, pretexting, or other social-engineering attacks targeting maintainers are not in scope for this policy.
- **Vulnerabilities in dependencies.** Report those upstream; we will update our pinned versions promptly. If a dependency vulnerability creates an exploitable path through EXPOSE, that is in scope.
- **Operator misconfigurations** — unless caused by misleading defaults or unclear documentation in our code.

## Security design principles

- **Tenant isolation enforced at every data path.** Entity, relationship, and run data are scoped by `tenant_id` at the repository layer. Cross-tenant queries are architecturally prevented, not just policy-gated (ADR-007).
- **FIPS-validated cryptography only.** All hashing, fingerprinting, and signature operations use FIPS 140-2/3 validated algorithms. Non-FIPS primitives are banned by CI gate and test enforcement (ADR-010).
- **External content always sanitized before graph insertion.** Data from adversary-controllable sources (certificate SANs, HTTP banners, DNS TXT records, WHOIS fields) passes through the sanitization layer before entering the observation graph (SPEC §7).
- **Tier-3 active probing gated by attribution and scope.** Active reconnaissance (DNS resolution, TLS handshakes, HTTP fingerprinting) is only performed against assets that pass attribution confidence thresholds within the operator's declared authorization scope (ADR-008).
- **Container images signed with cosign.** Published images carry keyless cosign signatures and SLSA provenance attestations (when published; see [Known limitations](#known-limitations)).
- **Secrets never logged; credentials just-in-time fetched.** The secrets backend abstraction ensures credentials are retrieved at the point of use and never serialized to logs, artifacts, or diagnostic output.

## Known limitations

The following are known gaps in the current development state. They are tracked and will be addressed in upcoming sprints:

- **In-memory secrets backend is dev-only.** The `InMemoryBackend` stores credentials in process memory without encryption. Production deployments require a real secrets backend (Vault, KMS). See issue #8.
- **Bearer token authentication not yet implemented.** API authentication is planned for Sprint 7+. Current development builds have no authentication layer.
- **Cosign signing not active in lab deployments.** Container image signing infrastructure is wired in CI but not exercised in internal lab builds. See issue #3.
- **Rate limiting is per-collector, not global.** Each collector enforces its own rate limits. There is no fleet-level throttle across all collectors in a run. Operators deploying at scale should implement external rate limiting.

## Verifying signed artifacts

Production artifacts (container images, releases) are signed via cosign keyless. To verify:

```bash
# Verify a container image
cosign verify ghcr.io/korlogos/expose:<tag> \
    --certificate-identity-regexp '^https://github.com/korlogos/expose/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Verify a canonical artifact
cosign verify-blob \
    --signature canonical.json.gz.sig \
    canonical.json.gz \
    --certificate-identity-regexp '^https://github.com/korlogos/expose/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Verification details and example workflows are documented in `docs/SPEC.md` §9.4.

## SBOM and supply chain

We publish SBOMs (SPDX format) for all container images via `syft`. Build provenance attestations target SLSA Level 2 with Level 3 as ongoing improvement.

## Security contacts

- **Email:** `security@korlogos.com`
- **GPG key:** GPG key for encrypted reports will be published with the first public release.
- **GitHub Security Advisories:** https://github.com/korlogos/expose/security/advisories/new

For general conduct concerns related to EXPOSE's intended use, contact `conduct@korlogos.com` (see `ETHICS.md`).

## Bug bounty

We do not currently offer a bug bounty program. We will revisit this when the project's deployment scale and funding justify it.

## Hall of fame

Reporters credited here when they consent to public credit:

(none yet — project pre-release)

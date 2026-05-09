# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in FatFinger6000, please report it privately. Do not file public GitHub issues for security vulnerabilities.

**Preferred channel:** GitHub Security Advisory at https://github.com/korlogos/fatfinger6000/security/advisories/new (private).

**Alternate channel:** email `security@korlogos.com` with PGP encryption preferred (PGP key fingerprint to be published when project goes public).

## What to include in a report

- Description of the vulnerability and its impact.
- Steps to reproduce (proof-of-concept code, test scenarios, affected versions).
- Whether the vulnerability has been disclosed elsewhere.
- Your name and contact information for follow-up (or pseudonymous if you prefer).
- Whether you wish to be credited in the security advisory.

## Response timeline

- **Acknowledgment of report:** within 72 hours (3 business days).
- **Initial triage and severity classification:** within 7 days.
- **Fix or mitigation:**
  - Critical/High severity: 30 days target, 90 days maximum.
  - Medium severity: 90 days target.
  - Low severity: 180 days or next minor release.

These are targets; we'll communicate if a specific case will exceed them.

## Severity classification

We use a CVSS-aligned classification:

- **Critical** — remote unauthenticated exploit producing data exfiltration, code execution, or tenant boundary compromise.
- **High** — authenticated exploit producing similar consequences, or unauthenticated denial of service against production deployments.
- **Medium** — exploit requiring local access or unusual conditions, or information disclosure of non-secret data.
- **Low** — best-practice deviations, hardening opportunities.

## Coordinated disclosure

We follow a coordinated disclosure model. After a fix is available:

- Public security advisory published on GitHub.
- CVE assigned via GitHub's CVE issuance program.
- Credit to the reporter (with their consent).
- Disclosure timeline: 14 days after fix is shipped, unless reporter and maintainers agree otherwise.

If a vulnerability is being actively exploited in the wild, we will accelerate disclosure with mitigations.

## What's in scope

- The FatFinger6000 engine source code in this repository.
- Container images published from this repository.
- Helm charts published from this repository.
- Schemas and example rule packs in this repository.

## What's out of scope

- Operator deployments and their misconfigurations (unless caused by misleading defaults in our code).
- Third-party collector API providers.
- Third-party LLM provider services.
- Customer-specific rule packs that live in private repositories.
- Vulnerabilities in dependencies (please report those upstream; we'll update our pinned versions).

## Verifying signed artifacts

Production artifacts (container images, releases) are signed via cosign keyless. To verify:

```bash
# Verify a container image
cosign verify ghcr.io/korlogos/fatfinger6000:<tag> \
    --certificate-identity-regexp '^https://github.com/korlogos/fatfinger6000/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Verify a canonical artifact
cosign verify-blob \
    --signature canonical.json.gz.sig \
    canonical.json.gz \
    --certificate-identity-regexp '^https://github.com/korlogos/fatfinger6000/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Verification details and example workflows are documented in `docs/SPEC.md` §9.4.

## SBOM and supply chain

We publish SBOMs (SPDX format) for all container images via `syft`. Build provenance attestations target SLSA Level 2 with Level 3 as ongoing improvement.

## Bug bounty

We do not currently offer a bug bounty program. We will revisit this when the project's deployment scale and funding justify it.

## Hall of fame

Reporters credited here when they consent to public credit:

(none yet — project pre-release)

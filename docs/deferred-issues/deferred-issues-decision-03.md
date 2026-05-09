# Deferred issues — Decision 3 (deployment posture)

These issues capture concerns surfaced during architectural decision-making that
were intentionally scoped out of v1 but must be tracked. Each is filed against
the `deployment-portability` epic.

---

## Issue: Scanner egress profile abstraction and cloud-side egress proxy

**Labels:** `epic:deployment-portability`, `area:scanner`, `priority:high`, `type:design`

**Summary**
Scanner workers run as containers, but the egress posture (source IP, attribution
isolation, IP reputation) does not containerize. ARC deployments egress from
home/lab IP space, which creates an attribution risk if a misattributed asset is
ever scanned. The system needs an injected egress profile abstraction.

**Background**
The control plane and collector workers can run anywhere with little egress
sensitivity. Scanner workers — performing TLS handshakes, HTTP fingerprinting,
and port surface enumeration against confirmed-yours assets — must egress from
infrastructure that is (a) attribution-isolated from anything that matters, and
(b) understood by external observers as security-scanning origin (cloud IP
space, expected; residential IP space, suspicious).

**Acceptance criteria**
- `EgressProfile` abstraction defined in the configuration schema with at least
  these implementations: `direct` (no proxy, default for full-cloud deployments),
  `socks5` (route via configured SOCKS proxy), `wireguard` (route via WG tunnel
  to a remote egress point), `http_connect` (HTTP CONNECT proxy)
- Scanner worker pods select egress profile via Helm values
- Reference deployment of a minimal cloud-side egress proxy (small instance in
  a dedicated AWS or Azure account, no other footprint) — Terraform module
- Documentation: when each profile is appropriate and why ARC deployments
  should never use `direct`
- Egress profile is logged in scan provenance so attribution audits can trace
  which IP space a scan came from

**Out of scope for this issue**
Tor egress, residential proxy services (don't, ever).

**Estimated effort:** 1 sprint

---

## Issue: Postgres-in-container is dev-only — production posture documentation and operator guidance

**Labels:** `epic:deployment-portability`, `area:data`, `priority:medium`, `type:documentation`

**Summary**
The Helm chart will ship with an optional bundled Postgres for development
convenience. This must be clearly documented as non-production, with explicit
guidance on production-grade Postgres provisioning for each supported deployment
target.

**Acceptance criteria**
- `docs/operations/postgres.md` covering: ARC self-managed posture (backup
  strategy, PITR, version upgrade path), AWS RDS/Aurora configuration, Azure
  Flexible Server configuration, GCP Cloud SQL configuration, customer-on-prem
  guidance
- Bundled Postgres in Helm chart is gated behind `postgres.bundled=true` with
  a default of `false` and a startup warning if enabled
- Connection string is the only contract — application has no Postgres-specific
  operational logic
- Backup and restore procedures documented, tested in staging
- Schema migration procedure documented (Alembic, run as Helm hook job)

**Estimated effort:** 1 sprint

---

## Issue: Multi-architecture container images (x86_64 + arm64) from first release

**Labels:** `epic:deployment-portability`, `area:build`, `priority:high`, `type:infrastructure`

**Summary**
Build all production images for both x86_64 and arm64 from day one. ARC and
CF-31 field nodes are x86_64; Apple Silicon dev laptops are arm64; AWS Graviton
is arm64 and ~20% cheaper. arm64 is non-optional for portability.

**Acceptance criteria**
- GitHub Actions CI builds multi-arch images via `docker buildx`
- Both architectures published to the registry with the same tag (manifest list)
- CI matrix runs at least smoke tests on both arches before publish
- Helm chart does not pin to architecture
- Documented in `docs/build.md`

**Estimated effort:** 2-3 days

---

## Issue: Kubernetes NetworkPolicies for east-west traffic isolation

**Labels:** `epic:deployment-portability`, `area:security`, `priority:high`, `type:security`

**Summary**
Ship the Helm chart with default-deny NetworkPolicies and explicit allow rules
for required traffic paths. Retrofitting network policy under customer pressure
is painful; baking it in is cheap.

**Acceptance criteria**
- Default-deny ingress and egress for all namespaces
- Explicit allow rules: collector workers → control plane API; scanner workers
  → external internet (egress profile-dependent); control plane → Postgres,
  object store, secrets backend, LLM API endpoint; nothing else
- NetworkPolicy enforcement validated in CI integration tests (k3s + Calico
  or Cilium)
- Policies are values-configurable for environments where they conflict with
  existing CNI policy (`networkPolicies.enabled=true` default)
- Documentation: required CNI capabilities, troubleshooting guide

**Estimated effort:** 1 sprint

---

## Issue: Image signing, SBOM generation, and supply chain hygiene

**Labels:** `epic:deployment-portability`, `area:build`, `priority:high`, `type:security`

**Summary**
This is a security product. Published images must be signed, accompanied by
SBOMs, and built reproducibly. Sophisticated buyers will notice in a security
review if these are missing. Internal Korlogos work has covered MCP supply chain
attacks (SANDWORM_MODE) — apply the same standard to our own artifacts.

**Acceptance criteria**
- All production images signed with cosign/sigstore in CI, keyed by GitHub
  Actions OIDC (no long-lived signing keys)
- SBOMs generated via syft for every image, attached as cosign attestations
- Provenance attestations (SLSA Level 2 minimum, Level 3 target) generated by
  GitHub Actions
- Helm chart published as an OCI artifact, also signed
- Verification commands and policies documented in `docs/security/supply-chain.md`
- Cosign verification example for downstream operators

**Dependencies**
None. Implement during initial CI pipeline build.

**Estimated effort:** 2-3 days

---

## Issue: Air-gapped operation — explicit non-support and documentation

**Labels:** `epic:deployment-portability`, `area:design`, `priority:low`, `type:documentation`

**Summary**
The system requires internet egress to specific allowlisted API providers
(Censys, Shodan, SecurityTrails, CT log endpoints, the LLM API endpoint, etc.)
to function. Air-gapped operation is fundamentally incompatible with the core
discovery and enrichment pipeline. Document this clearly so it does not become
a surprise in customer engagement.

**Acceptance criteria**
- `docs/deployment/network-requirements.md` listing all external endpoints,
  protocols, and ports required
- Allowlist published as a machine-readable file (JSON or YAML) for customers
  building egress firewall rules
- Position statement: air-gapped operation is out of scope; partial egress with
  allowlist-only firewall is supported
- For sensitive customer environments, document the option of running collectors
  in a DMZ with control plane fully internal

**Estimated effort:** 1-2 days

---

## Issue: Optional bundled observability stack as Helm subchart

**Labels:** `epic:deployment-portability`, `area:observability`, `priority:medium`, `type:infrastructure`

**Summary**
Application emits OpenTelemetry (OTLP) for traces, metrics, and logs. Customers
with existing observability stacks point at their infrastructure. Customers
without one need a working default. Ship a recommended stack as an optional
Helm subchart.

**Acceptance criteria**
- All application telemetry emitted via OTLP, no direct Prometheus/Loki/Tempo
  client dependencies
- Helm subchart `observability/` providing Prometheus + Grafana + Loki + Tempo
  with sane defaults, gated behind `observability.bundled=true`
- Pre-built Grafana dashboards for: collector throughput, attribution decision
  rates, LLM correlation latency and cost, feed generation health
- Documentation: pointing at existing observability infrastructure, dashboard
  import for those without bundled stack

**Estimated effort:** 1-2 sprints

---

## Issue: Secrets backend abstraction with multiple implementations

**Labels:** `epic:deployment-portability`, `area:security`, `priority:high`, `type:design`

**Summary**
Application reads secrets via a `SecretsProvider` abstraction. Implementation is
chosen by deployment configuration. v1 ships Vaultwarden (for ARC) and AWS
Secrets Manager (for cloud); HashiCorp Vault and Azure Key Vault are deferred
to demand.

**Acceptance criteria**
- `SecretsProvider` interface with `get_secret`, `get_secret_versioned`, with
  caching and rotation hooks
- Implementations: `VaultwardenProvider`, `AwsSecretsManagerProvider`,
  `EnvVarProvider` (development only, with loud warning)
- External Secrets Operator integration documented for k8s deployments
- No long-lived secrets in container memory; fetched just-in-time per call
  with short TTL caches
- Audit logging of secret access (who, when, which secret, not the value)
- Issue follow-up tracked for `VaultProvider` and `AzureKeyVaultProvider`

**Estimated effort:** 1 sprint

---

## Tracking summary

| Issue | Priority | Effort | Phase target |
|---|---|---|---|
| Scanner egress profile abstraction | High | 1 sprint | Phase 1 |
| Postgres production posture docs | Medium | 1 sprint | Phase 1 |
| Multi-arch images | High | 2-3 days | Phase 1 |
| NetworkPolicies | High | 1 sprint | Phase 1 |
| Image signing + SBOM | High | 2-3 days | Phase 1 |
| Air-gap non-support docs | Low | 1-2 days | Phase 2 |
| Bundled observability subchart | Medium | 1-2 sprints | Phase 2 |
| Secrets backend abstraction | High | 1 sprint | Phase 1 |

Six of eight are Phase 1 (concurrent with the deterministic-spine work). Two are
Phase 2 — observability subchart and air-gap documentation can wait until there
are real users with real questions.

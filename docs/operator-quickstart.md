# EXPOSE — Operator Quickstart

**Status:** Pre-release operator guide — tracks Phase 1 of the spec (`docs/SPEC.md` §11.1). Open for revision as the chart and CLI mature in Sprints 1-9.
**Date:** 2026-05-09
**Audience:** Security engineers and DevOps engineers deploying EXPOSE Core in lab, internal-corporate, or boutique-consultancy contexts.
**Public name:** EXPOSE / **Internal codename:** FF6K
**Source files cited:** `docs/SPEC.md`, `docs/adr/ADR-007-multi-tenancy.md`, `docs/adr/ADR-008-authorized-use-and-ethics.md`, `deploy/helm-chart/values.yaml`, `examples/tenant-config.yaml.template`.

This is the **lighter on-ramp**. If you are a federal agency operator deploying EXPOSE Core inside an Authority To Operate boundary with NIST SP 800-53 control inheritance work, **stop reading this and use `docs/strategy/federal-customer-deployment-guide.md`** instead — it covers FedRAMP-ready posture, SSP boundary documentation, control mapping, CDM/SIEM integration, and 3PAO assessment touchpoints. This quickstart is for everyone else: a CTEM team mapping its own perimeter, a boutique red team standing up a per-engagement tenant, a research lab evaluating attribution methodology.

---

## 1. Audience and assumptions

You are reading this if you are:

- A **security engineer** at an enterprise mapping your own external attack surface.
- A **DevOps engineer** standing EXPOSE Core up for your security team.
- A **boutique consultant** running a per-client tenant for an authorized engagement.
- A **researcher** testing attribution methodology on your own infrastructure or operator-owned synthetic targets.

You are **not** the target audience for this doc if you are a federal CDM engineer integrating into an agency ATO — that is `docs/strategy/federal-customer-deployment-guide.md`.

This guide assumes you are comfortable with:

- Kubernetes basics — namespaces, secrets, NetworkPolicies, Helm releases (`kubectl`, `helm`).
- A managed or self-managed Postgres instance you can reach from the cluster.
- An S3-compatible object store (MinIO is fine for lab; cloud-hosted bucket recommended for anything you depend on).
- A secrets backend — Vaultwarden for lab, AWS Secrets Manager / Azure Key Vault / GCP Secret Manager for production-grade. Inline secrets in YAML files are explicitly **not** supported (per `docs/adr/ADR-003-deployment-posture.md` §"State is externalized").
- The cosign CLI for verifying signed artifacts (`cosign verify-blob`).

If any of those are unfamiliar, the [Cloud Native Computing Foundation Helm tutorial](https://helm.sh/docs/intro/quickstart/) and the [Sigstore cosign quickstart](https://docs.sigstore.dev/cosign/overview/) are better starting points than this document.

---

## 2. Pre-flight checklist

Work through this before running `helm install`. Each row is a decision or a piece of infrastructure that must already exist.

| # | Item | Decision required |
|---|------|-------------------|
| 1 | **Helm 3.12 or newer installed** | `helm version` returns >= 3.12. The chart targets `kubeVersion: ">=1.28.0-0"` (`deploy/helm-chart/Chart.yaml`). |
| 2 | **Kubernetes cluster reachable** | `kubectl cluster-info` succeeds. k3s is fine for lab; managed (EKS/AKS/GKE) is fine for production. |
| 3 | **Postgres connection** | A reachable Postgres 14+ instance with a database `expose` and a user with full privileges on that database. Connection string stored in a Kubernetes secret. |
| 4 | **Object storage** | An S3-compatible bucket the cluster service account can write to. Lab: MinIO running in-cluster. Production: AWS S3 / Azure Blob / GCS. Bucket-level encryption recommended. |
| 5 | **Secrets backend** | One of: AWS Secrets Manager, Vaultwarden (lab), HashiCorp Vault. The chart references credentials by reference; you populate the backend separately. |
| 6 | **OTLP backend** *(optional but recommended)* | Any OpenTelemetry-compatible collector (Prometheus + Loki + Tempo, Datadog, Splunk OTel). Without this, you lose run/cost/health observability. |
| 7 | **Scanner egress decision** | Are you running active probing (DNS resolution, TLS handshake, HTTP fingerprint)? If yes, decide the egress profile: `direct` (cloud only), `socks5` (proxy / Tor), `wireguard` (dedicated egress tunnel), or `http_connect`. The chart fails closed on `direct` outside cloud deployments. |
| 8 | **Seeds enumerated** | A list of apex domains, organization names, and cloud account IDs you authorize EXPOSE to use as seed graph entry points. See `examples/seeds/` for templates. |
| 9 | **Authorization scope drafted** | The apex domains, cloud accounts, registrant patterns, and ASN ranges you authorize EXPOSE to attribute. See `examples/scope/` for examples; see `docs/adr/ADR-008-authorized-use-and-ethics.md` for enforcement-mode semantics. |
| 10 | **Cosign installed locally** | `cosign version` succeeds. Required to verify signatures on the artifacts EXPOSE produces. |

If any row is undecided, complete it before continuing — the chart install fails fast on missing references rather than silently coming up with insecure defaults.

---

## 3. Step-by-step deploy

These are the commands an operator runs. The chart is a Phase 1 skeleton (per `deploy/helm-chart/templates/NOTES.txt`); not every component is wired end-to-end yet. Treat this as the v1 GA target shape.

```bash
# 1. Clone the repository.
git clone https://github.com/korlogos/expose.git
cd expose
```

```bash
# 2. Inspect the chart and verify the rendered manifests look correct.
helm lint deploy/helm-chart/
helm template my-expose deploy/helm-chart/ --debug | less
```

```bash
# 3. Verify the chart's signature with cosign before installing it.
#    (Future: chart releases are cosign-signed in CI per SPEC §9.4.)
cosign verify deploy/helm-chart/ \
    --certificate-identity-regexp '^https://github.com/korlogos/expose/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

```bash
# 4. Create the namespace and the Postgres connection secret.
kubectl create namespace expose
kubectl create secret generic expose-postgres-conn \
    --namespace expose \
    --from-literal=username='<<your-pg-user>>' \
    --from-literal=password='<<your-pg-password>>'
```

```bash
# 5. Create the object storage credentials secret.
kubectl create secret generic expose-objectstore-creds \
    --namespace expose \
    --from-literal=access_key_id='<<your-access-key>>' \
    --from-literal=secret_access_key='<<your-secret-key>>'
```

```bash
# 6. Copy the tenant template and edit it for your seeds, scope, and collector preferences.
cp examples/tenant-config.yaml.template tenant-config.yaml
$EDITOR tenant-config.yaml
# DO NOT commit tenant-config.yaml — it is in the project .gitignore for a reason.
```

```bash
# 7. Populate collector credentials in your secrets backend.
#    Example for AWS Secrets Manager (replace with your backend's CLI):
aws secretsmanager create-secret \
    --name expose/tenant-default/collectors \
    --secret-string '{"securitytrails_api_key":"<<your-securitytrails-api-key>>","shodan_api_key":"<<your-shodan-api-key>>"}'
```

```bash
# 8. Install the Helm release with your tenant config as values overlay.
helm install expose ./deploy/helm-chart \
    --namespace expose \
    --values tenant-config.yaml \
    --set image.tag=0.1.0 \
    --set postgres.host=postgres.example.internal \
    --set postgres.existingSecret=expose-postgres-conn \
    --set objectStorage.endpoint=s3.us-east-1.amazonaws.com \
    --set objectStorage.existingSecret=expose-objectstore-creds \
    --set observability.otlp.endpoint=otel-collector.observability.svc:4317
```

```bash
# 9. Verify all pods reach Ready and the control-plane health endpoint responds.
kubectl get pods -n expose --watch
kubectl exec -n expose deploy/expose-control-plane -- expose health
```

```bash
# 10. Verify the default tenant has loaded your config.
kubectl exec -n expose deploy/expose-control-plane -- \
    expose tenant show --tenant default
```

If pods are crash-looping at this point, the most common causes are: Postgres unreachable from the cluster (check NetworkPolicies and DNS), object-store credentials mis-scoped (the bucket policy must allow the service account), or the secrets-backend reference unresolvable (the workload identity isn't authorized to read the named secret).

---

## 4. First run — produce and verify a signed artifact

```bash
# Trigger a manual run for the default tenant. Smoke runs typically complete in
# 10-60 minutes depending on seed surface size and which collectors are enabled.
kubectl exec -n expose deploy/expose-control-plane -- \
    expose run trigger --tenant default --reason "first-smoke-run"
```

```bash
# Watch the run progress. Run state transitions: queued -> running -> completed | failed.
kubectl exec -n expose deploy/expose-control-plane -- \
    expose run status --tenant default --follow
```

```bash
# List artifacts. Each successful run materializes:
#   runs/{tenant_id}/{run_id}/canonical.json.gz       (the deliverable)
#   runs/{tenant_id}/{run_id}/canonical.json.gz.sig   (detached cosign signature)
#   runs/{tenant_id}/{run_id}/manifest.json           (smaller, quickly inspectable)
kubectl exec -n expose deploy/expose-control-plane -- \
    expose artifact list --tenant default
```

```bash
# Pull the artifact bundle locally (control plane proxies object-store access).
mkdir -p ./first-run/
kubectl exec -n expose deploy/expose-control-plane -- \
    expose artifact get --tenant default --run-id <<run_id>> --output - | tar -x -C ./first-run/
ls ./first-run/
# canonical.json.gz  canonical.json.gz.sig  manifest.json
```

```bash
# Verify the signature with cosign. Keyless verification (production):
cosign verify-blob ./first-run/canonical.json.gz \
    --signature ./first-run/canonical.json.gz.sig \
    --certificate-identity-regexp '^https://github.com/korlogos/expose/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Or keypair verification (lab, with operator-controlled key):
cosign verify-blob ./first-run/canonical.json.gz \
    --signature ./first-run/canonical.json.gz.sig \
    --key cosign.pub
```

A successful verification prints `Verified OK`. If verification fails, **do not consume the artifact** — file a SECURITY.md disclosure rather than ignoring it; signature failures on EXPOSE artifacts are a high-severity event by design.

---

## 5. Reading the artifact

The artifact conforms to `schemas/canonical-artifact-v1.json`. Decompress it once and inspect the top-level fields with `jq`:

```bash
gunzip -k ./first-run/canonical.json.gz
jq 'keys' ./first-run/canonical.json
```

The fields you should look at first, in order:

1. **`run`** — `run_id`, `started_at`, `completed_at`, `pipeline_version`, `rule_pack_version`, `scope_version`. This is your audit trail. Record `run_id` and `pipeline_version` whenever you reference findings downstream.

2. **`outside_authorized_scope_summary`** — Aggregated count and structured breakdown of attribution events that operated outside your tenant authorization scope. **An empty or near-empty summary is the healthy state for a properly-scoped tenant.** A non-trivial summary is a signal that either your scope is too narrow (legitimate assets you missed) or your seeds are pulling in third-party assets (a data quality / scope-drift issue). Investigate either way; do not silence.

3. **`collector_health`** — Which collectors succeeded, which failed, which were rate-limited. A collector failure does not abort the run (per SPEC §6.5); it degrades it. Watch this field over multiple runs to spot collector-provider degradations early.

4. **`targets`** — The attributed external attack surface, one record per target. Filter by `attribution.tier` to focus your review. The four tiers are:
   - **`confirmed`** (deep-blue): cloud-account-authoritative or equivalently strong evidence. Trust without analyst review for most workflows.
   - **`high`**: multiple corroborating signals. Trust for active probing, monitoring, lead-prioritization.
   - **`medium`**: one strong signal or several weak ones. Surface for analyst review, but a sensible default for most CTEM dashboards.
   - **`requires_review`**: ambiguous. Flagged for Environment 2 analyst workflow (see SPEC §2.1). The `requires_analyst_review: true` flag combined with `review_reasons` tells you why.

5. **`delta_from_previous_run`** — `added`, `removed`, `changed` against the previous run. Removal reasons are structured (per SPEC §9.3); the distinction between `no_longer_observed` and `removal_uncertain_collector_failure` matters — never react to the latter as if assets disappeared.

6. **`targets[].lead_score`** — A numeric 0-100 score per target, computed deterministically from the rule pack's lead-score formula. Higher = more interesting. **Use this as a sort key, not as an authoritative risk score** — it is a triage prioritizer, not a risk model.

A tight quick-look query:

```bash
jq '{
  run: .run.run_id,
  by_tier: (.targets | group_by(.attribution.tier) | map({tier: .[0].attribution.tier, count: length})),
  scope_warnings: (.outside_authorized_scope_summary // {}),
  collector_failures: [.collector_health.collectors[] | select(.status != "ok") | .collector_id]
}' ./first-run/canonical.json
```

---

## 6. Common operations

### Resize worker pools

Workers are stateless (per SPEC §4.2). Scale up the pool that is bottlenecking your run.

```bash
# Collector workers — scale when external-API throughput is the bottleneck.
helm upgrade expose ./deploy/helm-chart \
    --namespace expose --reuse-values \
    --set collectorWorker.replicaCount=4

# Scanner workers — scale when active probing is the bottleneck.
helm upgrade expose ./deploy/helm-chart \
    --namespace expose --reuse-values \
    --set scannerWorker.replicaCount=2

# LLM workers — scale when LLM enrichment latency dominates run duration.
helm upgrade expose ./deploy/helm-chart \
    --namespace expose --reuse-values \
    --set llmWorker.enabled=true --set llmWorker.replicaCount=2
```

### Update the rule pack

Rule packs are data, not code (per SPEC §8.2). Bump the version reference in tenant config:

```bash
# Edit tenant-config.yaml — change rule_pack.pack_version to the new version.
$EDITOR tenant-config.yaml

# Apply via Helm upgrade (or the Phase 3 admin API once it lands).
helm upgrade expose ./deploy/helm-chart \
    --namespace expose --reuse-values \
    --values tenant-config.yaml

# The next run uses the new rule pack. Compare attribution decisions with the
# previous run via delta_from_previous_run to spot rule-pack regressions.
```

### Update tenant authorization scope

Scope changes appear in the artifact's `scope_version` field and produce structured `removed` deltas with reason `scope_changed_now_outside` for assets newly excluded.

```bash
# Edit authorization_scope in tenant-config.yaml. Common changes:
#   - Add a new apex domain after M&A.
#   - Tighten enforcement_mode from medium to hard.
#   - Add a registrant_patterns entry to capture a subsidiary.

helm upgrade expose ./deploy/helm-chart \
    --namespace expose --reuse-values \
    --values tenant-config.yaml
```

### Rotate collector or LLM-provider credentials

Credentials live in your secrets backend, not in EXPOSE. Rotation happens at the backend; EXPOSE picks up the new credential on its next just-in-time fetch (per SPEC §6.4). No restart needed unless your backend caches.

```bash
# Example for AWS Secrets Manager:
aws secretsmanager update-secret \
    --secret-id expose/tenant-default/collectors \
    --secret-string '{"securitytrails_api_key":"<<rotated-securitytrails-api-key>>"}'

# Verify the next collector run picks up the new credential.
kubectl exec -n expose deploy/expose-control-plane -- \
    expose collector health --tenant default
```

### Debug a failing collector

Failed collectors degrade runs; they do not abort them. The artifact's `collector_health` records the failure structure.

```bash
# Get the structured failure for the most recent run.
kubectl exec -n expose deploy/expose-control-plane -- \
    expose collector health --tenant default --run-id <<run_id>> --format json | \
    jq '.collectors[] | select(.status != "ok")'

# Inspect collector worker logs for the time window of the failed run.
kubectl logs -n expose -l app.kubernetes.io/component=collector-worker \
    --since=2h --tail=500 | grep -i 'collector_id=ct-crtsh'
```

Common causes: API key rotated but backend not updated, rate limits exceeded for the day, upstream provider outage, network egress blocked. The artifact distinguishes these via `collector_health.collectors[].status_reason`.

### Verify retention pruning

Non-yours observations are pruned from the graph after `retention.incidental_days` days (default 30) per SPEC §5.5. To confirm pruning is running:

```bash
# Inspect retention summary.
kubectl exec -n expose deploy/expose-control-plane -- \
    expose retention status --tenant default

# Force an immediate pruning pass (admin operation; logged in audit log).
kubectl exec -n expose deploy/expose-control-plane -- \
    expose retention prune --tenant default --reason "operator-initiated-verification"
```

---

## 7. Where to go next

| You are | Read |
|---------|------|
| **A federal agency operator** | `docs/strategy/federal-customer-deployment-guide.md` — the FedRAMP-ready, ATO-bounded, 3PAO-aware deployment playbook. |
| **A red team lead operating per-engagement tenants** | `examples/seeds/consulting-engagement.yaml` and `examples/scope/hard-mode-regulated.yaml` for the per-client tenant pattern. |
| **A researcher evaluating attribution methodology** | `examples/seeds/research-test-bed.yaml` and `examples/scope/soft-mode-research.yaml`. The eval harness in Phase 2 (per SPEC §11.2) will be the next thing you want once it lands. |
| **A CTEM team integrating with a SIEM** | SPEC §10.2 (Observability) for the OTLP integration; SPEC §9 (Artifact generation) for the ingestion contract. |
| **An operator hitting comprehensive-ops questions** | SPEC §10 (Operations) — the operator-facing surface in the spec. |
| **An operator with deeper questions than this guide answers** | The FAQ below; the SECURITY.md disclosure path for security questions; the GitHub Discussions for everything else. |

---

## 8. FAQ

**Q. Can I run EXPOSE without a Postgres or object store?**
No. State is externalized by design (per `docs/adr/ADR-003-deployment-posture.md`). The chart can stand up an in-cluster Postgres and MinIO for lab/dev (`postgres.enabled: true`, `objectStorage.enabled: true`), but production deployments must point at managed services for backup, HA, and operational hygiene.

**Q. Can I run EXPOSE air-gapped?**
The pipeline itself cannot run air-gapped — it requires internet egress to CT logs, passive DNS, internet-wide scan APIs, etc. (per SPEC §1.2). The **artifact** can be transported to air-gapped environments for downstream Environment 2 analysis.

**Q. Can I disable LLM enrichment entirely?**
Yes. Set `llmWorker.enabled: false` (the default for v1). Phase 1 produces a signed artifact without LLM enrichment. LLM enrichment is a Phase 2 deliverable (per SPEC §11.2).

**Q. How do I run EXPOSE for multiple clients (multi-tenant)?**
The data layer is multi-tenant from day one (per `docs/adr/ADR-007-multi-tenancy.md`), but v1 ships with a hardcoded single `default` tenant. Tenant lifecycle management is a Phase 3 production-hardening deliverable. For v1, run N deployments. Plan for the migration when the admin API lands.

**Q. What happens if I configure scope wrong and EXPOSE attributes someone else's assets to me?**
The medium-mode default flags this in `outside_authorized_scope_summary` and on per-target `review_reasons` (per `docs/adr/ADR-008-authorized-use-and-ethics.md`). It does not block. Hard mode refuses active probing of out-of-scope assets but still allows passive collection. Soft mode logs only. **Choose your enforcement mode deliberately** — see `examples/scope/`.

**Q. Why doesn't EXPOSE produce a CVE list / vulnerability report?**
Because it is not a vulnerability scanner. EXPOSE produces leads and tech-stack fingerprints; downstream toolchains (Nuclei, Burp Suite, manual analysis) are different categories explicitly out of scope per SPEC §1.2. The signed artifact is designed to feed those tools, not replace them.

**Q. Why is my LLM cost ceiling tripping after a few runs?**
The default ceiling is `$5.00 USD per run` (configurable per tenant). Costs accumulate via prompt/completion tokens for `medium` and `requires_review` candidates. Tighten the ceiling, switch the provider to Ollama-local, or narrow the `enrichment_policy` to fewer candidate categories. Cost trends are emitted as OpenTelemetry metrics; build a dashboard before the surprise bill.

**Q. The artifact says `removal_uncertain_collector_failure` for half my assets — what do I do?**
A primary collector failed this run. The asset has not gone away; the collector that proves it exists has gone away. Investigate the collector (logs, provider status page, rate limits, credentials). Do not page the on-call about disappearing assets.

**Q. How do I make EXPOSE produce a partition I can hand to a specific tool?**
The artifact ships with optional derived partition views (per SPEC §9.1) — `partitions/by-cloud-provider/aws.json`, `partitions/by-tier/confirmed.json`. These are filtered subsets of the canonical file and are not signed independently. For custom partitions, run `jq` against `canonical.json`.

**Q. How do I diff two runs?**
The artifact's `delta_from_previous_run` is the supported diff. For arbitrary inter-run comparisons (e.g., this week vs. last week), `jq` against two `canonical.json` files is the path until a `expose diff` command lands.

**Q. Where do I find the example rule pack?**
`examples/rulepacks/example-baseline.json` ships in the repo. Custom rule packs live in your own repository (or the private rule-pack repository per `docs/adr/ADR-006-repository-and-licensing.md`). Reference them by `pack_id` and `pack_version` in tenant config.

**Q. Can I run EXPOSE against assets I don't own without authorization?**
**No.** Read `ETHICS.md` and `docs/adr/ADR-008-authorized-use-and-ethics.md`. The medium-mode default warns; the tool cannot prevent misuse, but the project does not exist to facilitate it. Authorization scope is the operator's responsibility.

---

## 9. Where to file issues, request features, get help

| What you have | Where it goes |
|---------------|---------------|
| **Bug report or feature request** | GitHub Issues at `https://github.com/korlogos/expose/issues`. Include `pipeline_version` from the artifact, your Helm chart version, and a minimal reproduction. |
| **Security disclosure** | `SECURITY.md` — coordinated disclosure with PGP-encrypted email. **Do not file security issues in public GitHub Issues.** |
| **Question about the spec or operator workflow** | GitHub Discussions at `https://github.com/korlogos/expose/discussions`. |
| **Custom rule pack work or paid integration** | Korlogos / Pitt Street Labs commercial inquiry per `docs/adr/ADR-009-commercial-structure.md`. |
| **Federal-deployment specific questions** | Read `docs/strategy/federal-customer-deployment-guide.md` first; sponsoring-agency engagement model in §2 of that doc. |

This is a pre-release operator guide. Friction points you hit and document are unusually valuable feedback at this stage of the project — file them.

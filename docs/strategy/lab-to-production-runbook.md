# EXPOSE -- Lab-to-Production Migration Runbook

**Status:** Advisory -- not locked. Open for revision in subsequent sessions.
**Date:** 2026-05-10
**Author context:** AI-assisted operational runbook derived from the locked spec-phase artifacts, the Postgres deployment guide (`docs/strategy/postgres-deployment-guide.md`), the Federal Customer Deployment Guide (`docs/strategy/federal-customer-deployment-guide.md`), the Helm chart skeleton (`deploy/helm-chart/`), the Dockerfile, CI pipeline, cosign keypair documentation, and Wave 1 implementation (broker, crypto, repositories, retention pruner, secrets).
**Public name:** EXPOSE / **Internal codename:** FF6K
**Addresses:** Gitea issue #13

This runbook covers the full migration path from the Pitt Street Labs environment (z590 workstation, Node1/Node2 servers) to a production Kubernetes deployment with managed backing services. It is checklist-oriented for operators executing the migration.

---

## 1. Pre-migration checklist

Complete every item before provisioning production infrastructure.

### 1.1 PostgreSQL

| Item | Requirement | Verification |
|------|-------------|--------------|
| Version | PostgreSQL 16+ (minimum 14; see `postgres-deployment-guide.md` section 3.1) | `SELECT version();` |
| Extensions | `uuid-ossp`, `pg_trgm` | `\dx` in psql |
| Sizing | Match scale tier in `postgres-deployment-guide.md` section 4 (Small: 2 vCPU / 8 GB; Medium: 4 vCPU / 16 GB; Large: managed HA) | Provider console |
| TLS | TLS 1.2+ enforced; `sslmode: require` minimum, `verify-full` for self-managed or FedRAMP | Connection test with `psql "sslmode=require"` |
| Connection pool budget | `max_connections >= (replicas * (pool_size + max_overflow)) + 20` | `SHOW max_connections;` |
| Backup | Automated daily snapshots with PITR enabled; retention per `postgres-deployment-guide.md` section 5.4 | Provider backup console |
| Encryption at rest | KMS-managed (required for FedRAMP per ADR-010) | Provider encryption settings |
| Separate users | `expose` (runtime, minimal privileges) and `expose_migrate` (Alembic, DDL rights) per `postgres-deployment-guide.md` section 8.1 | `\du` in psql |

### 1.2 NATS JetStream

| Item | Requirement | Verification |
|------|-------------|--------------|
| Cluster size | Minimum 3-node cluster for production (R=3 replication); single node acceptable for pilot | `nats server list` |
| Persistence | File-based storage enabled; storage directory on durable volume (SSD recommended) | `nats server info` -- check `jetstream.store_dir` |
| TLS | mTLS between cluster peers; TLS for client connections | `nats server check connection --tls-required` |
| Authentication | NKey or JWT-based auth; token auth for lab only | Server config `authorization {}` block |
| Stream retention | `WorkQueuePolicy` per `src/expose/broker/stream_setup.py`; max age 7 days; max bytes sized to workload | `nats stream info EXPOSE` |
| Memory limits | JetStream max memory + max file storage configured per node | `nats server info` -- check `jetstream.max_mem`, `jetstream.max_file` |
| Monitoring | Prometheus exporter enabled (`-m 8222` or NATS surveyor) | `curl http://nats:8222/varz` |
| Subject namespace | `expose.runs.dispatch.<tenant_id>.<collector_id>` pattern per broker package | Stream config subjects match `SUBJECT_PATTERN` |

### 1.3 Object storage

| Item | Requirement | Verification |
|------|-------------|--------------|
| Provider | S3-compatible: AWS S3, GCS (interop mode), Azure Blob (S3 gateway), MinIO (self-managed) | SDK connectivity test |
| Bucket | `expose-artifacts` (configurable via `values.yaml` `objectStorage.bucket`) | `aws s3 ls s3://expose-artifacts/` or equivalent |
| Versioning | Enabled -- protects against accidental overwrites of signed artifacts | Bucket versioning status |
| Encryption at rest | SSE-KMS (AWS), CMEK (GCS), or SSE with customer-managed key | Bucket encryption config |
| Lifecycle policy | Transition to IA/Nearline after 90 days; delete after retention period (align with ETHICS.md quarterly review) | Lifecycle rules |
| IAM | Dedicated service account with `s3:GetObject`, `s3:PutObject`, `s3:ListBucket`, `s3:DeleteObject` only on the EXPOSE bucket | IAM policy review |
| CORS | Disabled unless API-served downloads are required | Bucket CORS config |
| Public access | Blocked -- `BlockPublicAccess` (AWS), `uniformBucketLevelAccess` (GCS) | Bucket access policy |

### 1.4 Container registry

| Item | Requirement | Verification |
|------|-------------|--------------|
| Registry | GHCR (`ghcr.io/korlogos`), ECR, ACR, or self-hosted Harbor | `docker pull` test |
| Image signing | Cosign keypair generated per `deploy/cosign-keypair-setup.md`; keyless (OIDC) for GitHub Actions CI | `cosign verify --key cosign.pub <image>` |
| Image scanning | Trivy or equivalent integrated in CI (pre-push gate) | CI pipeline logs |
| Pull secret | `imagePullSecrets` configured in `values.yaml` | `kubectl get secret` |
| Tag policy | Immutable tags recommended; no `:latest` in production | Registry tag immutability setting |

### 1.5 DNS

| Item | Requirement | Verification |
|------|-------------|--------------|
| API endpoint | A/CNAME record for `expose-api.<domain>` pointing to ingress LB | `dig expose-api.<domain>` |
| Observability | A/CNAME for `expose-metrics.<domain>` if externally accessible | `dig expose-metrics.<domain>` |
| TTL | 300s during migration (lower for faster failover); raise to 3600s post-validation | DNS record TTL |
| Health check | External health check on the API endpoint (Route53 health check, Cloud DNS, or UptimeRobot) | Health check status |

### 1.6 TLS

| Item | Requirement | Verification |
|------|-------------|--------------|
| Certificate provisioning | cert-manager with Let's Encrypt (ClusterIssuer) or Enterprise CA (Korlogos CA per lab convention) | `kubectl get clusterissuer` |
| Minimum TLS version | 1.2 (1.3 preferred); FIPS-approved cipher suites for federal deployments per ADR-010 | `openssl s_client -connect <host>:443` |
| Certificate rotation | Automated via cert-manager; 30-day renewal window | cert-manager certificate status |
| Internal service mesh | mTLS via Istio/Linkerd or native NATS TLS for inter-pod traffic (recommended, not required for v1) | Service mesh status |

### 1.7 Secrets management

| Item | Requirement | Verification |
|------|-------------|--------------|
| Backend | HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager per `values.yaml` `secretsBackend.type` | Backend health check |
| Kubernetes integration | External Secrets Operator (ESO) or Vault Agent Injector syncing secrets to Kubernetes Secrets | `kubectl get externalsecret` |
| Credentials to store | Postgres password, NATS credentials, object storage keys, cosign private key, collector API keys (Censys, Shodan, SecurityTrails, etc.), LLM provider keys (Phase 2) | Secret inventory audit |
| Rotation schedule | 90-day rotation for service accounts; 30-day for collector API keys; immediate on compromise | Rotation policy documented |
| Audit logging | All secret access logged (Vault audit log, CloudTrail, Activity Log) | Audit log query |

---

## 2. Infrastructure provisioning

### 2.1 Kubernetes cluster

| Requirement | Specification |
|-------------|---------------|
| Provider | EKS (AWS), AKS (Azure), GKE (GCP), or self-managed (kubeadm/k3s) |
| Version | >= 1.28 (per `Chart.yaml` `kubeVersion`) |
| Node pool (control plane + workers) | Minimum: 3 nodes, 4 vCPU / 16 GB each; scale per tenant count |
| CNI | Calico, Cilium, or provider default with NetworkPolicy support |
| Storage class | gp3 (AWS), Premium SSD (Azure), SSD PD (GCP) for PVCs |
| Autoscaling | Cluster Autoscaler or Karpenter; HPA on worker deployments |
| Pod security | Pod Security Standards `restricted` profile enforced at namespace level |

### 2.2 Namespace and RBAC

Create a dedicated namespace with least-privilege RBAC.

```bash
# Create namespace
kubectl create namespace expose

# Apply Pod Security Standard
kubectl label namespace expose \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted
```

RBAC roles:

| Role | Scope | Binds to |
|------|-------|----------|
| `expose-control-plane` | Pods, ConfigMaps, Secrets (read), Jobs (create for migrations) | `expose-control-plane` ServiceAccount |
| `expose-worker` | Pods (self), Secrets (read -- credentials only) | `expose-collector-worker`, `expose-scanner-worker` ServiceAccounts |
| `expose-admin` | Full namespace access | Operator user/group |
| `expose-readonly` | Get/list on all EXPOSE resources | Monitoring, audit |

### 2.3 NetworkPolicy

The Helm chart ships a default-deny policy (`deploy/helm-chart/templates/networkpolicy.yaml`). Add component-specific allow rules:

| Source | Destination | Port | Purpose |
|--------|-------------|------|---------|
| `expose-control-plane` | Postgres | 5432 | Database access |
| `expose-control-plane` | NATS | 4222 | Job dispatch |
| `expose-control-plane` | Object storage | 443 | Artifact writes |
| `expose-*-worker` | NATS | 4222 | Job consumption |
| `expose-collector-worker` | External APIs (CT, DNS, Censys, Shodan) | 443 | Data collection |
| `expose-scanner-worker` | Egress proxy or direct (per `egressProfile`) | Configured | Active probing |
| `expose-collector-worker` | Secrets backend | 443/8200 | Credential fetch |
| Ingress controller | `expose-control-plane` | 8000 | API traffic |
| Prometheus | All EXPOSE pods | 9090 | Metrics scrape |
| All EXPOSE pods | DNS (kube-dns) | 53 | Name resolution |

Deny all other ingress and egress. Federal deployments per ADR-008 should additionally restrict `expose-scanner-worker` egress to only the tenant's authorized scope CIDRs.

### 2.4 Resource limits and requests

From `values.yaml` defaults -- adjust per observed load:

| Component | CPU request | CPU limit | Memory request | Memory limit | Replicas |
|-----------|-------------|-----------|----------------|--------------|----------|
| `control-plane` | 200m | 1000m | 512Mi | 2Gi | 1 (HA: 2+) |
| `collector-worker` | 100m | 500m | 256Mi | 1Gi | 2 |
| `scanner-worker` | 100m | 500m | 256Mi | 1Gi | 1 |
| `llm-worker` (Phase 2) | 200m | 2000m | 1Gi | 4Gi | 1 |
| Init container (migrate) | 100m | 500m | 256Mi | 512Mi | Job |

Set resource quotas on the namespace to prevent runaway:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: expose-quota
  namespace: expose
spec:
  hard:
    requests.cpu: "8"
    requests.memory: "16Gi"
    limits.cpu: "16"
    limits.memory: "32Gi"
    pods: "20"
```

---

## 3. Data migration

### 3.1 Lab Postgres to production Postgres

**Pre-flight:**

- [ ] Verify lab Alembic version: `alembic current` (expect `0001_initial_schema` as of Wave 1)
- [ ] Verify production Postgres is reachable from migration host
- [ ] Verify production database `expose` exists with correct user/permissions

**Export from lab:**

```bash
# On lab host (z590 or Node1/Node2)
pg_dump \
  --format=custom \
  --no-owner \
  --no-privileges \
  --verbose \
  --dbname=expose \
  --file=expose-lab-$(date +%Y%m%d).dump
```

**Import to production:**

```bash
# From migration host with access to production Postgres
pg_restore \
  --format=custom \
  --no-owner \
  --no-privileges \
  --role=expose \
  --verbose \
  --dbname=expose \
  expose-lab-$(date +%Y%m%d).dump
```

**Post-import verification:**

- [ ] `alembic current` on production matches lab revision
- [ ] Row counts match: `SELECT COUNT(*) FROM tenants; SELECT COUNT(*) FROM entities; SELECT COUNT(*) FROM relationships; SELECT COUNT(*) FROM runs;`
- [ ] Tenant UUIDs match lab: `SELECT id, name FROM tenants;`
- [ ] No orphaned relationships: `SELECT COUNT(*) FROM relationships r LEFT JOIN entities e ON r.source_id = e.id WHERE e.id IS NULL;` (expect 0)

### 3.2 Schema version verification

```bash
# In the EXPOSE container or from a workstation with the codebase
alembic current    # Shows applied migration(s)
alembic history    # Shows full chain
alembic check      # Verifies head matches applied (exits 0 if up-to-date)
```

If the production schema is behind lab, run `alembic upgrade head` via the Helm init container or manually before starting pods.

### 3.3 Evidence blob migration

Lab stores evidence blobs on local filesystem. Production uses S3-compatible object storage.

**Migration steps:**

- [ ] Inventory lab evidence: `find /path/to/lab/evidence -type f | wc -l`
- [ ] Compute checksums: `find /path/to/lab/evidence -type f -exec sha256sum {} \; > evidence-checksums.txt`
- [ ] Upload to object storage (preserve content-hash key structure):

```bash
aws s3 sync \
  /path/to/lab/evidence \
  s3://expose-artifacts/evidence/ \
  --storage-class STANDARD \
  --metadata-directive COPY \
  --checksum-algorithm SHA256
```

- [ ] Verify upload count matches inventory
- [ ] Spot-check 10 random blobs: download, compare SHA-256 against `evidence-checksums.txt`
- [ ] Update evidence location references if stored in database (depends on implementation -- check `src/expose/repositories/` for path-vs-key storage)

### 3.4 Tenant configuration migration

- [ ] Export tenant configs from lab database: `SELECT id, name, config FROM tenants;`
- [ ] Review and update tenant-specific settings for production (authorization scope CIDRs, collector API key references, run schedule)
- [ ] Apply via the EXPOSE admin API or direct SQL insert (Phase 3 admin API; direct SQL for v1)

---

## 4. Helm deployment

### 4.1 values.yaml configuration

Create a `values-production.yaml` overlay. Do not commit secrets to source control.

```yaml
global:
  imageRegistry: "ghcr.io/korlogos"   # Or internal registry
  imagePullSecrets:
    - name: expose-registry-creds

image:
  repository: expose
  tag: "v1.0.0"                        # Pin to release tag, never :latest

# -- State services (external, operator-managed) --
postgres:
  enabled: false                       # NEVER true in production
  host: "expose-db.cxxxxxx.us-east-1.rds.amazonaws.com"
  port: 5432
  database: "expose"
  existingSecret: "expose-postgres-credentials"
  sslmode: "require"

objectStorage:
  enabled: false                       # NEVER true in production
  endpoint: "https://s3.us-east-1.amazonaws.com"
  bucket: "expose-artifacts"
  region: "us-east-1"
  existingSecret: "expose-s3-credentials"

secretsBackend:
  type: "aws-secrets-manager"          # Or: vault, azure-key-vault, gcp-secret-manager
  config:
    region: "us-east-1"

# -- Replicas and resources (adjust per scale tier) --
controlPlane:
  replicaCount: 2                      # HA for production
  resources:
    requests: { cpu: "500m", memory: "1Gi" }
    limits:   { cpu: "2000m", memory: "4Gi" }

collectorWorker:
  replicaCount: 3
  resources:
    requests: { cpu: "200m", memory: "512Mi" }
    limits:   { cpu: "1000m", memory: "2Gi" }

scannerWorker:
  replicaCount: 2
  egressProfile:
    type: "socks5"                     # Or: wireguard, http_connect
    config:
      proxy: "socks5://egress-proxy.expose.svc:1080"

# -- Observability --
observability:
  otlp:
    enabled: true
    endpoint: "otlp://otel-collector.observability.svc:4317"
    insecure: false

# -- Network and security --
networkPolicies:
  enabled: true
  defaultDeny: true

ingress:
  enabled: true
  className: "nginx"                   # Or: alb, traefik, istio
  hosts:
    - host: "expose-api.example.com"
      paths:
        - path: /
          pathType: Prefix

# -- Run scheduling --
runSchedule:
  defaultCron: "0 2 * * *"            # 02:00 UTC daily
```

### 4.2 Secrets injection

Before deploying, create Kubernetes Secrets (or configure ESO to sync from the secrets backend):

```bash
# Postgres credentials
kubectl create secret generic expose-postgres-credentials \
  --namespace expose \
  --from-literal=user=expose \
  --from-literal=password="$(vault kv get -field=password secret/expose/postgres)"

# Object storage credentials
kubectl create secret generic expose-s3-credentials \
  --namespace expose \
  --from-literal=access-key-id="$(vault kv get -field=access_key secret/expose/s3)" \
  --from-literal=secret-access-key="$(vault kv get -field=secret_key secret/expose/s3)"

# NATS credentials
kubectl create secret generic expose-nats-credentials \
  --namespace expose \
  --from-literal=nkey="$(vault kv get -field=nkey secret/expose/nats)"

# Registry pull secret (if private registry)
kubectl create secret docker-registry expose-registry-creds \
  --namespace expose \
  --docker-server=ghcr.io \
  --docker-username=korlogos \
  --docker-password="$(vault kv get -field=token secret/expose/ghcr)"
```

For External Secrets Operator, create `ExternalSecret` resources instead:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: expose-postgres-credentials
  namespace: expose
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: expose-postgres-credentials
  data:
    - secretKey: user
      remoteRef:
        key: secret/expose/postgres
        property: user
    - secretKey: password
      remoteRef:
        key: secret/expose/postgres
        property: password
```

### 4.3 Rollout strategy

**Initial deployment (fresh cluster):**

```bash
helm install expose deploy/helm-chart/ \
  --namespace expose \
  --values values-production.yaml \
  --wait --timeout 10m
```

**Upgrades (rolling update, zero-downtime):**

```bash
helm upgrade expose deploy/helm-chart/ \
  --namespace expose \
  --values values-production.yaml \
  --wait --timeout 10m \
  --atomic                            # Auto-rollback on failure
```

**Canary rollout (with Argo Rollouts):**

If Argo Rollouts is installed, convert the control-plane Deployment to a Rollout with a canary strategy:

| Step | Weight | Pause |
|------|--------|-------|
| 1 | 10% | 5 minutes (manual promote or auto) |
| 2 | 25% | 5 minutes |
| 3 | 50% | 5 minutes |
| 4 | 100% | -- |

Analysis template: verify p95 latency < 500ms and error rate < 1% at each step before promotion.

### 4.4 Health check verification

After deployment, verify all pods are healthy:

```bash
# All pods running
kubectl get pods -n expose -o wide

# Control plane health endpoint
kubectl exec -n expose deploy/expose-control-plane -- \
  curl -sf http://localhost:8000/health

# Check init container migration completed
kubectl logs -n expose deploy/expose-control-plane -c migrate

# Alembic version in production
kubectl exec -n expose deploy/expose-control-plane -- \
  alembic current

# NATS stream exists with correct config
kubectl exec -n expose deploy/expose-control-plane -- \
  python -c "from expose.broker import STREAM_NAME; print(STREAM_NAME)"
```

---

## 5. Post-migration validation

### 5.1 Smoke test

Execute in order. Each step depends on the previous.

| Step | Action | Expected result | Command / verification |
|------|--------|-----------------|----------------------|
| 1 | Verify API reachable | HTTP 200 on health endpoint | `curl -sf https://expose-api.example.com/health` |
| 2 | Verify database connectivity | Alembic current shows correct revision | `alembic current` via exec |
| 3 | Verify NATS connectivity | Stream `EXPOSE` exists, consumer `EXPOSE_WORKER` active | `nats stream info EXPOSE` |
| 4 | Verify object storage connectivity | Test write + read + delete on `expose-artifacts` bucket | Write test object, read back, compare, delete |
| 5 | Create test tenant | Tenant row created in database | API call or direct SQL |
| 6 | Trigger test run | Run dispatched via NATS, collectors execute, observations written | API call; verify run record in `runs` table |
| 7 | Verify artifact generated | Canonical JSON artifact in object storage, signed with cosign | `cosign verify` on the artifact; download and validate against schema |
| 8 | Verify retention pruner | Pruner executes without error against test data | Check pruner logs or trigger manual run |
| 9 | Delete test tenant (cleanup) | Tenant and associated data removed | Direct SQL or admin API |

### 5.2 Observability verification

| Check | Method | Expected |
|-------|--------|----------|
| OTel traces flowing | Query trace backend (Tempo, X-Ray, Datadog) for `expose.*` service spans | Spans for run lifecycle, collector execution, DB queries visible |
| Metrics scraping | `curl http://<pod-ip>:9090/metrics` or Prometheus target status | EXPOSE metrics present in Prometheus |
| Log aggregation | Query log backend (Loki, CloudWatch Logs) for `namespace=expose` | Structured JSON logs from all components |
| Alert rules loaded | Check alerting backend for EXPOSE alert rules | Rules from section 7.1 are active |

### 5.3 Performance baseline

Capture these metrics during the first production run to establish baselines:

| Metric | Target | Measurement |
|--------|--------|-------------|
| API health check p95 latency | < 50ms | Load test with `hey` or `k6` |
| Full run duration (small tenant, passive-only) | < 30 minutes | Run timestamp delta |
| Full run duration (medium tenant, passive + active) | < 2 hours | Run timestamp delta |
| Collector job p95 latency | < 10 seconds per collector | OTel span duration |
| Database query p95 latency | < 200ms | `pg_stat_statements` or OTel |
| Artifact generation time | < 60 seconds for 10K entities | OTel span for Stage 5 |
| Memory high-water mark (control plane) | < 1.5 Gi | `kubectl top pod` |
| Memory high-water mark (collector worker) | < 768 Mi | `kubectl top pod` |

### 5.4 Backup verification

Execute a restore test within the first week of production:

- [ ] Provision a staging Postgres instance
- [ ] Restore the latest automated backup
- [ ] Apply WAL replay to verify PITR (target: within last 5 minutes)
- [ ] Run `alembic current` on restored instance
- [ ] Run EXPOSE health check against restored instance
- [ ] Record restore duration and compare against RTO target
- [ ] Destroy staging instance

Schedule this monthly going forward per `postgres-deployment-guide.md` section 5.3.

---

## 6. Rollback plan

### 6.1 Helm rollback

```bash
# View release history
helm history expose -n expose

# Roll back to previous release
helm rollback expose <REVISION> -n expose --wait --timeout 10m

# Verify pods are healthy after rollback
kubectl get pods -n expose
kubectl exec -n expose deploy/expose-control-plane -- \
  curl -sf http://localhost:8000/health
```

### 6.2 Database rollback

Only needed if the failed release included a schema migration.

```bash
# Check current applied migration
alembic current

# Roll back one migration
alembic downgrade -1

# Or roll back to a specific revision
alembic downgrade <target_revision>
```

**Warning:** Downgrades that drop columns or tables are destructive. Always verify the downgrade path in staging first. If a downgrade is not safe, restore from backup instead.

### 6.3 DNS failover to lab

If production is unrecoverable and lab is still operational:

| Step | Action | Duration |
|------|--------|----------|
| 1 | Lower DNS TTL to 60s (if not already low) | Propagation time |
| 2 | Update DNS A/CNAME to point to lab ingress | < 1 minute |
| 3 | Verify lab services are running | `curl` health check |
| 4 | Notify stakeholders via communication template (section 6.4) | Immediate |
| 5 | Investigate production failure | -- |
| 6 | Restore production, re-run data sync, re-point DNS | Post-investigation |

### 6.4 Stakeholder communication template

Use for any production incident requiring rollback or failover:

```
Subject: [EXPOSE] Production incident -- [BRIEF DESCRIPTION]
Severity: [P1/P2/P3]
Status: [Investigating / Mitigated / Resolved]

Impact:
- [What is affected -- runs paused, API unavailable, etc.]

Timeline:
- [HH:MM UTC] Issue detected
- [HH:MM UTC] Rollback initiated
- [HH:MM UTC] Service restored / failover active

Current state:
- [Running on lab / running on previous release / investigating]

Next update: [HH:MM UTC or "when resolved"]

Contact: [On-call engineer]
```

---

## 7. Operational handoff

### 7.1 Monitoring alerts to configure

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Pod crash loop | `kube_pod_container_status_restarts_total` increase > 3 in 15m | P1 | Investigate pod logs; check resource limits |
| Run failure | Run record with `status=failed` | P2 | Check control-plane logs; verify collector API keys valid |
| Database connection exhaustion | Active connections > 80% of `max_connections` | P2 | Scale down replicas or increase `max_connections` |
| Database query latency | p95 > 200ms sustained 5m | P3 | Check `pg_stat_statements`; vacuum if dead tuples high |
| NATS consumer lag | Pending messages > 1000 for 10m | P2 | Scale collector workers; check for stuck consumers |
| Object storage write failure | Any 5xx from object store | P2 | Check credentials, bucket policy, provider status |
| Certificate expiry | < 14 days to expiry | P3 | Verify cert-manager renewal; manual renewal if needed |
| OTel export failure | Exporter errors > 0 for 5m | P3 | Check OTel collector connectivity |
| Disk usage | PVC usage > 80% | P2 | Expand PVC or clean old data |
| Artifact signature failure | Cosign sign exits non-zero | P1 | Check cosign key availability; verify key not rotated |
| Retention pruner failure | Pruner job exits non-zero | P3 | Check pruner logs; verify DB connectivity |
| Authorization scope violation | `outside_authorized_scope` events in run artifacts | P2 (investigate) | Review tenant scope config; may indicate misconfiguration or genuine finding |

### 7.2 On-call runbook references

| Scenario | Reference |
|----------|-----------|
| Postgres issues (connections, latency, failover) | `docs/strategy/postgres-deployment-guide.md` sections 6-7 |
| Container image verification failure | `deploy/cosign-keypair-setup.md` |
| Federal deployment questions | `docs/strategy/federal-customer-deployment-guide.md` |
| Ethical use concerns / scope violations | `ETHICS.md` |
| Security vulnerability report | `SECURITY.md` |
| Schema migration issues | `docs/strategy/postgres-deployment-guide.md` section 6 |
| NATS broker issues | `src/expose/broker/` package docstring; NATS server docs |
| FIPS compliance questions | ADR-010; `src/expose/crypto/` package |

### 7.3 Credential rotation schedule

| Credential | Rotation interval | Method | Owner |
|------------|-------------------|--------|-------|
| Postgres password (`expose` user) | 90 days | Secrets backend rotation + restart pods | Platform team |
| Postgres password (`expose_migrate` user) | 90 days | Secrets backend rotation | Platform team |
| NATS NKey/JWT | 90 days | Regenerate + update secret + restart | Platform team |
| Object storage access key | 90 days | IAM key rotation + update secret | Platform team |
| Cosign private key password | 180 days | Regenerate keypair + re-sign current release | Release engineer |
| Collector API keys (Censys, Shodan, etc.) | 30 days or per provider policy | Provider console + update secrets backend | Security team |
| LLM provider keys (Phase 2) | 30 days | Provider console + update secrets backend | Security team |
| Registry pull token | 90 days | Registry console + update pull secret | Platform team |
| Vault/KMS service account | 90 days | Cloud IAM rotation | Platform team |

On compromise of any credential: rotate immediately, audit access logs, notify stakeholders.

### 7.4 Quarterly review schedule

Per ETHICS.md and ADR-008, conduct quarterly reviews covering:

| Review item | Frequency | Owner | Tracking |
|-------------|-----------|-------|----------|
| Authorization scope accuracy | Quarterly | Security team | Gitea issue per review |
| Retention policy compliance (incidental data pruning) | Quarterly | Platform team | Pruner run reports |
| Credential rotation compliance | Quarterly | Platform team | Rotation log audit |
| Backup restore test | Monthly | Platform team | Restore test records |
| Dependency vulnerability scan | Weekly (automated) + quarterly manual review | Security team | CI pipeline + manual audit |
| ETHICS.md obligations review | Quarterly | Project lead | Gitea issue #35 |
| Performance baseline comparison | Quarterly | Platform team | Dashboard comparison |
| Cost review (LLM spend, infra, API keys) | Quarterly | Project lead | Cost report |

---

## Appendix A: Migration day timeline

Suggested execution order for a planned migration window.

| Time | Action | Duration | Rollback point |
|------|--------|----------|----------------|
| T-7d | Complete pre-migration checklist (section 1) | -- | -- |
| T-3d | Provision production infrastructure (section 2) | -- | -- |
| T-2d | Deploy to production with lab data excluded; run smoke tests against empty DB | 2h | Tear down cluster |
| T-1d | Final lab backup; freeze lab changes | 1h | -- |
| T+0h | Begin data migration (section 3) | 2-4h | Abort; lab unchanged |
| T+4h | Schema verification + evidence blob migration | 1-2h | Restore from backup |
| T+6h | Helm deploy with production values (section 4) | 30m | `helm rollback` |
| T+7h | Post-migration validation (section 5) | 1-2h | Rollback to lab |
| T+9h | DNS cutover to production | 15m | DNS failover (section 6.3) |
| T+10h | Monitor first production run | 2h | Rollback to lab |
| T+12h | Declare migration complete; raise DNS TTL | 5m | -- |

**Total estimated window: 12 hours.** Schedule during low-activity period. Keep lab operational for 7 days post-migration as hot standby.

---

## Appendix B: Environment variable reference

All EXPOSE configuration via 12-factor environment variables (per ADR-003):

| Variable | Default | Production recommendation |
|----------|---------|--------------------------|
| `EXPOSE_DB_HOST` | `localhost` | Managed Postgres endpoint |
| `EXPOSE_DB_PORT` | `5432` | `5432` |
| `EXPOSE_DB_DATABASE` | `expose` | `expose` |
| `EXPOSE_DB_USER` | `expose` | `expose` (via Secret) |
| `EXPOSE_DB_PASSWORD` | (empty) | Via Secret, never inline |
| `EXPOSE_DB_SSLMODE` | `prefer` | `require` or `verify-full` |
| `EXPOSE_DB_POOL_SIZE` | `10` | Tune per replica count |
| `EXPOSE_DB_MAX_OVERFLOW` | `20` | Tune per replica count |
| `EXPOSE_DB_POOL_PRE_PING` | `true` | `true` |
| `EXPOSE_DB_ECHO` | `false` | `false` (NEVER `true` in production) |
| `EXPOSE_LOG_LEVEL` | `info` | `info` (`debug` only for troubleshooting) |
| `EXPOSE_NATS_URL` | `nats://localhost:4222` | NATS cluster URL |
| `EXPOSE_OBJECT_STORAGE_ENDPOINT` | (empty) | S3-compatible endpoint |
| `EXPOSE_OBJECT_STORAGE_BUCKET` | `expose-artifacts` | Production bucket name |
| `EXPOSE_FIPS_MODE` | `false` | `true` for federal deployments |

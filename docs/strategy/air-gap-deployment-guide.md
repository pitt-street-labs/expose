# EXPOSE -- Air-Gap Deployment Guide

**Status:** Advisory -- not locked. Open for revision in subsequent sessions.
**Date:** 2026-05-10
**Author context:** AI-assisted synthesis grounded in the locked spec-phase artifacts (`docs/SPEC.md` SS2.1, SS3.1, SS4.1, SS6.2-6.3, SS9; `docs/adr/ADR-003-deployment-posture.md`, `docs/adr/ADR-004-output-artifact.md`, `docs/adr/ADR-005-llm-integration.md`, `docs/adr/ADR-010-fedramp-ready-posture.md`), the Federal Customer Deployment Guide (`docs/strategy/federal-customer-deployment-guide.md`), the Helm chart (`deploy/helm-chart/`), the Dockerfile, and `SECURITY.md`.
**Public name:** EXPOSE (selected 2026-05-10 in Session H) / **Internal codename:** FF6K
**Source files cited:** See above.

This document maps every EXPOSE component and workflow against air-gap constraints, identifies what works, what breaks, and what partial patterns bridge the gap. It is the operational companion to the two-environment model defined in SPEC SS2.1 and the FedRAMP-ready posture committed in ADR-010.

---

## 1. The two-environment model and air-gap boundaries

EXPOSE's architecture deliberately separates two environments (SPEC SS2.1):

| Environment | Purpose | Network requirement |
|---|---|---|
| **E1 -- Discovery pipeline** | Deterministic collection, sanitization, attribution, artifact generation | Internet egress to collector API endpoints (SPEC SS1 explicitly excludes air-gapped E1 operation) |
| **E2 -- Downstream analysis** | LLM-driven narrative reasoning, red team briefing, CTEM workflow consumption | May be fully air-gapped; receives only the signed JSON artifact |

The canonical artifact (`canonical.json.gz` + `.sig` + `manifest.json`) is the sole contract between environments. It is designed for air-gap transport (ADR-004).

**Key constraint:** E1 cannot operate in a full air gap. Collectors require internet access to CT logs, passive DNS providers, internet-wide scan APIs, cloud IP range endpoints, and (for Tier-3) direct probing of target hosts. This is a fundamental architectural property, not a configuration limitation.

---

## 2. What works in an air gap

The following components and workflows function with zero internet connectivity.

| Capability | Air-gap status | Notes |
|---|---|---|
| Artifact consumption and parsing | Works | `canonical.json.gz` is a self-contained JSON file; standard `gzip` + `jq` tooling |
| Artifact schema validation | Works | Validate against `schemas/canonical-artifact-v1.json` offline with any JSON Schema validator |
| Rule pack evaluation (offline) | Works | Rule packs are declarative JSON; the predicate evaluator operates on the observation graph with no external calls |
| Delta comparison between runs | Works | `delta_from_previous_run` is embedded in each artifact; offline diff of two artifacts is `jq`-trivial |
| Cosign signature verification (keypair mode) | Works | `cosign verify-blob` with pre-distributed public key requires no network access |
| SBOM review | Works | SPDX SBOMs ship alongside container images; offline tooling (`syft`, `grype`) operates locally |
| LLM analysis via local Ollama | Works | `OllamaProvider` runs entirely local; quality tradeoff documented in ADR-005 |
| Helm chart installation (from local archive) | Works | `helm install` from a `.tgz` chart archive with pre-pulled images |
| Database operations (Postgres) | Works | Postgres is an in-cluster or co-located service; no external dependency |
| NATS JetStream broker | Works | In-cluster message bus; no external connectivity required |
| Object storage (MinIO) | Works | MinIO runs in-cluster or on the same network |

### 2.1 Artifact validator CLI (offline)

The `expose validate` CLI subcommand (Sprint 8+) performs offline validation:

```bash
# Validate artifact schema conformance
expose validate artifact canonical.json.gz

# Verify cosign signature with local public key
cosign verify-blob \
    --key /path/to/cosign.pub \
    --signature canonical.json.gz.sig \
    canonical.json.gz

# Validate rule pack schema conformance
expose validate rulepack custom-rules.json
```

No internet access is required for any validation operation.

---

## 3. What does not work in an air gap

| Component | Failure mode | Root cause |
|---|---|---|
| **All collectors (Tier 1-3)** | Cannot execute | Require HTTPS egress to external APIs (crt.sh, Censys, Shodan, SecurityTrails, etc.) |
| **Active probing (Tier 3)** | Cannot execute | Requires direct network access to target hosts for DNS resolution, TLS handshake, HTTP fingerprinting |
| **Cosign keyless verification** | Cannot verify | Requires network access to Sigstore Rekor transparency log and GitHub OIDC issuer |
| **Cloud LLM providers** | Cannot call | Anthropic, OpenAI, Gemini APIs require internet egress |
| **NATS (split-brain across air gap)** | Cluster incoherent | NATS JetStream requires continuous connectivity between cluster members; cannot span an air gap |
| **Helm chart pull from remote registry** | Cannot pull | `helm repo add` and `helm pull` require registry access |
| **Container image pull** | Cannot pull | `ghcr.io/pitt-street-labs/expose` requires registry access |
| **SBOM vulnerability scanning** | Stale results | `grype` needs updated vulnerability databases; air-gapped scans use last-synced DB |
| **CA certificate updates** | Stale trust store | No CRL/OCSP for certificate revocation checks |

### 3.1 Collector dependency map

Every v1 collector and its required egress endpoint:

| Collector ID | Endpoint(s) | Protocol | Auth |
|---|---|---|---|
| `ct-crtsh` | `crt.sh` | HTTPS | None |
| `ct-certstream` | `certstream.calidog.io` | WSS | None |
| `ct-censys` | `search.censys.io` | HTTPS | API key |
| `pdns-securitytrails` | `api.securitytrails.com` | HTTPS | API key |
| `pdns-validin` | `api.validin.com` | HTTPS | API key |
| `pdns-farsight` | `api.dnsdb.info` | HTTPS | API key |
| `iwide-censys` | `search.censys.io` | HTTPS | API key |
| `iwide-shodan` | `api.shodan.io` | HTTPS | API key |
| `iwide-binaryedge` | `api.binaryedge.io` | HTTPS | API key |
| `whois-rdap` | Various RDAP servers | HTTPS | None |
| `whois-whoisxml` | `www.whoisxmlapi.com` | HTTPS | API key |
| `whois-domaintools` | `api.domaintools.com` | HTTPS | API key |
| `bgp-he-toolkit` | `bgp.he.net` | HTTPS | None |
| `bgp-ripestat` | `stat.ripe.net` | HTTPS | None |
| `bgp-team-cymru` | `whois.cymru.com` | DNS/HTTPS | None |
| `cloud-aws-ranges` | `ip-ranges.amazonaws.com` | HTTPS | None |
| `cloud-azure-ranges` | `download.microsoft.com` | HTTPS | None |
| `cloud-gcp-ranges` | `_cloud-netblocks` (DNS TXT) | DNS | None |
| `active-dns-resolve` | Target nameservers | DNS (53) | None |
| `active-tls-handshake` | Target hosts | TLS (443+) | None |
| `active-http-fingerprint` | Target hosts | HTTP/HTTPS | None |
| `active-port-surface` | Target hosts | TCP (variable) | None |

---

## 4. Partial air-gap patterns

These patterns address the most common deployment constraint: the analysis environment is air-gapped but collection can happen elsewhere.

### 4.1 Pattern A -- Outbound-only proxy (HTTP CONNECT)

**Scenario:** Environment 1 sits on a network that permits outbound HTTPS through a forward proxy but has no inbound connectivity and no general internet access.

```
[E1: EXPOSE pipeline]
        |
        | HTTPS via HTTP CONNECT proxy
        v
[Forward proxy / content filter]
        |
        | Allowlisted egress only
        v
[Internet: collector APIs]
```

**Configuration:**

```yaml
# Helm values override
scannerWorker:
  egressProfile:
    type: "http_connect"
    config:
      proxy_url: "http://proxy.internal:3128"
      # Optional: separate proxy for active probing
      active_probe_proxy_url: "http://scanner-proxy.internal:3128"

# Environment variables for collector workers
collectorWorker:
  env:
    HTTPS_PROXY: "http://proxy.internal:3128"
    NO_PROXY: "postgres.internal,nats.internal,minio.internal"
```

**Proxy allowlist (minimum for Tier-1 passive collectors):**

| Destination | Port | Purpose |
|---|---|---|
| `crt.sh` | 443 | Certificate Transparency |
| `ip-ranges.amazonaws.com` | 443 | AWS IP ranges |
| `download.microsoft.com` | 443 | Azure service tags |
| `stat.ripe.net` | 443 | BGP/ASN lookups |
| `bgp.he.net` | 443 | BGP toolkit |

Paid collector endpoints (Censys, Shodan, SecurityTrails, etc.) are added per the operator's enabled collector set.

**Checklist:**

- [ ] Proxy supports HTTP CONNECT method for HTTPS tunneling
- [ ] Proxy permits WebSocket upgrade (needed for `ct-certstream`)
- [ ] DNS resolution available for collector endpoints (or proxy resolves)
- [ ] Proxy logs retained for audit (NIST 800-53 AU-2)
- [ ] `NO_PROXY` set for all internal services (Postgres, NATS, MinIO, Ollama)
- [ ] TLS inspection, if active, does not break certificate pinning on collector SDKs

### 4.2 Pattern B -- Scheduled data ferry

**Scenario:** Collection runs on an internet-connected host. Artifacts are physically transported to an air-gapped analysis environment. This is the canonical two-environment pattern described in SPEC SS2.1.

```
+---------------------------+          +---------------------------+
|  INTERNET-CONNECTED HOST  |          |  AIR-GAPPED ENVIRONMENT   |
|                           |          |                           |
|  EXPOSE E1 pipeline       |  ferry   |  Artifact consumer        |
|  - collectors             | -------> |  - schema validation      |
|  - attribution engine     | (USB/    |  - cosign verify          |
|  - artifact generation    |  SFTP/   |  - delta review           |
|  - cosign sign            |  diode)  |  - Ollama LLM analysis    |
|                           |          |  - CTEM ingestion         |
+---------------------------+          +---------------------------+
```

**Transfer package contents:**

| File | Purpose | Required |
|---|---|---|
| `canonical.json.gz` | The artifact | Yes |
| `canonical.json.gz.sig` | Detached cosign signature | Yes |
| `manifest.json` | Run metadata, collector health, timing | Yes |
| `cosign.pub` | Public key for verification (first transfer only) | First time |
| `partitions/*.json` | Convenience filtered views | Optional |
| `sha256sums.txt` | Transfer integrity check | Recommended |

**Transfer procedure:**

1. On the internet-connected host, after a successful run:
   ```bash
   # Package the transfer bundle
   RUNDIR="runs/${TENANT_ID}/${RUN_ID}"
   tar czf "expose-transfer-${RUN_ID}.tar.gz" \
       "${RUNDIR}/canonical.json.gz" \
       "${RUNDIR}/canonical.json.gz.sig" \
       "${RUNDIR}/manifest.json" \
       "${RUNDIR}/partitions/"

   # Compute transfer checksum
   sha256sum "expose-transfer-${RUN_ID}.tar.gz" > "expose-transfer-${RUN_ID}.sha256"
   ```

2. Transfer via approved medium (see SS4.3 below).

3. On the air-gapped host:
   ```bash
   # Verify transfer integrity
   sha256sum -c "expose-transfer-${RUN_ID}.sha256"

   # Extract
   tar xzf "expose-transfer-${RUN_ID}.tar.gz"

   # Verify artifact signature (keypair mode -- no network needed)
   cosign verify-blob \
       --key /opt/expose/cosign.pub \
       --signature "${RUNDIR}/canonical.json.gz.sig" \
       "${RUNDIR}/canonical.json.gz"

   # Validate schema
   expose validate artifact "${RUNDIR}/canonical.json.gz"

   # Review delta
   jq '.delta_from_previous_run' <(gunzip -c "${RUNDIR}/canonical.json.gz")
   ```

**Cadence alignment:** EXPOSE runs daily by default (`0 2 * * *`). The data ferry cadence should match or exceed the run cadence. Stale artifacts lose value as the attack surface drifts.

### 4.3 Transfer media comparison

| Medium | Bandwidth | Latency | Security | Use case |
|---|---|---|---|---|
| **Encrypted USB** | High (USB 3.x) | Manual carry | Physical custody chain; LUKS or BitLocker encryption required | Classified environments, SCIF transfers |
| **SFTP (one-way network)** | Moderate | Near-real-time | TLS + public-key auth; firewall permits only outbound SCP/SFTP from E1 to E2 | Semi-air-gapped with unidirectional network link |
| **Data diode (hardware)** | Moderate | Near-real-time | Physically enforced one-way data flow; no return channel | High-assurance environments; NIST 800-53 SC-7(5) |
| **Optical disc (CD-R/DVD-R)** | Low | Manual carry | Write-once medium; tamper-evident | Evidence preservation, chain-of-custody requirements |

### 4.4 Pattern C -- Local LLM for enrichment (Ollama)

**Scenario:** The operator wants LLM enrichment in E1 without cloud API egress, or wants LLM-driven analysis in the air-gapped E2.

**E1 deployment (enrichment without cloud egress):**

```yaml
# Helm values -- Ollama as the LLM provider
llmWorker:
  enabled: true
  provider: "ollama"
  costCeilingUSD: 0.00  # local compute, no API cost

# Ollama sidecar or co-located pod
ollama:
  enabled: true
  models:
    - "qwen2.5:7b-instruct-q4_K_M"    # default per ADR-005
    - "llama3.1:8b-instruct-q4_K_M"   # alternate
  resources:
    limits:
      nvidia.com/gpu: 1  # if GPU available
      memory: "12Gi"
```

**E2 deployment (analysis in the air gap):**

Ollama runs standalone on the air-gapped host. Models must be pre-loaded before the air gap is established.

```bash
# On an internet-connected staging host
ollama pull qwen2.5:7b-instruct-q4_K_M
ollama pull llama3.1:8b-instruct-q4_K_M

# Export model blobs for transfer
# Models live in ~/.ollama/models/
tar czf ollama-models.tar.gz ~/.ollama/models/

# Transfer to air-gapped host via approved medium
# On air-gapped host:
tar xzf ollama-models.tar.gz -C ~/
ollama serve  # models available locally
```

**Quality tradeoff (from ADR-005):** Local 7B-8B models produce meaningfully lower enrichment quality than frontier models (Claude Opus, GPT-5.5, Gemini 2.5 Pro). On an RTX 2080 Super (8GB VRAM), throughput is limited to 25-40 tokens/sec. This is acceptable for bounded enrichment work on small-to-medium tenant volumes. It is not suitable for large-scale production.

---

## 5. Container deployment in air-gapped Kubernetes

### 5.1 Image mirroring to private registry

Air-gapped Kubernetes clusters cannot pull from `ghcr.io`. Images must be pre-staged in a private registry accessible from the cluster.

**Mirror procedure:**

```bash
# On internet-connected workstation
EXPOSE_VERSION="0.1.0"
SOURCE="ghcr.io/pitt-street-labs/expose:${EXPOSE_VERSION}"

# Pull multi-arch images
docker pull --platform linux/amd64 "${SOURCE}"
docker pull --platform linux/arm64 "${SOURCE}"

# Verify cosign signature before mirroring
cosign verify "${SOURCE}" \
    --certificate-identity-regexp '^https://github.com/pitt-street-labs/expose/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Save to tar for transfer
docker save "${SOURCE}" -o "expose-${EXPOSE_VERSION}.tar"

# Transfer to air-gapped environment via approved medium

# On air-gapped host with registry access
docker load -i "expose-${EXPOSE_VERSION}.tar"
docker tag "${SOURCE}" "registry.internal/expose:${EXPOSE_VERSION}"
docker push "registry.internal/expose:${EXPOSE_VERSION}"
```

**Supporting images to mirror:**

| Image | Purpose | Required |
|---|---|---|
| `ghcr.io/pitt-street-labs/expose` | EXPOSE engine | Yes |
| `postgres:16-bookworm` | Database (if in-cluster dev mode) | Dev only |
| `minio/minio` | Object storage (if in-cluster) | Lab only |
| `nats:2.10-alpine` | Message broker | Yes |
| `ollama/ollama` | Local LLM (if enabled) | Optional |

### 5.2 Helm chart from local archive

```bash
# On internet-connected workstation
helm repo add expose https://charts.korlogos.com
helm pull expose/expose --version 0.1.0
# Produces expose-0.1.0.tgz

# Transfer to air-gapped environment

# On air-gapped host
helm install expose ./expose-0.1.0.tgz \
    --namespace expose \
    --create-namespace \
    -f air-gap-values.yaml
```

### 5.3 Air-gap Helm values overlay

```yaml
# air-gap-values.yaml -- overrides for air-gapped K8s deployment
global:
  imageRegistry: "registry.internal"   # private registry
  imagePullSecrets:
    - name: expose-registry-creds

# Disable components that require internet
collectorWorker:
  enabled: false   # no internet = no collection

scannerWorker:
  enabled: false   # no internet = no active probing

# LLM: local only
llmWorker:
  enabled: true
  provider: "ollama"
  costCeilingUSD: 0.00

# In-cluster state services (no external dependencies)
postgres:
  enabled: true    # in-cluster for isolated deployments
  sslmode: "require"

objectStorage:
  enabled: true    # in-cluster MinIO

# Observability: local-only backend
observability:
  otlp:
    enabled: true
    endpoint: "otlp://prometheus.monitoring.svc:4317"
    insecure: true  # cluster-internal only

# Network policies: deny all egress
networkPolicies:
  enabled: true
  defaultDeny: true
  # No egress rules -- fully isolated
```

### 5.4 Registry credential setup

```bash
# Create pull secret for private registry
kubectl create secret docker-registry expose-registry-creds \
    --docker-server=registry.internal \
    --docker-username=expose-pull \
    --docker-password="${REGISTRY_PASSWORD}" \
    --namespace expose
```

---

## 6. Verification in the air gap

### 6.1 Cosign verification modes

| Mode | Network required | Use case |
|---|---|---|
| **Keyless (OIDC)** | Yes -- Rekor + OIDC issuer | Production CI/CD with GitHub Actions |
| **Keypair** | No | Air-gapped verification with pre-distributed public key |

**Air-gapped environments must use keypair mode.** The cosign public key (`cosign.pub`) is distributed once during initial setup and verified out-of-band (fingerprint comparison, physical handoff).

**Keypair setup (one-time, on internet-connected host):**

```bash
# Generate keypair (store private key securely)
cosign generate-key-pair

# Record public key fingerprint for out-of-band verification
sha256sum cosign.pub
# Example: a1b2c3d4...  cosign.pub

# Transfer cosign.pub to air-gapped environment
# Verify fingerprint matches on both sides
```

**Artifact verification (air-gapped, every transfer):**

```bash
# Verify canonical artifact signature
cosign verify-blob \
    --key /opt/expose/cosign.pub \
    --signature canonical.json.gz.sig \
    canonical.json.gz
# Exit code 0 = valid; non-zero = tampered or wrong key

# Verify container image (from private registry, keypair mode)
cosign verify \
    --key /opt/expose/cosign.pub \
    registry.internal/expose:0.1.0
```

### 6.2 SBOM review

SBOMs are generated at build time via `syft` in SPDX format and attached to the container image as an attestation.

```bash
# Extract SBOM from image (pre-mirrored to private registry)
cosign download attestation \
    --key /opt/expose/cosign.pub \
    registry.internal/expose:0.1.0 | jq -r '.payload' | base64 -d > sbom.spdx.json

# Scan with local vulnerability DB (grype, air-gapped mode)
# DB must be pre-staged: https://github.com/anchore/grype#offline-use
grype sbom:sbom.spdx.json --db /opt/grype/db/
```

**Grype DB update for air-gapped scanning:**

```bash
# On internet-connected host
grype db update
grype db export /tmp/grype-db-export.tar.gz

# Transfer to air-gapped host
grype db import /tmp/grype-db-export.tar.gz
```

### 6.3 Verification checklist (per transfer)

- [ ] Transfer medium integrity: `sha256sum -c` on the transfer bundle
- [ ] Cosign signature valid: `cosign verify-blob` exits 0
- [ ] Manifest `run_id` matches expected run
- [ ] Manifest `collector_health` reviewed -- no unexpected failures
- [ ] Artifact schema validates against `schemas/canonical-artifact-v1.json`
- [ ] Delta reviewed for unexpected removals (especially `removal_uncertain_collector_failure`)
- [ ] Previous artifact archived before overwrite

---

## 7. Compliance considerations

### 7.1 NIST 800-53 Rev 5 -- SC-7 Boundary Protection

The air-gap deployment model directly addresses several SC-7 sub-controls:

| Control | Relevance | EXPOSE posture |
|---|---|---|
| **SC-7(5)** Deny by default / allow by exception | Air-gapped E2 has no egress; Pattern A allowlists specific collector endpoints | Default-deny network policies in Helm chart; proxy allowlist is explicit |
| **SC-7(7)** Prevent split tunneling | E1-to-E2 transfer is physical or unidirectional; no persistent tunnel | Data ferry pattern enforces physical separation |
| **SC-7(8)** Route traffic to managed interfaces | Pattern A routes all collector traffic through forward proxy | Proxy logs satisfy AU-2 audit requirements |
| **SC-7(11)** Restrict incoming traffic | E2 accepts no inbound connections; E1 accepts inbound only for admin API (if enabled) | Helm network policies enforce; scanner worker has egress-only profile |
| **SC-7(14)** Protect against unauthorized physical connections | USB transfer requires physical custody chain | Operator procedure; EXPOSE provides artifact signing for tamper detection |
| **SC-7(21)** Isolation of system components | E1 and E2 are separate systems with no shared network | Two-environment model is architectural, not configurable |

### 7.2 FedRAMP alignment

Per ADR-010, EXPOSE is FedRAMP-ready by design. Air-gap deployments satisfy additional FedRAMP Moderate baseline controls:

| FedRAMP concern | Air-gap posture |
|---|---|
| **Authorization boundary clarity** | E1 and E2 are separate systems with a documented, physical data-transfer boundary -- the cleanest possible authorization boundary for SSP narrative |
| **Data-in-transit protection** | Artifacts are signed (cosign) and checksummed (SHA-256); transfer medium provides physical-layer protection |
| **Continuous monitoring** | E1 produces OpenTelemetry metrics and logs locally; E2 monitors locally; cross-boundary monitoring is via artifact metadata (collector health, run timing) |
| **Incident response** | Artifact tampering detected by signature failure; chain of custody enforced by transfer procedures |
| **FIPS 140-2/3 cryptography** | SHA-256 hashing via FIPS-validated adapter (ADR-010); cosign uses ECDSA P-256 (FIPS-approved curve) |

### 7.3 FedRAMP High baseline considerations

FedRAMP High deployments (roadmap-future per ADR-010) impose additional constraints relevant to air-gap patterns:

| Requirement | Impact on EXPOSE deployment |
|---|---|
| **SC-7(18)** Fail-secure | If the data ferry fails, E2 operates on stale artifacts rather than falling back to internet connectivity |
| **SC-13** Cryptographic protection | All crypto operations use FIPS 140-3 validated modules; EXPOSE's FIPS adapter enforces this at the code level |
| **SI-4(22)** Network-connected privileged access | Air-gapped E2 has no network-connected privileged access by definition |
| **SC-28(1)** Cryptographic protection of information at rest | Artifacts at rest should be encrypted (LUKS for USB, encrypted filesystem for local storage) -- operator responsibility |

---

## 8. Deployment decision matrix

Use this table to determine which pattern fits your environment:

| Constraint | Pattern A (Proxy) | Pattern B (Data Ferry) | Pattern C (Local LLM) | Full air gap (E2 only) |
|---|---|---|---|---|
| Can collectors reach the internet? | Yes, via proxy | Yes, on separate host | Yes (or no, if E2-only) | No |
| Can LLM enrichment use cloud APIs? | Yes, via proxy | Yes, on E1 host | No -- local Ollama only | No -- local Ollama only |
| Is artifact generation on-site? | Yes | No -- on E1 host | Yes (if E1 has proxy/internet) | No -- artifacts imported |
| Transfer medium needed? | No | Yes (USB/SFTP/diode) | No (if E1 local) | Yes |
| NIST SC-7 boundary separation? | Partial (proxy-mediated) | Strong (physical) | Partial | Complete |
| LLM enrichment quality? | Full (frontier models) | Full (frontier models on E1) | Reduced (7B local) | Reduced (7B local) |
| Operational complexity? | Low | Moderate (ferry cadence) | Low-Moderate | Low (consume-only) |

---

## 9. Operational considerations

### 9.1 Stale data risk

Air-gapped E2 environments operate on artifacts that are at least one transfer-cycle old. Attack surface changes between the last scan and the current analysis window are invisible.

**Mitigations:**
- Align ferry cadence with scan cadence (daily scans = daily ferry minimum)
- Review `collector_health` in manifest for degraded-data indicators
- Use `removal_uncertain_collector_failure` delta entries as signals to investigate, not to dismiss

### 9.2 Key management across the air gap

| Key type | Lifecycle | Air-gap consideration |
|---|---|---|
| Cosign signing key (private) | Lives on E1; never crosses to E2 | Standard -- signing happens at artifact generation |
| Cosign verification key (public) | Distributed to E2 once; verified out-of-band | Rotation requires new physical distribution + fingerprint verification |
| Collector API keys | E1 only | Never cross to E2 |
| LLM provider API keys | E1 only (if using cloud providers) | Never cross to E2; not needed if Ollama-only |
| Postgres credentials | Per-environment | E1 and E2 have independent databases |
| NATS credentials | Per-environment | E1 and E2 have independent NATS clusters |

### 9.3 Update and patch cadence

Air-gapped systems lag internet-connected systems on updates. Plan for:

| Asset | Update source | Transfer method | Staleness tolerance |
|---|---|---|---|
| EXPOSE container image | `ghcr.io/pitt-street-labs/expose` | Image tar via approved medium | Match CVE remediation SLAs (30d high, 90d moderate per SECURITY.md) |
| Grype vulnerability DB | `grype db update` on connected host | DB export tar | Weekly recommended; monthly acceptable |
| Ollama model weights | `ollama pull` on connected host | Model tar | Low urgency; model updates are quality, not security |
| CA certificate bundle | OS package manager | OS update mechanism | Quarterly recommended |
| Rule packs | Operator-authored or distributed | File transfer | Per operator change cadence |
| Helm chart | Chart registry or source repo | Chart `.tgz` archive | Match EXPOSE release cadence |

---

## 10. Reference architecture diagrams

### 10.1 Full air-gap (E2 consume-only)

```
INTERNET                         AIR GAP                    CLASSIFIED / ISOLATED
                                    |
+--------------------+              |    +----------------------------+
| E1: Collection     |              |    | E2: Analysis               |
|                    |              |    |                            |
| EXPOSE pipeline    |   signed     |    | cosign verify              |
| collectors ------> |   artifact   |    | schema validate            |
| attribution -----> | ----------> ||    | delta review               |
| artifact gen ----> |   via USB/   |    | Ollama LLM analysis        |
| cosign sign -----> |   diode/     |    | CTEM platform ingest       |
|                    |   SFTP       |    | red team briefing (E2)     |
+--------------------+              |    +----------------------------+
                                    |
```

### 10.2 Proxy-mediated E1 with air-gapped E2

```
INTERNET              DMZ / PROXY           INTERNAL              AIR GAP
                           |                    |                     |
+------------------+  +---------+  +--------------------+  +------------------+
| Collector APIs   |  | Forward |  | E1: EXPOSE         |  | E2: Analysis     |
| - crt.sh         |<-| proxy   |<-| pipeline           |  |                  |
| - censys.io      |  | (allow- |  | (all components)   |  | artifact         |
| - shodan.io      |  |  list)  |  | artifact gen       |->| consumption      |
| - etc.           |  |         |  | cosign sign        |  | Ollama (local)   |
+------------------+  +---------+  +--------------------+  +------------------+
```

---

## Appendix A: Quick-start checklist by deployment type

### A.1 Air-gapped E2 (artifact consumer only)

- [ ] Pre-distribute `cosign.pub` to E2 host; verify fingerprint
- [ ] Install `cosign` binary on E2 (transfer from connected host)
- [ ] Install `jq` and `gzip` for artifact inspection
- [ ] (Optional) Install `expose` CLI for `validate` subcommand
- [ ] (Optional) Install Ollama + pre-stage model weights for LLM analysis
- [ ] Establish ferry cadence and transfer procedure
- [ ] Document chain-of-custody for transfer media

### A.2 Proxy-mediated E1 deployment

- [ ] Configure forward proxy with collector endpoint allowlist (see SS3.1)
- [ ] Set `HTTPS_PROXY` and `NO_PROXY` environment variables
- [ ] Verify proxy supports HTTP CONNECT for HTTPS tunneling
- [ ] Verify proxy supports WebSocket upgrade (for certstream)
- [ ] Test each enabled collector through the proxy before production runs
- [ ] Configure proxy logging for NIST 800-53 AU-2 compliance
- [ ] Deploy Helm chart with proxy-aware values

### A.3 Full air-gapped Kubernetes cluster

- [ ] Mirror all required container images to private registry (see SS5.1)
- [ ] Verify mirrored images with `cosign verify --key`
- [ ] Transfer Helm chart `.tgz` to air-gapped host
- [ ] Create `air-gap-values.yaml` (see SS5.3)
- [ ] Create registry pull secret (see SS5.4)
- [ ] Deploy with `helm install` from local chart archive
- [ ] Verify pods start and pass health checks
- [ ] Pre-stage Grype DB for SBOM vulnerability scanning
- [ ] Establish image update cadence aligned with CVE remediation SLAs

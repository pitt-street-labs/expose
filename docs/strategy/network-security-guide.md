# EXPOSE Core -- Network Security Guide

**Status:** Advisory -- not locked

**Gitea:** #4 (Network policy and pod-to-pod restrictions)

---

## Why Default-Deny Matters for an EASI Platform

An external attack surface intelligence platform collects, processes, and stores data about target organizations' internet-facing infrastructure. This makes EXPOSE a high-value target for adversaries seeking to:

- Exfiltrate reconnaissance data (entity inventories, certificate chains, DNS records)
- Tamper with scan results to hide exposed assets
- Pivot from a compromised collector to internal state services (Postgres, NATS)
- Use scanner workers as an open proxy for unauthorized outbound scanning

Default-deny network policy eliminates implicit trust between pods. Every allowed communication path is explicitly declared, auditable, and version-controlled in the Helm chart. A compromised collector worker cannot reach Postgres except on port 5432, cannot accept inbound connections, and cannot reach cluster-internal RFC 1918 addresses.

## Architecture

The chart deploys six NetworkPolicy resources when `networkPolicy.enabled=true`:

| Policy | Pod Selector | Ingress | Egress |
|--------|-------------|---------|--------|
| `default-deny` | All EXPOSE pods | None | None |
| `control-plane` | `component: control-plane` | HTTP from configurable CIDR | Postgres, NATS, DNS |
| `collector-worker` | `component: collector-worker` | None | Postgres, NATS, HTTPS (443) to public IPs, DNS |
| `scanner-worker` | `component: scanner-worker` | None | Postgres, NATS, HTTP/HTTPS to public IPs, egress proxy, DNS |
| `postgres` | `component: postgres` | From control-plane + workers on 5432 | DNS only |
| `nats` | `component: nats` | From control-plane + workers on 4222; cluster peers on 6222 | Cluster peers, DNS |

The default-deny policy matches all pods with EXPOSE selector labels and blocks everything. The per-component policies then punch specific holes. This is additive -- Kubernetes NetworkPolicy is a union of all matching policies for a pod.

## Customizing Collector Egress

### Domain-Level Filtering

Kubernetes-native NetworkPolicy operates at L3/L4 (IP + port). It cannot filter by DNS name. The `networkPolicy.collectorEgress.allowedDomains` list in `values.yaml` is informational documentation for operators.

For domain-level enforcement, use your CNI's extended policy:

**Cilium (CiliumNetworkPolicy):**
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: expose-collector-dns-egress
spec:
  endpointSelector:
    matchLabels:
      app.kubernetes.io/component: collector-worker
  egress:
    - toFQDNs:
        - matchName: "crt.sh"
        - matchName: "rdap.org"
        - matchName: "ip-ranges.amazonaws.com"
        - matchName: "download.microsoft.com"
        - matchName: "www.gstatic.com"
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
```

**Calico (GlobalNetworkPolicy with DNS policy):**
```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: expose-collector-dns-egress
spec:
  selector: app.kubernetes.io/component == 'collector-worker'
  egress:
    - action: Allow
      destination:
        domains:
          - "crt.sh"
          - "rdap.org"
          - "ip-ranges.amazonaws.com"
          - "download.microsoft.com"
          - "www.gstatic.com"
        ports: [443]
      protocol: TCP
```

To add new collector data sources, append domains to both the `values.yaml` informational list and your CNI-specific policy.

### Disabling Public Egress

To run collectors in a fully air-gapped configuration (see #6), set:

```yaml
networkPolicy:
  collectorEgress:
    httpsEnabled: false
  scannerEgress:
    enabled: false
```

This blocks all outbound HTTP/HTTPS from workers. Collectors would then operate only against data imported via the SpiderFoot importer or other offline ingestion paths.

## Restricting API Ingress

The default `apiServer.ingressCIDR: "0.0.0.0/0"` allows connections from any source. In production:

```yaml
networkPolicy:
  apiServer:
    # Only allow traffic from the ingress controller subnet
    ingressCIDR: "10.0.1.0/24"
```

For multi-source access (e.g., ingress controller + monitoring + internal VPN), the single-CIDR field may be insufficient. Options:

1. Use a broader CIDR that covers all sources (e.g., `10.0.0.0/16`)
2. Disable the chart's policy (`networkPolicy.enabled: false`) and manage policies externally with multiple `from` blocks
3. Extend the template to accept a list of CIDRs (future enhancement)

For federal deployments behind a WAF/reverse proxy, restrict to the proxy's egress IP range.

## Monitoring Blocked Traffic

NetworkPolicy drops are silent by default. To gain visibility:

### Cilium

Enable Hubble flow logging:
```
cilium hubble enable
hubble observe --verdict DROPPED --namespace <expose-namespace>
```

Export to Prometheus via `hubble-metrics`:
```yaml
# Cilium Helm values
hubble:
  metrics:
    enabled:
      - drop
      - flow
      - policy
```

### Calico

Enable flow logs:
```yaml
# FelixConfiguration
apiVersion: projectcalico.org/v3
kind: FelixConfiguration
metadata:
  name: default
spec:
  flowLogsFileEnabled: true
  flowLogsFlushInterval: "15s"
  policySyncPathPrefix: "/var/run/nodeagent"
```

Calico Enterprise provides a dedicated "Denied Packets" dashboard.

### Generic (iptables-based CNIs)

Some CNIs support logging denied packets via `LOG` targets. Check your CNI documentation. For environments with OpenTelemetry (the EXPOSE default per ADR-003), export network metrics to the operator's observability backend.

## Pod Security Standards

The chart enforces the Kubernetes "restricted" Pod Security Standard via namespace labels (see `templates/podsecurity.yaml`). This enforces at the admission level:

- `runAsNonRoot: true`
- No privilege escalation
- All capabilities dropped
- Seccomp `RuntimeDefault` or `Localhost`
- No host namespaces, ports, or path mounts

These constraints are also set explicitly in `podSecurityContext` and `containerSecurityContext` in `values.yaml`, providing defense-in-depth: the PSA labels block non-compliant pods at admission, while the explicit security contexts set the runtime posture.

## Air-Gap Considerations

For fully air-gapped deployments (reference #6, container egress lockdown):

1. Disable all outbound egress:
   ```yaml
   networkPolicy:
     collectorEgress:
       httpsEnabled: false
     scannerEgress:
       enabled: false
   ```

2. Pre-populate data via offline import (SpiderFoot importer, file-based ingestion)

3. Use an internal registry mirror (`global.imageRegistry`) for container images

4. NATS and Postgres must be cluster-internal or on a physically isolated network

5. If DNS resolution is not available, configure all service references as IP addresses and ensure kube-dns is reachable within the cluster network

The NetworkPolicy rules still permit DNS (UDP/TCP 53) egress to support Kubernetes service discovery even in air-gapped configurations. If the cluster DNS must also be locked down, operators should apply custom policies at the CNI level.

# EXPOSE Egress Deployment Guide

_Advisory — not locked. Deployment reference for operators._

**Status:** Advisory — not locked. Open for revision in subsequent sessions.
**Date:** 2026-05-10
**Scope:** Deployment reference for operators configuring egress profiles for EXPOSE's active (Tier-3) collectors.

---

## Overview

EXPOSE's active collectors — `active-dns-resolve` (dnspython) and `active-http-fingerprint` (httpx) — make outbound connections to target infrastructure. Without egress controls, these connections originate from the operator's own IP address, creating three problems:

1. **Attribution exposure.** Target infrastructure sees the operator's IP in server logs, DNS query logs, and WAF telemetry. For authorized red team engagements, this defeats the purpose of external reconnaissance.
2. **Rate-limit convergence.** Repeated requests from a single source IP trigger rate limiters, CAPTCHAs, and IP bans on target infrastructure, degrading scan coverage.
3. **Geographic limitation.** Some targets serve different content based on the requester's geography (CDN edge routing, geo-blocked content, localized responses). A single egress point cannot observe these variations.

The egress profile abstraction lets operators route active collector traffic through controlled exit points — SOCKS5 proxies, WireGuard tunnels, or HTTP CONNECT proxies — so active scanning is not attributed to the operator's infrastructure. Passive (Tier-1) and semi-passive (Tier-2) collectors are unaffected by egress configuration; they consume public data sources and do not contact target infrastructure directly.

---

## Egress Profiles in EXPOSE

EXPOSE implements four egress profile types, selectable at deployment time via the `create_egress_profile()` factory. Each profile configures two things: how httpx routes HTTP/HTTPS traffic, and how dnspython resolves hostnames.

### Direct (default)

Pass-through — no proxy, no tunnel. Active collectors connect from the operator's own IP address. Correct for internal/lab deployments where attribution to the operator's infrastructure is acceptable, and for air-gapped deployments running passive collectors only.

- **httpx configuration:** No proxy — empty kwargs.
- **DNS resolution:** System resolver.
- **Health check:** Always healthy (if the host has network connectivity, direct egress works).
- **Infrastructure required:** None.

### SOCKS5

Routes traffic through a SOCKS5 proxy. The profile supports DNS-leak prevention via the `socks5h://` protocol variant, which instructs the proxy to resolve hostnames on behalf of the client rather than using the operator's system resolver.

- **httpx configuration:** `proxy` kwarg set to `socks5h://<host>:<port>` (or `socks5://` when DNS-through-proxy is disabled).
- **DNS resolution:** When `dns_through_proxy=True` (default), nameservers are set to empty, signalling collectors to skip independent DNS resolution. The proxy handles it.
- **Health check:** TCP connect probe to the proxy host:port (validates the daemon is listening).
- **Infrastructure required:** A running SOCKS5 proxy — Dante, microsocks, SSH tunnel (`ssh -D`), or the Tor-based gateway described below.

### WireGuard

Routes traffic through a WireGuard tunnel interface. Unlike proxy-based profiles, WireGuard operates at the network level — the OS routing table directs traffic through the tunnel. The profile optionally binds httpx to the tunnel interface's source address to guarantee traffic exits via the tunnel even when default routing does not cover all destinations.

- **httpx configuration:** `transport` kwarg with `AsyncHTTPTransport(local_address=<wg-ip>)` when a source address is specified; empty otherwise.
- **DNS resolution:** System resolver (DNS routes through the WG tunnel via OS routing).
- **Health check:** Checks `/sys/class/net/<interface>/operstate` for interface presence and link status. WireGuard interfaces report `unknown` as operstate when up (this is normal); `down` means inactive.
- **Infrastructure required:** A WireGuard peer providing egress (typically a cloud VPS).

### HTTP CONNECT

Routes traffic through an HTTP CONNECT proxy (Squid, tinyproxy, or any proxy supporting the `CONNECT` method for HTTPS tunnelling). The proxy establishes a TCP tunnel to the target on behalf of the client, so the target sees the proxy's IP.

- **httpx configuration:** `proxy` kwarg set to `http://<host>:<port>`.
- **DNS resolution:** System resolver (HTTP CONNECT proxies receive the target hostname in the `CONNECT` request line and resolve it themselves).
- **Health check:** TCP connect probe to the proxy host:port.
- **Infrastructure required:** A running HTTP CONNECT proxy.

---

## Reference Architecture: Tor + Public Proxy Gateway

This section documents a production-tested egress architecture providing geographic IP diversity via Tor country-pinned exit nodes and a public proxy pool. This design has been validated in continuous operation since January 2026.

The architecture deploys 13 containers:

- **11 Tor instances** — 10 country-pinned (`us`, `de`, `nl`, `ch`, `se`, `gb`, `ca`, `fr`, `jp`, `au`) plus 1 unrestricted (maximum anonymity).
- **1 public proxy broker** — scrapes, validates, and rotates free SOCKS5/HTTP proxy lists for IP diversity (not privacy).
- **1 metrics exporter** — Prometheus-compatible health metrics with cookie-authenticated Tor control port access.

Each Tor instance runs an independent circuit (~20 MB RAM each), providing simultaneous egress through 11 different exit nodes across 10 countries.

### Container Architecture

```
                      EXPOSE Active Collectors
                              |
                    +---------+---------+
                    |   SOCKS5 Profile  |
                    |  (port selection) |
                    +---------+---------+
                              |
         +--------------------+--------------------+
         |                    |                     |
    +---------+         +---------+          +-----------+
    | tor-any |         | tor-us  |          | tor-au    |  ... (11 instances)
    | :10899  |         | :10900  |          | :10909    |
    | ANY exit|         | US exit |          | AU exit   |
    +---------+         +---------+          +-----------+
         |                    |                     |
         +--------------------+--------------------+
         |                                          |
  [tor-internal network]                   [proxy-net network]
         |                                          |
  +--------------+                         +----------------+
  | metrics      |                         | public-proxy   |
  | exporter     |--------+               | broker         |
  | :10920       |        |               | :10910 SOCKS5  |
  +--------------+        |               | :10911 health  |
    (reads cookies        |               +----------------+
     from all Tor         |                  |
     instances, RO)       |                  | (scrapes external
                          |                  |  proxy lists)
                          v                  v
                    [Prometheus]        [Public internet
                                        via untrusted
                                        proxies]
```

Key isolation property: Tor containers live on `tor-internal` network; the public proxy broker lives on `proxy-net`. They cannot communicate with each other. The metrics exporter bridges both networks (read-only cookie access to Tor, health endpoint on proxy-net).

### Port Mapping

| Port | Egress Path | Protocol | Use Case |
|------|-------------|----------|----------|
| 10899 | Tor — any country (unrestricted) | SOCKS5 | Maximum anonymity, no geographic constraint |
| 10900 | Tor — United States | SOCKS5 | US-geolocated exit |
| 10901 | Tor — Germany | SOCKS5 | DE-geolocated exit |
| 10902 | Tor — Netherlands | SOCKS5 | NL-geolocated exit |
| 10903 | Tor — Switzerland | SOCKS5 | CH-geolocated exit |
| 10904 | Tor — Sweden | SOCKS5 | SE-geolocated exit |
| 10905 | Tor — United Kingdom | SOCKS5 | GB-geolocated exit |
| 10906 | Tor — Canada | SOCKS5 | CA-geolocated exit |
| 10907 | Tor — France | SOCKS5 | FR-geolocated exit |
| 10908 | Tor — Japan | SOCKS5 | JP-geolocated exit |
| 10909 | Tor — Australia | SOCKS5 | AU-geolocated exit |
| 10910 | Public proxy pool | SOCKS5 + HTTP | IP diversity only (NOT privacy) |
| 10911 | Public proxy health | HTTP JSON | Pool stats and health status |
| 10920 | Prometheus metrics | HTTP | Circuit health, latency, exit verification |

All ports bind to a single internal interface address. Adjust the bind address in the compose file to match your deployment network.

### Tor Circuit Management

Each Tor instance generates its `torrc` from a template at container startup, injecting country-specific exit node pinning via the `ExitNodes` and `StrictNodes` directives.

**Core torrc directives:**

```
SocksPort 0.0.0.0:9050

# DNS resolution through Tor (prevent leaks)
DNSPort 5353
AutomapHostsOnResolve 1

# Circuit settings
CircuitBuildTimeout 30
LearnCircuitBuildTimeout 1
NumEntryGuards 3
KeepalivePeriod 60

# Circuit rotation — prevent stale circuits
MaxCircuitDirtiness 600
NewCircuitPeriod 30

# Control port for health checks — cookie auth required
ControlPort 0.0.0.0:9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1

# Country-pinned exit (injected per container)
ExitNodes {us}
StrictNodes 1
```

**Circuit rotation timers:**

| Directive | Value | Effect |
|-----------|-------|--------|
| `MaxCircuitDirtiness` | 600 seconds | Existing circuits are abandoned after 10 minutes |
| `NewCircuitPeriod` | 30 seconds | Tor considers building a new circuit every 30 seconds |
| `NumEntryGuards` | 3 | Limits entry guard selection for path diversity |

**External circuit refresh:** A systemd timer (30-minute interval) sends `SIGNAL NEWNYM` to all 11 Tor containers via their control ports. This forces Tor to use new circuits for new connections without breaking existing ones. The refresh script authenticates using cookie files, reading them as the `tor` user (UID 100, GID 101) since `cap_drop: ALL` prevents root from reading the cookie via `DAC_OVERRIDE`.

Example circuit refresh logic:

```bash
#!/bin/bash
# Force new Tor circuits on all containers via SIGNAL NEWNYM
set -euo pipefail

CONTAINERS=(tor-any tor-us tor-de tor-nl tor-ch tor-se tor-gb tor-ca tor-fr tor-jp tor-au)

for ctr in "${CONTAINERS[@]}"; do
    # Read cookie as tor user — container root lacks DAC_OVERRIDE
    cookie_hex=$(podman exec -u 100:101 "$ctr" sh -c \
        'od -A n -t x1 /var/lib/tor/control_auth_cookie | tr -d " \n"')

    # Send NEWNYM via control port
    response=$(podman exec -u 100:101 "$ctr" sh -c \
        "printf 'AUTHENTICATE ${cookie_hex}\r\nSIGNAL NEWNYM\r\nQUIT\r\n' | nc -w 5 127.0.0.1 9051")

    if echo "$response" | grep -q "250 OK"; then
        echo "OK: $ctr — new circuits requested"
    else
        echo "FAIL: $ctr — NEWNYM failed"
    fi
done
```

### Container Hardening

Every container in the gateway stack follows a defense-in-depth hardening posture:

| Control | Implementation | Purpose |
|---------|---------------|---------|
| `cap_drop: ALL` | Drop all Linux capabilities | Minimum-privilege container |
| `cap_add: CHOWN, SETUID, SETGID` | Tor containers only | Required for `su-exec` to drop to tor user |
| `no-new-privileges: true` | All containers | Prevents privilege escalation via setuid binaries |
| `read_only: true` | All containers | Immutable root filesystem |
| `tmpfs: /tmp:size=10M` | All containers | Bounded writable scratch space |
| Rootless Podman | Host-level | No root daemon; user-namespaced containers |
| SELinux enforcing | Host-level | Mandatory access control on container processes |
| `CookieAuthentication` | Tor control port | No password in config; ephemeral cookie auth |
| `CookieAuthFileGroupReadable` | Tor data directory | Metrics exporter reads cookies via group permission |
| Network isolation | `tor-internal` vs `proxy-net` | Public proxy broker cannot reach Tor containers |
| Named volumes with `:U` | Tor data directories | User-namespace ownership mapping |

**Container image:** Alpine Linux base (~5 MB), with only `tor`, `su-exec`, and `netcat-openbsd` installed. No shell interpreters beyond `/bin/sh`, no development tools, no package manager cache.

### DNS Leak Prevention

DNS leaks are the most common operational failure in proxy-based egress. A DNS leak occurs when the operator's system resolver sends DNS queries directly to upstream resolvers instead of routing them through the proxy, revealing the operator's infrastructure to target DNS servers.

EXPOSE prevents DNS leaks at two layers:

1. **Profile layer (EXPOSE code):** The `Socks5EgressProfile` rewrites `socks5://` to `socks5h://` when `dns_through_proxy=True` (the default). The `h` suffix instructs httpx to pass hostnames to the SOCKS5 proxy for resolution rather than resolving them locally. The profile also returns empty nameservers from `configure_dns_resolver()`, signalling collectors to skip independent DNS resolution.

2. **Tor layer (torrc):** Each Tor instance configures `DNSPort 5353` and `AutomapHostsOnResolve 1`, ensuring all DNS resolution happens through the Tor network.

**Operator responsibility:** Always use hostname-resolving client variants:

| Client | Correct | Incorrect (leaks DNS) |
|--------|---------|----------------------|
| curl | `--socks5-hostname host:port` | `--socks5 host:port` |
| Python httpx | `socks5h://host:port` | `socks5://host:port` |
| Python requests | `socks5h://host:port` | `socks5://host:port` |
| Firefox | "Proxy DNS when using SOCKS v5" enabled | Setting unchecked |

---

## Tor Exit Detection and Scan Fidelity

**This is the most important operational tradeoff in egress deployment.**

Tor exit node IP addresses are publicly listed. The Tor Project publishes the full list of exit relays, and many target organizations maintain blocklists derived from it. This creates a fidelity problem:

- **Targets may block Tor exits entirely**, returning connection resets or HTTP 403 responses instead of legitimate content.
- **Targets may serve altered content** to known Tor exits — CAPTCHAs, honeypot responses, or stripped-down pages that differ from what a "normal" visitor sees.
- **WAFs and CDNs (Cloudflare, Akamai, AWS WAF) commonly flag Tor traffic** with elevated challenge levels, bot-detection interstitials, or rate limiting that would not apply to residential or commercial IP ranges.

When EXPOSE detects that a response obtained via Tor differs from a response obtained via a non-Tor path, the canonical artifact should include the `egress_response_divergent` flag to indicate reduced fidelity.

### Decision Matrix: Choosing the Right Egress Profile

| Requirement | Direct | SOCKS5 (Tor) | WireGuard | HTTP CONNECT (commercial) |
|-------------|--------|--------------|-----------|--------------------------|
| **Attribution avoidance** | None | Strong (Tor network) | Moderate (cloud VPS IP) | Strong (residential IP pool) |
| **Scan fidelity** | Highest | Lowest (Tor exits are listed) | High (clean IP) | Highest (residential IPs) |
| **Geographic diversity** | None | Excellent (10 countries) | Per-VPS | Excellent (provider-dependent) |
| **Cost** | $0 | $0 | $5-20/mo per VPS | $100-500+/mo |
| **Latency** | Lowest | Highest (3-hop relay) | Low-moderate | Moderate |
| **Infrastructure complexity** | None | 13 containers | 1 VPS + WG config | API credentials only |
| **Tor exit detection risk** | N/A | High | None | None |
| **DNS leak risk** | N/A | Low (socks5h://) | Low (OS routing) | Low (proxy resolves) |

**When to use each:**

- **Direct:** Internal/lab deployments, air-gapped environments, passive-only collector configurations.
- **SOCKS5 (Tor):** Red team engagements where anonymity outweighs fidelity, research scanning where Tor exit detection is acceptable, geographic diversity requirements across multiple countries simultaneously.
- **WireGuard:** Production scanning where clean (non-listed) exit IPs are required, single-geography deployments where one VPS provides the needed egress point, cost-sensitive deployments needing moderate attribution avoidance.
- **HTTP CONNECT (commercial proxy):** Enterprise deployments where both anonymity and fidelity are required, residential IP pools for the most realistic traffic profile, high-volume scanning where IP rotation is needed.

### Fidelity Monitoring

Operators should implement response-divergence detection in their scan pipeline:

1. **Baseline via Direct:** Periodically scan a sample of targets via Direct egress to establish baseline responses.
2. **Compare via Tor/proxy:** Compare the proxied response against the baseline. Flag divergences in response code, content length, or content hash.
3. **Record divergence:** When divergence is detected, mark the observation with `egress_response_divergent: true` in the canonical artifact so downstream consumers know the data may be incomplete or altered.

---

## Alternative Egress Strategies

### WireGuard Tunnel

A cloud VPS with WireGuard provides clean (non-listed) exit IPs with low latency and full scan fidelity. This is the recommended production egress for most deployments.

**Architecture:**

```
EXPOSE Host                    Cloud VPS (egress endpoint)
+-----------+                  +------------------+
| Collector | ---[wg0 tunnel]---> | WireGuard peer   |
| (httpx)   |   10.0.0.2/32   | 10.0.0.1/32      |
|           |                  | NAT masquerade    |
+-----------+                  | to public IP      |
                               +------------------+
```

**VPS setup (example — Ubuntu 24.04 on any cloud provider):**

```bash
# Install WireGuard
apt install wireguard

# Generate keys
wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key

# Configure /etc/wireguard/wg0.conf
cat > /etc/wireguard/wg0.conf <<'EOF'
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <vps-private-key>
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = <expose-host-public-key>
AllowedIPs = 10.0.0.2/32
EOF

# Enable and start
systemctl enable --now wg-quick@wg0

# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
sysctl -p
```

**EXPOSE host setup:**

```bash
# Configure /etc/wireguard/wg0.conf
cat > /etc/wireguard/wg0.conf <<'EOF'
[Interface]
Address = 10.0.0.2/24
PrivateKey = <expose-host-private-key>

[Peer]
PublicKey = <vps-public-key>
Endpoint = <vps-public-ip>:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

wg-quick up wg0
```

**Advantages over Tor:** Clean IP (not on any blocklist), lower latency (single hop vs. three), full scan fidelity, deterministic exit geography. **Disadvantages:** Monthly VPS cost, single exit IP per VPS (no rotation without multiple VPSes), VPS provider can log traffic.

### Enterprise Proxy Services

Commercial residential proxy services provide the highest-fidelity egress with large IP pools that appear as normal residential or mobile traffic. These map directly to EXPOSE's HTTP CONNECT egress profile.

| Provider | Protocol | IP Pool | Pricing Model |
|----------|----------|---------|---------------|
| Bright Data | HTTP CONNECT, SOCKS5 | 72M+ residential IPs | Per-GB ($8-15/GB) |
| Smartproxy | HTTP CONNECT | 55M+ residential IPs | Per-GB or per-request |
| Oxylabs | HTTP CONNECT, SOCKS5 | 100M+ residential IPs | Per-GB ($8-12/GB) |
| IPRoyal | HTTP CONNECT, SOCKS5 | 8M+ residential IPs | Per-GB ($5-7/GB) |

**Integration pattern:** Configure the HTTP CONNECT profile with the provider's proxy endpoint:

```python
from expose.egress import create_egress_profile

profile = create_egress_profile(
    "http_connect",
    proxy_url="http://user:pass@proxy.provider.com:7777"
)
```

**Compliance note:** Verify that commercial proxy usage complies with your authorization scope and rules of engagement. Some enterprise customers prohibit routing through third-party infrastructure in their security policies.

### Air-Gapped Deployments

Air-gapped or restricted-network deployments use the Direct profile exclusively. In this configuration:

- Only passive (Tier-1) and semi-passive (Tier-2) collectors operate.
- Active (Tier-3) collectors are disabled or configured with explicit target allowlists.
- No egress infrastructure is needed.
- The EXPOSE instance consumes imported data (CT logs, DNS zone files, WHOIS bulk data) rather than querying live sources.

This is the correct deployment posture for classified environments, isolated test labs, and offline analysis of previously-collected datasets.

---

## Customer Deployment Checklist

### 1. Choose an egress profile

| Question | If yes | If no |
|----------|--------|-------|
| Do you need active collectors? | Continue to step 2 | Use `direct` profile — done |
| Is attribution avoidance required? | Continue to step 3 | Use `direct` profile — done |
| Is scan fidelity critical? | Use `wireguard` or `http_connect` | Continue to step 4 |
| Do you need geographic diversity? | Use SOCKS5 (Tor gateway) or `http_connect` (commercial) | Use `wireguard` |
| Is budget constrained? | Use SOCKS5 (Tor gateway) | Use `http_connect` (commercial) |

### 2. Deploy egress infrastructure

| Profile | What to deploy |
|---------|---------------|
| Direct | Nothing |
| SOCKS5 (Tor) | 13-container gateway stack (see Reference Architecture above) |
| SOCKS5 (SSH) | `ssh -D <port> user@exit-host` |
| SOCKS5 (microsocks) | `microsocks -p <port>` on exit host |
| WireGuard | Cloud VPS + WireGuard peer (see WireGuard Tunnel above) |
| HTTP CONNECT (self-hosted) | Squid or tinyproxy on exit host |
| HTTP CONNECT (commercial) | Account with Bright Data, Smartproxy, Oxylabs, etc. |

### 3. Configure EXPOSE

```python
from expose.egress import create_egress_profile

# Choose one:
profile = create_egress_profile("direct")
profile = create_egress_profile("socks5", proxy_url="socks5://gateway:10899")
profile = create_egress_profile("wireguard", interface_name="wg0", source_address="10.0.0.2")
profile = create_egress_profile("http_connect", proxy_url="http://proxy.internal:3128")
```

### 4. Verify health check

```python
import asyncio

async def verify():
    check = await profile.health_check()
    print(f"Profile: {check.profile_type}")
    print(f"Healthy: {check.healthy}")
    print(f"Latency: {check.latency_ms} ms")
    if check.error_message:
        print(f"Error: {check.error_message}")

asyncio.run(verify())
```

Expected output for a healthy SOCKS5 (Tor) profile:

```
Profile: socks5
Healthy: True
Latency: 2.3 ms
```

### 5. Monitor in production

- **Tor gateway:** Monitor the Prometheus metrics endpoint (port 10920) for circuit health, exit IP verification, and latency.
- **WireGuard:** Monitor `/sys/class/net/wg0/operstate` and `wg show wg0 latest-handshakes` for peer liveness.
- **Commercial proxies:** Monitor provider dashboards for bandwidth usage, IP pool health, and error rates.
- **All profiles:** Run periodic exit-IP verification to confirm traffic is actually routing through the intended egress path.

---

## EXPOSE Configuration Examples

### Docker Compose: Tor Gateway Stack

```yaml
x-tor-common: &tor-common
  build:
    context: ./tor
  restart: unless-stopped
  security_opt:
    - no-new-privileges:true
  cap_drop:
    - ALL
  cap_add:
    - CHOWN
    - SETUID
    - SETGID
  read_only: true
  tmpfs:
    - /tmp:size=10M
  networks:
    - tor-internal

services:
  tor-any:
    <<: *tor-common
    container_name: egress-tor-any
    environment:
      TOR_COUNTRY_CODE: "ANY"
      TOR_COUNTRY_NAME: "Any (unrestricted)"
    ports:
      - "127.0.0.1:10899:9050"
    volumes:
      - tor-data-any:/var/lib/tor:U

  tor-us:
    <<: *tor-common
    container_name: egress-tor-us
    environment:
      TOR_COUNTRY_CODE: "us"
      TOR_COUNTRY_NAME: "United States"
    ports:
      - "127.0.0.1:10900:9050"
    volumes:
      - tor-data-us:/var/lib/tor:U

  # Repeat for each country: de(:10901), nl(:10902), ch(:10903),
  # se(:10904), gb(:10905), ca(:10906), fr(:10907), jp(:10908), au(:10909)

  public-proxy:
    build:
      context: ./public-proxy
    container_name: egress-public-proxy
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp:size=10M
    ports:
      - "127.0.0.1:10910:10910"
      - "127.0.0.1:10911:10911"
    networks:
      - proxy-net

  metrics-exporter:
    build:
      context: ./monitoring
    container_name: egress-metrics
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp:size=10M
    ports:
      - "127.0.0.1:10920:10920"
    volumes:
      - tor-data-any:/cookies/any:ro
      # Mount all Tor data volumes read-only for cookie access
    networks:
      - tor-internal
      - proxy-net

volumes:
  tor-data-any:
  tor-data-us:
  # ... one per country

networks:
  tor-internal:
    # Tor containers need outbound internet to reach relays.
    # Isolation from public-proxy achieved by network separation.
  proxy-net:
```

### Helm Values: SOCKS5 Egress via Tor Gateway

```yaml
expose:
  egress:
    profile: socks5
    socks5:
      proxyUrl: "socks5://egress-gateway.internal:10899"
      dnsThroughProxy: true
```

### Helm Values: WireGuard Egress

```yaml
expose:
  egress:
    profile: wireguard
    wireguard:
      interfaceName: wg0
      sourceAddress: "10.0.0.2"
```

### Helm Values: HTTP CONNECT via Commercial Provider

```yaml
expose:
  egress:
    profile: http_connect
    httpConnect:
      proxyUrl: "http://user:pass@proxy.provider.com:7777"
```

### Helm Values: Direct (No Egress Infrastructure)

```yaml
expose:
  egress:
    profile: direct
```

### Environment Variable Override

All egress configuration can be overridden via environment variables for containerized deployments:

```bash
EXPOSE_EGRESS_PROFILE=socks5
EXPOSE_EGRESS_SOCKS5_PROXY_URL=socks5://egress-gateway.internal:10900
EXPOSE_EGRESS_SOCKS5_DNS_THROUGH_PROXY=true
```

---

## Appendix: Exit IP Verification Script

Use this pattern to verify all proxy ports are returning distinct exit IPs and that Tor ports are confirmed as Tor exits:

```bash
#!/bin/bash
# Verify egress gateway exit IPs
GATEWAY="127.0.0.1"
TIMEOUT=15

declare -A PORT_LABELS=(
  [10899]="any"  [10900]="us"  [10901]="de"  [10902]="nl"
  [10903]="ch"   [10904]="se"  [10905]="gb"  [10906]="ca"
  [10907]="fr"   [10908]="jp"  [10909]="au"  [10910]="public"
)

printf "%-7s %-10s %-18s\n" "PORT" "COUNTRY" "EXIT IP"
printf "%-7s %-10s %-18s\n" "------" "---------" "-----------------"

for port in "${!PORT_LABELS[@]}"; do
    label="${PORT_LABELS[$port]}"
    exit_ip=$(curl -s --max-time "$TIMEOUT" \
        --socks5-hostname "${GATEWAY}:${port}" \
        "https://ipinfo.io/ip" 2>/dev/null)

    if [ -z "$exit_ip" ]; then
        printf "%-7s %-10s %-18s\n" "$port" "$label" "FAILED"
    else
        printf "%-7s %-10s %-18s\n" "$port" "$label" "$exit_ip"
    fi
done
```

# EXPOSE -- Collector Catalog

**Status:** Advisory -- visual companion to the locked spec, not a substitute for it.
**Date:** 2026-05-10
**Spec references:** SPEC.md section 6 (Collectors), section 6.3 (Tier Model), section 6.4 (Credentials), ADR-008 (Authorized Use), ADR-010 (FIPS Crypto)

This document catalogs every built-in collector shipped with EXPOSE, their tier classification, data sources, accepted seed types, produced observation types, and credential requirements. It is generated from source and kept in sync with the implementation.

---

## Summary Table

| Collector ID | Tier | Source | Seeds | Observations | Credentials | Status |
|---|---|---|---|---|---|---|
| `ct-crtsh` | T1 | crt.sh | Domain | CT_LOG_ENTRY | No | Stable |
| `ct-certstream` | T1 | crt.sh (recency-filtered) | Domain | CT_LOG_ENTRY | No | Stable |
| `cloud-ranges` | T1 | AWS/Azure/GCP manifests | IP, CIDR | CLOUD_IP_RANGE | No | Stable |
| `rdap-whois` | T1 | rdap.org (RFC 9083) | Domain, IP | RDAP_REGISTRATION | No | Stable |
| `bgp-he-toolkit` | T1 | bgp.he.net | IP, ASN | BGP_ASN_LOOKUP | No | Stable |
| `bgp-ripestat` | T1 | stat.ripe.net | IP, ASN | BGP_ASN_LOOKUP | No | Stable |
| `bgp-team-cymru` | T1 | Team Cymru DNS | IP | BGP_ASN_LOOKUP | No | Stable |
| `spf-dkim-dmarc` | T1 | DNS (TXT records) | Domain | DNS_RECORD | No | Stable |
| `github-exposed` | T1 | api.github.com | Domain, Organization | SCANNER_HOST | Optional | Stable |
| `favicon-hash` | T2 | Target host HTTP | Domain, IP | HTTP_RESPONSE | No | Stable |
| `active-dns-resolve` | T3 | System DNS resolver | Domain | DNS_RESOLUTION | No | Stable |
| `active-tls-handshake` | T3 | Target host TLS | Domain, IP | TLS_HANDSHAKE | No | Stable |
| `active-http-fingerprint` | T3 | Target host HTTP | Domain, IP | HTTP_RESPONSE | No | Stable |
| `active-port-surface` | T3 | Target host TCP | IP | PORT_SCAN_RESULT | No | Stable |

---

## 1. Overview

### What collectors are

A collector is a pluggable module that, given a **seed** (a typed input such as a domain name or IP address), queries a specific data source and yields **observations** -- structured evidence records that flow into the EXPOSE pipeline. Collectors are the data-acquisition layer of the pipeline; they never write to the observation graph directly. All persistence flows through the dispatcher.

Each collector implements the `Collector` abstract base class defined in `src/expose/collectors/base.py`:

- `expand(seed)` -- async generator that yields `Observation` records for the given seed.
- `health_check()` -- quick pre-run reachability probe. Collectors that fail their health check are skipped for the run.

Collectors are registered at import time via the `@register_collector` decorator. The dispatcher looks them up by `collector_id` string through the `CollectorRegistry`.

### The three-tier model

EXPOSE classifies collectors into three tiers based on the sensitivity of the data-collection method (per SPEC section 6.3):

**Tier 1 -- Passive, Broad.** Queries public databases and bulk data sources. No direct contact with the target infrastructure. Examples: Certificate Transparency logs, RDAP/WHOIS, cloud IP-range manifests, BGP routing data. No attribution gating required.

**Tier 2 -- Passive, Targeted.** Queries internet-wide scan databases or public APIs specifically about entities already in the observation graph. Still passive (no packets sent to the target), but targeted at specific hosts. Example: favicon hash correlation against known web assets. No attribution gating required.

**Tier 3 -- Active, Attribution-Gated.** Sends packets directly to the target infrastructure: DNS resolution, TLS handshakes, HTTP requests, TCP port probes. Tier-3 dispatch is gated by the dispatcher -- a Tier-3 collector can only be dispatched against an entity whose attribution tier is `confirmed` or `high`, OR which is explicitly listed in the tenant's authorization scope (per ADR-008). This gating is enforced centrally by `is_tier_3_dispatch_allowed()` in `src/expose/collectors/tiers.py`; individual collectors do NOT self-gate.

### How dispatch works

1. The tenant configuration specifies which collectors are enabled via `collectors.enabled` (a list of collector IDs).
2. The dispatcher looks up each enabled collector ID in the `CollectorRegistry`.
3. For each seed in the run, the dispatcher constructs a fresh `CollectorConfig` (with tenant context, run ID, resolved credentials, rate limits, and timeouts).
4. For Tier-3 collectors, the dispatcher checks `is_tier_3_dispatch_allowed()` before dispatching. Denied dispatches are recorded as structured refusal events.
5. The dispatcher instantiates the collector with the config and calls `expand(seed)`, collecting yielded observations for graph upsert.

---

## 2. Tier 1 -- Passive, Broad

### ct-crtsh

| Field | Value |
|---|---|
| **Collector ID** | `ct-crtsh` |
| **Class** | `CrtShCollector` |
| **Source file** | `src/expose/collectors/builtin/ct_crtsh.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [crt.sh](https://crt.sh/) JSON API |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `CT_LOG_ENTRY` |
| **Credentials** | None |
| **Rate limit** | Advisory (crt.sh has no published contract; may return 429 under heavy load) |

Queries the crt.sh JSON API for certificates matching a domain seed (including subdomains via wildcard query `%.example.com`). crt.sh aggregates Certificate Transparency log entries from Google, Cloudflare, and DigiCert logs. Results include both pre-certificates and final certificates.

**Key payload fields:**

- `issuer_name` -- Certificate issuer (sanitized)
- `common_name` -- Certificate common name (sanitized)
- `sans` -- Subject Alternative Names (sanitized, 255-byte cap per SAN)
- `not_before`, `not_after` -- Certificate validity window
- `serial_number` -- Hex serial (lowercase), used as proxy identifier per ADR-010

Deduplication is performed within a single run by serial number.

---

### ct-certstream

| Field | Value |
|---|---|
| **Collector ID** | `ct-certstream` |
| **Class** | `CertstreamCollector` |
| **Source file** | `src/expose/collectors/builtin/ct_certstream.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [crt.sh](https://crt.sh/) JSON API (recency-filtered) |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `CT_LOG_ENTRY` |
| **Credentials** | None |
| **Rate limit** | Advisory (same as ct-crtsh) |

Near-real-time Certificate Transparency monitoring. Queries the same crt.sh API as `ct-crtsh` but filters results to certificates issued within a configurable recency window (default: 24 hours). This simulates the behavior of a true certstream WebSocket feed without WebSocket complexity.

The recency window is configurable via `config.extra["recency_hours"]`.

**Key payload fields:** Same as `ct-crtsh`, plus:

- `source` -- Always `"certstream"` (distinguishes from `ct-crtsh` output)
- `recency_hours` -- The configured recency window

A future version (v0.2+) will replace the polling approach with the Certstream WebSocket API (`wss://certstream.calidog.io/`).

---

### cloud-ranges

| Field | Value |
|---|---|
| **Collector ID** | `cloud-ranges` |
| **Class** | `CloudRangesCollector` |
| **Source file** | `src/expose/collectors/builtin/cloud_ranges.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | AWS, Azure, GCP IP range manifests (cached on disk) |
| **Seeds accepted** | `IP`, `CIDR` |
| **Observation type** | `CLOUD_IP_RANGE` |
| **Credentials** | None |
| **Rate limit** | N/A (local lookup, no network calls during expand) |

Compares seed IP addresses and CIDR blocks against pre-cached cloud provider IP range manifests. Matches indicate which cloud provider, region, and service own a given address.

The collector loads range data from cached JSON files on disk (fetched daily from provider endpoints in production). The cache directory is configured via `config.extra["ranges_dir"]`. Expected files:

- `aws-ip-ranges.json` -- from `https://ip-ranges.amazonaws.com/ip-ranges.json`
- `azure-ip-ranges.json` -- from Microsoft's ServiceTags download
- `gcp-ip-ranges.json` -- from `https://www.gstatic.com/ipranges/cloud.json`

Per SPEC section 6.1, this collector never makes live network calls during `expand()`. All lookups are against in-memory data loaded at construction time.

**Key payload fields:**

- `provider` -- Cloud provider name (`aws`, `azure`, `gcp`)
- `region` -- Provider region/scope
- `service` -- Provider service name
- `prefix` -- The matching cloud CIDR prefix

---

### rdap-whois

| Field | Value |
|---|---|
| **Collector ID** | `rdap-whois` |
| **Class** | `RdapWhoisCollector` |
| **Source file** | `src/expose/collectors/builtin/rdap_whois.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [rdap.org](https://rdap.org) bootstrap service (RFC 9083) |
| **Seeds accepted** | `DOMAIN`, `IP` |
| **Observation type** | `RDAP_REGISTRATION` |
| **Credentials** | None |
| **Rate limit** | Framework-level |

Queries RDAP endpoints via the `rdap.org` bootstrap service for domain and IP registration metadata. Extracts registrant organization, registrar, dates, nameservers, and status codes.

**PII non-enrichment policy:** This collector deliberately skips personal names, email addresses, phone numbers, and street addresses. Only organization names are extracted from RDAP `vcardArray` entities. If a registrant entity's `fn` field appears to be a personal name (detected by heuristic), it is discarded.

**Key payload fields:**

- `registrant_org` -- Registrant organization name (sanitized, PII-filtered)
- `registrar` -- Registrar name (sanitized)
- `registration_date`, `expiration_date` -- RFC 3339 timestamps
- `nameservers` -- List of authoritative nameserver hostnames (canonicalized)
- `status` -- RDAP status codes (e.g., `clientTransferProhibited`)
- `rdap_port43` -- Legacy WHOIS server hostname

The evidence blob contains the full RDAP JSON response (`application/rdap+json`).

---

### bgp-he-toolkit

| Field | Value |
|---|---|
| **Collector ID** | `bgp-he-toolkit` |
| **Class** | `HeToolkitCollector` |
| **Source file** | `src/expose/collectors/builtin/bgp_he_toolkit.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [Hurricane Electric BGP Toolkit](https://bgp.he.net/) |
| **Seeds accepted** | `IP`, `ASN` |
| **Observation type** | `BGP_ASN_LOOKUP` |
| **Credentials** | None |
| **Rate limit** | Advisory |

Scrapes the Hurricane Electric BGP Toolkit web pages for BGP routing information. For IP seeds, queries the IP detail page to extract the announcing ASN, holder name, and announced prefixes. For ASN seeds, queries the ASN detail page.

Parsing uses regex and string matching -- no HTML parser dependencies.

**Key payload fields:**

- `asn` -- Autonomous System Number (e.g., `AS13335`)
- `holder` -- ASN holder/organization name (sanitized)
- `prefixes` -- List of announced CIDR prefixes
- `source` -- Always `"he-toolkit"`

---

### bgp-ripestat

| Field | Value |
|---|---|
| **Collector ID** | `bgp-ripestat` |
| **Class** | `RipeStatCollector` |
| **Source file** | `src/expose/collectors/builtin/bgp_ripestat.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [RIPEstat Data API](https://stat.ripe.net/data/) |
| **Seeds accepted** | `IP`, `ASN` |
| **Observation type** | `BGP_ASN_LOOKUP` |
| **Credentials** | None |
| **Rate limit** | Advisory (heavy users should register for an API key) |

Queries the RIPEstat Data API for BGP routing information. For IP seeds, uses the `network-info` endpoint to find the announcing ASN and covering prefix. For ASN seeds, uses the `announced-prefixes` endpoint.

**Key payload fields:**

- `asn` -- Autonomous System Number (e.g., `AS13335`)
- `holder` -- ASN holder name (sanitized)
- `prefixes` -- List of announced CIDR prefixes
- `source` -- Always `"ripestat"`

---

### bgp-team-cymru

| Field | Value |
|---|---|
| **Collector ID** | `bgp-team-cymru` |
| **Class** | `TeamCymruCollector` |
| **Source file** | `src/expose/collectors/builtin/bgp_team_cymru.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [Team Cymru](https://www.team-cymru.com/) DNS-based IP-to-ASN mapping |
| **Seeds accepted** | `IP` |
| **Observation type** | `BGP_ASN_LOOKUP` |
| **Credentials** | None |
| **Rate limit** | Framework-level |
| **Optional dependency** | `dnspython` (install via `expose[collectors-dns]`) |

Queries the Team Cymru IP-to-ASN mapping service via DNS TXT lookups. Uses a two-step process:

1. Reverse the IP octets and query `{reversed}.origin.asn.cymru.com` TXT to get ASN, prefix, country, and registry.
2. Query `AS{asn}.asn.cymru.com` TXT for the ASN holder name.

**Key payload fields:**

- `asn` -- Autonomous System Number (e.g., `AS13335`)
- `asn_name` -- ASN holder name (sanitized)
- `prefix` -- Covering CIDR prefix
- `country` -- Country code
- `registry` -- Regional Internet Registry (e.g., `arin`, `ripe`)
- `source` -- Always `"team-cymru"`

---

### spf-dkim-dmarc

| Field | Value |
|---|---|
| **Collector ID** | `spf-dkim-dmarc` |
| **Class** | `EmailAuthCollector` |
| **Source file** | `src/expose/collectors/builtin/email_auth.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | DNS TXT records |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `DNS_RECORD` |
| **Credentials** | None |
| **Rate limit** | Framework-level |
| **Optional dependency** | `dnspython` (install via `expose[collectors-dns]`) |

Queries DNS for email authentication records associated with a domain:

1. **SPF** -- TXT record at `{domain}` containing `v=spf1 ...`
2. **DKIM** -- TXT records at `{selector}._domainkey.{domain}` for common selectors (`default`, `google`, `selector1`, `selector2`, `k1`, `s1`, `s2`, `dkim`, `mail`)
3. **DMARC** -- TXT record at `_dmarc.{domain}`

The output reveals mail infrastructure, authorized third-party senders (SPF includes), and potential shadow IT (SaaS platforms authorized to send as the organization).

**Key payload fields:**

- `has_spf`, `spf_record`, `spf_includes`, `spf_mechanisms` -- SPF policy
- `has_dkim`, `dkim_selectors_found`, `dkim_records` -- DKIM selector presence
- `has_dmarc`, `dmarc_record`, `dmarc_policy`, `dmarc_rua` -- DMARC enforcement

---

### github-exposed

| Field | Value |
|---|---|
| **Collector ID** | `github-exposed` |
| **Class** | `GitHubExposedCollector` |
| **Source file** | `src/expose/collectors/builtin/github_exposed.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [GitHub REST API v3](https://docs.github.com/en/rest) |
| **Seeds accepted** | `DOMAIN`, `ORGANIZATION` |
| **Observation type** | `SCANNER_HOST` |
| **Credentials** | Optional (`api_key` slot increases rate limit from 10 to 30 req/min) |
| **Rate limit** | 10 req/min unauthenticated, 30 req/min authenticated |

Searches the public GitHub API for repositories and code belonging to or mentioning the target organization or domain. Reveals:

- Organization repositories with potential config files, internal hostnames, and API endpoints.
- Public repositories mentioning the domain in code or configuration files.
- Potential leaked credential indicators (metadata only -- the collector flags the repository, it does NOT extract secrets).

For organization seeds, performs a repository search. For domain seeds, performs both a repository search and a code search (filtering to configuration file extensions: yml, yaml, json, env, toml, ini, cfg, conf).

**Key payload fields:**

- `source` -- Always `"github"`
- `search_type` -- `"repository"` or `"code"`
- `total_results` -- Total match count from the API
- `repositories` -- Up to 20 repository summaries (`full_name`, `description`, `html_url`, `stars`, `updated_at`)
- `code_matches` -- Up to 20 code match summaries (`repository`, `path`, `html_url`)

---

## 3. Tier 2 -- Passive, Targeted

### favicon-hash

| Field | Value |
|---|---|
| **Collector ID** | `favicon-hash` |
| **Class** | `FaviconHashCollector` |
| **Source file** | `src/expose/collectors/builtin/favicon_hash.py` |
| **Tier** | 2 (passive, targeted) |
| **Data source** | Target host HTTP (`/favicon.ico`, `/apple-touch-icon.png`) |
| **Seeds accepted** | `DOMAIN`, `IP` |
| **Observation type** | `HTTP_RESPONSE` |
| **Credentials** | None |
| **Rate limit** | Framework-level |

Fetches favicon files from discovered web assets and computes a SHA-256 hash via the FIPS crypto adapter (ADR-010). The same favicon hash across different hosts implies the same operator or application -- useful for cluster correlation and technology fingerprinting.

The collector tries HTTPS first, then HTTP. It probes `/favicon.ico` first, then `/apple-touch-icon.png` as a fallback. Only one favicon per host is collected (the first found).

A stub MurmurHash3 field is included in the payload for future Shodan-compatible correlation (pending `mmh3` dependency addition).

**Key payload fields:**

- `favicon_sha256` -- FIPS-validated SHA-256 hex digest of the favicon bytes
- `favicon_mmh3` -- MurmurHash3 (stubbed as `0` in v0.1.0)
- `favicon_size_bytes` -- Size of the favicon file
- `favicon_url` -- Final URL after redirects
- `favicon_content_type` -- HTTP Content-Type header

The evidence blob contains the raw favicon bytes.

---

## 4. Tier 3 -- Active, Attribution-Gated

All Tier-3 collectors send packets directly to the target infrastructure. Dispatch is gated by the dispatcher -- a Tier-3 collector can only run against an entity whose attribution tier is `confirmed` or `high`, OR which is explicitly listed in the tenant's authorization scope. This gating is enforced upstream; individual Tier-3 collectors do NOT self-gate.

Enforcement mode (per Gitea issue #29) controls the dispatcher's response to denied dispatches:

- **medium** (default): Denial is advisory; the dispatcher may log a warning and proceed at its discretion.
- **hard**: Denial is absolute; the dispatcher records a structured `ScopeRefusalEvent` for audit.

### active-dns-resolve

| Field | Value |
|---|---|
| **Collector ID** | `active-dns-resolve` |
| **Class** | `ActiveDnsCollector` |
| **Source file** | `src/expose/collectors/builtin/active_dns.py` |
| **Tier** | 3 (active, attribution-gated) |
| **Data source** | System DNS resolver (or configured egress-profile nameservers) |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `DNS_RESOLUTION` |
| **Credentials** | None |
| **Rate limit** | Framework-level |
| **Optional dependency** | `dnspython` (install via `expose[collectors-dns]`) |

Performs active DNS resolution against target domains, querying A, AAAA, CNAME, MX, NS, TXT, and SOA record types. On NXDOMAIN, emits no observations (not an error). Individual record-type failures (e.g., NoAnswer for TXT) are skipped without failing the whole expansion.

Supports egress profile integration: if `config.extra["egress_profile"]` is set to an `EgressProfile` instance, the resolver uses its configured nameservers.

**Key payload fields (vary by record type):**

- A/AAAA: `values` (list of canonicalized IPs), `ttl`
- CNAME: `target` (canonicalized domain)
- MX: `exchanges` (list of `{priority, exchange}`)
- NS: `nameservers` (list of canonicalized domains)
- TXT: `values` (list of sanitized text records)
- SOA: `mname`, `rname`, `serial`, `refresh`, `retry`, `expire`, `minimum`

---

### active-tls-handshake

| Field | Value |
|---|---|
| **Collector ID** | `active-tls-handshake` |
| **Class** | `ActiveTlsCollector` |
| **Source file** | `src/expose/collectors/builtin/active_tls.py` |
| **Tier** | 3 (active, attribution-gated) |
| **Data source** | Target host TLS (default port 443, configurable via seed `properties.port`) |
| **Seeds accepted** | `DOMAIN`, `IP` |
| **Observation type** | `TLS_HANDSHAKE` |
| **Credentials** | None |
| **Rate limit** | Framework-level |

Performs TLS handshakes against discovered hosts and extracts certificate chain details, negotiated protocol version, cipher suite, and a JARM fingerprint stub.

Certificate verification is intentionally disabled (`CERT_NONE`) because the collector needs to observe all certificates -- including self-signed and expired ones -- for attack-surface enumeration. The `cryptography` library is used to parse DER certificates for rich metadata (subject CN, issuer, SANs, validity dates). Certificate fingerprints are computed via the FIPS SHA-256 adapter (ADR-010).

JARM fingerprinting is stubbed in v0.1.0 (returns `None`); full implementation is a follow-up.

**Key payload fields:**

- `tls_version` -- Negotiated TLS version (e.g., `TLSv1.3`)
- `cipher_suite` -- Negotiated cipher suite
- `cert_subject_cn` -- Certificate subject Common Name
- `cert_issuer_cn`, `cert_issuer_org` -- Issuer details
- `cert_serial` -- Hex serial number (lowercase)
- `cert_not_before`, `cert_not_after` -- ISO 8601 validity dates
- `cert_sans` -- Subject Alternative Names (sanitized)
- `cert_fingerprint_sha256` -- FIPS-validated SHA-256 fingerprint of DER cert
- `jarm_fingerprint` -- JARM hash (stubbed as `null` in v0.1.0)

The evidence blob contains the leaf certificate in PEM format.

---

### active-http-fingerprint

| Field | Value |
|---|---|
| **Collector ID** | `active-http-fingerprint` |
| **Class** | `ActiveHttpCollector` |
| **Source file** | `src/expose/collectors/builtin/active_http.py` |
| **Tier** | 3 (active, attribution-gated) |
| **Data source** | Target host HTTP (ports 80 and 443) |
| **Seeds accepted** | `DOMAIN`, `IP` |
| **Observation type** | `HTTP_RESPONSE` |
| **Credentials** | None |
| **Rate limit** | Per-host token-bucket (default 1 req/sec, configurable via `config.extra["requests_per_second"]`) plus framework-level |

Probes target hosts on ports 80 (HTTP) and 443 (HTTPS) to capture HTTP response metadata. Follows up to 5 redirects. Certificate verification is intentionally disabled for HTTPS probes (same rationale as the TLS collector).

Includes a belt-and-braces per-host async token-bucket rate limiter that caps request rate independently of the framework-level limiter.

**Key payload fields:**

- `url` -- Final URL after redirects (sanitized)
- `status_code` -- HTTP response status code
- `server_header` -- Server header value (sanitized)
- `content_type` -- Content-Type header (sanitized)
- `title` -- Page title extracted from first 2048 bytes of response body
- `headers` -- Security-relevant headers: `strict-transport-security`, `x-frame-options`, `content-security-policy`, `x-content-type-options`, `x-xss-protection`, `permissions-policy`
- `redirect_chain` -- Ordered list of redirect URLs (sanitized)
- `banner` -- First 4096 bytes of response body (sanitized)

The evidence blob contains the raw response headers serialized as text.

---

### active-port-surface

| Field | Value |
|---|---|
| **Collector ID** | `active-port-surface` |
| **Class** | `ActivePortSurfaceCollector` |
| **Source file** | `src/expose/collectors/builtin/active_port_surface.py` |
| **Tier** | 3 (active, attribution-gated) |
| **Data source** | Target host TCP (curated port list) |
| **Seeds accepted** | `IP` |
| **Observation type** | `PORT_SCAN_RESULT` |
| **Credentials** | None |
| **Rate limit** | Framework-level |

Light port-surface enumeration on attributed IP addresses. Probes a curated set of 27 common service ports to identify exposed services. This is NOT a full Nmap-style scan -- it is a targeted check of high-value ports using async TCP connect probes.

Default ports probed: 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 2222, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 9200, 9443, 27017.

The port list can be overridden per seed via `seed.properties["ports"]`. The TCP connect timeout (default 3 seconds) is configurable via `config.extra["probe_timeout_seconds"]`.

All ports are probed concurrently via `asyncio.gather`. The collector yields exactly one observation per seed (even when no ports are open -- the absence of open ports is informative).

**Key payload fields:**

- `open_ports` -- Sorted list of open port numbers
- `closed_ports_probed` -- Count of ports that were closed or filtered
- `total_ports_probed` -- Total number of ports probed
- `probe_timeout_seconds` -- The configured TCP connect timeout

---

## 5. Writing a Custom Collector

To create a custom collector:

1. Subclass `expose.collectors.Collector`.
2. Set the four class-level metadata attributes: `collector_id`, `collector_version`, `requires_credentials`, `tier`.
3. Implement `expand(seed)` as an async generator yielding `Observation` records.
4. Implement `health_check()` returning a `CollectorHealthCheck`.
5. Register the collector with `@register_collector` or call `CollectorRegistry.register()` directly.

Refer to `CONTRIBUTING.md` for coding conventions, testing expectations, and the pull request process. The existing built-in collectors in `src/expose/collectors/builtin/` serve as reference implementations.

Key contracts to honor:

- Respect `CollectorConfig.request_timeout_seconds` and configured rate limits.
- Never raise on individual observation failures; surface them as `Observation.warnings` entries.
- Catastrophic failures (auth invalid, source unreachable) may raise `CollectorError` subclasses.
- Never write to the observation graph directly. Yielding into the dispatcher is the only persistence path.
- Never import `hashlib` or `secrets` directly; use the FIPS adapter in `expose.crypto` (ADR-010).

---

## 6. Credential Management

### How the CredentialResolver works

The `CredentialResolver` (in `src/expose/pipeline/credential_resolver.py`) bridges the secrets backend and the dispatcher's `CollectorConfig` construction. The flow:

1. Each collector has a `CollectorCredentialSpec` declaring its required credential slots (e.g., `github-exposed` has an optional `api_key` slot).
2. At dispatch time, the resolver fetches tenant-specific secret values from the configured `SecretsBackend` using the key convention: `collector.{collector_id}.{key_name}`.
3. Resolved credentials are injected into the `CollectorConfig.credentials` dict as `CollectorCredential` instances.
4. The collector accesses credentials via `self.config.credentials["slot_name"].secret_value`.
5. Per SPEC section 6.4, credential material is held only for the lifetime of a single `expand()` invocation. Instances are not persisted.

If a required key is absent from the backend, `CredentialResolutionError` is raised before the collector is constructed. Secret values are never logged.

### Secrets backends

EXPOSE ships three `SecretsBackend` implementations:

| Backend | Class | Use case |
|---|---|---|
| **In-Memory** | `InMemoryBackend` | Testing and development only. Secrets are stored in a Python dict. |
| **Environment** | `EnvSecretsBackend` | Lightweight production. Reads secrets from environment variables. Suitable for Kubernetes `Secret` objects mounted as env vars. |
| **Vault** | `VaultSecretsBackend` | Full production. Reads from HashiCorp Vault KV v2 via httpx. Supports token and approle authentication. |

All backends are defined in `src/expose/secrets/`. The backend is selected at application startup and injected into the pipeline configuration.

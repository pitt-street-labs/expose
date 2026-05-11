# EXPOSE -- Collector Catalog

**Status:** Advisory -- visual companion to the locked spec, not a substitute for it.
**Date:** 2026-05-11
**Spec references:** SPEC.md section 6 (Collectors), section 6.3 (Tier Model), section 6.4 (Credentials), ADR-008 (Authorized Use), ADR-010 (FIPS Crypto)

This document catalogs every built-in collector shipped with EXPOSE, their tier classification, data sources, accepted seed types, produced observation types, and credential requirements. It is generated from source and kept in sync with the implementation.

---

## Summary Table

| # | Collector ID | Tier | Category | Seeds | ATT&CK | Credentials | Status |
|---|---|---|---|---|---|---|---|
| 1 | `ct-crtsh` | T1 | Certificate Transparency | Domain | T1596.003 | No | Stable |
| 2 | `ct-censys` | T1 | Certificate Transparency | Domain | T1596.003 | Required | Stable |
| 3 | `ct-certspotter` | T1 | Certificate Transparency | Domain | T1596.003 | No | Stable |
| 4 | `ct-certstream` | T1 | Certificate Transparency | Domain | T1596.003 | No | Stable |
| 5 | `active-dns-resolve` | T3 | DNS | Domain | T1596.001 | No | Stable |
| 6 | `dns-subdomain-enum` | T3 | DNS | Domain | T1596.001 | No | Stable |
| 7 | `dns-chaos` | T1 | DNS | Domain | T1596.001 | Optional | Stable |
| 8 | `dns-zone-transfer` | T3 | DNS | Domain | T1596.001 | No | Stable |
| 9 | `dns-passive-history` | T1 | DNS | Domain, IP | T1596.001 | Required | Stable |
| 10 | `dns-reverse-ptr` | T2 | DNS | IP | T1596.001 | No | Stable |
| 11 | `dns-blacklist` | T1 | DNS | IP | T1596.001 | No | Stable |
| 12 | `bgp-ripestat` | T1 | BGP/ASN | IP, ASN | -- | No | Stable |
| 13 | `bgp-he-toolkit` | T1 | BGP/ASN | IP, ASN | -- | No | Stable |
| 14 | `bgp-team-cymru` | T1 | BGP/ASN | IP | -- | No | Stable |
| 15 | `active-http-fingerprint` | T3 | HTTP/Web | Domain, IP | -- | No | Stable |
| 16 | `robots-txt` | T2 | HTTP/Web | Domain | T1592.004 | No | Stable |
| 17 | `security-txt` | T1 | HTTP/Web | Domain | T1592.004 | No | Stable |
| 18 | `favicon-hash` | T2 | HTTP/Web | Domain, IP | -- | No | Stable |
| 19 | `waf-detection` | T2 | HTTP/Web | Domain, IP | T1592.004 | No | Stable |
| 20 | `screenshot-vision` | T2 | HTTP/Web | Domain, IP | T1592.004 | No | Stable |
| 21 | `cloud-ranges` | T1 | Cloud | IP, CIDR | -- | No | Stable |
| 22 | `cloud-storage-exposure` | T1 | Cloud | Organization, Domain | T1526 | No | Stable |
| 23 | `github-exposed` | T1 | Code | Domain, Organization | -- | Optional | Stable |
| 24 | `git-commit-emails` | T2 | Code | Organization, Domain | T1593.003 | Required | Stable |
| 25 | `spf-dkim-dmarc` | T1 | Email | Domain | -- | No | Stable |
| 26 | `mail-headers` | T1 | Email | Domain | T1598 | No | Stable |
| 27 | `scan-shodan` | T1 | Scan Aggregators | Domain, IP | T1596 | Required | Stable |
| 28 | `scan-censys` | T1 | Scan Aggregators | Domain, IP | T1596 | Required | Stable |
| 29 | `scan-binaryedge` | T1 | Scan Aggregators | Domain, IP | T1596 | Required | Stable |
| 30 | `wayback-machine` | T1 | Historical | Domain, IP | -- | No | Stable |
| 31 | `common-crawl` | T1 | Historical | Domain | -- | No | Stable |
| 32 | `rdap-whois` | T1 | Specialized | Domain, IP | -- | No | Stable |
| 33 | `ma-discovery` | T1 | Specialized | Organization | -- | No | Stable |
| 34 | `sip-discovery` | T1 | Specialized | Domain | -- | No | Stable |
| 35 | `wikipedia-edits` | T1 | Specialized | Organization, Domain | -- | No | Stable |
| 36 | `paste-monitor` | T2 | Specialized | Domain, Organization | -- | Optional | Stable |
| 37 | `otx-alienvault` | T1 | Specialized | Domain | T1596 | Optional | Stable |
| 38 | `waf-origin-discovery` | T2 | Specialized | Domain, IP | -- | No | Stable |
| 39 | `active-port-surface` | T3 | Specialized | IP | -- | No | Stable |
| 40 | `active-tls-handshake` | T3 | Specialized | Domain, IP | -- | No | Stable |
| 41 | `dark-web-indicators` | T3 | Specialized | Domain | T1597 | Required | Stable |

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

## 2. Certificate Transparency

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
| **ATT&CK** | T1596.003 (Search Open Technical Databases: Digital Certificates) |
| **Credentials** | None |

Queries the crt.sh JSON API for certificates matching a domain seed (including subdomains via wildcard query `%.example.com`). crt.sh aggregates Certificate Transparency log entries from Google, Cloudflare, and DigiCert logs. Results include both pre-certificates and final certificates. Deduplication is performed within a single run by serial number.

---

### ct-censys

| Field | Value |
|---|---|
| **Collector ID** | `ct-censys` |
| **Class** | `CensysCertCollector` |
| **Source file** | `src/expose/collectors/builtin/ct_censys.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [Censys Certificates API v2](https://search.censys.io/api/v2) |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `CT_LOG_ENTRY` |
| **ATT&CK** | T1596.003 |
| **Credentials** | Required: `censys_api_id`, `censys_api_secret` (HTTP Basic auth) |

Alternate CT source when crt.sh is unavailable. Queries the Censys Certificates Search API for certificates matching a domain, extracting Subject Alternative Names (SANs) as subdomain entities. Distinct from `scan-censys` which searches the Censys *hosts* endpoint for port/service discovery. Self-rate-limits to 2 requests/second (Censys free tier).

---

### ct-certspotter

| Field | Value |
|---|---|
| **Collector ID** | `ct-certspotter` |
| **Class** | `CertSpotterCollector` |
| **Source file** | `src/expose/collectors/builtin/ct_certspotter.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [CertSpotter / SSLMate API](https://api.certspotter.com/v1/issuances) |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `CT_LOG_ENTRY` |
| **ATT&CK** | T1596.003 |
| **Credentials** | None |

Free, no-auth-required CT backup. Queries CertSpotter for certificate issuances matching a domain (including subdomains). Filters out wildcard SANs (`*.example.com`). Uses the `tbs_sha256` fingerprint for deduplication. Includes an in-memory TTL cache (1 hour) to avoid redundant queries across repeated scans. Rate limited to 60 requests/minute.

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
| **ATT&CK** | T1596.003 |
| **Credentials** | None |

Near-real-time Certificate Transparency monitoring. Queries the same crt.sh API as `ct-crtsh` but filters results to certificates issued within a configurable recency window (default: 24 hours). Configurable via `config.extra["recency_hours"]`. A future version (v0.2+) will replace the polling approach with the Certstream WebSocket API.

---

## 3. DNS

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
| **ATT&CK** | T1596.001 (Search Open Technical Databases: DNS/Passive DNS) |
| **Credentials** | None |
| **Optional dependency** | `dnspython` (install via `expose[collectors-dns]`) |

Performs active DNS resolution against target domains, querying A, AAAA, CNAME, MX, NS, TXT, and SOA record types. On NXDOMAIN, emits no observations. Individual record-type failures are skipped without failing the whole expansion. Supports egress profile integration for alternate nameservers.

---

### dns-subdomain-enum

| Field | Value |
|---|---|
| **Collector ID** | `dns-subdomain-enum` |
| **Class** | `SubdomainEnumCollector` |
| **Source file** | `src/expose/collectors/builtin/dns_subdomain_enum.py` |
| **Tier** | 3 (active, attribution-gated) |
| **Data source** | System DNS resolver |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `DNS_RESOLUTION` |
| **ATT&CK** | T1596.001 |
| **Credentials** | None |
| **Optional dependency** | `dnspython` (install via `expose[collectors-dns]`) |

Wordlist-based subdomain discovery. Resolves `{word}.{apex}` for each word in the configured wordlist via parallel A/AAAA queries (default: 50 concurrent, configurable). Includes wildcard detection -- before enumeration, resolves a random subdomain; if it resolves, all subsequent results matching those IPs are filtered out. Also resolves CNAME chains for each candidate. Wordlist path configurable via `config.extra["wordlist_path"]`; default is `examples/wordlists/subdomains-5000.txt`.

---

### dns-chaos

| Field | Value |
|---|---|
| **Collector ID** | `dns-chaos` |
| **Class** | `DnsChaosCollector` |
| **Source file** | `src/expose/collectors/builtin/dns_chaos.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [ProjectDiscovery Chaos API](https://dns.projectdiscovery.io/) |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `DNS_RECORD` |
| **ATT&CK** | T1596.001 |
| **Credentials** | Optional: `api_key` (Authorization header for expanded results) |

Queries the ProjectDiscovery Chaos public API for known subdomains of a target domain. The API returns subdomain labels (e.g., "www", "mail"), which are assembled into FQDNs. No credentials required for public-tier access; an API key enables expanded results. Rate limited to 30 requests/minute.

---

### dns-zone-transfer

| Field | Value |
|---|---|
| **Collector ID** | `dns-zone-transfer` |
| **Class** | `ZoneTransferCollector` |
| **Source file** | `src/expose/collectors/builtin/dns_zone_transfer.py` |
| **Tier** | 3 (active, attribution-gated) |
| **Data source** | Target domain authoritative nameservers (AXFR) |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `DNS_RECORD` |
| **ATT&CK** | T1596.001 |
| **Credentials** | None |
| **Optional dependency** | `dnspython` (install via `expose[collectors-dns]`) |

Attempts AXFR zone transfers against the authoritative nameservers for a domain. Most well-configured nameservers refuse AXFR (recorded as informational observations). When a transfer succeeds, it is a critical finding -- every record in the zone is exposed, and the collector emits one observation per record plus a summary. AXFR timeout: 10 seconds per nameserver.

---

### dns-passive-history

| Field | Value |
|---|---|
| **Collector ID** | `dns-passive-history` |
| **Class** | `PassiveDnsHistoryCollector` |
| **Source file** | `src/expose/collectors/builtin/dns_passive_history.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [SecurityTrails API](https://api.securitytrails.com/v1), [VirusTotal API](https://www.virustotal.com/api/v3) |
| **Seeds accepted** | `DOMAIN`, `IP` |
| **Observation type** | `PASSIVE_DNS`, `DNS_RECORD` |
| **ATT&CK** | T1596.001 |
| **Credentials** | Required (at least one): `securitytrails_api_key`, `virustotal_api_key` |

Queries SecurityTrails (primary) and VirusTotal (secondary) for historical DNS resolution records. Reveals infrastructure changes over time: IP migrations, hosting provider switches, CDN adoption, and previously-associated subdomains. For domain seeds, queries SecurityTrails historical DNS for A/AAAA/MX/NS/CNAME records plus subdomain enumeration. For IP seeds, performs reverse lookups. Degrades gracefully if only one key is configured.

---

### dns-reverse-ptr

| Field | Value |
|---|---|
| **Collector ID** | `dns-reverse-ptr` |
| **Class** | `ReversePtrCollector` |
| **Source file** | `src/expose/collectors/builtin/dns_reverse_ptr.py` |
| **Tier** | 2 (passive, targeted) |
| **Data source** | DNS PTR records (in-addr.arpa / ip6.arpa) |
| **Seeds accepted** | `IP` |
| **Observation type** | `DNS_RECORD` |
| **ATT&CK** | T1596.001 |
| **Credentials** | None |
| **Optional dependency** | `dnspython` (install via `expose[collectors-dns]`) |

Given an IP address seed, constructs the reverse DNS name and performs a PTR query. Discovered hostnames are emitted as observations and tagged as potential new domain seeds for downstream expansion (`is_new_domain_seed: true`). Supports both IPv4 (in-addr.arpa) and IPv6 (ip6.arpa nibble format).

---

### dns-blacklist

| Field | Value |
|---|---|
| **Collector ID** | `dns-blacklist` |
| **Class** | `DnsBlacklistCollector` |
| **Source file** | `src/expose/collectors/builtin/dns_blacklist.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | 7 DNSBL providers (Spamhaus ZEN, Barracuda, SORBS, SpamCop, UCEProtect L1/L2, Abusix) |
| **Seeds accepted** | `IP` |
| **Observation type** | `DNS_RECORD` |
| **ATT&CK** | T1596.001 |
| **Credentials** | None |
| **Optional dependency** | `dnspython` (install via `expose[collectors-dns]`) |

Queries well-known DNS Blacklist (DNSBL) providers to check whether an IP is listed on any spam or abuse blacklist. All providers are queried in parallel. Spamhaus return codes have specific severity mappings (e.g., `127.0.0.4` = exploit/botnet = critical). For listed IPs, a TXT query retrieves the listing reason.

---

## 4. BGP/ASN

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

Queries the RIPEstat Data API for BGP routing information. For IP seeds, uses the `network-info` endpoint to find the announcing ASN and covering prefix. For ASN seeds, uses the `announced-prefixes` endpoint.

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

Scrapes the Hurricane Electric BGP Toolkit web pages for BGP routing information. For IP seeds, queries the IP detail page to extract the announcing ASN, holder name, and announced prefixes. Parsing uses regex and string matching -- no HTML parser dependencies.

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
| **Optional dependency** | `dnspython` (install via `expose[collectors-dns]`) |

Queries the Team Cymru IP-to-ASN mapping service via DNS TXT lookups. Two-step process: (1) reverse-IP query to `origin.asn.cymru.com` for ASN/prefix/country/registry, (2) ASN query to `asn.cymru.com` for holder name.

---

## 5. HTTP/Web

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

Probes target hosts on ports 80 (HTTP) and 443 (HTTPS) to capture HTTP response metadata. Follows up to 5 redirects. Includes a per-host async token-bucket rate limiter (default 1 req/sec, configurable via `config.extra["requests_per_second"]`). Captures security-relevant headers (HSTS, CSP, X-Frame-Options, etc.), page title, server banner, and redirect chain.

---

### robots-txt

| Field | Value |
|---|---|
| **Collector ID** | `robots-txt` |
| **Class** | `RobotsTxtCollector` |
| **Source file** | `src/expose/collectors/builtin/robots_txt.py` |
| **Tier** | 2 (passive, targeted) |
| **Data source** | Target host `/robots.txt` |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `HTTP_RESPONSE` |
| **ATT&CK** | T1592.004 (Gather Victim Host Information: Client Configurations) |
| **Credentials** | None |

Fetches `/robots.txt` from target domains over HTTPS and HTTP, then parses `Disallow:`, `Allow:`, and `Sitemap:` directives. Each path is classified by security interest level -- critical (`.git`, `.env`, debug endpoints), high (admin panels, API endpoints, backup directories), or medium (uploads, staging environments). Low-interest paths (images, CSS, JS) are filtered out. Evidence blob contains the raw robots.txt content.

---

### security-txt

| Field | Value |
|---|---|
| **Collector ID** | `security-txt` |
| **Class** | `SecurityTxtCollector` |
| **Source file** | `src/expose/collectors/builtin/security_txt.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | Target host `/.well-known/security.txt` (RFC 9116) |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `HTTP_RESPONSE` |
| **ATT&CK** | T1592.004 |
| **Credentials** | None |

Fetches security.txt (RFC 9116) from the well-known path (primary) and legacy `/security.txt` (fallback). Parses Contact, Expires, Encryption, Policy, Hiring, Acknowledgments, Preferred-Languages, and Canonical fields. Domains extracted from URLs in those fields are emitted as separate observations, revealing bug bounty platforms (HackerOne, Bugcrowd), PGP key servers, and related infrastructure.

---

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

Fetches favicon files and computes a SHA-256 hash via the FIPS crypto adapter (ADR-010). The same favicon hash across different hosts implies the same operator or application -- useful for cluster correlation and technology fingerprinting. Tries HTTPS first, then HTTP; probes `/favicon.ico` first, then `/apple-touch-icon.png` as fallback. A stub MurmurHash3 field is included for future Shodan-compatible correlation.

---

### waf-detection

| Field | Value |
|---|---|
| **Collector ID** | `waf-detection` |
| **Class** | `WafDetectionCollector` |
| **Source file** | `src/expose/collectors/builtin/waf_detection.py` |
| **Tier** | 2 (passive, targeted) |
| **Data source** | Target host HTTP response headers |
| **Seeds accepted** | `DOMAIN`, `IP` |
| **Observation type** | `HTTP_RESPONSE` |
| **ATT&CK** | T1592.004 |
| **Credentials** | None |

Detects WAF and CDN layers by inspecting HTTP response headers against a signature database covering 8 vendors: Cloudflare, Akamai, CloudFront, Fastly, Incapsula, Sucuri, AWS WAF, and Azure Front Door. Issues a single HTTP HEAD request per seed. Confidence scales with the number of matching signatures per vendor. Also checks DNS CNAME records for CDN-indicative patterns. Per-host token-bucket rate limiter (default 1 req/sec).

---

### screenshot-vision

| Field | Value |
|---|---|
| **Collector ID** | `screenshot-vision` |
| **Class** | `ScreenshotVisionCollector` |
| **Source file** | `src/expose/collectors/builtin/screenshot_vision.py` |
| **Tier** | 2 (passive, targeted) |
| **Data source** | Target host HTTP |
| **Seeds accepted** | `DOMAIN`, `IP` |
| **Observation type** | `HTTP_RESPONSE` |
| **ATT&CK** | T1592.004 |
| **Credentials** | None |

Captures HTTP response content for downstream vision analysis (Stage 4c). Extracts page title, meta description, body text preview (first 2000 characters), status code, and content type. Only processes HTML responses; non-HTML is skipped. Response bodies capped at 1 MB. Supports egress profile integration for proxied requests. Evidence blob contains the raw HTML.

---

## 6. Cloud

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

Compares seed IP addresses and CIDR blocks against pre-cached cloud provider IP range manifests. No live network calls during `expand()` -- all lookups are against in-memory data loaded at construction time. Cache directory configured via `config.extra["ranges_dir"]`.

---

### cloud-storage-exposure

| Field | Value |
|---|---|
| **Collector ID** | `cloud-storage-exposure` |
| **Class** | `CloudStorageExposureCollector` |
| **Source file** | `src/expose/collectors/builtin/cloud_storage_exposure.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | AWS S3, Azure Blob Storage, GCP Cloud Storage (public endpoints) |
| **Seeds accepted** | `ORGANIZATION`, `DOMAIN` |
| **Observation type** | `CLOUD_IP_RANGE` |
| **ATT&CK** | T1526 (Cloud Service Discovery) |
| **Credentials** | None |

Discovers publicly accessible cloud storage buckets/containers. Generates candidate bucket names via a permutation engine (20 common suffixes: `-backups`, `-data`, `-staging`, `-dev`, etc.) and probes each across all three providers using HTTP HEAD requests. If a bucket exists and is publicly listable, parses the listing to inventory objects and flag sensitive files. Filters out common-word false positives (www, api, cdn, etc.). Max 5 concurrent probes with 0.2s inter-probe delay.

---

## 7. Code

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
| **Credentials** | Optional: `api_key` (increases rate limit from 10 to 30 req/min) |

Searches public GitHub API for repositories and code belonging to or mentioning the target. For organization seeds, performs a repository search. For domain seeds, performs both repository and code search (filtering to configuration file extensions: yml, yaml, json, env, toml, ini, cfg, conf). Flags potential leaked credential indicators (metadata only -- does NOT extract secrets).

---

### git-commit-emails

| Field | Value |
|---|---|
| **Collector ID** | `git-commit-emails` |
| **Class** | `GitCommitEmailsCollector` |
| **Source file** | `src/expose/collectors/builtin/git_commit_emails.py` |
| **Tier** | 2 (passive, targeted) |
| **Data source** | [GitHub Commits Search API](https://docs.github.com/en/rest) |
| **Seeds accepted** | `ORGANIZATION`, `DOMAIN` |
| **Observation type** | `PASSIVE_DNS` |
| **ATT&CK** | T1593.003 (Search Open Websites/Domains: Code Repositories) |
| **Credentials** | Required: `token` (GitHub API authentication) |

Searches GitHub commits for the target and extracts unique committer email domains. Reveals internal email domains, contractor/partner domains, and shadow domains linked to the organization's codebase. Filters out generic free-email providers (Gmail, Outlook, etc.) and GitHub noreply addresses. Rate limited to 30 requests/minute.

---

## 8. Email

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
| **Optional dependency** | `dnspython` (install via `expose[collectors-dns]`) |

Queries DNS for email authentication records: SPF (TXT at domain), DKIM (TXT at `{selector}._domainkey.{domain}` for 8 common selectors), and DMARC (TXT at `_dmarc.{domain}`). Reveals mail infrastructure, authorized third-party senders (SPF includes), and potential shadow IT.

---

### mail-headers

| Field | Value |
|---|---|
| **Collector ID** | `mail-headers` |
| **Class** | `MailHeaderAnalyzerCollector` |
| **Source file** | `src/expose/collectors/builtin/mail_header_analyzer.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | Public mailing list archives (HTTP) |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `HTTP_RESPONSE`, `SCANNER_HOST` |
| **ATT&CK** | T1598 (Phishing for Information) |
| **Credentials** | None |

Probes for publicly accessible mailing list archives at common subdomains (`lists.`, `mail.`, `mailman.`) and extracts infrastructure hints: IP addresses from `Received:` headers, mailing list software fingerprints (Mailman, Sympa, Majordomo, HyperKitty), and internal hostnames. Rate limited to 30 requests/minute.

---

## 9. Scan Aggregators

### scan-shodan

| Field | Value |
|---|---|
| **Collector ID** | `scan-shodan` |
| **Class** | `ShodanScanCollector` |
| **Source file** | `src/expose/collectors/builtin/scan_shodan.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [Shodan API](https://api.shodan.io/) |
| **Seeds accepted** | `DOMAIN`, `IP` |
| **Observation type** | `PORT_SCAN_RESULT`, `SCANNER_HOST` |
| **ATT&CK** | T1596 (Search Open Technical Databases) |
| **Credentials** | Required: `shodan_api_key` |

Queries Shodan for host data: open ports, banners, known CVEs, hostnames, OS, and ISP information. For domain seeds, resolves the domain to an IP via Shodan DNS first. Emits per-service observations (with port, transport, product, banner, vulnerabilities, and optional SSL cert details) plus a host-level summary. Self-rate-limits to 1 request/second.

---

### scan-censys

| Field | Value |
|---|---|
| **Collector ID** | `scan-censys` |
| **Class** | `CensysScanCollector` |
| **Source file** | `src/expose/collectors/builtin/scan_censys.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [Censys Search API v2](https://search.censys.io/api/v2) (hosts endpoint) |
| **Seeds accepted** | `DOMAIN`, `IP` |
| **Observation type** | `PORT_SCAN_RESULT`, `SCANNER_HOST` |
| **ATT&CK** | T1596 |
| **Credentials** | Required: `censys_api_id`, `censys_api_secret` |

Queries the Censys Search API v2 hosts endpoint for open ports, service names, TLS certificates, banners, and OS fingerprints. For domain seeds, searches by TLS certificate name. Distinct from `ct-censys` which uses the certificates endpoint for CT enumeration. Self-rate-limits to 2 requests/second.

---

### scan-binaryedge

| Field | Value |
|---|---|
| **Collector ID** | `scan-binaryedge` |
| **Class** | `BinaryEdgeScanCollector` |
| **Source file** | `src/expose/collectors/builtin/scan_binaryedge.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [BinaryEdge API v2](https://api.binaryedge.io/v2) |
| **Seeds accepted** | `DOMAIN`, `IP` |
| **Observation type** | `PORT_SCAN_RESULT`, `SCANNER_HOST` |
| **ATT&CK** | T1596 |
| **Credentials** | Required: `binaryedge_api_key` |

Queries BinaryEdge for host data: open ports, services, certificates, and torrent activity. For domain seeds, performs subdomain enumeration. Self-rate-limits to 1 request/second.

---

## 10. Historical

### wayback-machine

| Field | Value |
|---|---|
| **Collector ID** | `wayback-machine` |
| **Class** | `WaybackMachineCollector` |
| **Source file** | `src/expose/collectors/builtin/wayback_machine.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [Internet Archive Wayback CDX API](https://web.archive.org/cdx/search/cdx) |
| **Seeds accepted** | `DOMAIN`, `IP` |
| **Observation type** | `HTTP_RESPONSE` |
| **Credentials** | None |

Queries the Wayback CDX API to discover historical URLs and content snapshots. Reveals endpoints, configuration files, and historical structure no longer visible on the live site. Filters for interesting content types (HTML, JSON, plain text, XML, JavaScript). Polite rate limit: 1 request/second.

---

### common-crawl

| Field | Value |
|---|---|
| **Collector ID** | `common-crawl` |
| **Class** | `CommonCrawlCollector` |
| **Source file** | `src/expose/collectors/builtin/common_crawl.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [Common Crawl Index API](https://index.commoncrawl.org/) |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `HTTP_RESPONSE` |
| **Credentials** | None |

Free, no-auth backup to the Wayback Machine. Queries the Common Crawl Index API (NDJSON) to discover historical URLs, subdomains, and interesting endpoints (admin, API, login, dashboard, config paths). Discovers the latest crawl index automatically via `collinfo.json`. Rate limited to 30 requests/minute.

---

## 11. Specialized

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

Queries RDAP endpoints for domain and IP registration metadata. Extracts registrant organization, registrar, dates, nameservers, and status codes. PII non-enrichment policy: deliberately skips personal names, email addresses, phone numbers, and street addresses. Only organization names are extracted.

---

### ma-discovery

| Field | Value |
|---|---|
| **Collector ID** | `ma-discovery` |
| **Class** | `MaDiscoveryCollector` |
| **Source file** | `src/expose/collectors/builtin/ma_discovery.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [Wikidata SPARQL](https://query.wikidata.org/sparql), [Wikipedia API](https://en.wikipedia.org/w/api.php) |
| **Seeds accepted** | `ORGANIZATION` |
| **Observation type** | `SCANNER_HOST` |
| **Credentials** | None |

Discovers mergers-and-acquisitions activity using public data. Queries Wikidata for subsidiaries (wdt:P1830 / wdt:P127) and Wikipedia for acquisition mentions. For each discovered company, attempts DNS resolution of candidate domains across 10 TLDs. Emits one observation per acquisition with relationship type, dates, source URL, and candidate domains.

---

### sip-discovery

| Field | Value |
|---|---|
| **Collector ID** | `sip-discovery` |
| **Class** | `SipDiscoveryCollector` |
| **Source file** | `src/expose/collectors/builtin/sip_discovery.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | DNS SRV and NAPTR records |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `DNS_RECORD` |
| **Credentials** | None |
| **Optional dependency** | `dnspython` (install via `expose[collectors-dns]`) |

Discovers VoIP/SIP infrastructure by querying standard DNS SRV records per RFC 3263: `_sip._tcp`, `_sips._tcp`, `_sip._udp`, `_h323cs._tcp`, `_stun._udp`, `_turn._udp`. Also queries NAPTR records for SIP routing preferences. SRV records reveal VoIP provider, internal hostnames, and non-standard port configurations.

---

### wikipedia-edits

| Field | Value |
|---|---|
| **Collector ID** | `wikipedia-edits` |
| **Class** | `WikipediaEditsCollector` |
| **Source file** | `src/expose/collectors/builtin/wikipedia_edits.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [Wikipedia MediaWiki API](https://en.wikipedia.org/w/api.php) |
| **Seeds accepted** | `ORGANIZATION`, `DOMAIN` |
| **Observation type** | `SCANNER_HOST` |
| **Credentials** | None |

Discovers IP addresses from anonymous Wikipedia edits. Anonymous editors are identified by IP in the revision history `user` field. These IPs may belong to corporate networks, cloud egress, VPNs, or employee locations. Fetches the top article's revision history (up to 500 edits) and filters for IPv4/IPv6 anonymous editors. Rate limited to 30 requests/minute.

---

### paste-monitor

| Field | Value |
|---|---|
| **Collector ID** | `paste-monitor` |
| **Class** | `PasteMonitorCollector` |
| **Source file** | `src/expose/collectors/builtin/paste_monitor.py` |
| **Tier** | 2 (passive, targeted) |
| **Data source** | [GitHub Code Search API](https://docs.github.com/en/rest) |
| **Seeds accepted** | `DOMAIN`, `ORGANIZATION` |
| **Observation type** | `SCANNER_HOST` |
| **Credentials** | Optional: `api_key` (increases rate limit) |

Searches GitHub Code Search for configuration file leaks referencing the target. Queries for `.env`, `.conf`, `.yml`, and `filename:.env` files. Extracts IP addresses, hostnames, subdomains, and URLs from matched code snippets. Rate limited to 10 requests/minute due to aggressive GitHub code search limits.

---

### otx-alienvault

| Field | Value |
|---|---|
| **Collector ID** | `otx-alienvault` |
| **Class** | `OtxAlienVaultCollector` |
| **Source file** | `src/expose/collectors/builtin/otx_alienvault.py` |
| **Tier** | 1 (passive, broad) |
| **Data source** | [AlienVault OTX API](https://otx.alienvault.com/api/) |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `PASSIVE_DNS`, `SCANNER_HOST` |
| **ATT&CK** | T1596 |
| **Credentials** | Optional: `otx_api_key` (higher rate limits) |

Free backup source for passive DNS history. Queries two OTX endpoints: passive_dns (historical DNS resolutions showing which IPs a domain has pointed to) and url_list (URLs observed in threat intelligence feeds). No API key required for basic access; optional key for higher rate limits. Rate limited to 30 requests/minute.

---

### waf-origin-discovery

| Field | Value |
|---|---|
| **Collector ID** | `waf-origin-discovery` |
| **Class** | `WafOriginDiscoveryCollector` |
| **Source file** | `src/expose/collectors/builtin/waf_origin_discovery.py` |
| **Tier** | 2 (passive, targeted) |
| **Data source** | Target host HTTP headers, DNS, TLS certificates |
| **Seeds accepted** | `DOMAIN`, `IP` |
| **Observation type** | `HTTP_RESPONSE` |
| **Credentials** | None |

Discovers origin server IPs behind CDN/WAF layers using five passive techniques: CDN header leakage (X-Forwarded-For, X-Real-IP, X-Originating-IP, CF-Connecting-IP), certificate SAN analysis, subdomain enumeration (`ftp.*`, `mail.*`, `direct.*`, `cpanel.*`), MX record analysis, and DNS history. Reuses the WAF signature database from `waf-detection`. Per-host token-bucket rate limiter (default 1 req/sec).

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

Light port-surface enumeration on attributed IP addresses. Probes 27 common service ports (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 2222, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 9200, 9443, 27017) using async TCP connect probes. All ports probed concurrently. Port list overridable per seed via `seed.properties["ports"]`. TCP connect timeout default 3 seconds (configurable via `config.extra["probe_timeout_seconds"]`). Yields exactly one observation per seed.

---

### active-tls-handshake

| Field | Value |
|---|---|
| **Collector ID** | `active-tls-handshake` |
| **Class** | `ActiveTlsCollector` |
| **Source file** | `src/expose/collectors/builtin/active_tls.py` |
| **Tier** | 3 (active, attribution-gated) |
| **Data source** | Target host TLS (default port 443) |
| **Seeds accepted** | `DOMAIN`, `IP` |
| **Observation type** | `TLS_HANDSHAKE` |
| **Credentials** | None |

Performs TLS handshakes and extracts certificate chain details, negotiated protocol version, cipher suite, and a JARM fingerprint stub. Certificate verification intentionally disabled (`CERT_NONE`) to observe all certificates including self-signed and expired. Certificate fingerprints computed via the FIPS SHA-256 adapter (ADR-010). JARM fingerprinting stubbed in v0.1.0 (returns `None`).

---

### dark-web-indicators

| Field | Value |
|---|---|
| **Collector ID** | `dark-web-indicators` |
| **Class** | `DarkWebIndicatorsCollector` |
| **Source file** | `src/expose/collectors/builtin/dark_web_indicators.py` |
| **Tier** | 3 (active, attribution-gated) |
| **Data source** | Have I Been Pwned, IntelX, DeHashed (via `DarkWebEnricher`) |
| **Seeds accepted** | `DOMAIN` |
| **Observation type** | `SCANNER_HOST` |
| **ATT&CK** | T1597 (Search Closed Sources) |
| **Credentials** | Required: `hibp_api_key`. Optional: `intelx_api_key`, `dehashed_email` + `dehashed_api_key` |

Queries public dark web aggregator APIs for breach data, leaked credentials, and dark web mentions. Delegates API calls to the `DarkWebEnricher` module (part of the commercial Threat Context surface). FIPS gate compliant -- no direct hashlib/secrets imports. Rate limited to 10 requests/minute.

---

## 12. Writing a Custom Collector

To create a custom collector:

1. Subclass `expose.collectors.Collector`.
2. Set the class-level metadata attributes: `collector_id`, `collector_version`, `requires_credentials`, `tier`, `technique_ids`.
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

## 13. Credential Management

### How the CredentialResolver works

The `CredentialResolver` (in `src/expose/pipeline/credential_resolver.py`) bridges the secrets backend and the dispatcher's `CollectorConfig` construction. The flow:

1. Each collector has a `CollectorCredentialSpec` declaring its required credential slots (e.g., `github-exposed` has an optional `api_key` slot).
2. At dispatch time, the resolver fetches tenant-specific secret values from the configured `SecretsBackend` using the key convention: `collector.{collector_id}.{key_name}`.
3. Resolved credentials are injected into the `CollectorConfig.credentials` dict as `CollectorCredential` instances.
4. The collector accesses credentials via `self.config.credentials["slot_name"].secret_value`.
5. Per SPEC section 6.4, credential material is held only for the lifetime of a single `expand()` invocation. Instances are not persisted.

If a required key is absent from the backend, `CredentialResolutionError` is raised before the collector is constructed. Secret values are never logged.

### Credential summary by collector

| Collector ID | Slot(s) | Required? |
|---|---|---|
| `ct-censys` | `censys_api_id`, `censys_api_secret` | Yes |
| `dns-passive-history` | `securitytrails_api_key`, `virustotal_api_key` | At least one |
| `dns-chaos` | `api_key` | No |
| `github-exposed` | `api_key` | No |
| `git-commit-emails` | `token` | Yes |
| `scan-shodan` | `shodan_api_key` | Yes |
| `scan-censys` | `censys_api_id`, `censys_api_secret` | Yes |
| `scan-binaryedge` | `binaryedge_api_key` | Yes |
| `paste-monitor` | `api_key` | No |
| `otx-alienvault` | `otx_api_key` | No |
| `dark-web-indicators` | `hibp_api_key` (req), `intelx_api_key` (opt), `dehashed_email` + `dehashed_api_key` (opt) | Partially |

All other collectors require no credentials.

### Secrets backends

EXPOSE ships three `SecretsBackend` implementations:

| Backend | Class | Use case |
|---|---|---|
| **In-Memory** | `InMemoryBackend` | Testing and development only. Secrets are stored in a Python dict. |
| **Environment** | `EnvSecretsBackend` | Lightweight production. Reads secrets from environment variables. Suitable for Kubernetes `Secret` objects mounted as env vars. |
| **Vault** | `VaultSecretsBackend` | Full production. Reads from HashiCorp Vault KV v2 via httpx. Supports token and approle authentication. |

All backends are defined in `src/expose/secrets/`. The backend is selected at application startup and injected into the pipeline configuration.

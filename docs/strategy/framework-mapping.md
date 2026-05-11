# MITRE ATT&CK Framework Mapping

**Status:** Advisory -- not locked
**Last updated:** 2026-05-11

## Overview

All EXPOSE collectors map to the **Reconnaissance** tactic (TA0043) in the
MITRE ATT&CK Enterprise framework. This is by design: EXPOSE Core operates
exclusively in the reconnaissance domain, identifying externally visible
attack surface without crossing into exploitation or resource development.

Resource Development (TA0042) mappings are deferred to the commercial
**EXPOSE Threat Context** module, which analyzes adversary infrastructure
reuse and overlaps with threat intelligence feeds.

Each collector carries a `technique_ids: ClassVar[list[str]]` attribute
on its class definition, enabling programmatic framework queries, artifact
annotation, and compliance reporting.

## Technique Reference

| Technique ID | Name | ATT&CK URL |
|---|---|---|
| T1046 | Network Service Discovery | https://attack.mitre.org/techniques/T1046/ |
| T1526 | Cloud Service Discovery | https://attack.mitre.org/techniques/T1526/ |
| T1589.002 | Gather Victim Identity Information: Email Addresses | https://attack.mitre.org/techniques/T1589/002/ |
| T1591.004 | Gather Victim Org Information: Identify Roles | https://attack.mitre.org/techniques/T1591/004/ |
| T1592.004 | Gather Victim Host Information: Client Configurations | https://attack.mitre.org/techniques/T1592/004/ |
| T1593 | Search Open Websites/Domains | https://attack.mitre.org/techniques/T1593/ |
| T1593.003 | Search Open Websites/Domains: Code Repositories | https://attack.mitre.org/techniques/T1593/003/ |
| T1596 | Search Open Technical Databases | https://attack.mitre.org/techniques/T1596/ |
| T1596.001 | Search Open Technical Databases: DNS/Passive DNS | https://attack.mitre.org/techniques/T1596/001/ |
| T1596.002 | Search Open Technical Databases: WHOIS | https://attack.mitre.org/techniques/T1596/002/ |
| T1596.003 | Search Open Technical Databases: Digital Certificates | https://attack.mitre.org/techniques/T1596/003/ |
| T1598 | Phishing for Information | https://attack.mitre.org/techniques/T1598/ |

## Collector-to-Technique Mapping

### T1596.003 -- Digital Certificates

| Collector ID | Module | Tier | Description |
|---|---|---|---|
| ct-crtsh | ct_crtsh | 1 | crt.sh Certificate Transparency search |
| ct-censys | ct_censys | 1 | Censys Certificates API v2 CT search |
| ct-certspotter | ct_certspotter | 1 | CertSpotter / SSLMate CT search |
| ct-certstream | ct_certstream | 1 | Near-real-time CT monitoring via crt.sh |
| active-tls-handshake | active_tls | 3 | Active TLS handshake certificate extraction |

### T1596.001 -- DNS/Passive DNS

| Collector ID | Module | Tier | Description |
|---|---|---|---|
| active-dns-resolve | active_dns | 3 | Active DNS resolution (A/AAAA/CNAME/MX/NS/TXT/SOA) |
| dns-subdomain-enum | dns_subdomain_enum | 3 | Wordlist-based subdomain enumeration |
| dns-chaos | dns_chaos | 1 | ProjectDiscovery Chaos subdomain discovery |
| dns-zone-transfer | dns_zone_transfer | 3 | AXFR zone transfer attempts |
| dns-passive-history | dns_passive_history | 1 | SecurityTrails + VirusTotal passive DNS history |
| dns-reverse-ptr | dns_reverse_ptr | 2 | Reverse PTR lookup |
| dns-blacklist | dns_blacklist | 1 | DNSBL / spam-blacklist checking |
| bgp-ripestat | bgp_ripestat | 1 | RIPEstat Data API BGP/ASN lookups |
| bgp-he-toolkit | bgp_he_toolkit | 1 | Hurricane Electric BGP Toolkit |
| bgp-team-cymru | bgp_team_cymru | 1 | Team Cymru IP-to-ASN DNS service |

### T1596.002 -- WHOIS

| Collector ID | Module | Tier | Description |
|---|---|---|---|
| rdap-whois | rdap_whois | 1 | RDAP/WHOIS registration data |

### T1592.004 -- Client Configurations

| Collector ID | Module | Tier | Description |
|---|---|---|---|
| active-http-fingerprint | active_http | 3 | HTTP response fingerprinting (headers, titles, security headers) |
| robots-txt | robots_txt | 2 | robots.txt endpoint discovery and classification |
| security-txt | security_txt | 1 | RFC 9116 security.txt parsing |
| favicon-hash | favicon_hash | 2 | Favicon SHA-256 hash for cluster correlation |
| waf-detection | waf_detection | 2 | WAF/CDN vendor detection via HTTP headers |

### T1526 -- Cloud Service Discovery

| Collector ID | Module | Tier | Description |
|---|---|---|---|
| cloud-ranges | cloud_ranges | 1 | AWS/Azure/GCP IP range manifest matching |
| cloud-storage-exposure | cloud_storage_exposure | 1 | Public cloud storage bucket discovery |

### T1589.002 -- Email Addresses

| Collector ID | Module | Tier | Description |
|---|---|---|---|
| spf-dkim-dmarc | email_auth | 1 | SPF/DKIM/DMARC email authentication policy discovery |

### T1593.003 -- Code Repositories

| Collector ID | Module | Tier | Description |
|---|---|---|---|
| github-exposed | github_exposed | 1 | GitHub public repository and code search |
| git-commit-emails | git_commit_emails | 2 | Git commit email domain extraction |

### T1596 -- Search Open Technical Databases (parent)

| Collector ID | Module | Tier | Description |
|---|---|---|---|
| scan-shodan | scan_shodan | 1 | Shodan internet-wide scan data |
| scan-censys | scan_censys | 1 | Censys Search API v2 host data |
| scan-binaryedge | scan_binaryedge | 1 | BinaryEdge API v2 host data |
| otx-alienvault | otx_alienvault | 1 | AlienVault OTX passive DNS and URL data |

### T1593 -- Search Open Websites/Domains (parent)

| Collector ID | Module | Tier | Description |
|---|---|---|---|
| wayback-machine | wayback_machine | 1 | Wayback Machine CDX API historical search |
| common-crawl | common_crawl | 1 | Common Crawl Index endpoint discovery |
| wikipedia-edits | wikipedia_edits | 1 | Wikipedia edit history anonymous IP extraction |

### T1046 -- Network Service Discovery

| Collector ID | Module | Tier | Description |
|---|---|---|---|
| active-port-surface | active_port_surface | 3 | TCP port surface enumeration |
| sip-discovery | sip_discovery | 1 | SIP/VoIP infrastructure via DNS SRV/NAPTR |

### T1591.004 -- Identify Roles

| Collector ID | Module | Tier | Description |
|---|---|---|---|
| ma-discovery | ma_discovery | 1 | M&A / subsidiary discovery via Wikidata/Wikipedia |

### T1598 -- Phishing for Information

| Collector ID | Module | Tier | Description |
|---|---|---|---|
| paste-monitor | paste_monitor | 2 | GitHub code search for leaked configuration files |
| mail-headers | mail_header_analyzer | 1 | Mailing list archive header analysis |

## Rationale for Technique Assignments

**BGP collectors (T1596.001):** BGP routing data (ASN, prefix announcements)
is accessed through open technical databases (RIPEstat, HE BGP Toolkit,
Team Cymru DNS). While not strictly "DNS," these sources provide network
infrastructure intelligence analogous to passive DNS lookups. T1596.001 is
the closest sub-technique.

**Scanner collectors (T1596):** Shodan, Censys, and BinaryEdge are
internet-wide scan databases. They map to the parent T1596 (Search Open
Technical Databases) rather than a specific sub-technique because they
aggregate multiple data types (ports, banners, certificates, hostnames).

**Paste monitor / mail headers (T1598):** These collectors search for
leaked information that could facilitate phishing or social engineering.
The paste monitor searches for configuration file leaks; the mail header
analyzer extracts infrastructure hints from public mailing list archives.
T1598 (Phishing for Information) captures the intelligence-gathering
intent, though these collectors are passive and do not perform phishing.

**WAF detection / favicon hash / robots.txt (T1592.004):** These
collectors fingerprint client-facing configurations -- HTTP headers,
security.txt policies, favicon hashes, WAF vendor signatures. T1592.004
(Client Configurations) covers intelligence gathered about how victim
infrastructure is configured.

## Implementation Details

The `technique_ids` attribute is defined as `ClassVar[list[str]]` on the
`Collector` ABC in `src/expose/collectors/base.py`. The ABC default is
an empty list; all concrete collectors override it with their assigned
technique IDs.

Validation rules (enforced by tests in `tests/test_collectors_framework.py`):

1. Every registered collector must have a non-empty `technique_ids` list.
2. All technique IDs must match the pattern `T[0-9]{4}(\.[0-9]{3})?`.
3. The base ABC default remains `[]` (concrete subclasses must override).

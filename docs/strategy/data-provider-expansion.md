# Third-Party Data Provider Expansion Roadmap

*Advisory — not locked. Refs #176.*

## Current State (v0.4.x)

44 collectors across 5 tiers. 12 API keys configured (Shodan, Censys, SecurityTrails, BinaryEdge, GitHub, IntelX, Chaos, PassiveTotal, VirusTotal, GreyNoise, urlscan, HIBP). BinaryEdge shutting down. Censys free tier limited.

## Priority 1: Replace Dying Providers

| Lost Provider | Replacement | Coverage Gap | Effort |
|---------------|-------------|-------------|--------|
| BinaryEdge (shutting down) | **Netlas.io** — similar API, port/service scanning, free tier available | Port/banner/vulnerability scanning | Low — API is Shodan-compatible |
| Censys (free tier broken) | **FullHunt.io** — attack surface discovery, free tier with 100 queries/day | Host discovery, exposed services | Low |

## Priority 2: Commercial Data Feeds (Pro/Enterprise)

These require paid API access and are gated behind the commercial license.

| Provider | Data Type | Use Case | Estimated Cost |
|----------|-----------|----------|----------------|
| **GreyNoise Community** | IP reputation + classification | Separate noise from targeted scanning | Free (community) |
| **Shodan Enterprise** | Full banner data + vuln matching | Deep port/service analysis | ~$500/mo |
| **SecurityTrails Enterprise** | Historical DNS + WHOIS | Domain timeline, ownership changes | ~$300/mo |
| **Rapid7 Project Sonar** | Forward DNS + reverse DNS datasets | Bulk passive reconnaissance | Free (research) |
| **CIRCL Passive DNS** | European passive DNS | GDPR-compatible DNS intelligence | Free (registration) |
| **PhishTank** | Known phishing URLs | Brand impersonation detection | Free |
| **URLhaus** | Malware distribution URLs | Compromised asset detection | Free |

## Priority 3: Federal/GovCloud Providers

Required for FedRAMP trajectory and government customers.

| Provider | Data Type | Classification | Requirement |
|----------|-----------|---------------|-------------|
| **CISA Known Exploited Vulns (KEV)** | Actively exploited CVEs | Public | Already referenced in vendor_cve_history |
| **NVD API v2** | Full CVE database | Public | Already implemented |
| **Shodan GovCloud** | FedRAMP-authorized scan data | CUI | Enterprise license |
| **MaxMind GeoIP** | IP geolocation + ASN | Commercial | ~$100/mo |
| **Team Cymru Scout** | IP reputation + threat intel | Commercial | Custom pricing |

## Priority 4: Community Collectors

Collectors that can be contributed by the community under the rule pack framework.

| Collector Idea | Data Source | Complexity |
|----------------|------------|------------|
| **DNS over HTTPS probing** | Cloudflare/Google DoH | Low |
| **HTTP security headers audit** | Direct probe (Tier 3) | Low — extends active_http |
| **SPF/DMARC policy grading** | Direct DNS (Tier 1) | Low — extends email_auth |
| **JavaScript library detection** | CDN fingerprinting | Medium |
| **API endpoint discovery** | robots.txt + sitemap.xml + common paths | Medium |
| **Cloud metadata endpoint probe** | 169.254.169.254 (Tier 3, internal only) | Low |
| **Subdomain takeover detection** | CNAME dangling check | Medium |
| **S3/GCS bucket policy audit** | Direct probe (Tier 3) | Medium |

## Implementation Plan

**Phase 1 (v0.5):** Netlas.io + FullHunt.io replacements, CIRCL passive DNS, PhishTank, URLhaus. 5 new collectors, all free tier.

**Phase 2 (v0.6):** GreyNoise integration, Rapid7 Sonar import, MaxMind GeoIP enrichment. Requires commercial license for full access.

**Phase 3 (v1.0 GA):** Shodan Enterprise, SecurityTrails Enterprise, Team Cymru Scout. Revenue-funded after initial sales.

**Phase 4 (Federal):** Shodan GovCloud, CISA KEV live feed, FedRAMP-authorized data sources only.

## Collector Development Guide

New collectors follow the pattern in `src/expose/collectors/builtin/`:
1. Extend `Collector` base class
2. Register with `@register_collector`
3. Implement `expand(seed) -> AsyncIterator[Observation]`
4. Add credential spec in `credential_resolver.py`
5. Add health check
6. Add to `__init__.py` imports

See `docs/community-rulepacks.md` for the community contribution process.

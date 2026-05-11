# EXPOSE Smoke Test: cyberark.com (Tier-1 Passive Only)

_Generated 2026-05-11. Zero packets sent to target infrastructure._

## Data Sources

| Source | Type | Result |
|--------|------|--------|
| crt.sh (Certificate Transparency) | Tier-1, public | 4,148 entries, 338 unique names |
| RDAP (domain registration) | Tier-1, public | Registration, status, nameservers |
| RIPEstat (BGP/ASN) | Tier-1, public | IP → AS mapping |
| Wayback Machine (CDX) | Tier-1, public | Historical snapshots since 1997 |
| DNS TXT (SPF/DMARC) | Tier-1, public | Email authentication posture |

## Infrastructure Fingerprint

| Property | Value |
|----------|-------|
| Domain registered | 1996-03-07 |
| Domain expires | 2027-03-08 |
| Registrar | Cloudflare, Inc. |
| Nameservers | andy.ns.cloudflare.com, kia.ns.cloudflare.com |
| Primary IPs | 104.16.68.86, 104.16.69.86 |
| ASN | AS13335 (CLOUDFLARENET - Cloudflare, Inc.) |
| WAF/CDN | Cloudflare |
| Email gateway | Proofpoint (pphosted.com) |
| SPF | `v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all` |
| DMARC | `p=reject` (strict enforcement) |
| MX | mxa-0021d601.gslb.pphosted.com, mxb-0021d601.gslb.pphosted.com |

## Environment Classification

13 non-production subdomains identified from certificate common names:

| Environment | Subdomain | Risk |
|-------------|-----------|------|
| SANDBOX | *.artemis-sandbox.atlantis.cyberark.com | Reduced security controls |
| DEVELOPMENT | *.dev.ampm.cyberark.com | Weaker auth, debug mode likely |
| DEVELOPMENT | *.dev.atlantis.cyberark.com | Weaker auth, debug mode likely |
| DEVELOPMENT | *.dev.cps.cyberark.com | Weaker auth, debug mode likely |
| DEVELOPMENT | *.pcloud.dev.pegasus.cyberark.com | Dev Privilege Cloud on Pegasus |
| INTEGRATION | *.integration.atlantis.cyberark.com | May accept test credentials |
| PERFORMANCE | *.performance.atlantis.cyberark.com | Load test data may include realistic configs |
| TEST | *.snir-test.pamoncloud.cyberark.com | Named developer test in prod infra |
| TEST | *.test.ampm.cyberark.com | Test environment |
| STAGING | *.pcloud.staging.pegasus.cyberark.com | Pre-production Privilege Cloud |
| STAGING | *.staging.alcatraz.cyberark.com | Pre-production Alcatraz |
| STAGING | *.staging.atlantis.cyberark.com | Pre-production Atlantis |
| STAGING | *.stg.ampm.cyberark.com | Pre-production AMPM |

## SaaS Product Alignment

| Product | Endpoints | Subdomains |
|---------|-----------|------------|
| CyberArk PAM / Privilege Cloud | 10 | *.pamoncloud, *.pcloud.*, *.privilegecloud, *.vault |
| CyberArk EPM | 1 | *.epm.cyberark.com |
| CyberArk CEM | 3 | *.cem, *.api.cem, *.rookout.cem |
| CyberArk SCA | 1 | *.sca.cyberark.com |
| CyberArk Impact | 1 | *.impact.cyberark.com |

## Internal Codename Discovery

8 internal project codenames discovered from certificate naming patterns:

| Codename | Certificates | Notes |
|----------|-------------|-------|
| Atlantis | 6 | Major platform — has dev, staging, integration, performance envs |
| Pegasus | 4 | Hosts Privilege Cloud (dev, prod, staging) |
| Bronco | 3 | Includes per-developer cert (p-pce-1711) |
| Alcatraz | 2 | Has staging environment |
| Buraq | 1 | |
| Unicorn | 1 | |
| Pony | 1 | |
| Rookout | 1 | Under CEM — likely debugging/observability integration |

## M&A Transitive Exposure

| Acquisition | Year | Transitive Seeds |
|-------------|------|-----------------|
| Venafi | 2024 | venafi.com, venafi.cloud |
| Zilla Security | 2024 | zillasecurity.com |

Note: `8x8pcistatus.oakinnovate.com` appeared in CyberArk's CT data — potential partner, vendor, or unannounced acquisition.

## Priority Findings (Lead Score)

| Score | Tier | Entity | Justification |
|-------|------|--------|---------------|
| 85 | CRITICAL | *.snir-test.pamoncloud.cyberark.com | Test environment in production Privilege Cloud infrastructure |
| 75 | CRITICAL | *.dev.ampm.cyberark.com | Development environment with wildcard cert |
| 72 | CRITICAL | *.artemis-sandbox.atlantis.cyberark.com | Sandbox environment in Atlantis platform |
| 70 | CRITICAL | *.test.ampm.cyberark.com | Test environment with wildcard cert |
| 65 | HIGH | *.integration.atlantis.cyberark.com | Integration environment — may accept test credentials |
| 60 | HIGH | *.performance.atlantis.cyberark.com | Performance test environment |
| 55 | HIGH | *.staging.atlantis.cyberark.com | Staging with potential config drift |
| 50 | HIGH | *.staging.alcatraz.cyberark.com | Staging for Alcatraz project |
| 45 | HIGH | *.pcloud.staging.pegasus.cyberark.com | Staging Privilege Cloud on Pegasus |
| 40 | HIGH | *.stg.ampm.cyberark.com | Staging for AMPM product |

## Analysis Summary

| Metric | Value |
|--------|-------|
| CT entries analyzed | 4,148 |
| Unique subdomains | 338 |
| Non-production environments | 13 |
| Internal codenames | 8 |
| Products mapped | 5 |
| Priority findings | 10 (4 CRITICAL, 6 HIGH) |
| M&A targets identified | 2 confirmed + 1 anomaly |
| Data sources | 5 (all Tier-1 passive) |
| Packets to target | 0 |

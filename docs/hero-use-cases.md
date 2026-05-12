# EXPOSE -- Hero Use Cases

Every EASM tool discovers assets. EXPOSE is the only open-core platform that tells you *why each asset is yours*, packages the findings for your SOC to act on immediately, and signs every claim with a cryptographic provenance chain your auditors can verify offline. These five use cases walk through the workflows that distinguish EXPOSE from everything else on the market -- not as feature lists, but as end-to-end stories with real API calls and real outputs.

---

## Use Case 1: Corporate Attack Surface Assessment

### Scenario

A security analyst at NovaTech Solutions, a mid-size SaaS company with 800 employees, has been tasked with a full external attack surface assessment. NovaTech operates across three cloud providers, maintains several acquired product lines, and has no authoritative inventory of internet-facing assets. The analyst needs to discover everything, determine what belongs to NovaTech, prioritize what matters, and deliver actionable intelligence to both the SOC team and the CISO -- in one pipeline run.

### Step-by-step walkthrough

**1. Seed configuration**

The analyst creates a tenant and configures seeds for NovaTech's known domains, organization name, and cloud CIDR blocks:

```bash
# Create tenant
curl -X POST http://expose:8090/api/v1/tenants \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "NovaTech Solutions - Corporate Assessment",
    "authorization_scope": {
      "domains": ["novatech.io", "novatech-solutions.com", "ntcloud.dev"],
      "cidrs": ["198.51.100.0/24", "203.0.113.0/24"],
      "organizations": ["NovaTech Solutions Inc"]
    }
  }'
```

Response:

```json
{
  "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "NovaTech Solutions - Corporate Assessment",
  "created_at": "2026-05-10T14:00:00Z"
}
```

**2. Multi-pass pipeline (passive to active, attribution-gated)**

The analyst starts a scan. EXPOSE runs collectors in tiered phases -- Tier 1 (passive, broad) fires first, Tier 2 (passive, targeted) queries about entities already in the graph, and Tier 3 (active) sends packets only to entities with `confirmed` or `high` attribution:

```bash
# Start a full pipeline run
curl -X POST http://expose:8090/api/v1/tenants/$TENANT_ID/runs \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "seed": "novatech.io",
    "seed_type": "domain",
    "tiers": [1, 2, 3],
    "rule_pack": "examples/rulepacks/cloud-first.json"
  }'
```

Response:

```json
{
  "run_id": "f8e7d6c5-b4a3-2109-8765-432109876543",
  "status": "pending",
  "started_at": "2026-05-10T14:02:00Z"
}
```

Pass 1 (Tier 1 -- passive): Certificate Transparency logs find 47 certificates referencing `*.novatech.io` and `*.ntcloud.dev`. RDAP/WHOIS returns registrant data. BGP/ASN mapping identifies the prefixes. Cloud IP range manifests match 12 IPs to NovaTech's AWS account.

Pass 2 (Tier 2 -- targeted): Favicon hashing finds 3 assets sharing the NovaTech favicon on IPs not in the original seed. Shodan/Censys historical data fills in port and banner history. WAF detection identifies which assets sit behind CloudFront.

Pass 3 (Tier 3 -- active, attribution-gated): Active DNS resolution, TLS handshake with JARM fingerprinting, and HTTP fingerprinting fire only against entities the attribution engine has already classified as `confirmed` (>= 0.95) or `high` (>= 0.75). An entity at `medium` (0.62) discovered via a CT log SAN correlation does NOT receive active probing -- the enforcement module logs the refusal.

**3. Lead scoring produces prioritized findings**

After the run completes, the analyst queries the findings endpoint, which returns entities scored 0--100 across 14 signal families:

```bash
curl http://expose:8090/api/v1/tenants/$TENANT_ID/findings/ \
  -H "Authorization: Bearer $TOKEN"
```

Response (abbreviated):

```json
{
  "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "total_scored": 73,
  "findings": [
    {
      "rank": 1,
      "entity_identifier": "staging-api.novatech.io",
      "entity_type": "domain",
      "score": 85,
      "priority_tier": "critical",
      "justification": "staging-api.novatech.io: non-production endpoint, no WAF protection and blacklisted IP (score: 85)",
      "signals": [
        {
          "signal_name": "non_production_exposed",
          "points": 30,
          "evidence": "Classified as staging",
          "source_module": "environment_classifier"
        },
        {
          "signal_name": "no_waf_protection",
          "points": 20,
          "evidence": "No CDN/WAF detected — direct exposure",
          "source_module": "waf_detection"
        },
        {
          "signal_name": "dnsbl_listed",
          "points": 25,
          "evidence": "Listed on 2 DNSBL(s): zen.spamhaus.org, b.barracudacentral.org",
          "source_module": "dns_blacklist"
        },
        {
          "signal_name": "deprecated_tls",
          "points": 10,
          "evidence": "TLSv1.1 offered alongside TLSv1.3",
          "source_module": "tls_analysis"
        }
      ]
    },
    {
      "rank": 2,
      "entity_identifier": "legacy-portal.novatech-solutions.com",
      "entity_type": "domain",
      "score": 55,
      "priority_tier": "high",
      "justification": "legacy-portal.novatech-solutions.com: missing security headers, weak/self-signed certificate and debug mode enabled (score: 55)",
      "signals": [
        {
          "signal_name": "missing_security_headers",
          "points": 5,
          "evidence": "Missing: Strict-Transport-Security, Content-Security-Policy",
          "source_module": "http_fingerprint"
        },
        {
          "signal_name": "weak_certificate",
          "points": 10,
          "evidence": "Self-signed certificate, expired 2025-12-01",
          "source_module": "tls_handshake"
        },
        {
          "signal_name": "debug_mode_detected",
          "points": 10,
          "evidence": "X-Debug-Mode: true header present",
          "source_module": "environment_classifier"
        },
        {
          "signal_name": "open_port_risk",
          "points": 15,
          "evidence": "Port 3306 (MySQL) exposed, port 6379 (Redis) exposed",
          "source_module": "port_scan"
        },
        {
          "signal_name": "http_technology_exposure",
          "points": 10,
          "evidence": "X-Powered-By: PHP/7.4.3, Server: Apache/2.4.41",
          "source_module": "http_fingerprint"
        },
        {
          "signal_name": "no_waf_protection",
          "points": 20,
          "evidence": "No CDN/WAF detected — direct exposure",
          "source_module": "waf_detection"
        }
      ]
    }
  ]
}
```

The scoring breakdown across all 14 signal families:

| Signal Family | Max Points | What It Detects |
|---|---|---|
| Non-production exposed | +30 | Staging, dev, test environments on the internet |
| No WAF protection | +20 | Direct exposure without CDN/WAF |
| DNSBL listed | +15 to +25 | IP on blocklists (Spamhaus, Barracuda, etc.) |
| Trust degradation | +10 to +15 | Recent infrastructure changes, CA switches |
| Post-acquisition asset | +10 | Entity discovered via M&A transitive search |
| SaaS misalignment | +10 | Shadow IT -- unexpected SaaS products |
| Vision findings | +10 | Security indicators from screenshot analysis |
| Missing security headers | +5 | Missing HSTS, CSP, X-Frame-Options |
| Weak certificate | +5 to +10 | Self-signed, expired, short key length |
| Debug mode detected | +10 | Debug headers, stack traces, verbose errors |
| Open port risk | +5 to +20 | Database ports, admin interfaces exposed |
| Deprecated TLS | +10 to +15 | TLSv1.0/1.1, weak cipher suites |
| DNS exposure | +5 to +15 | Zone transfer allowed, DNSSEC issues |
| HTTP technology exposure | +5 to +10 | Server version disclosure, framework headers |

**4. Temporal analysis detects security regression**

The analyst queries the temporal analysis endpoint for `staging-api.novatech.io`. EXPOSE compares current observations against Wayback Machine and Shodan historical data:

```bash
curl http://expose:8090/api/v1/tenants/$TENANT_ID/entities/$ENTITY_ID/timeline \
  -H "Authorization: Bearer $TOKEN"
```

Response (abbreviated):

```json
{
  "entity_identifier": "staging-api.novatech.io",
  "timeline": {
    "span_days": 120,
    "snapshots": [
      {
        "timestamp": "2026-01-15T00:00:00Z",
        "source": "wayback",
        "tls_version": "TLSv1.3",
        "server_header": "nginx/1.24.0",
        "headers": { "strict-transport-security": "max-age=31536000" }
      },
      {
        "timestamp": "2026-05-10T14:30:00Z",
        "source": "active_scan",
        "tls_version": "TLSv1.1",
        "server_header": "nginx/1.18.0",
        "headers": {}
      }
    ]
  },
  "patterns": [
    {
      "pattern_type": "security_regression",
      "severity": "critical",
      "description": "TLS downgraded from TLSv1.3 to TLSv1.1; HSTS header removed",
      "scoring_delta": 15,
      "detected_at": "2026-05-10T14:35:00Z",
      "evidence": [
        { "field": "tls_version", "before": "TLSv1.3", "after": "TLSv1.1" },
        { "field": "header:strict-transport-security", "before": "max-age=31536000", "after": null }
      ]
    },
    {
      "pattern_type": "infrastructure_drift",
      "severity": "medium",
      "description": "Server software downgraded from nginx/1.24.0 to nginx/1.18.0",
      "scoring_delta": 5,
      "detected_at": "2026-05-10T14:35:00Z",
      "evidence": [
        { "field": "server_header", "before": "nginx/1.24.0", "after": "nginx/1.18.0" }
      ]
    }
  ],
  "temporal_score_delta": 20
}
```

The temporal analysis reveals that `staging-api.novatech.io` had proper TLS 1.3 and HSTS four months ago, but someone rebuilt or reconfigured the server and the security posture degraded. This is not a new asset -- it is a *regression*, which is operationally more urgent because it indicates a broken process.

**5. Provenance chain shows attribution logic**

For every entity, the provenance chain answers "why do we think this belongs to NovaTech?" The analyst inspects the provenance for the staging API:

```bash
curl http://expose:8090/api/v1/tenants/$TENANT_ID/entities/$ENTITY_ID/provenance \
  -H "Authorization: Bearer $TOKEN"
```

Response (abbreviated):

```json
{
  "entity_identifier": "staging-api.novatech.io",
  "entity_type": "domain",
  "attribution_tier": "confirmed",
  "confidence": 0.97,
  "observations": [
    {
      "collector_id": "ct-crtsh",
      "observation_type": "CT_LOG_ENTRY",
      "observed_at": "2026-05-10T14:05:00Z",
      "dimension": "cert",
      "evidence_summary": "Certificate SAN includes staging-api.novatech.io, issued to novatech.io"
    },
    {
      "collector_id": "rdap-whois",
      "observation_type": "WHOIS_RECORD",
      "observed_at": "2026-05-10T14:06:00Z",
      "dimension": "whois",
      "evidence_summary": "Registrant: NovaTech Solutions Inc, email: domains@novatech.io"
    },
    {
      "collector_id": "cloud-ranges",
      "observation_type": "CLOUD_RANGE_MATCH",
      "observed_at": "2026-05-10T14:07:00Z",
      "dimension": "cloud",
      "evidence_summary": "Resolved IP 198.51.100.42 matches authorized AWS range"
    }
  ],
  "rule_applications": [
    {
      "rule_id": "cloud-first-01",
      "predicate": "target_ip_in_authorized_cloud_account_range",
      "matched": true,
      "contribution": 0.35
    },
    {
      "rule_id": "cloud-first-02",
      "predicate": "target_has_certificate_with_san_in_scope",
      "matched": true,
      "contribution": 0.30
    },
    {
      "rule_id": "cloud-first-03",
      "predicate": "target_registrant_matches_authorized_pattern",
      "matched": true,
      "contribution": 0.32
    }
  ],
  "relationships": [
    {
      "related_entity": "novatech.io",
      "relationship_type": "subdomain_of",
      "confidence": 1.0
    }
  ]
}
```

Every claim traces to a specific collector observation, a specific rule evaluation, and a specific predicate. An auditor can reconstruct exactly how the 0.97 confidence was derived -- no black box.

**6. SOC team gets STIX bundle for SIEM import**

The SOC team needs actionable threat intelligence, not another PDF. EXPOSE packages the findings as a STIX 2.1 bundle:

```bash
curl http://expose:8090/api/v1/tenants/$TENANT_ID/soc/stix \
  -H "Authorization: Bearer $TOKEN" -o novatech-findings.stix.json
```

Response (abbreviated):

```json
{
  "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "generated_at": "2026-05-10T15:00:00Z",
  "bundle": {
    "type": "bundle",
    "id": "bundle--8f4b2a9e-1c3d-4e5f-a6b7-c8d9e0f12345",
    "objects": [
      {
        "type": "indicator",
        "id": "indicator--staging-api-novatech",
        "name": "staging-api.novatech.io - Exposed staging environment",
        "pattern": "[domain-name:value = 'staging-api.novatech.io']",
        "pattern_type": "stix",
        "valid_from": "2026-05-10T14:05:00Z",
        "labels": ["anomalous-activity"],
        "confidence": 97
      },
      {
        "type": "sighting",
        "sighting_of_ref": "indicator--staging-api-novatech",
        "observed_data_refs": ["observed-data--ct-crtsh-001"],
        "first_seen": "2026-05-10T14:05:00Z",
        "count": 3
      }
    ]
  }
}
```

The SOC analyst imports the STIX bundle into Splunk via the Threat Intelligence Framework or into MISP as an event. Each indicator carries the attribution confidence, the discovery timeline, and the evidence chain -- the analyst can prioritize without re-investigating.

For MISP import:

```bash
curl http://expose:8090/api/v1/tenants/$TENANT_ID/soc/misp \
  -H "Authorization: Bearer $TOKEN" -o novatech-misp.json
```

For a raw IoC feed (IP addresses, domains, certificate fingerprints):

```bash
curl http://expose:8090/api/v1/tenants/$TENANT_ID/soc/ioc-feed \
  -H "Authorization: Bearer $TOKEN"
```

**7. CISO gets executive report with threat actor profiling**

The CISO needs a board-ready summary, not raw findings. EXPOSE generates a strategic report with sector analysis, threat actor profiling, and an attraction assessment:

```bash
curl http://expose:8090/api/v1/tenants/$TENANT_ID/reports/ciso \
  -H "Authorization: Bearer $TOKEN"
```

Response (abbreviated):

```json
{
  "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "report_period": "2026-05-10",
  "sector_analysis": {
    "sector": "Technology / SaaS",
    "confidence": 0.92,
    "indicators": ["Cloud-native infrastructure", "API-first architecture", "Multi-region deployment"]
  },
  "threat_actors": [
    {
      "name": "APT41 (Double Dragon)",
      "motivation": "Financial gain, IP theft",
      "relevance_score": 0.78,
      "typical_ttps": ["T1190 - Exploit Public-Facing Application", "T1133 - External Remote Services"],
      "description": "Chinese state-affiliated group known for targeting technology companies for IP theft and financial gain. Known to exploit exposed staging environments and API endpoints."
    }
  ],
  "attraction_assessment": {
    "overall_score": 62,
    "factors": [
      { "factor": "Exposed non-production environments", "score": 85, "description": "Staging API accessible from the internet increases reconnaissance value" },
      { "factor": "Cloud infrastructure complexity", "score": 55, "description": "Multi-cloud deployment across 3 providers increases attack surface" },
      { "factor": "Deprecated TLS configurations", "score": 45, "description": "TLS 1.1 endpoints signal legacy infrastructure" }
    ]
  },
  "executive_summary": "NovaTech's external attack surface includes 73 attributed entities across 3 cloud providers. 2 findings are critical priority, including an exposed staging API with security regression. The sector threat landscape includes APT groups targeting SaaS companies for IP theft. Recommended immediate actions: remediate staging-api.novatech.io TLS configuration and WAF coverage."
}
```

Mandiant sells this analysis as consulting at $50K--$200K per engagement. EXPOSE automates it.

**8. Signed artifact with evidence chain**

The run produces a signed canonical artifact -- the single, versioned deliverable:

```bash
# Download the signed artifact
curl http://expose:8090/api/v1/tenants/$TENANT_ID/runs/$RUN_ID/artifact \
  -H "Authorization: Bearer $TOKEN" -o novatech-artifact.json

# Verify integrity offline
cosign verify-blob --key expose-cosign.pub \
  --signature novatech-artifact.json.sig \
  novatech-artifact.json

# Verify content hash
sha256sum novatech-artifact.json
# Compare against manifest content_hash field
```

The artifact is a portable, signed JSON file that NovaTech owns. It is not trapped in a vendor dashboard. Feed it to Splunk, Sentinel, a Jupyter notebook, or a filing cabinet. When the red team engagement report arrives next quarter, both sides reference the same artifact format.

### Key differentiators

- **Attribution with provenance:** Every claim traces to specific collector observations, rules, and predicates. No other EASM vendor exposes this.
- **Lead scoring across 14 signal families:** Not just "found these assets" but "investigate this one first because it is a staging server on a blacklisted IP with no WAF."
- **Temporal regression detection:** EXPOSE does not just find current state -- it detects that security posture *degraded*, which competitors miss entirely.
- **SOC-ready output:** STIX 2.1, MISP events, IoC feeds flow directly to the SIEM. No manual reformatting.
- **Signed artifacts:** Ed25519/ECDSA cryptographic signatures with SLSA provenance. No other major EASM vendor produces signed deliverables.

### Outcome

The analyst delivers: a prioritized findings list for the security team, a STIX bundle already flowing into Splunk, and a board-ready CISO report -- all from a single pipeline run, all traceable to signed evidence, all generated in under an hour.

---

## Use Case 2: Post-M&A Attack Surface Integration

### Scenario

Meridian Holdings has acquired WidgetCo, a 200-person manufacturing company with product lines in IoT sensors and industrial control systems. Meridian's security team needs to discover what internet-facing infrastructure they just inherited, including assets that WidgetCo's IT team does not know about. The deal closed last week. The asset inventory WidgetCo provided during due diligence listed 12 domains and 2 IP ranges. The actual number is unknown.

### Step-by-step walkthrough

**1. Organization seed triggers M&A discovery**

The security team creates a tenant for the acquisition and seeds it with WidgetCo's known identifiers plus the organization name:

```bash
# Create tenant for the acquisition
curl -X POST http://expose:8090/api/v1/tenants \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Project Cobalt - WidgetCo Acquisition",
    "authorization_scope": {
      "domains": ["widgetco.com", "widgetco.io", "widget-sensors.com"],
      "cidrs": ["192.0.2.0/24"],
      "organizations": ["WidgetCo Inc", "Widget Sensor Systems LLC"]
    }
  }'
```

When the organization seed `"WidgetCo Inc"` enters the pipeline, the M&A subsidiary discovery collector (`ma-subsidiary-discovery`) queries public records -- SEC filings, press releases, WHOIS organizational fields -- for entities related to the parent company. This is a Tier 1 collector (passive, no target contact).

**2. WidgetCo's domains and IPs discovered via registrant pivot**

After the initial run completes, the analyst queries the Identity Surface module's registrant pivot endpoint:

```bash
curl "http://expose:8090/api/v1/tenants/$TENANT_ID/identity/registrant-pivot?domain=widgetco.com" \
  -H "Authorization: Bearer $TOKEN"
```

Response (abbreviated):

```json
{
  "tenant_id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
  "query_domain": "widgetco.com",
  "clusters": [
    {
      "dimension": "registrant_email",
      "key": "domains@widgetco.com",
      "confidence": 0.94,
      "members": [
        { "domain": "widgetco.com", "registrant_org": "WidgetCo Inc" },
        { "domain": "widgetco.io", "registrant_org": "WidgetCo Inc" },
        { "domain": "widget-iot-portal.com", "registrant_org": "WidgetCo Inc" },
        { "domain": "wco-internal.net", "registrant_org": "WidgetCo Inc" }
      ]
    },
    {
      "dimension": "registrant_org",
      "key": "Widget Sensor Systems LLC",
      "confidence": 0.87,
      "members": [
        { "domain": "widget-sensors.com", "registrant_org": "Widget Sensor Systems LLC" },
        { "domain": "ws-firmware-updates.com", "registrant_org": "Widget Sensor Systems LLC" },
        { "domain": "widget-sensor-api.io", "registrant_org": "Widget Sensor Systems LLC" }
      ]
    }
  ],
  "total_discovered": 7,
  "previously_known": 3,
  "new_discoveries": 4
}
```

Four domains that were not in WidgetCo's due diligence inventory are now discovered: `widget-iot-portal.com`, `wco-internal.net`, `ws-firmware-updates.com`, and `widget-sensor-api.io`. The registrant pivot found them by correlating WHOIS registrant email addresses and organization names across the global RDAP dataset.

**3. Post-acquisition assets scored higher (+10 M&A signal)**

Entities discovered via M&A transitive search automatically receive a +10 point boost in lead scoring, because acquired infrastructure is inherently higher risk -- the new owner has not yet validated its security posture:

```bash
curl http://expose:8090/api/v1/tenants/$TENANT_ID/findings/ \
  -H "Authorization: Bearer $TOKEN"
```

Response (abbreviated):

```json
{
  "findings": [
    {
      "rank": 1,
      "entity_identifier": "ws-firmware-updates.com",
      "score": 75,
      "priority_tier": "critical",
      "justification": "ws-firmware-updates.com: post-acquisition asset, no WAF protection and deprecated TLS configuration (score: 75)",
      "signals": [
        {
          "signal_name": "post_acquisition_asset",
          "points": 10,
          "evidence": "Discovered via M&A transitive search for Widget Sensor Systems LLC",
          "source_module": "ma_discovery"
        },
        {
          "signal_name": "no_waf_protection",
          "points": 20,
          "evidence": "No CDN/WAF detected — direct exposure",
          "source_module": "waf_detection"
        },
        {
          "signal_name": "deprecated_tls",
          "points": 15,
          "evidence": "TLSv1.0 only, no TLSv1.2/1.3 support",
          "source_module": "tls_analysis"
        },
        {
          "signal_name": "open_port_risk",
          "points": 20,
          "evidence": "Port 21 (FTP) exposed, port 8080 (HTTP alt) exposed",
          "source_module": "port_scan"
        },
        {
          "signal_name": "missing_security_headers",
          "points": 5,
          "evidence": "Missing: Strict-Transport-Security, X-Frame-Options",
          "source_module": "http_fingerprint"
        },
        {
          "signal_name": "http_technology_exposure",
          "points": 5,
          "evidence": "Server: Apache/2.2.34, X-Powered-By: PHP/5.6.40",
          "source_module": "http_fingerprint"
        }
      ]
    }
  ]
}
```

`ws-firmware-updates.com` is serving firmware updates for IoT sensors over FTP with TLS 1.0 and PHP 5.6. This is a firmware supply-chain risk that WidgetCo's 12-domain inventory completely missed.

**4. Identity Surface org-graph shows the organizational hierarchy**

The analyst queries the org-graph endpoint to visualize the full organizational structure:

```bash
curl "http://expose:8090/api/v1/tenants/$TENANT_ID/identity/org-graph" \
  -H "Authorization: Bearer $TOKEN"
```

Response (abbreviated):

```json
{
  "nodes": [
    { "id": "org-widgetco", "label": "WidgetCo Inc", "type": "organization" },
    { "id": "org-wss", "label": "Widget Sensor Systems LLC", "type": "organization" },
    { "id": "dom-widgetco-com", "label": "widgetco.com", "type": "domain" },
    { "id": "dom-widget-iot-portal", "label": "widget-iot-portal.com", "type": "domain" },
    { "id": "dom-ws-firmware", "label": "ws-firmware-updates.com", "type": "domain" },
    { "id": "ip-192-0-2-50", "label": "192.0.2.50", "type": "ip_address" }
  ],
  "edges": [
    { "source": "org-widgetco", "target": "org-wss", "type": "subsidiary_of", "evidence": "SEC filing, M&A public record" },
    { "source": "org-widgetco", "target": "dom-widgetco-com", "type": "registers", "evidence": "RDAP registrant match" },
    { "source": "org-wss", "target": "dom-ws-firmware", "type": "registers", "evidence": "RDAP registrant match" },
    { "source": "dom-ws-firmware", "target": "ip-192-0-2-50", "type": "resolves_to", "evidence": "Active DNS resolution" }
  ]
}
```

The graph reveals that Widget Sensor Systems LLC is a subsidiary of WidgetCo Inc, with its own set of domains and infrastructure that Meridian now owns. The EXPOSE UI renders this as an interactive D3 force-directed graph with click-to-expand on each node.

**5. Subdomain takeover risks on acquired domains**

EXPOSE's active DNS resolution and HTTP fingerprinting collectors detect dangling DNS records -- subdomains pointing to decommissioned services that an attacker could claim:

```bash
curl http://expose:8090/api/v1/tenants/$TENANT_ID/soc/suspicious \
  -H "Authorization: Bearer $TOKEN"
```

Response (abbreviated):

```json
{
  "suspicious_endpoints": [
    {
      "entity_identifier": "status.widgetco.com",
      "reason": "CNAME points to unregistered Heroku app (widget-co-status.herokuapp.com)",
      "severity": "critical",
      "recommended_action": "Remove DNS CNAME record or reclaim the Heroku app name to prevent subdomain takeover"
    },
    {
      "entity_identifier": "blog.widget-sensors.com",
      "reason": "CNAME points to unregistered Ghost(Pro) instance",
      "severity": "high",
      "recommended_action": "Remove DNS CNAME record or register the Ghost(Pro) instance"
    }
  ]
}
```

**6. CISO report highlights integration gaps**

The CISO gets a strategic report covering the entire acquired surface:

```bash
curl http://expose:8090/api/v1/tenants/$TENANT_ID/reports/ciso \
  -H "Authorization: Bearer $TOKEN"
```

The report summarizes: 19 total attributed entities (vs. 12 in the due diligence inventory), 4 previously unknown domains, 2 critical subdomain takeover risks, 1 firmware supply-chain exposure, and an overall integration risk score. The executive summary recommends immediate actions prioritized by lead score.

### Key differentiators

- **M&A-aware discovery:** The Identity Surface module discovers assets that acquired companies forgot about. Competitors require you to know the domains first.
- **Registrant pivot analysis:** Correlates WHOIS registrant data across the global RDAP dataset to find related domains -- not just subdomains of known domains, but entirely separate domain families registered by the same entity.
- **Organizational graph:** Visualizes the corporate hierarchy from registration data, showing subsidiaries and their infrastructure relationships.
- **Automatic M&A risk uplift:** The +10 point M&A signal in lead scoring ensures acquired assets get appropriate priority without manual triage.

### Outcome

Meridian's security team discovers 7 additional domains beyond WidgetCo's self-reported inventory, identifies 2 subdomain takeover risks and a firmware supply-chain exposure, and delivers a board-ready integration risk report -- all within the first week after the deal closes.

---

## Use Case 3: Continuous Monitoring with Drift Detection

### Scenario

The SOC team at Pinnacle Financial, a mid-market financial services company, needs to move from quarterly EASM assessments to continuous monitoring. They want to detect attack surface changes as they happen -- new subdomains appearing, TLS configurations degrading, certificates expiring -- and feed alerts directly into their Splunk-based SOC workflow. They run EXPOSE on their own infrastructure.

### Step-by-step walkthrough

**1. Cron schedule configuration via API**

The SOC engineer configures a daily scan schedule:

```bash
curl -X POST http://expose:8090/api/v1/scheduler/schedules \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "tenant_id": "c3d4e5f6-a7b8-9012-cdef-345678901234",
    "cron_expression": "0 2 * * *",
    "tiers": [1, 2, 3],
    "rule_pack": "examples/rulepacks/conservative.json"
  }'
```

Response:

```json
{
  "tenant_id": "c3d4e5f6-a7b8-9012-cdef-345678901234",
  "cron_expression": "0 2 * * *",
  "next_run_at": "2026-05-11T02:00:00Z",
  "created_at": "2026-05-10T16:00:00Z"
}
```

The conservative rule pack uses higher attribution thresholds, appropriate for a regulated financial services environment where false positives have operational cost.

**2. Temporal analysis comparing this week's scan to last month**

After several weeks of daily scans, the analyst queries the temporal analysis endpoint to understand how the attack surface has evolved:

```bash
curl http://expose:8090/api/v1/tenants/$TENANT_ID/entities/$ENTITY_ID/timeline \
  -H "Authorization: Bearer $TOKEN"
```

Response (abbreviated):

```json
{
  "entity_identifier": "api.pinnacle-financial.com",
  "timeline": {
    "span_days": 30,
    "snapshots": [
      {
        "timestamp": "2026-04-10T02:15:00Z",
        "source": "active_scan",
        "tls_version": "TLSv1.3",
        "headers": {
          "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
          "content-security-policy": "default-src 'self'",
          "x-frame-options": "DENY"
        },
        "server_header": "cloudflare"
      },
      {
        "timestamp": "2026-05-10T02:15:00Z",
        "source": "active_scan",
        "tls_version": "TLSv1.3",
        "headers": {
          "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
          "x-frame-options": "DENY"
        },
        "server_header": "cloudflare"
      }
    ]
  },
  "patterns": [
    {
      "pattern_type": "security_regression",
      "severity": "medium",
      "description": "Content-Security-Policy header removed between 2026-04-10 and 2026-05-10",
      "scoring_delta": 5,
      "evidence": [
        { "field": "header:content-security-policy", "before": "default-src 'self'", "after": null }
      ]
    }
  ],
  "temporal_score_delta": 5
}
```

The CSP header was present in April but disappeared in May -- likely a deployment that overwrote the header configuration. Without temporal analysis, this would be invisible: the current state looks "mostly fine" (still has HSTS, still on TLS 1.3). But the trend is negative.

**3. Security regression alerts (TLS downgrade, header removal)**

EXPOSE's 5 progression pattern detectors run automatically on every scan:

| Pattern Type | What It Detects | Example |
|---|---|---|
| Security regression | TLS downgrade, security header removal, server version downgrade | TLSv1.3 to TLSv1.1, HSTS removed |
| Environment promotion | Staging-to-production transitions, debug mode persisting after promotion | `staging.example.com` now serves production traffic |
| Infrastructure drift | Server software changes, technology stack migration | nginx to Apache, PHP version change |
| Certificate lifecycle | Stale certs, rapid rotation, self-signed replacement | Cert unchanged for 18 months, 3 rotations in 1 week |
| New exposure | New ports or services that were absent in earlier snapshots | Port 8443 appeared, new subdomain responding |

**4. New exposure detection**

When the daily scan discovers a new subdomain that was not present yesterday, it appears in the findings with full provenance:

```bash
# Query findings filtered to entities first seen in the last 24 hours
curl http://expose:8090/api/v1/tenants/$TENANT_ID/findings/ \
  -H "Authorization: Bearer $TOKEN"
```

New entities carry their first-seen timestamp and the collector that discovered them. If `internal-tools.pinnacle-financial.com` appeared overnight, the SOC analyst sees exactly when it was first observed and which CT log entry or DNS resolution revealed it.

**5. Automated IoC feed updates pushed to SIEM**

The Splunk HEC adapter pushes findings directly into Splunk as structured events:

```bash
# Configure Splunk HEC integration
curl -X PUT http://expose:8090/api/v1/tenants/$TENANT_ID/config \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "siem_integration": {
      "provider": "splunk",
      "hec_url": "https://splunk.pinnacle.internal:8088/services/collector",
      "hec_token": "configured-via-secrets-backend",
      "index": "expose_findings",
      "enabled": true
    }
  }'
```

Each daily run pushes new and changed findings to Splunk automatically. The SOC analyst sees EXPOSE findings as Splunk alerts alongside their existing detection rules -- same console, same workflow, same triage process.

For Microsoft Sentinel or Google Chronicle environments, swap the provider:

```bash
# Sentinel configuration
curl -X PUT http://expose:8090/api/v1/tenants/$TENANT_ID/config \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "siem_integration": {
      "provider": "sentinel",
      "workspace_id": "your-workspace-id",
      "shared_key": "configured-via-secrets-backend",
      "log_type": "EXPOSE_Findings",
      "enabled": true
    }
  }'
```

**6. Certificate lifecycle monitoring**

The temporal analysis module tracks certificate lifecycles across the entire surface:

```json
{
  "pattern_type": "cert_lifecycle",
  "severity": "high",
  "description": "Certificate for payments.pinnacle-financial.com unchanged for 380 days (approaching Let's Encrypt 90-day renewal window violation)",
  "scoring_delta": 10,
  "evidence": [
    { "field": "cert_not_after", "value": "2026-06-15T00:00:00Z", "days_remaining": 36 },
    { "field": "cert_age_days", "value": 380 }
  ]
}
```

An expiring certificate on a payment endpoint is a different category of risk than a missing header. EXPOSE's temporal analysis surfaces it as a distinct pattern type with its own severity assessment and scoring contribution.

### Key differentiators

- **Five progression pattern detectors:** Security regression, environment promotion, infrastructure drift, certificate lifecycle, and new exposure -- each a distinct detection category, not just "something changed."
- **Native SIEM push:** Splunk HEC, Microsoft Sentinel, and Google Chronicle adapters push findings directly into the SOC's existing tooling. No ETL pipeline required.
- **Temporal score delta:** Changes contribute to lead scores. A regression adds points; remediation reduces them. The score tracks direction, not just state.
- **Delta-native architecture:** Every run computes a delta against the previous run. "What changed?" is a query, not a manual diff of two spreadsheets.

### Outcome

Pinnacle Financial's SOC team detects a CSP header removal within 24 hours of it happening, identifies an expiring certificate 36 days before it expires, and receives all findings as structured Splunk events -- replacing a quarterly manual assessment with continuous, automated monitoring.

---

## Use Case 4: Federal / Compliance Customer

### Scenario

The information security team at a civilian federal agency operates under a NIST 800-53 Moderate baseline and needs continuous external surface monitoring for their CDM (Continuous Diagnostics and Mitigation) program. Commercial EASM vendors are SaaS -- adopting them requires either inheriting a FedRAMP authorization or sponsoring one (18-24 months). The agency's attack surface is expanding now. They deploy EXPOSE Core within their existing authorization boundary for authorized red team assessment of their own systems.

### Step-by-step walkthrough

**1. FIPS 140-2 compliant cryptography**

All cryptographic operations in EXPOSE route through a centralized `fips_adapter` module. No raw `hashlib` or `secrets` calls exist in the codebase:

```bash
# Verify FIPS compliance (CI gate)
python -m expose.crypto.fips_adapter --verify
```

The adapter supports Ed25519 and ECDSA P-256 signing, FIPS SHA-256 content hashing, and HMAC-based key derivation. When deployed in FIPS mode, all crypto operations use FIPS 140-2 validated implementations:

```bash
# Deploy with FIPS enabled
helm install expose deploy/helm-chart/ \
  -f deploy/helm-chart/values-federal.yaml \
  --set fips.enabled=true \
  --set networkPolicy.enabled=true \
  --set podSecurity.enforce=restricted
```

**2. NIST AU-2/AU-3 audit logging**

Every pipeline action, collector invocation, and attribution decision generates a structured audit event satisfying NIST SP 800-53 AU-2 (Audit Events) and AU-3 (Content of Audit Records):

```json
{
  "event_id": "evt-2026-05-10-14-30-001",
  "event_type": "collector_invocation",
  "timestamp": "2026-05-10T14:30:00Z",
  "actor": "pipeline-executor",
  "action": "invoke_collector",
  "target": {
    "collector_id": "active-tls-handshake",
    "entity_identifier": "portal.agency.gov"
  },
  "outcome": "success",
  "correlation_id": "run-f8e7d6c5-b4a3-2109",
  "detail": {
    "tier": 3,
    "attribution_tier": "confirmed",
    "confidence": 0.98,
    "enforcement_mode": "hard"
  }
}
```

Each event includes: timestamp, actor, action, target, outcome, and correlation ID -- sufficient for complete reconstruction of any pipeline run during an audit.

```bash
# Export audit log for assessment period
curl http://expose:8090/api/v1/audit/export \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "from_date": "2025-10-01",
    "to_date": "2026-09-30",
    "format": "json",
    "include_provenance": true
  }'
```

**3. Rule pack customized for government (conservative thresholds)**

The agency uses the conservative rule pack with higher attribution thresholds to minimize false positives in a compliance-sensitive environment:

```bash
# Use the conservative rule pack
expose run start agency.gov \
  --tenant $TENANT_ID \
  --tiers 1,2,3 \
  --rule-pack examples/rulepacks/conservative.json
```

The conservative rule pack raises the `confirmed` threshold from 0.95 to 0.97 and the `high` threshold from 0.75 to 0.85. Rule packs are JSON Schema-validated data files -- the agency's compliance team can inspect every attribution rule and threshold without reading source code:

```json
{
  "$schema": "https://raw.githubusercontent.com/pitt-street-labs/expose/main/schemas/rulepack-v1.json",
  "name": "Government / Conservative",
  "tier_thresholds": {
    "confirmed": 0.97,
    "high": 0.85,
    "medium": 0.60
  },
  "rules": [
    {
      "id": "gov-01",
      "description": "Cloud account range match with registrant confirmation",
      "conditions": {
        "operator": "AND",
        "predicates": [
          "target_ip_in_authorized_cloud_account_range",
          "target_registrant_matches_authorized_pattern"
        ]
      },
      "confidence_contribution": 0.50
    }
  ]
}
```

**4. Enforcement module audit trail (what was NOT scanned and why)**

The enforcement module logs every scope refusal -- when a Tier 3 active collector is NOT fired against an entity because the attribution confidence is too low. This audit trail is critical for legal defensibility in authorized red team assessments:

```bash
curl http://expose:8090/api/v1/tenants/$TENANT_ID/runs/$RUN_ID/enforcement \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "run_id": "f8e7d6c5-b4a3-2109-8765-432109876543",
  "refusals": [
    {
      "entity_identifier": "mail.agency-partner.gov",
      "attribution_tier": "medium",
      "enforcement_mode": "hard",
      "collector_id": "active-http-fingerprint",
      "reason": "Entity attribution confidence 0.62 below Tier 3 threshold (requires confirmed >= 0.97 or high >= 0.85 in hard enforcement mode)",
      "timestamp": "2026-05-10T14:45:00Z"
    }
  ],
  "total_refusals": 3,
  "total_permitted": 47
}
```

The agency can demonstrate to their ISSM and authorizing official exactly what was scanned, what was not, and why -- a complete record of restraint that strengthens the legal authorization framework.

**5. Signed artifacts with provenance chain for legal defensibility**

Every artifact is signed with Ed25519 and carries a provenance chain documenting the engine version, rule pack hash, collector set, seed configuration, and timestamp:

```bash
# Download signed artifact
curl http://expose:8090/api/v1/tenants/$TENANT_ID/runs/$RUN_ID/artifact \
  -H "Authorization: Bearer $TOKEN" -o assessment-artifact.json

# Verify signature offline (no network required)
cosign verify-blob --key expose-cosign.pub \
  --signature assessment-artifact.json.sig \
  assessment-artifact.json

# Verify content hash
sha256sum assessment-artifact.json
```

The provenance chain in the artifact:

```json
{
  "provenance": {
    "engine_version": "0.2.0",
    "rule_pack_hash": "sha256:a1b2c3d4e5f6...",
    "collectors_used": ["ct-crtsh", "rdap-whois", "active-dns-resolve", "active-tls-handshake"],
    "seed_configuration": { "domain": "agency.gov", "tiers": [1, 2, 3] },
    "started_at": "2026-05-10T14:00:00Z",
    "completed_at": "2026-05-10T14:52:00Z",
    "content_hash": "sha256:e5f6a7b8c9d0..."
  }
}
```

An assessor in a future audit can reconstruct exactly how any finding was produced -- same engine version, same rule pack, same inputs yield the same artifact (deterministic E1 architecture).

**6. Evidence storage with integrity verification**

The agency configures evidence storage with content-addressed keys and retention policies aligned to federal records management requirements:

```bash
curl -X PUT http://expose:8090/api/v1/tenants/$TENANT_ID/config \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "storage": {
      "evidence_retention_days": 2555,
      "artifact_retention_days": 2555,
      "content_addressed": true,
      "backend": "s3",
      "s3_bucket": "agency-expose-evidence",
      "s3_endpoint": "https://s3.agency.internal"
    }
  }'
```

Content-addressed storage means every piece of evidence is stored under a key derived from its SHA-256 hash. Integrity verification is inherent -- if the content changes, the key no longer matches.

**7. Helm chart deployment in air-gapped environment**

For fully air-gapped environments, EXPOSE supports offline deployment. LLM enrichment runs against a local Ollama instance -- no data leaves the network:

```bash
# Air-gapped deployment with local LLM
helm install expose deploy/helm-chart/ \
  -f deploy/helm-chart/values-federal.yaml \
  --set fips.enabled=true \
  --set networkPolicy.enabled=true \
  --set llm.provider=ollama \
  --set llm.endpoint=http://ollama.internal:11434 \
  --set egress.allowlist.enabled=true
```

The egress allowlist documents every external endpoint the collectors contact (CT logs, DNS resolvers, RDAP registries). The agency's network team reviews and approves the allowlist before deployment:

```bash
# View egress allowlist
expose config show-egress-allowlist
```

### Key differentiators

- **Self-host within the ATO boundary:** No FedRAMP dependency. Deploy the Apache 2.0 engine on existing authorized infrastructure.
- **FIPS 140-3 validated cryptography:** All crypto through `fips_adapter` -- no raw hashlib, no unvalidated implementations.
- **Enforcement audit trail:** A provable record of what was NOT scanned, required for authorized red team legal frameworks.
- **Deterministic E1 architecture:** Regulators can reproduce any finding given the same inputs. No black-box AI decisions.
- **12-18 month compliance engineering moat:** NIST control mapping, FIPS crypto, append-only audit logging, content-addressed evidence storage -- competitors would need to replicate all of it.

### Outcome

The agency deploys EXPOSE within their existing High ATO boundary, begins continuous external surface monitoring within days (not the 18-24 months a FedRAMP vendor authorization would require), and produces the tamper-evident, signed, provenance-chained artifacts their assessors need for NIST 800-53 CA-7 continuous monitoring compliance.

---

## Use Case 5: Security Research and Evaluation

### Scenario

Dr. Sarah Chen is a postdoctoral researcher at a university security lab studying attribution accuracy in external attack surface management. Her upcoming paper proposes a novel graph-based attribution methodology and needs to benchmark it against existing approaches using common datasets. Every commercial EASM vendor keeps its attribution logic and test sets proprietary. Censys claims ">95% attribution accuracy" but the methodology and reference data are closed. Reproducibility in the field is aspirational.

### Step-by-step walkthrough

**1. Reference datasets (confirmed_yours, adversarial, ambiguous)**

Dr. Chen deploys EXPOSE Core (Apache 2.0) on university compute infrastructure:

```bash
git clone https://github.com/pitt-street-labs/expose.git
cd expose
uv pip install -e ".[all]"
```

EXPOSE Research publishes reference datasets under CC BY 4.0 across four categories designed to stress-test attribution accuracy:

| Dataset | Purpose | Example Cases |
|---|---|---|
| `confirmed_yours` | Entities with ground-truth positive attribution | Known domains, verified cloud assets, confirmed registrant matches |
| `confirmed_not_yours` | Entities that should NOT be attributed to the target | Third-party CDN IPs, shared hosting, unrelated domains |
| `ambiguous` | Edge cases where attribution is genuinely uncertain | Expired domains, migrated infrastructure, shared certificates |
| `adversarial` | Deliberately misleading signals designed to fool naive attribution | Typosquatting, certificate cloning, BGP hijack patterns |

The datasets live in `examples/eval-datasets/` and contain structured observation graphs with known ground truth labels.

**2. Eval CLI producing precision/recall/F1 metrics**

The eval harness benchmarks any attribution function against these datasets:

```bash
# Run the baseline rule pack against all four categories
expose eval --all \
  --rulepack examples/rulepacks/example-baseline.json \
  --json-output > baseline-results.json
```

Output:

```
EXPOSE Eval Harness — Attribution Accuracy Report
==================================================

Rule pack: example-baseline.json (sha256: 4a5b6c7d...)
Engine version: 0.2.0

Category: confirmed_yours (15 cases)
  TP: 14  FP: 0  FN: 1  TN: 0
  Precision: 1.000  Recall: 0.933  F1: 0.966

Category: confirmed_not_yours (15 cases)
  TP: 0  FP: 1  TN: 14  FN: 0
  Precision: 0.000  Recall: N/A  F1: N/A
  False positive rate: 0.067

Category: ambiguous (15 cases)
  Attributed: 8  Not attributed: 7
  Mean confidence (attributed): 0.68
  Mean confidence (not attributed): 0.32

Category: adversarial (15 cases)
  TP: 0  FP: 2  TN: 13  FN: 0
  False positive rate: 0.133
  Adversarial resistance: 0.867

Aggregate:
  Precision: 0.875  Recall: 0.933  F1: 0.903
  Pass threshold: 0.80 — PASS
```

**3. Custom rule packs for different attribution strategies**

Dr. Chen implements her novel graph-based methodology as a custom rule pack and benchmarks it against the baseline:

```bash
# Run the novel methodology against the same datasets
expose eval --all \
  --rulepack research/graph-attribution-v1.json \
  --json-output > graph-results.json

# Compare results side by side
expose eval compare baseline-results.json graph-results.json --format table
```

The eval harness uses the `EvalRunner` class, which accepts any function matching the `AttributionFn` signature:

```python
# Type signature: (entity_type, canonical_identifier, observations) -> (tier, confidence)
AttributionFn = Callable[[str, str, list[dict]], tuple[str, float]]
```

For more sophisticated methodologies, the researcher wraps a `RuleEvaluator` loaded from a custom rule pack:

```python
from expose.eval.runner import EvalRunner
from expose.pipeline.rule_evaluator import RuleEvaluator

# Load the novel rule pack
evaluator = RuleEvaluator.from_file("research/graph-attribution-v1.json")

# Create a runner using the rule evaluator
runner = EvalRunner.from_rule_evaluator(evaluator)

# Run against all datasets
report = runner.run_all()
print(report.summary())
```

**4. Collector framework for adding new data sources**

Dr. Chen's research includes a novel data source -- academic paper citation networks as attribution evidence (papers citing a domain as belonging to an organization). She implements it as a custom collector:

```python
from expose.collectors.base import BaseCollector, CollectorMeta, CollectorTier, Seed

class AcademicCitationCollector(BaseCollector):
    meta = CollectorMeta(
        collector_id="academic-citation",
        display_name="Academic Citation Network",
        tier=CollectorTier.TIER_1,
        description="Attribution evidence from academic paper citations",
        mitre_techniques=["T1596.005"],
    )

    async def expand(self, seed: Seed, *, run_id=None, tenant_id=None, session_factory=None):
        # Query academic citation APIs for domain references
        observations = await self._query_citations(seed)
        return observations
```

The collector inherits the full framework: tier-gated dispatch, attribution integration, audit logging, and eval harness compatibility. The new data source slots into the existing pipeline without modifying the engine.

**5. Reproducible attribution with deterministic E1**

Dr. Chen's paper methodology section:

> We evaluate our graph-based attribution methodology using the EXPOSE platform (v0.2.0, Apache 2.0) and the EXPOSE Research reference datasets (CC BY 4.0). All experiments use the deterministic Environment 1 engine, which guarantees that given identical inputs and rule configurations, identical artifacts are produced. No LLM enrichment was used in the evaluation to ensure full reproducibility.
>
> To reproduce our results:
> ```
> git clone https://github.com/pitt-street-labs/expose.git
> git checkout v0.2.0
> expose eval --all --rulepack research/graph-attribution-v1.json
> ```
>
> The rule pack file hash (SHA-256: `7c8d9e0f...`), engine version, and dataset version are sufficient to reproduce all reported metrics.

A reviewer in a different country, a different university, a different continent can:

```bash
git checkout v0.2.0
expose eval --all --rulepack research/graph-attribution-v1.json --json-output > reviewer-results.json
# Deterministic output matches published results
```

No API keys required. No vendor relationship required. No collection infrastructure to build. The deterministic E1 engine guarantees reproducibility.

### Key differentiators

- **Open reference datasets:** CC BY 4.0 licensed datasets with ground truth labels across four difficulty categories. No other EASM vendor publishes reference data.
- **Eval harness with pluggable attribution:** Swap in any attribution function matching the `AttributionFn` signature. Compare precision, recall, and F1 across strategies.
- **Deterministic reproducibility:** Same inputs + same rules = same artifact. Reviewers can verify results without trusting the original researcher's infrastructure.
- **Extensible collector framework:** New data sources plug into the existing pipeline with full framework integration. No fork required.
- **Apache 2.0 license:** Researchers can inspect, modify, and publish without vendor permission or licensing negotiation.

### Outcome

Dr. Chen publishes a paper with reproducible benchmarks: her graph-based methodology achieves F1 0.94 on the EXPOSE reference datasets vs. the baseline's 0.90. Every result is independently reproducible by any researcher with a Python environment and a git clone. The EASM research community finally has a common benchmark.

---

## The Commercial Moat, Demonstrated

These five use cases exercise different layers of the EXPOSE platform, but they share a common thread: **every claim is traceable, every decision is auditable, and every artifact is signed.**

| Moat Layer | Use Case 1 | Use Case 2 | Use Case 3 | Use Case 4 | Use Case 5 |
|---|---|---|---|---|---|
| Attribution intelligence | Provenance chain | Registrant pivot | Temporal scoring | Conservative rules | Eval harness |
| SOC threat package | STIX bundle | Suspicious endpoints | SIEM push | Audit trail | -- |
| CISO strategic report | Threat actor profiling | Integration gaps | -- | -- | -- |
| Two-environment model | E1 deterministic + E2 enrichment | E1 deterministic | E1 deterministic | E1 deterministic | E1 reproducibility |
| Federal-ready architecture | Signed artifacts | -- | -- | FIPS + AU-2/AU-3 | -- |
| Identity Surface | -- | Org graph | -- | -- | -- |
| Open-core community | -- | -- | -- | -- | Reference datasets |

Competitors sell asset inventories. EXPOSE sells intelligence -- attributed, scored, temporally aware, SOC-ready, cryptographically signed, and auditable from collector observation to executive report.

To get started, clone the repository and run your first scan:

```bash
git clone https://github.com/pitt-street-labs/expose.git
cd expose
uv pip install -e ".[all]"
expose run start your-domain.com --tenant $(uuidgen)
```

- **Repository:** [github.com/pitt-street-labs/expose](https://github.com/pitt-street-labs/expose)
- **Specification:** `docs/SPEC.md`
- **Quickstart guide:** `docs/quickstart.md`
- **Competitive comparison:** `docs/why-expose.md`
- **Example rule packs:** `examples/rulepacks/`
- **Reference datasets:** `examples/eval-datasets/`

# Copyright 2026 Korlogos / Pitt Street Labs. All rights reserved.
# This file is part of EXPOSE Commercial Modules and is NOT covered by the
# Apache 2.0 license that governs the core engine. Unauthorized copying,
# distribution, or use of this file is strictly prohibited. Contact
# licensing@korlogos.com for commercial licensing terms.

"""Full provider fingerprint database for supply chain inference (commercial module).

This module is part of EXPOSE Threat Context (ADR-009) and contains the
curated provider intelligence database.  The detection ENGINE lives in
``expose.pipeline.supply_chain`` and is open-source; this file is the
curated KNOWLEDGE -- the patterns that map DNS artefacts to specific
cloud/SaaS/infrastructure providers, along with risk notes that encode
analyst expertise.

The open-core ``supply_chain.py`` keeps five common example providers
inline so the engine remains functional without this module.  When this
module is importable, the full database is merged in automatically.

The data structure matches ``supply_chain.PROVIDER_DB``::

    FULL_PROVIDER_DB[provider_id] = {
        "name": str,
        "category": str,
        "patterns": { evidence_type: [glob_patterns] },
        "risk_notes": str,
    }
"""

from __future__ import annotations

FULL_PROVIDER_DB: dict[str, dict] = {
    "cloudflare": {
        "name": "Cloudflare",
        "category": "cdn_waf",
        "patterns": {
            "cname": [
                "*.cdn.cloudflare.net",
                "*.cloudflare.com",
                "*.cloudflareaccess.com",
                "*.cloudflare-dns.com",
            ],
            "ns": ["*.ns.cloudflare.com"],
            "txt": ["cloudflare-verify*"],
        },
        "risk_notes": (
            "Infrastructure behind Cloudflare proxy. Direct IP scanning "
            "reaches CDN edge, not origin server. Check for origin IP "
            "leaks via historical DNS, certificate transparency, or "
            "misconfigured subdomains."
        ),
    },
    "google_workspace": {
        "name": "Google Workspace",
        "category": "email",
        "patterns": {
            "mx": [
                "*.google.com",
                "*.googlemail.com",
                "aspmx.l.google.com",
                "alt*.aspmx.l.google.com",
            ],
            "spf": ["include:_spf.google.com"],
            "txt": ["google-site-verification=*"],
        },
        "risk_notes": (
            "Email hosted by Google Workspace. Phishing campaigns must "
            "target Google's infrastructure. Check for misconfigured "
            "SPF/DKIM/DMARC that may allow spoofing."
        ),
    },
    "microsoft_365": {
        "name": "Microsoft 365",
        "category": "email",
        "patterns": {
            "mx": ["*.mail.protection.outlook.com"],
            "spf": ["include:spf.protection.outlook.com"],
            "cname": [
                "*.outlook.com",
                "*.sharepoint.com",
                "*.onmicrosoft.com",
            ],
            "txt": ["ms=*", "MS=*"],
        },
        "risk_notes": (
            "Email and collaboration hosted by Microsoft 365. Check for "
            "Azure AD enumeration vectors, misconfigured sharing policies, "
            "and Exchange Online autodiscover exposure."
        ),
    },
    "aws": {
        "name": "Amazon Web Services",
        "category": "hosting",
        "patterns": {
            "cname": [
                "*.amazonaws.com",
                "*.cloudfront.net",
                "*.elasticbeanstalk.com",
                "*.elb.amazonaws.com",
                "*.s3.amazonaws.com",
                "*.s3-website-*.amazonaws.com",
            ],
            "ns": ["*.awsdns-*"],
            "spf": ["include:amazonses.com"],
            "txt": ["amazonses:*"],
        },
        "risk_notes": (
            "Infrastructure hosted on AWS. Check for S3 bucket "
            "misconfigurations, exposed EC2 metadata endpoints, "
            "and subdomain takeover on dangling CNAME records."
        ),
    },
    "azure": {
        "name": "Microsoft Azure",
        "category": "hosting",
        "patterns": {
            "cname": [
                "*.azurewebsites.net",
                "*.azure-api.net",
                "*.azureedge.net",
                "*.blob.core.windows.net",
                "*.trafficmanager.net",
                "*.azurefd.net",
            ],
        },
        "risk_notes": (
            "Infrastructure hosted on Azure. Check for storage account "
            "exposure, Azure App Service misconfigurations, and dangling "
            "DNS records pointing to deprovisioned resources."
        ),
    },
    "gcp": {
        "name": "Google Cloud Platform",
        "category": "hosting",
        "patterns": {
            "cname": [
                "*.googleapis.com",
                "*.appspot.com",
                "*.run.app",
                "*.web.app",
                "*.firebaseapp.com",
                "*.cloudfunctions.net",
                "*.storage.googleapis.com",
            ],
        },
        "risk_notes": (
            "Infrastructure hosted on GCP. Check for exposed Cloud "
            "Storage buckets, App Engine admin consoles, and Firebase "
            "database rules."
        ),
    },
    "fastly": {
        "name": "Fastly",
        "category": "cdn_waf",
        "patterns": {
            "cname": [
                "*.fastly.net",
                "*.fastlylb.net",
                "*.global.ssl.fastly.net",
            ],
        },
        "risk_notes": (
            "Content served via Fastly CDN. Origin IP may differ from "
            "CDN edge. Check for cache poisoning and subdomain takeover "
            "on unclaimed Fastly services."
        ),
    },
    "akamai": {
        "name": "Akamai",
        "category": "cdn_waf",
        "patterns": {
            "cname": [
                "*.akamaiedge.net",
                "*.akamai.net",
                "*.akamaized.net",
                "*.akadns.net",
                "*.edgekey.net",
                "*.edgesuite.net",
            ],
            "ns": ["*.akam.net"],
        },
        "risk_notes": (
            "Content delivered via Akamai CDN/WAF. Origin server IP is "
            "hidden behind Akamai edge. Check for origin exposure via "
            "direct IP scanning or SSL certificate Subject Alternative Names."
        ),
    },
    "mailgun": {
        "name": "Mailgun",
        "category": "email",
        "patterns": {
            "mx": ["*.mailgun.org"],
            "cname": ["*.mailgun.org"],
            "spf": ["include:mailgun.org"],
            "txt": ["mailgun*"],
        },
        "risk_notes": (
            "Transactional email via Mailgun. Check for API key exposure "
            "and misconfigured sending domains."
        ),
    },
    "sendgrid": {
        "name": "SendGrid",
        "category": "email",
        "patterns": {
            "cname": ["*.sendgrid.net"],
            "spf": ["include:sendgrid.net"],
        },
        "risk_notes": (
            "Transactional email via SendGrid (Twilio). Check for API key "
            "exposure in public code repositories."
        ),
    },
    "zendesk": {
        "name": "Zendesk",
        "category": "support",
        "patterns": {
            "cname": [
                "*.zendesk.com",
                "*.zdassets.com",
            ],
            "txt": ["zendesk-verification*"],
        },
        "risk_notes": (
            "Customer support hosted on Zendesk. May expose internal "
            "ticketing structure, agent names, and customer email addresses "
            "through public-facing help center."
        ),
    },
    "shopify": {
        "name": "Shopify",
        "category": "ecommerce",
        "patterns": {
            "cname": [
                "*.myshopify.com",
                "*.shopify.com",
            ],
        },
        "risk_notes": (
            "E-commerce on Shopify. Check for exposed admin panel "
            "(/admin), API access tokens, and storefront enumeration."
        ),
    },
    "github_pages": {
        "name": "GitHub Pages",
        "category": "hosting",
        "patterns": {
            "cname": [
                "*.github.io",
                "*.githubusercontent.com",
            ],
        },
        "risk_notes": (
            "Static site on GitHub Pages. Check for subdomain takeover "
            "if the repository or organization is deleted. May expose "
            "internal documentation or staging content."
        ),
    },
    "vercel": {
        "name": "Vercel",
        "category": "hosting",
        "patterns": {
            "cname": [
                "*.vercel.app",
                "*.vercel-dns.com",
                "cname.vercel-dns.com",
            ],
        },
        "risk_notes": (
            "Application hosted on Vercel. Check for exposed environment "
            "variables via _next/data paths and serverless function "
            "endpoint enumeration."
        ),
    },
    "netlify": {
        "name": "Netlify",
        "category": "hosting",
        "patterns": {
            "cname": [
                "*.netlify.app",
                "*.netlify.com",
            ],
        },
        "risk_notes": (
            "Static/JAMstack site on Netlify. Check for subdomain takeover "
            "on unclaimed Netlify sites and exposed build logs."
        ),
    },
    "proofpoint": {
        "name": "Proofpoint",
        "category": "email_security",
        "patterns": {
            "mx": ["*.pphosted.com"],
            "spf": ["include:*.pphosted.com"],
            "cname": ["*.proofpoint.com"],
        },
        "risk_notes": (
            "Email security gateway via Proofpoint. Inbound mail is "
            "filtered before reaching the final MX. Check for bypass "
            "routes that skip the gateway."
        ),
    },
    "mimecast": {
        "name": "Mimecast",
        "category": "email_security",
        "patterns": {
            "mx": ["*.mimecast.com"],
            "spf": ["include:*.mimecast.com"],
        },
        "risk_notes": (
            "Email security via Mimecast. Check for direct-delivery "
            "bypass and misconfigured SPF that allows spoofing."
        ),
    },
    "cloudflare_dns": {
        "name": "Cloudflare DNS",
        "category": "dns",
        "patterns": {
            "ns": [
                "*.ns.cloudflare.com",
            ],
        },
        "risk_notes": (
            "DNS hosted by Cloudflare. Zone transfers blocked by default. "
            "DNS-over-HTTPS/TLS available. Registrar-lock status should "
            "be verified."
        ),
    },
    "route53": {
        "name": "AWS Route 53",
        "category": "dns",
        "patterns": {
            "ns": [
                "*.awsdns-*",
            ],
        },
        "risk_notes": (
            "DNS hosted on AWS Route 53. Check for dangling hosted zones "
            "and subdomain takeover via NS delegation."
        ),
    },
    "heroku": {
        "name": "Heroku",
        "category": "hosting",
        "patterns": {
            "cname": [
                "*.herokuapp.com",
                "*.herokussl.com",
                "*.herokudns.com",
            ],
        },
        "risk_notes": (
            "Application hosted on Heroku. Check for subdomain takeover "
            "on deleted/unclaimed Heroku apps and exposed config vars."
        ),
    },
}


__all__ = ["FULL_PROVIDER_DB"]

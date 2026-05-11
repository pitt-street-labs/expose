"""Provider fingerprint database for DNS-based SaaS/infrastructure detection (Issue #90).

Maps DNS record patterns (CNAME, MX, SPF includes, NS, TXT) to known
SaaS and infrastructure providers.  Used by the seed-expansion and
enrichment stages to automatically identify third-party services in a
target's DNS footprint.

The database ships 50 providers across 12 categories.  Each entry
carries glob-style patterns for DNS value matching and risk notes
relevant to EASI assessment.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderFingerprint:
    """Immutable descriptor for a SaaS/infrastructure provider's DNS footprint."""

    id: str  # machine-readable, e.g. "cloudflare"
    name: str  # display name, e.g. "Cloudflare"
    category: str  # cdn_waf, email, email_delivery, support, status_page,
    #                 hosting, dns, auth_sso, ci_cd, monitoring, analytics,
    #                 crm, security
    cname_patterns: tuple[str, ...] = ()  # glob patterns for CNAME targets
    mx_patterns: tuple[str, ...] = ()  # glob patterns for MX records
    spf_includes: tuple[str, ...] = ()  # exact SPF include domains
    ns_patterns: tuple[str, ...] = ()  # glob patterns for NS records
    txt_patterns: tuple[str, ...] = ()  # substring matches in TXT records
    risk_notes: str = ""  # security implications for the target


def match_provider(value: str, patterns: tuple[str, ...]) -> bool:
    """Check if a DNS value matches any pattern (glob-style with ``*``).

    Matching is case-insensitive.

    >>> match_provider("foo.cloudfront.net", ("*.cloudfront.net",))
    True
    >>> match_provider("unrelated.example.com", ("*.cloudfront.net",))
    False
    """
    return any(fnmatch.fnmatch(value.lower(), p.lower()) for p in patterns)


# ---------------------------------------------------------------------------
# Provider database — 50 providers, 12 categories
# ---------------------------------------------------------------------------

_PROVIDERS: list[ProviderFingerprint] = [
    # -----------------------------------------------------------------------
    # CDN / WAF  (7)
    # -----------------------------------------------------------------------
    ProviderFingerprint(
        id="cloudflare",
        name="Cloudflare",
        category="cdn_waf",
        cname_patterns=("*.cloudflare.com", "*.cloudflareaccess.com"),
        ns_patterns=("*.ns.cloudflare.com",),
        risk_notes=(
            "Cloudflare proxied records hide origin IP.  Check for origin "
            "leaks via historical DNS, certificate transparency, or direct-IP "
            "access.  Misconfigured Cloudflare Access policies may expose "
            "internal apps."
        ),
    ),
    ProviderFingerprint(
        id="aws_cloudfront",
        name="AWS CloudFront",
        category="cdn_waf",
        cname_patterns=("*.cloudfront.net",),
        risk_notes=(
            "CloudFront distributions may serve stale S3 content or expose "
            "alternative origins.  Check for unclaimed S3 bucket origins and "
            "permissive CORS headers."
        ),
    ),
    ProviderFingerprint(
        id="akamai",
        name="Akamai",
        category="cdn_waf",
        cname_patterns=(
            "*.akamai.net",
            "*.akamaiedge.net",
            "*.akamaitechnologies.com",
        ),
        risk_notes=(
            "Akamai edge hostnames can reveal backend origin through "
            "Akamai-debug headers (Pragma: akamai-x-get-extracted-values).  "
            "Misconfigured Site Shield may leave origin exposed."
        ),
    ),
    ProviderFingerprint(
        id="fastly",
        name="Fastly",
        category="cdn_waf",
        cname_patterns=("*.fastly.net", "*.fastlylb.net"),
        risk_notes=(
            "Fastly CNAMEs to unclaimed services return Fastly error pages "
            "that confirm the CDN.  Check for domain takeover on dangling "
            "Fastly service records."
        ),
    ),
    ProviderFingerprint(
        id="imperva",
        name="Imperva/Incapsula",
        category="cdn_waf",
        cname_patterns=("*.incapdns.net", "*.impervadns.net"),
        risk_notes=(
            "Incapsula WAF can be bypassed if the origin IP is discovered.  "
            "Check historical DNS and CT logs for pre-Incapsula records."
        ),
    ),
    ProviderFingerprint(
        id="sucuri",
        name="Sucuri",
        category="cdn_waf",
        cname_patterns=("*.sucuri.net",),
        risk_notes=(
            "Sucuri WAF proxying hides origin.  Origin IP may be exposed in "
            "non-web services (MX, FTP) or historical records."
        ),
    ),
    ProviderFingerprint(
        id="stackpath",
        name="StackPath",
        category="cdn_waf",
        cname_patterns=("*.stackpathdns.com",),
        risk_notes=(
            "StackPath CDN may expose origin via cache-miss behaviour.  "
            "Unclaimed StackPath sites can be taken over."
        ),
    ),
    # -----------------------------------------------------------------------
    # Email  (3)
    # -----------------------------------------------------------------------
    ProviderFingerprint(
        id="google_workspace",
        name="Google Workspace",
        category="email",
        mx_patterns=("*.google.com", "*.googlemail.com"),
        spf_includes=("_spf.google.com",),
        txt_patterns=("google-site-verification",),
        risk_notes=(
            "Google Workspace domains may expose user enumeration via "
            "calendar/contacts sharing defaults.  Check for public Google "
            "Groups and overshared Drive documents."
        ),
    ),
    ProviderFingerprint(
        id="microsoft_365",
        name="Microsoft 365",
        category="email",
        mx_patterns=("*.outlook.com", "*.protection.outlook.com"),
        spf_includes=("spf.protection.outlook.com",),
        txt_patterns=("MS=ms",),
        risk_notes=(
            "M365 tenants may expose Azure AD user enumeration via login "
            "page behaviour.  Check for misconfigured SharePoint/OneDrive "
            "sharing and Teams guest access."
        ),
    ),
    ProviderFingerprint(
        id="zoho",
        name="Zoho",
        category="email",
        mx_patterns=("*.zoho.com",),
        spf_includes=("zoho.com",),
        risk_notes=(
            "Zoho Mail domains may have default sharing policies that "
            "expose internal documents through Zoho Docs/Projects."
        ),
    ),
    # -----------------------------------------------------------------------
    # Email Delivery  (5)
    # -----------------------------------------------------------------------
    ProviderFingerprint(
        id="sendgrid",
        name="SendGrid",
        category="email_delivery",
        spf_includes=("sendgrid.net",),
        cname_patterns=("*.sendgrid.net",),
        risk_notes=(
            "SendGrid CNAME records for link/open tracking and DKIM may "
            "reveal the SendGrid account.  Misconfigured API keys in public "
            "repos are a common leak vector."
        ),
    ),
    ProviderFingerprint(
        id="mailchimp",
        name="Mailchimp/Mandrill",
        category="email_delivery",
        spf_includes=("mandrillapp.com",),
        cname_patterns=("*.mandrillapp.com",),
        risk_notes=(
            "Mandrill DKIM CNAMEs confirm transactional email usage.  "
            "Check for exposed Mailchimp campaign archives at "
            "*.campaign-archive.com."
        ),
    ),
    ProviderFingerprint(
        id="aws_ses",
        name="AWS SES",
        category="email_delivery",
        spf_includes=("amazonses.com",),
        cname_patterns=("*.ses.amazonaws.com",),
        risk_notes=(
            "SES DKIM CNAMEs confirm AWS email sending.  Over-permissive "
            "SES sending policies can enable phishing from verified domains."
        ),
    ),
    ProviderFingerprint(
        id="postmark",
        name="Postmark",
        category="email_delivery",
        spf_includes=("postmarkapp.com",),
        risk_notes=(
            "Postmark SPF includes confirm transactional email delivery.  "
            "Postmark message streams may expose webhook endpoints."
        ),
    ),
    ProviderFingerprint(
        id="sparkpost",
        name="SparkPost",
        category="email_delivery",
        spf_includes=("sparkpostmail.com",),
        risk_notes=(
            "SparkPost SPF includes indicate bulk/transactional email.  "
            "Tracking subdomains may expose sending infrastructure details."
        ),
    ),
    # -----------------------------------------------------------------------
    # Support  (4)
    # -----------------------------------------------------------------------
    ProviderFingerprint(
        id="zendesk",
        name="Zendesk",
        category="support",
        cname_patterns=("*.zendesk.com",),
        risk_notes=(
            "Check for unauthenticated ticket access at "
            "{target}.zendesk.com.  Public-facing help centres may leak "
            "internal process details, employee names, and product roadmaps."
        ),
    ),
    ProviderFingerprint(
        id="freshdesk",
        name="Freshdesk",
        category="support",
        cname_patterns=("*.freshdesk.com",),
        risk_notes=(
            "Freshdesk portals may expose ticket forms without "
            "authentication.  Solution articles can leak internal tooling "
            "and architecture details."
        ),
    ),
    ProviderFingerprint(
        id="intercom",
        name="Intercom",
        category="support",
        cname_patterns=("*.intercom.io",),
        risk_notes=(
            "Intercom widget code may expose workspace ID and app ID.  "
            "Help-centre articles may reveal internal processes."
        ),
    ),
    ProviderFingerprint(
        id="hubspot",
        name="HubSpot",
        category="support",
        cname_patterns=("*.hubspot.com", "*.hs-sites.com"),
        risk_notes=(
            "HubSpot landing pages and forms may expose marketing "
            "automation workflows.  Check for portal ID leakage and "
            "unauthenticated form submissions.  Also used as CRM — "
            "consider contact/deal data exposure."
        ),
    ),
    # -----------------------------------------------------------------------
    # Status Pages  (3)
    # -----------------------------------------------------------------------
    ProviderFingerprint(
        id="statuspage",
        name="Atlassian Statuspage",
        category="status_page",
        cname_patterns=("*.statuspage.io",),
        risk_notes=(
            "Status pages reveal infrastructure components, incident "
            "history, and maintenance windows — useful for timing attacks "
            "or identifying technology stack."
        ),
    ),
    ProviderFingerprint(
        id="instatus",
        name="Instatus",
        category="status_page",
        cname_patterns=("*.instatus.com",),
        risk_notes=(
            "Instatus pages reveal monitored components and historical "
            "uptime, exposing infrastructure topology."
        ),
    ),
    ProviderFingerprint(
        id="betteruptime",
        name="BetterUptime",
        category="status_page",
        cname_patterns=("*.betteruptime.com",),
        risk_notes=(
            "BetterUptime status pages expose monitored endpoints and "
            "incident response patterns."
        ),
    ),
    # -----------------------------------------------------------------------
    # Hosting / Cloud  (8)
    # -----------------------------------------------------------------------
    ProviderFingerprint(
        id="aws",
        name="AWS",
        category="hosting",
        ns_patterns=("*.awsdns-*.com",),
        cname_patterns=("*.amazonaws.com", "*.elasticbeanstalk.com"),
        risk_notes=(
            "AWS-hosted assets may expose S3 buckets, EC2 metadata, or "
            "Elastic Beanstalk environment variables.  Check for public "
            "snapshots, security group misconfigurations, and IAM role "
            "enumeration via STS."
        ),
    ),
    ProviderFingerprint(
        id="google_cloud",
        name="Google Cloud",
        category="hosting",
        ns_patterns=("*.googledomains.com",),
        cname_patterns=("*.googleapis.com", "*.appspot.com"),
        risk_notes=(
            "GCP assets may expose Cloud Storage buckets, App Engine "
            "admin consoles, or Firebase databases.  Check for public "
            "GCS buckets and overshared IAM bindings."
        ),
    ),
    ProviderFingerprint(
        id="azure",
        name="Azure",
        category="hosting",
        ns_patterns=("*.azure-dns.com",),
        cname_patterns=(
            "*.azurewebsites.net",
            "*.azure.com",
            "*.microsoftonline.com",
        ),
        risk_notes=(
            "Azure resources may expose Blob Storage, App Service "
            "deployment slots, or Azure AD tenant information.  Check "
            "for subdomain takeover on unclaimed *.azurewebsites.net."
        ),
    ),
    ProviderFingerprint(
        id="digitalocean",
        name="DigitalOcean",
        category="hosting",
        cname_patterns=("*.digitaloceanspaces.com",),
        risk_notes=(
            "DigitalOcean Spaces may have public listing enabled.  "
            "Check for exposed Droplet metadata endpoints."
        ),
    ),
    ProviderFingerprint(
        id="heroku",
        name="Heroku",
        category="hosting",
        cname_patterns=("*.herokuapp.com", "*.herokussl.com"),
        risk_notes=(
            "Dangling Heroku CNAMEs are a common subdomain takeover "
            "vector.  Unclaimed *.herokuapp.com names can be registered "
            "by any Heroku user."
        ),
    ),
    ProviderFingerprint(
        id="vercel",
        name="Vercel",
        category="hosting",
        cname_patterns=("*.vercel.app", "cname.vercel-dns.com"),
        risk_notes=(
            "Vercel deployments may expose source maps and preview URLs.  "
            "Dangling CNAME to cname.vercel-dns.com can be claimed by "
            "another Vercel project."
        ),
    ),
    ProviderFingerprint(
        id="netlify",
        name="Netlify",
        category="hosting",
        cname_patterns=("*.netlify.app", "*.netlify.com"),
        risk_notes=(
            "Netlify sites with dangling CNAMEs are vulnerable to "
            "subdomain takeover.  Deploy previews may expose unreleased "
            "features or credentials in environment variables."
        ),
    ),
    ProviderFingerprint(
        id="github_pages",
        name="GitHub Pages",
        category="hosting",
        cname_patterns=("*.github.io",),
        risk_notes=(
            "Custom domain may expose repository via DNS misconfiguration.  "
            "If the GitHub repo is public, source code and commit history "
            "are fully visible.  Dangling CNAME to *.github.io enables "
            "subdomain takeover."
        ),
    ),
    # -----------------------------------------------------------------------
    # Auth / SSO  (4)
    # -----------------------------------------------------------------------
    ProviderFingerprint(
        id="okta",
        name="Okta",
        category="auth_sso",
        cname_patterns=("*.okta.com", "*.oktapreview.com"),
        risk_notes=(
            "Okta tenant discovery at {target}.okta.com may expose the "
            "login page with username enumeration.  Preview environments "
            "(*.oktapreview.com) may have weaker security controls."
        ),
    ),
    ProviderFingerprint(
        id="auth0",
        name="Auth0",
        category="auth_sso",
        cname_patterns=("*.auth0.com",),
        risk_notes=(
            "Auth0 tenant names are guessable.  Misconfigured callback "
            "URLs can enable OAuth redirect attacks.  Management API "
            "exposure is a high-severity risk."
        ),
    ),
    ProviderFingerprint(
        id="onelogin",
        name="OneLogin",
        category="auth_sso",
        cname_patterns=("*.onelogin.com",),
        risk_notes=(
            "OneLogin subdomains expose the SSO login page.  Check for "
            "weak MFA policies and exposed app connectors."
        ),
    ),
    ProviderFingerprint(
        id="azure_ad",
        name="Azure AD",
        category="auth_sso",
        cname_patterns=("*.login.microsoftonline.com",),
        risk_notes=(
            "Azure AD login endpoints can confirm tenant existence and "
            "may allow username enumeration depending on configuration.  "
            "Check for legacy auth protocols (basic auth, IMAP) still "
            "enabled."
        ),
    ),
    # -----------------------------------------------------------------------
    # CI/CD  (3)
    # -----------------------------------------------------------------------
    ProviderFingerprint(
        id="github_actions",
        name="GitHub Actions",
        category="ci_cd",
        txt_patterns=("_github-challenge-",),
        risk_notes=(
            "GitHub challenge TXT records confirm GitHub org ownership.  "
            "Check for exposed workflow files, secrets in logs, and "
            "overpermissive GITHUB_TOKEN scopes."
        ),
    ),
    ProviderFingerprint(
        id="gitlab",
        name="GitLab",
        category="ci_cd",
        cname_patterns=("*.gitlab.io",),
        risk_notes=(
            "GitLab Pages CNAMEs may expose public repositories.  Check "
            "for CI/CD pipeline configuration leaks in public projects."
        ),
    ),
    ProviderFingerprint(
        id="circleci",
        name="CircleCI",
        category="ci_cd",
        txt_patterns=("circleci-domain-verification",),
        risk_notes=(
            "CircleCI domain verification TXT records confirm CI/CD usage.  "
            "Check for exposed build artifacts and environment variable "
            "leaks in public project builds."
        ),
    ),
    # -----------------------------------------------------------------------
    # Monitoring  (5)
    # -----------------------------------------------------------------------
    ProviderFingerprint(
        id="datadog",
        name="Datadog",
        category="monitoring",
        cname_patterns=("*.datadoghq.com",),
        risk_notes=(
            "Datadog CNAMEs may expose custom metrics endpoints or RUM "
            "application IDs.  Check for publicly accessible dashboards "
            "and notebook shares."
        ),
    ),
    ProviderFingerprint(
        id="newrelic",
        name="New Relic",
        category="monitoring",
        cname_patterns=("*.newrelic.com",),
        risk_notes=(
            "New Relic CNAMEs confirm APM/infrastructure monitoring.  "
            "Exposed browser agent configuration may leak license keys."
        ),
    ),
    ProviderFingerprint(
        id="pagerduty",
        name="PagerDuty",
        category="monitoring",
        cname_patterns=("*.pagerduty.com",),
        risk_notes=(
            "PagerDuty subdomains may expose on-call schedules, escalation "
            "policies, and incident response timing — useful for social "
            "engineering."
        ),
    ),
    ProviderFingerprint(
        id="opsgenie",
        name="OpsGenie",
        category="monitoring",
        cname_patterns=("*.opsgenie.com",),
        risk_notes=(
            "OpsGenie integration endpoints may reveal on-call rotation "
            "and alerting thresholds."
        ),
    ),
    ProviderFingerprint(
        id="pingdom",
        name="Pingdom",
        category="monitoring",
        cname_patterns=("*.pingdom.com",),
        risk_notes=(
            "Pingdom public status pages expose monitored endpoints "
            "and uptime history, revealing infrastructure topology."
        ),
    ),
    # -----------------------------------------------------------------------
    # Analytics  (3)
    # -----------------------------------------------------------------------
    ProviderFingerprint(
        id="google_analytics",
        name="Google Analytics",
        category="analytics",
        txt_patterns=("google-site-verification",),
        cname_patterns=("*.google-analytics.com",),
        risk_notes=(
            "Google Analytics tracking IDs (UA-/G-) link properties owned "
            "by the same account — useful for discovering related domains.  "
            "Site-verification TXT records confirm ownership."
        ),
    ),
    ProviderFingerprint(
        id="segment",
        name="Segment",
        category="analytics",
        cname_patterns=("*.segment.io", "*.segment.com"),
        risk_notes=(
            "Segment CDN CNAMEs expose the analytics write key in "
            "client-side JavaScript.  Enumeration of connected "
            "destinations may reveal the data pipeline."
        ),
    ),
    ProviderFingerprint(
        id="mixpanel",
        name="Mixpanel",
        category="analytics",
        cname_patterns=("*.mixpanel.com",),
        risk_notes=(
            "Mixpanel proxy CNAMEs expose the project token.  Custom "
            "events and user properties may leak business logic."
        ),
    ),
    # -----------------------------------------------------------------------
    # CRM  (2)
    # -----------------------------------------------------------------------
    ProviderFingerprint(
        id="salesforce",
        name="Salesforce",
        category="crm",
        cname_patterns=("*.salesforce.com", "*.force.com"),
        mx_patterns=("*.salesforce.com",),
        risk_notes=(
            "Salesforce CNAMEs may expose Communities/Experience Cloud "
            "sites with guest user misconfiguration — a common source of "
            "mass data exposure.  Check for API-enabled guest profiles."
        ),
    ),
    ProviderFingerprint(
        id="hubspot_crm",
        name="HubSpot CRM",
        category="crm",
        cname_patterns=("*.hubspot.com", "*.hs-sites.com"),
        risk_notes=(
            "HubSpot CRM portals may expose contact lists, deal pipelines, "
            "and marketing automation via misconfigured API keys or public "
            "content settings.  See also 'hubspot' (support category)."
        ),
    ),
    # -----------------------------------------------------------------------
    # Security  (3)
    # -----------------------------------------------------------------------
    ProviderFingerprint(
        id="proofpoint",
        name="Proofpoint",
        category="security",
        mx_patterns=("*.pphosted.com",),
        spf_includes=("pphosted.com",),
        risk_notes=(
            "Proofpoint MX records confirm email security gateway usage.  "
            "Check for URL Defense rewrite patterns that may expose "
            "internal mail routing and original link destinations."
        ),
    ),
    ProviderFingerprint(
        id="mimecast",
        name="Mimecast",
        category="security",
        mx_patterns=("*.mimecast.com",),
        spf_includes=("mimecast.com",),
        risk_notes=(
            "Mimecast MX confirms email security gateway.  Targeted "
            "Awareness Training phishing simulations may be detectable.  "
            "Check for exposed administration portal."
        ),
    ),
    ProviderFingerprint(
        id="barracuda",
        name="Barracuda",
        category="security",
        mx_patterns=("*.barracudanetworks.com",),
        risk_notes=(
            "Barracuda MX records indicate email security appliance or "
            "cloud service.  Check for exposed Barracuda Cloud Control "
            "portals and firmware version disclosure."
        ),
    ),
]

# ---------------------------------------------------------------------------
# Build the lookup dict keyed by provider id
# ---------------------------------------------------------------------------

PROVIDER_DATABASE: dict[str, ProviderFingerprint] = {p.id: p for p in _PROVIDERS}

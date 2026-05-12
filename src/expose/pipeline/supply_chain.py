"""Supply chain inference — detect third-party providers from DNS records.

Scans entity properties (CNAME targets, MX records, SPF includes, NS records,
TXT records) for fingerprints matching known cloud/SaaS/infrastructure
providers. For each detection, creates a ``ProviderDetection`` record that
the ``RunExecutor`` uses to:

1. Create or update a ``provider`` entity with ``canonical_identifier`` set
   to the provider's stable ID (e.g., ``cloudflare``, ``google_workspace``).
2. Create a ``depends_on`` relationship from the source entity (the domain
   or subdomain whose DNS records revealed the provider) to the provider
   entity.

The fingerprint database (``PROVIDER_DB``) is a dict-of-dicts keyed by
provider ID. If/when issue #90 produces a separate ``fingerprints.py``
module, the import can be swapped in — the interface is:

    PROVIDER_DB[provider_id] = {
        "name": str,          # display name
        "category": str,      # cdn_waf, email, dns, hosting, ...
        "patterns": {         # evidence_type -> list[glob patterns]
            "cname": ["*.example.com"],
            "mx": ["*.mail.example.com"],
            ...
        },
        "risk_notes": str,
    }

Pattern matching uses ``fnmatch`` semantics (``*`` matches any sequence of
non-dot characters within a label; use ``*.foo.com`` to match
``bar.foo.com``). The match is case-insensitive and strips trailing dots.
"""

from __future__ import annotations

import fnmatch
import logging
from collections.abc import Sequence
from dataclasses import dataclass

from expose.db.models import Entity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Provider fingerprint database
# ---------------------------------------------------------------------------
# The detection ENGINE (pattern matching) is open-source.  The curated
# KNOWLEDGE (which patterns identify which providers) is the commercial
# value.  This file ships five common example providers so the engine
# remains functional standalone.  The full database lives in the
# EXPOSE Threat Context commercial module
# (expose.modules.threat_context.provider_db).

_BUILTIN_PROVIDERS: dict[str, dict] = {
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
}

# ---------------------------------------------------------------------------
# Merge full database from commercial Threat Context module if available
# ---------------------------------------------------------------------------

try:
    from expose.modules.threat_context.provider_db import FULL_PROVIDER_DB

    # Commercial module present — full database takes precedence, with
    # builtin examples as fallback for any provider not in the full DB.
    PROVIDER_DB: dict[str, dict] = {**_BUILTIN_PROVIDERS, **FULL_PROVIDER_DB}
    logger.debug(
        "Loaded full provider database from Threat Context module "
        "(%d providers, %d builtin)",
        len(FULL_PROVIDER_DB),
        len(_BUILTIN_PROVIDERS),
    )
except ImportError:
    # Commercial module not installed — engine works with builtin examples.
    PROVIDER_DB = dict(_BUILTIN_PROVIDERS)
    logger.debug(
        "Threat Context provider_db not available; using %d builtin providers",
        len(_BUILTIN_PROVIDERS),
    )


# ---------------------------------------------------------------------------
# Detection result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderDetection:
    """A single provider fingerprint match against an entity's properties."""

    provider_id: str  # e.g. "cloudflare", "google_workspace"
    provider_name: str  # e.g. "Cloudflare", "Google Workspace"
    category: str  # e.g. "cdn_waf", "email", "support"
    evidence_type: str  # "cname", "mx", "spf", "ns", "txt"
    evidence_value: str  # the actual DNS record value that matched
    source_entity: str  # the entity whose properties contained the match
    risk_notes: str  # security implications


# ---------------------------------------------------------------------------
# Fingerprint matching
# ---------------------------------------------------------------------------


def _normalize(value: str) -> str:
    """Lowercase and strip trailing dots for consistent matching."""
    return value.lower().rstrip(".")


def _matches_pattern(value: str, pattern: str) -> bool:
    """Check if a value matches a glob-style pattern (case-insensitive).

    Uses ``fnmatch`` semantics: ``*`` matches everything within the value.
    Both the value and pattern are normalized before comparison.
    """
    return fnmatch.fnmatch(_normalize(value), _normalize(pattern))


def _extract_evidence_values(
    properties: dict,
    evidence_type: str,
) -> list[str]:
    """Pull candidate values from entity properties for the given evidence type.

    Maps evidence types to the property keys where DNS record data is stored
    by the active_dns, email_auth, and dns_subdomain_enum collectors:

    - ``cname``: ``target`` (active_dns CNAME), ``cname_chain`` (subdomain_enum)
    - ``mx``: ``exchanges[].exchange`` (active_dns MX)
    - ``spf``: ``spf_record``, ``spf_includes`` (email_auth)
    - ``ns``: ``nameservers`` (active_dns NS)
    - ``txt``: ``values`` when record_type is TXT, ``txt_records``
    """
    values: list[str] = []

    if evidence_type == "cname":
        # active_dns CNAME record
        if properties.get("record_type") == "CNAME" and "target" in properties:
            values.append(str(properties["target"]))
        # dns_subdomain_enum CNAME chain
        for cname in properties.get("cname_chain", []):
            values.append(str(cname))
        # Standalone cname_target field (some collectors)
        if "cname_target" in properties:
            values.append(str(properties["cname_target"]))

    elif evidence_type == "mx":
        for mx in properties.get("exchanges", []):
            if isinstance(mx, dict) and "exchange" in mx:
                values.append(str(mx["exchange"]))
            elif isinstance(mx, str):
                values.append(mx)
        # Flat mx_records list (some collectors)
        for mx in properties.get("mx_records", []):
            values.append(str(mx))

    elif evidence_type == "spf":
        # Full SPF record string — scan for include: directives
        spf_record = properties.get("spf_record", "")
        if spf_record:
            for token in str(spf_record).split():
                if token.lower().startswith("include:"):
                    values.append(token)
        # Pre-parsed includes list
        for inc in properties.get("spf_includes", []):
            values.append(f"include:{inc}" if not str(inc).startswith("include:") else str(inc))

    elif evidence_type == "ns":
        for ns in properties.get("nameservers", []):
            values.append(str(ns))
        # Standalone ns_records list
        for ns in properties.get("ns_records", []):
            values.append(str(ns))

    elif evidence_type == "txt":
        # TXT record values
        if properties.get("record_type") == "TXT":
            for v in properties.get("values", []):
                values.append(str(v))
        for v in properties.get("txt_records", []):
            values.append(str(v))

    return values


def detect_providers(
    entities: Sequence[Entity],
    provider_db: dict[str, dict] | None = None,
) -> list[ProviderDetection]:
    """Scan entity properties for provider fingerprints.

    For each entity, checks properties against the fingerprint database for:
    - CNAME targets matching provider patterns
    - MX records matching provider patterns
    - SPF includes matching provider patterns
    - NS records matching provider patterns
    - TXT records matching provider patterns

    Args:
        entities: sequence of Entity ORM objects to scan.
        provider_db: optional override for the fingerprint database
            (defaults to ``PROVIDER_DB``). Useful for testing or when
            issue #90 lands a separate module.

    Returns:
        A deduplicated list of ``ProviderDetection`` objects. Deduplication
        is by ``(provider_id, source_entity)`` — the same provider is only
        reported once per entity even if multiple records match.
    """
    db = provider_db if provider_db is not None else PROVIDER_DB
    detections: list[ProviderDetection] = []
    # Track (provider_id, source_entity_canonical) for deduplication
    seen: set[tuple[str, str]] = set()

    for entity in entities:
        props = entity.properties or {}
        source_canonical = entity.canonical_identifier

        for provider_id, provider_info in db.items():
            patterns_by_type = provider_info.get("patterns", {})

            for evidence_type, pattern_list in patterns_by_type.items():
                candidate_values = _extract_evidence_values(props, evidence_type)

                for value in candidate_values:
                    for pattern in pattern_list:
                        if _matches_pattern(value, pattern):
                            dedup_key = (provider_id, source_canonical)
                            if dedup_key in seen:
                                break  # already detected for this entity
                            seen.add(dedup_key)
                            detections.append(
                                ProviderDetection(
                                    provider_id=provider_id,
                                    provider_name=provider_info["name"],
                                    category=provider_info["category"],
                                    evidence_type=evidence_type,
                                    evidence_value=value,
                                    source_entity=source_canonical,
                                    risk_notes=provider_info.get("risk_notes", ""),
                                )
                            )
                            break  # found a match; move to next provider
                    else:
                        continue
                    break  # matched a value for this evidence_type; move on
                else:
                    continue
                break  # matched for this provider; move to next provider

    return detections


__all__ = [
    "PROVIDER_DB",
    "ProviderDetection",
    "detect_providers",
]

"""Target profiling from discovered entities after Pass 1 reconnaissance.

After the first collection pass discovers entities (domains, IPs, orgs, etc.),
this module analyzes their properties to build a ``TargetProfile`` that
characterizes the target's infrastructure. The profile drives intelligent
collector selection for subsequent passes via ``collector_filter``.

Signal sources inspected:

- **RDAP/WHOIS properties** -- registrar, nameservers, WHOIS privacy.
- **SPF TXT records** -- ``include:`` directives reveal email providers
  (Google Workspace, Microsoft 365, SendGrid, SES, etc.).
- **DNS records** -- MX records reveal email infrastructure; NS records reveal
  hosting (Cloudflare, AWS Route53, etc.); CNAME records reveal CDN usage.
- **CT certificate count** -- high cert counts suggest large subdomain surfaces
  behind CDN; low counts suggest small/self-hosted targets.
- **SIP SRV records** -- presence of ``_sip._tcp`` / ``_sip._udp`` SRV records
  indicates VoIP infrastructure.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# === Entity protocol =========================================================
# We depend on the shape, not the concrete ORM class, so tests can pass
# lightweight mocks without importing the database layer.


@runtime_checkable
class EntityLike(Protocol):
    """Minimal shape required from entity objects."""

    @property
    def entity_type(self) -> str: ...

    @property
    def canonical_identifier(self) -> str: ...

    @property
    def properties(self) -> dict[str, Any]: ...


# === Target profile ===========================================================


@dataclass(frozen=True)
class TargetProfile:
    """Characterization of a target's infrastructure after reconnaissance.

    All fields use a closed vocabulary with an ``"unknown"`` fallback so
    downstream consumers can pattern-match exhaustively.
    """

    infrastructure_type: str  # "cloud_proxied" | "self_hosted" | "hybrid" | "unknown"
    email_provider: str  # "google" | "microsoft" | "self_hosted" | "outsourced" | "unknown"
    cdn_provider: str  # "cloudflare" | "aws_cloudfront" | "akamai" | "fastly" | "none"
    has_voip: bool
    cert_count: int
    org_name_available: bool
    detected_providers: list[str] = field(default_factory=list)


# === Detection helpers ========================================================

# CDN detection patterns for CNAME targets and NS records.
_CDN_CNAME_PATTERNS: dict[str, str] = {
    "cloudflare": r"\.cloudflare\.",
    "aws_cloudfront": r"\.cloudfront\.net",
    "akamai": r"\.akamai\.|\.akamaized\.net|\.edgekey\.net|\.edgesuite\.net",
    "fastly": r"\.fastly\.net|\.fastlylb\.net",
}

# Cloudflare NS pattern (ns are like ada.ns.cloudflare.com).
_CLOUDFLARE_NS_PATTERN = re.compile(r"\.cloudflare\.com$", re.IGNORECASE)

# SPF include patterns that identify email providers/relays.
_SPF_INCLUDE_PATTERNS: dict[str, list[str]] = {
    "google": ["_spf.google.com", "include:_spf.google.com"],
    "microsoft": [
        "spf.protection.outlook.com",
        "include:spf.protection.outlook.com",
    ],
    "sendgrid": ["sendgrid.net"],
    "ses": ["amazonses.com"],
    "mailchimp": ["servers.mcsv.net"],
    "mailgun": ["mailgun.org"],
    "zoho": ["zoho.com", "zoho.eu"],
    "protonmail": ["protonmail.ch"],
    "fastmail": ["fastmail.com"],
    "mimecast": ["mimecast.com"],
    "barracuda": ["barracudanetworks.com"],
}

# MX patterns that identify email hosting providers.
_MX_PROVIDER_PATTERNS: dict[str, str] = {
    "google": r"(aspmx\.l\.google\.com|googlemail\.com|google\.com)",
    "microsoft": r"(mail\.protection\.outlook\.com|outlook\.com)",
    "protonmail": r"protonmail\.ch",
    "zoho": r"zoho\.(com|eu|in)",
    "fastmail": r"fastmail\.(com|fm)",
    "mimecast": r"mimecast\.com",
    "barracuda": r"barracudanetworks\.com",
}

# SIP SRV record indicators.
_SIP_INDICATORS = frozenset({
    "_sip._tcp",
    "_sip._udp",
    "_sips._tcp",
})


def _get_property(entity: EntityLike, *keys: str) -> Any:
    """Return the first non-None value for the given property keys."""
    props = entity.properties
    if not props or not isinstance(props, dict):
        return None
    for key in keys:
        val = props.get(key)
        if val is not None:
            return val
    return None


def _detect_cdn_from_cnames(entities: Sequence[EntityLike]) -> str:
    """Detect CDN provider from CNAME targets in entity properties."""
    for entity in entities:
        # Check cname_chain (from dns_subdomain_enum)
        for key in ("cname_chain", "target"):
            val = _get_property(entity, key)
            if val is None:
                continue
            targets = val if isinstance(val, list) else [val]
            for target in targets:
                if not isinstance(target, str):
                    continue
                for provider, pattern in _CDN_CNAME_PATTERNS.items():
                    if re.search(pattern, target, re.IGNORECASE):
                        return provider
    return "none"


def _detect_cdn_from_ns(entities: Sequence[EntityLike]) -> str:
    """Detect cloud-proxied infrastructure from NS records."""
    for entity in entities:
        nameservers = _get_property(entity, "nameservers")
        if not nameservers or not isinstance(nameservers, list):
            continue
        for ns in nameservers:
            if isinstance(ns, str) and _CLOUDFLARE_NS_PATTERN.search(ns):
                return "cloudflare"
    return "none"


def _detect_email_provider(entities: Sequence[EntityLike]) -> str:
    """Detect email provider from MX records and SPF includes."""
    # Check MX records first (more authoritative than SPF).
    for entity in entities:
        exchanges = _get_property(entity, "exchanges")
        if exchanges and isinstance(exchanges, list):
            for mx in exchanges:
                exchange = mx.get("exchange") if isinstance(mx, dict) else mx
                if not isinstance(exchange, str):
                    continue
                for provider, pattern in _MX_PROVIDER_PATTERNS.items():
                    if re.search(pattern, exchange, re.IGNORECASE):
                        return provider

    # Fall back to SPF include analysis.
    for entity in entities:
        for key in ("spf_record", "spf_value", "value"):
            spf = _get_property(entity, key)
            if not spf or not isinstance(spf, str):
                continue
            if not spf.startswith("v=spf1"):
                continue
            spf_lower = spf.lower()
            for provider, patterns in _SPF_INCLUDE_PATTERNS.items():
                for pat in patterns:
                    if pat.lower() in spf_lower:
                        return provider

    return "unknown"


def _detect_spf_providers(entities: Sequence[EntityLike]) -> list[str]:
    """Extract all third-party providers referenced in SPF records."""
    providers: list[str] = []
    seen: set[str] = set()

    for entity in entities:
        for key in ("spf_record", "spf_value", "value"):
            spf = _get_property(entity, key)
            if not spf or not isinstance(spf, str):
                continue
            if not spf.startswith("v=spf1"):
                continue
            spf_lower = spf.lower()
            for provider, patterns in _SPF_INCLUDE_PATTERNS.items():
                if provider in seen:
                    continue
                for pat in patterns:
                    if pat.lower() in spf_lower:
                        providers.append(provider)
                        seen.add(provider)
                        break
    return providers


def _count_certs(entities: Sequence[EntityLike]) -> int:
    """Count distinct certificate entities or CT log entries."""
    count = 0
    for entity in entities:
        if entity.entity_type in ("certificate", "ct_log_entry"):
            count += 1
        # Also count cert_count from CT collectors stored in properties.
        ct_count = _get_property(entity, "cert_count", "certificate_count")
        if isinstance(ct_count, int) and ct_count > 0:
            count += ct_count
    return count


def _has_voip(entities: Sequence[EntityLike]) -> bool:
    """Check for SIP SRV records in entity properties."""
    for entity in entities:
        # Check for sip_srv presence from sip-discovery collector.
        sip_data = _get_property(entity, "sip_srv", "sip_services")
        if sip_data:
            return True

        # Check for SRV record types that indicate SIP.
        record_type = _get_property(entity, "record_type", "_observation_type")
        if isinstance(record_type, str) and record_type.upper() == "SRV":
            name = _get_property(entity, "name", "canonical_identifier")
            if isinstance(name, str):
                for indicator in _SIP_INDICATORS:
                    if indicator in name.lower():
                        return True

        # Check collector_id for sip-discovery.
        collector_id = _get_property(entity, "_collector_id")
        if collector_id == "sip-discovery":
            return True

    return False


def _has_org_name(entities: Sequence[EntityLike]) -> bool:
    """Check whether any entity has a registrant organization name."""
    for entity in entities:
        for key in ("registrant_org", "_registrant_org", "org_name"):
            val = _get_property(entity, key)
            if val and isinstance(val, str) and val.strip():
                return True
    return False


def _has_whois_privacy(entities: Sequence[EntityLike]) -> bool:
    """Check whether RDAP/WHOIS data shows privacy protection."""
    privacy_indicators = (
        "privacy", "redacted", "whoisguard", "domains by proxy",
        "contact privacy", "withheld", "data protected",
    )
    for entity in entities:
        for key in ("registrant_org", "_registrant_org", "registrant_name",
                     "registrant", "admin_contact"):
            val = _get_property(entity, key)
            if not val or not isinstance(val, str):
                continue
            val_lower = val.lower()
            for indicator in privacy_indicators:
                if indicator in val_lower:
                    return True
    return False


def _determine_infrastructure_type(
    cdn_provider: str,
    entities: Sequence[EntityLike],
) -> str:
    """Classify infrastructure type based on CDN and hosting signals."""
    has_cdn = cdn_provider != "none"

    # Check for self-hosted indicators: private IPs, on-prem nameservers, etc.
    has_self_hosted_signals = False
    for entity in entities:
        # Server headers suggesting self-hosted.
        server = _get_property(entity, "server_header", "server")
        if isinstance(server, str):
            server_lower = server.lower()
            if any(s in server_lower for s in ("apache", "nginx", "iis", "lighttpd")):
                has_self_hosted_signals = True
                break

        # Direct IP serving (no CDN CNAME chain).
        if entity.entity_type in ("ip", "ip_address"):
            has_self_hosted_signals = True

    if has_cdn and has_self_hosted_signals:
        return "hybrid"
    if has_cdn:
        return "cloud_proxied"
    if has_self_hosted_signals:
        return "self_hosted"
    return "unknown"


# === Public API ===============================================================


def build_target_profile(entities: Sequence[EntityLike]) -> TargetProfile:
    """Analyze entity properties to build a target profile.

    Parameters
    ----------
    entities:
        All entities discovered during Pass 1 reconnaissance.

    Returns
    -------
    TargetProfile
        Frozen characterization of the target's infrastructure, email setup,
        CDN usage, VoIP presence, certificate surface, and detected providers.
    """
    if not entities:
        return TargetProfile(
            infrastructure_type="unknown",
            email_provider="unknown",
            cdn_provider="none",
            has_voip=False,
            cert_count=0,
            org_name_available=False,
            detected_providers=[],
        )

    # Detect CDN from CNAME records, falling back to NS records.
    cdn_provider = _detect_cdn_from_cnames(entities)
    if cdn_provider == "none":
        cdn_provider = _detect_cdn_from_ns(entities)

    # Detect email provider.
    email_provider = _detect_email_provider(entities)

    # Detect SPF-referenced third-party providers.
    spf_providers = _detect_spf_providers(entities)

    # Build the detected_providers list.
    detected_providers: list[str] = []
    seen: set[str] = set()
    if cdn_provider != "none" and cdn_provider not in seen:
        detected_providers.append(cdn_provider)
        seen.add(cdn_provider)
    if email_provider not in ("unknown", "self_hosted") and email_provider not in seen:
        # Normalize to the provider naming convention used in rules.
        provider_name = {
            "google": "google_workspace",
            "microsoft": "microsoft_365",
        }.get(email_provider, email_provider)
        detected_providers.append(provider_name)
        seen.add(email_provider)
    for sp in spf_providers:
        if sp not in seen:
            detected_providers.append(sp)
            seen.add(sp)

    # Classify infrastructure type.
    infrastructure_type = _determine_infrastructure_type(cdn_provider, entities)

    # Count certificates.
    cert_count = _count_certs(entities)

    # Check for VoIP.
    voip = _has_voip(entities)

    # Check for org name availability.
    org_available = _has_org_name(entities)

    profile = TargetProfile(
        infrastructure_type=infrastructure_type,
        email_provider=email_provider,
        cdn_provider=cdn_provider,
        has_voip=voip,
        cert_count=cert_count,
        org_name_available=org_available,
        detected_providers=detected_providers,
    )

    logger.info(
        "Target profile built: infra=%s, email=%s, cdn=%s, voip=%s, "
        "certs=%d, org=%s, providers=%s",
        profile.infrastructure_type,
        profile.email_provider,
        profile.cdn_provider,
        profile.has_voip,
        profile.cert_count,
        profile.org_name_available,
        profile.detected_providers,
    )

    return profile


__all__ = [
    "TargetProfile",
    "build_target_profile",
]

"""Tests for target profile building from entity properties.

Covers detection of CDN providers, email providers, VoIP infrastructure,
certificate surfaces, WHOIS privacy, and infrastructure type classification.
All tests use lightweight mock entities (SimpleNamespace) that satisfy the
``EntityLike`` protocol without importing the database layer.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from expose.pipeline.target_profile import TargetProfile, build_target_profile


# === Helpers ==================================================================


def _entity(
    entity_type: str = "domain",
    canonical_identifier: str = "example.com",
    properties: dict | None = None,
) -> SimpleNamespace:
    """Build a lightweight entity-like object for tests."""
    return SimpleNamespace(
        entity_type=entity_type,
        canonical_identifier=canonical_identifier,
        properties=properties or {},
    )


# === Empty / minimal inputs ===================================================


def test_empty_entities_returns_unknown_profile() -> None:
    """No entities produces a fully unknown profile."""
    profile = build_target_profile([])
    assert profile.infrastructure_type == "unknown"
    assert profile.email_provider == "unknown"
    assert profile.cdn_provider == "none"
    assert profile.has_voip is False
    assert profile.cert_count == 0
    assert profile.org_name_available is False
    assert profile.detected_providers == []


def test_single_domain_entity_no_properties() -> None:
    """A bare domain entity with no properties produces a minimal profile."""
    profile = build_target_profile([_entity()])
    assert profile.infrastructure_type == "unknown"
    assert profile.email_provider == "unknown"
    assert profile.cdn_provider == "none"


# === CDN detection ============================================================


def test_cloudflare_cdn_from_cname() -> None:
    """Detect Cloudflare from CNAME target pattern."""
    e = _entity(properties={"target": "example.com.cdn.cloudflare.net"})
    profile = build_target_profile([e])
    assert profile.cdn_provider == "cloudflare"
    assert "cloudflare" in profile.detected_providers


def test_cloudflare_cdn_from_ns() -> None:
    """Detect Cloudflare from NS records."""
    e = _entity(properties={
        "nameservers": ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"],
    })
    profile = build_target_profile([e])
    assert profile.cdn_provider == "cloudflare"


def test_aws_cloudfront_cdn_from_cname() -> None:
    """Detect AWS CloudFront from CNAME target."""
    e = _entity(properties={"target": "d123456.cloudfront.net"})
    profile = build_target_profile([e])
    assert profile.cdn_provider == "aws_cloudfront"


def test_akamai_cdn_from_cname_chain() -> None:
    """Detect Akamai from cname_chain entries."""
    e = _entity(properties={
        "cname_chain": ["e123.dscx.akamaized.net"],
    })
    profile = build_target_profile([e])
    assert profile.cdn_provider == "akamai"


def test_fastly_cdn_from_cname() -> None:
    """Detect Fastly from CNAME target."""
    e = _entity(properties={"target": "prod.global.fastly.net"})
    profile = build_target_profile([e])
    assert profile.cdn_provider == "fastly"


def test_no_cdn_detected() -> None:
    """No CDN patterns matched -> cdn_provider = 'none'."""
    e = _entity(properties={"target": "direct.example.com"})
    profile = build_target_profile([e])
    assert profile.cdn_provider == "none"


# === Email provider detection =================================================


def test_google_email_from_mx() -> None:
    """Detect Google email from MX exchange patterns."""
    e = _entity(properties={
        "exchanges": [{"priority": 10, "exchange": "aspmx.l.google.com"}],
    })
    profile = build_target_profile([e])
    assert profile.email_provider == "google"
    assert "google_workspace" in profile.detected_providers


def test_microsoft_email_from_mx() -> None:
    """Detect Microsoft email from MX exchange patterns."""
    e = _entity(properties={
        "exchanges": [{"priority": 10, "exchange": "example-com.mail.protection.outlook.com"}],
    })
    profile = build_target_profile([e])
    assert profile.email_provider == "microsoft"
    assert "microsoft_365" in profile.detected_providers


def test_google_email_from_spf() -> None:
    """Detect Google email from SPF include directive."""
    e = _entity(properties={
        "spf_record": "v=spf1 include:_spf.google.com ~all",
    })
    profile = build_target_profile([e])
    assert profile.email_provider == "google"


def test_microsoft_email_from_spf() -> None:
    """Detect Microsoft email from SPF include directive."""
    e = _entity(properties={
        "spf_record": "v=spf1 include:spf.protection.outlook.com -all",
    })
    profile = build_target_profile([e])
    assert profile.email_provider == "microsoft"


def test_sendgrid_from_spf_providers() -> None:
    """SendGrid detected as a provider from SPF includes."""
    e = _entity(properties={
        "spf_record": "v=spf1 include:sendgrid.net include:_spf.google.com ~all",
    })
    profile = build_target_profile([e])
    # Google is the primary email provider (MX takes precedence, but falls
    # back to first SPF match).
    assert profile.email_provider == "google"
    # Both google and sendgrid should appear in detected_providers.
    assert "sendgrid" in profile.detected_providers


def test_unknown_email_provider() -> None:
    """No recognized email patterns -> email_provider = 'unknown'."""
    e = _entity(properties={"spf_record": "v=spf1 ip4:10.0.0.0/8 -all"})
    profile = build_target_profile([e])
    assert profile.email_provider == "unknown"


# === VoIP detection ===========================================================


def test_voip_detected_from_sip_srv() -> None:
    """SIP SRV data in properties -> has_voip = True."""
    e = _entity(properties={"sip_srv": [{"target": "sip.example.com"}]})
    profile = build_target_profile([e])
    assert profile.has_voip is True


def test_voip_detected_from_collector_id() -> None:
    """sip-discovery collector_id in properties -> has_voip = True."""
    e = _entity(properties={"_collector_id": "sip-discovery"})
    profile = build_target_profile([e])
    assert profile.has_voip is True


def test_no_voip() -> None:
    """No VoIP indicators -> has_voip = False."""
    e = _entity(properties={"record_type": "A"})
    profile = build_target_profile([e])
    assert profile.has_voip is False


# === Certificate count ========================================================


def test_cert_count_from_entity_type() -> None:
    """Certificate entities count toward cert_count."""
    entities = [
        _entity(entity_type="certificate", canonical_identifier="cert1"),
        _entity(entity_type="certificate", canonical_identifier="cert2"),
    ]
    profile = build_target_profile(entities)
    assert profile.cert_count == 2


def test_cert_count_from_property() -> None:
    """cert_count in properties adds to the total."""
    e = _entity(properties={"cert_count": 42})
    profile = build_target_profile([e])
    assert profile.cert_count == 42


def test_cert_count_combined() -> None:
    """Certificate entities + cert_count properties combine."""
    entities = [
        _entity(entity_type="certificate", canonical_identifier="cert1"),
        _entity(properties={"cert_count": 10}),
    ]
    profile = build_target_profile(entities)
    assert profile.cert_count == 11


def test_zero_cert_count() -> None:
    """No certificate entities or properties -> cert_count = 0."""
    profile = build_target_profile([_entity()])
    assert profile.cert_count == 0


# === Organization name availability ==========================================


def test_org_name_available_from_registrant_org() -> None:
    """registrant_org in properties -> org_name_available = True."""
    e = _entity(properties={"registrant_org": "Acme Corp"})
    profile = build_target_profile([e])
    assert profile.org_name_available is True


def test_org_name_available_from_underscore_registrant_org() -> None:
    """_registrant_org (pipeline-internal key) also detected."""
    e = _entity(properties={"_registrant_org": "Acme Corp"})
    profile = build_target_profile([e])
    assert profile.org_name_available is True


def test_org_name_not_available() -> None:
    """No registrant org -> org_name_available = False."""
    profile = build_target_profile([_entity()])
    assert profile.org_name_available is False


def test_org_name_empty_string_not_available() -> None:
    """Empty or whitespace-only org name is not considered available."""
    e = _entity(properties={"registrant_org": "   "})
    profile = build_target_profile([e])
    assert profile.org_name_available is False


# === Infrastructure type classification =======================================


def test_cloud_proxied_with_cdn() -> None:
    """CDN detected + no self-hosted signals -> cloud_proxied."""
    e = _entity(properties={"target": "d123.cloudfront.net"})
    profile = build_target_profile([e])
    assert profile.infrastructure_type == "cloud_proxied"


def test_self_hosted_ip_entity() -> None:
    """IP entity present + no CDN -> self_hosted."""
    e = _entity(entity_type="ip", canonical_identifier="203.0.113.1")
    profile = build_target_profile([e])
    assert profile.infrastructure_type == "self_hosted"


def test_self_hosted_server_header() -> None:
    """Apache/nginx server header + no CDN -> self_hosted."""
    e = _entity(properties={"server_header": "nginx/1.18.0"})
    profile = build_target_profile([e])
    assert profile.infrastructure_type == "self_hosted"


def test_hybrid_cdn_plus_ip() -> None:
    """CDN detected AND IP/server signals -> hybrid."""
    entities = [
        _entity(properties={"target": "cdn.cloudflare.net"}),
        _entity(entity_type="ip", canonical_identifier="203.0.113.1"),
    ]
    profile = build_target_profile(entities)
    assert profile.infrastructure_type == "hybrid"


def test_unknown_infrastructure_no_signals() -> None:
    """No CDN and no self-hosted signals -> unknown."""
    e = _entity(properties={"record_type": "TXT"})
    profile = build_target_profile([e])
    assert profile.infrastructure_type == "unknown"


# === Profile is frozen ========================================================


def test_target_profile_is_frozen() -> None:
    """TargetProfile is a frozen dataclass -- attributes are immutable."""
    profile = build_target_profile([])
    with pytest.raises(AttributeError):
        profile.infrastructure_type = "hacked"  # type: ignore[misc]


# === Detected providers aggregation ==========================================


def test_detected_providers_includes_cdn_and_email() -> None:
    """detected_providers aggregates CDN and email providers."""
    entities = [
        _entity(properties={"target": "cdn.cloudflare.net"}),
        _entity(properties={
            "exchanges": [{"priority": 10, "exchange": "aspmx.l.google.com"}],
        }),
    ]
    profile = build_target_profile(entities)
    assert "cloudflare" in profile.detected_providers
    assert "google_workspace" in profile.detected_providers


def test_detected_providers_deduplication() -> None:
    """Same provider from multiple signals only appears once."""
    entities = [
        _entity(properties={"target": "cdn.cloudflare.net"}),
        _entity(properties={
            "nameservers": ["ada.ns.cloudflare.com"],
        }),
    ]
    profile = build_target_profile(entities)
    assert profile.detected_providers.count("cloudflare") == 1


# === WHOIS privacy detection ==================================================


def test_whois_privacy_not_detected_with_org_name() -> None:
    """With a real org name, org_name_available is True."""
    e = _entity(properties={"registrant_org": "Acme Corp"})
    profile = build_target_profile([e])
    assert profile.org_name_available is True


def test_whois_privacy_detected_no_org() -> None:
    """With no org name at all, org_name_available is False."""
    e = _entity(properties={})
    profile = build_target_profile([e])
    assert profile.org_name_available is False


# === Edge cases ===============================================================


def test_properties_none_handled() -> None:
    """Entity with None properties does not crash."""
    e = SimpleNamespace(
        entity_type="domain",
        canonical_identifier="example.com",
        properties=None,
    )
    profile = build_target_profile([e])
    assert profile.infrastructure_type == "unknown"


def test_multiple_mx_providers_first_wins() -> None:
    """When multiple MX providers are present, the first match wins."""
    e = _entity(properties={
        "exchanges": [
            {"priority": 5, "exchange": "aspmx.l.google.com"},
            {"priority": 10, "exchange": "mail.protection.outlook.com"},
        ],
    })
    profile = build_target_profile([e])
    assert profile.email_provider == "google"


def test_spf_with_no_v_prefix_ignored() -> None:
    """SPF values not starting with 'v=spf1' are ignored."""
    e = _entity(properties={"spf_record": "not-an-spf-record"})
    profile = build_target_profile([e])
    assert profile.email_provider == "unknown"

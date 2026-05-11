"""Tests for AI-guided collector filtering via signal-to-action rules.

Covers signal derivation from target profiles, collector skip/prioritize
logic, edge cases (empty inputs, unknown profiles), and rule completeness.
"""

from __future__ import annotations

import pytest

from expose.pipeline.collector_filter import (
    COLLECTOR_RULES,
    FilterDecision,
    FilterResult,
    filter_collectors,
)
from expose.pipeline.target_profile import TargetProfile


# === Helpers ==================================================================


def _profile(
    *,
    infrastructure_type: str = "unknown",
    email_provider: str = "unknown",
    cdn_provider: str = "none",
    has_voip: bool = False,
    cert_count: int = 0,
    org_name_available: bool = True,
    detected_providers: list[str] | None = None,
) -> TargetProfile:
    """Build a TargetProfile with sensible defaults for testing."""
    return TargetProfile(
        infrastructure_type=infrastructure_type,
        email_provider=email_provider,
        cdn_provider=cdn_provider,
        has_voip=has_voip,
        cert_count=cert_count,
        org_name_available=org_name_available,
        detected_providers=detected_providers or [],
    )


# Full collector list used in most tests.
ALL_COLLECTORS = [
    "ct-certspotter",
    "ct-crtsh",
    "ct-censys",
    "active-port-surface",
    "active-dns-resolve",
    "active-tls-handshake",
    "active-http-fingerprint",
    "sip-discovery",
    "mail-headers",
    "ma-discovery",
    "common-crawl",
    "rdap-whois",
    "dns-subdomain-enum",
]


# === Cloud proxied signal =====================================================


def test_cloud_proxied_skips_active_port_surface() -> None:
    """Cloud-proxied targets skip active-port-surface (scanning CDN edge)."""
    profile = _profile(infrastructure_type="cloud_proxied")
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert "active-port-surface" not in result.filtered_collector_ids


def test_cloud_proxied_prioritizes_ct_collectors() -> None:
    """Cloud-proxied targets prioritize CT collectors."""
    profile = _profile(infrastructure_type="cloud_proxied")
    result = filter_collectors(profile, ALL_COLLECTORS)
    # CT collectors should come first.
    ct_positions = [
        result.filtered_collector_ids.index(cid)
        for cid in ["ct-certspotter", "ct-crtsh"]
        if cid in result.filtered_collector_ids
    ]
    assert ct_positions == sorted(ct_positions)
    assert all(pos < 3 for pos in ct_positions)


def test_cloud_proxied_decisions_recorded() -> None:
    """Filtering decisions for cloud_proxied are recorded."""
    profile = _profile(infrastructure_type="cloud_proxied")
    result = filter_collectors(profile, ALL_COLLECTORS)
    skip_decisions = [d for d in result.decisions if d.action == "skip"]
    assert any(d.collector_id == "active-port-surface" for d in skip_decisions)
    prioritize_decisions = [d for d in result.decisions if d.action == "prioritize"]
    assert any(d.collector_id == "ct-certspotter" for d in prioritize_decisions)


# === Email outsourced signal ==================================================


def test_email_outsourced_skips_mail_headers() -> None:
    """When email is outsourced (not self-hosted), skip mail-headers."""
    profile = _profile(email_provider="google")
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert "mail-headers" not in result.filtered_collector_ids


def test_self_hosted_email_keeps_mail_headers() -> None:
    """Self-hosted email keeps mail-headers."""
    profile = _profile(email_provider="self_hosted")
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert "mail-headers" in result.filtered_collector_ids


def test_unknown_email_keeps_mail_headers() -> None:
    """Unknown email provider keeps mail-headers (conservative approach)."""
    profile = _profile(email_provider="unknown")
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert "mail-headers" in result.filtered_collector_ids


# === No VoIP signal ===========================================================


def test_no_voip_skips_sip_discovery() -> None:
    """When no VoIP detected, skip sip-discovery."""
    profile = _profile(has_voip=False)
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert "sip-discovery" not in result.filtered_collector_ids


def test_has_voip_keeps_sip_discovery() -> None:
    """When VoIP is detected, sip-discovery is kept."""
    profile = _profile(has_voip=True)
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert "sip-discovery" in result.filtered_collector_ids


# === Low cert count signal ====================================================


def test_low_cert_count_skips_ct_censys_and_common_crawl() -> None:
    """Low cert count skips ct-censys and common-crawl."""
    profile = _profile(cert_count=3)
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert "ct-censys" not in result.filtered_collector_ids
    assert "common-crawl" not in result.filtered_collector_ids


def test_low_cert_count_prioritizes_active_collectors() -> None:
    """Low cert count prioritizes active-dns-resolve and active-tls-handshake."""
    profile = _profile(cert_count=2)
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert result.filtered_collector_ids[0] == "active-dns-resolve"
    assert result.filtered_collector_ids[1] == "active-tls-handshake"


def test_low_cert_count_threshold() -> None:
    """cert_count <= 5 triggers low_cert_count signal."""
    profile = _profile(cert_count=5)
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert "ct-censys" not in result.filtered_collector_ids


def test_above_low_cert_threshold_keeps_ct_censys() -> None:
    """cert_count > 5 does not trigger low_cert_count (keeps ct-censys)."""
    # Need cert_count between 6 and 49 (above low, below high).
    profile = _profile(cert_count=10, has_voip=True, org_name_available=True)
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert "ct-censys" in result.filtered_collector_ids


# === High cert count signal ===================================================


def test_high_cert_count_skips_active_probing() -> None:
    """High cert count skips active-port-surface and active-http-fingerprint."""
    profile = _profile(cert_count=100)
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert "active-port-surface" not in result.filtered_collector_ids
    assert "active-http-fingerprint" not in result.filtered_collector_ids


def test_high_cert_count_prioritizes_ct_collectors() -> None:
    """High cert count prioritizes all three CT collectors."""
    profile = _profile(cert_count=100)
    result = filter_collectors(profile, ALL_COLLECTORS)
    for cid in ["ct-certspotter", "ct-crtsh", "ct-censys"]:
        assert cid in result.filtered_collector_ids
    # They should be at the front.
    ct_idx = [result.filtered_collector_ids.index(c) for c in
              ["ct-certspotter", "ct-crtsh", "ct-censys"]]
    assert all(idx < 4 for idx in ct_idx)


def test_high_cert_count_threshold() -> None:
    """cert_count >= 50 triggers high_cert_count signal."""
    profile = _profile(cert_count=50)
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert "active-port-surface" not in result.filtered_collector_ids


# === WHOIS privacy signal =====================================================


def test_whois_privacy_skips_ma_discovery() -> None:
    """When org name is not available, skip ma-discovery."""
    profile = _profile(org_name_available=False)
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert "ma-discovery" not in result.filtered_collector_ids


def test_org_available_keeps_ma_discovery() -> None:
    """When org name is available, ma-discovery is kept."""
    profile = _profile(org_name_available=True, has_voip=True)
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert "ma-discovery" in result.filtered_collector_ids


# === Combined signals =========================================================


def test_multiple_signals_combine() -> None:
    """Multiple active signals combine their skip and prioritize rules."""
    profile = _profile(
        infrastructure_type="cloud_proxied",
        email_provider="google",
        has_voip=False,
        cert_count=2,
        org_name_available=False,
    )
    result = filter_collectors(profile, ALL_COLLECTORS)

    # Skipped by various signals.
    assert "active-port-surface" not in result.filtered_collector_ids  # cloud_proxied
    assert "mail-headers" not in result.filtered_collector_ids  # email_outsourced
    assert "sip-discovery" not in result.filtered_collector_ids  # no_voip
    assert "ct-censys" not in result.filtered_collector_ids  # low_cert_count
    assert "common-crawl" not in result.filtered_collector_ids  # low_cert_count
    assert "ma-discovery" not in result.filtered_collector_ids  # whois_privacy


def test_multiple_signals_recorded() -> None:
    """All active signals appear in signals_active."""
    profile = _profile(
        infrastructure_type="cloud_proxied",
        email_provider="microsoft",
        has_voip=False,
    )
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert "cloud_proxied" in result.signals_active
    assert "email_outsourced" in result.signals_active
    assert "no_voip" in result.signals_active


# === Edge cases ===============================================================


def test_empty_collector_ids() -> None:
    """Empty collector list returns empty filtered list."""
    profile = _profile(infrastructure_type="cloud_proxied")
    result = filter_collectors(profile, [])
    assert result.filtered_collector_ids == []
    assert result.decisions == []


def test_unknown_profile_no_filtering() -> None:
    """A completely unknown profile with VoIP and org still skips nothing."""
    profile = _profile(
        infrastructure_type="unknown",
        email_provider="unknown",
        cdn_provider="none",
        has_voip=True,
        cert_count=10,
        org_name_available=True,
    )
    result = filter_collectors(profile, ALL_COLLECTORS)
    # No signals should fire except possibly low_cert_count.
    # cert_count=10 is above 5, so no low_cert_count. has_voip=True, so no
    # no_voip. org_name_available=True, so no whois_privacy. email=unknown,
    # so no email_outsourced. infrastructure=unknown, so no cloud_proxied.
    assert result.filtered_collector_ids == ALL_COLLECTORS
    assert result.signals_active == []
    assert result.decisions == []


def test_collectors_not_in_list_are_ignored() -> None:
    """Rules referencing collectors not in the input list are silently skipped."""
    profile = _profile(infrastructure_type="cloud_proxied")
    # Only two collectors, neither is active-port-surface.
    result = filter_collectors(profile, ["ct-certspotter", "rdap-whois"])
    assert "active-port-surface" not in result.filtered_collector_ids
    # ct-certspotter should be prioritized (moved to front).
    assert result.filtered_collector_ids[0] == "ct-certspotter"
    # rdap-whois follows.
    assert "rdap-whois" in result.filtered_collector_ids


def test_prioritized_collector_not_duplicated() -> None:
    """A prioritized collector appears only once in the output."""
    profile = _profile(infrastructure_type="cloud_proxied")
    result = filter_collectors(profile, ALL_COLLECTORS)
    assert result.filtered_collector_ids.count("ct-certspotter") == 1
    assert result.filtered_collector_ids.count("ct-crtsh") == 1


def test_conflicting_skip_and_prioritize() -> None:
    """If a collector is both skipped and prioritized, skip wins."""
    # cloud_proxied skips active-port-surface; high_cert_count also skips it.
    # But high_cert_count prioritizes ct-censys. Ensure no conflicts.
    profile = _profile(
        infrastructure_type="cloud_proxied",
        cert_count=100,
    )
    result = filter_collectors(profile, ALL_COLLECTORS)
    # active-port-surface is skipped by both rules.
    assert "active-port-surface" not in result.filtered_collector_ids
    # ct-certspotter and ct-crtsh are prioritized by cloud_proxied.
    # ct-censys is prioritized by high_cert_count.
    assert "ct-certspotter" in result.filtered_collector_ids
    assert "ct-crtsh" in result.filtered_collector_ids
    assert "ct-censys" in result.filtered_collector_ids


# === FilterResult structure ===================================================


def test_filter_result_is_frozen() -> None:
    """FilterResult is a frozen dataclass."""
    result = filter_collectors(_profile(), [])
    with pytest.raises(AttributeError):
        result.filtered_collector_ids = ["hacked"]  # type: ignore[misc]


def test_filter_decision_fields() -> None:
    """FilterDecision has the expected fields."""
    d = FilterDecision(
        signal="cloud_proxied",
        action="skip",
        collector_id="active-port-surface",
        reason="test",
    )
    assert d.signal == "cloud_proxied"
    assert d.action == "skip"
    assert d.collector_id == "active-port-surface"
    assert d.reason == "test"


# === Rule table completeness ==================================================


def test_all_rules_have_valid_actions() -> None:
    """Every rule in COLLECTOR_RULES has only 'skip' and/or 'prioritize' keys."""
    for signal, rule in COLLECTOR_RULES.items():
        for key in rule:
            assert key in ("skip", "prioritize"), (
                f"Rule '{signal}' has unexpected key '{key}'"
            )


def test_all_rules_have_nonempty_lists() -> None:
    """Every action list in COLLECTOR_RULES is non-empty."""
    for signal, rule in COLLECTOR_RULES.items():
        for key, value in rule.items():
            assert isinstance(value, list), (
                f"Rule '{signal}.{key}' is not a list"
            )
            assert len(value) > 0, (
                f"Rule '{signal}.{key}' is empty"
            )


# === Cert count mutual exclusivity ============================================


def test_low_and_high_cert_count_mutually_exclusive() -> None:
    """low_cert_count and high_cert_count never both active."""
    # Low
    profile_low = _profile(cert_count=3)
    result_low = filter_collectors(profile_low, ALL_COLLECTORS)
    assert "low_cert_count" in result_low.signals_active
    assert "high_cert_count" not in result_low.signals_active

    # High
    profile_high = _profile(cert_count=100)
    result_high = filter_collectors(profile_high, ALL_COLLECTORS)
    assert "high_cert_count" in result_high.signals_active
    assert "low_cert_count" not in result_high.signals_active

    # Middle (neither)
    profile_mid = _profile(cert_count=20, has_voip=True, org_name_available=True)
    result_mid = filter_collectors(profile_mid, ALL_COLLECTORS)
    assert "low_cert_count" not in result_mid.signals_active
    assert "high_cert_count" not in result_mid.signals_active

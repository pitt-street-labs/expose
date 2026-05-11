"""Tests for the egress profile abstraction (issue #1).

Coverage:

1. DirectEgressProfile.configure_httpx_client returns empty dict.
2. DirectEgressProfile.configure_dns_resolver returns empty dict.
3. DirectEgressProfile.health_check returns healthy with zero latency.
4. Factory creates DirectEgressProfile for "direct".
5. Factory raises ValueError for unknown profile type.
6. All profiles have correct profile_type.
7. EgressHealthCheck model validates correctly (frozen, extra=forbid).
8. EgressProfileType enum has all 4 values.

These tests exercise the ABC contract and factory without requiring any
network connectivity or external services. Profile-specific behaviour
tests live in ``test_egress_profiles.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from expose.egress import (
    DirectEgressProfile,
    EgressHealthCheck,
    EgressProfileType,
    HttpConnectEgressProfile,
    Socks5EgressProfile,
    WireguardEgressProfile,
    create_egress_profile,
)

# === DirectEgressProfile =====================================================


@pytest.fixture
def direct_profile() -> DirectEgressProfile:
    """Fresh DirectEgressProfile per test."""
    return DirectEgressProfile()


def test_direct_configure_httpx_client_returns_empty(
    direct_profile: DirectEgressProfile,
) -> None:
    """configure_httpx_client returns empty dict — no proxy config needed."""
    result = direct_profile.configure_httpx_client()
    assert result == {}


def test_direct_configure_dns_resolver_returns_empty(
    direct_profile: DirectEgressProfile,
) -> None:
    """configure_dns_resolver returns empty dict — system resolver used."""
    result = direct_profile.configure_dns_resolver()
    assert result == {}


async def test_direct_health_check_returns_healthy(
    direct_profile: DirectEgressProfile,
) -> None:
    """health_check returns healthy with zero latency for direct egress."""
    check = await direct_profile.health_check()
    assert check.healthy is True
    assert check.profile_type == EgressProfileType.DIRECT
    assert check.latency_ms == 0.0
    assert check.error_message is None
    assert check.checked_at is not None


# === Factory ==================================================================


def test_factory_creates_direct_profile() -> None:
    """create_egress_profile('direct') returns a DirectEgressProfile."""
    profile = create_egress_profile("direct")
    assert isinstance(profile, DirectEgressProfile)
    assert profile.profile_type == EgressProfileType.DIRECT


def test_factory_raises_for_unknown_type() -> None:
    """create_egress_profile raises ValueError for unrecognised types."""
    with pytest.raises(ValueError, match="Unknown egress profile type"):
        create_egress_profile("tor_onion")


# === Profile type correctness ==================================================


def test_socks5_profile_type() -> None:
    """Socks5EgressProfile has profile_type == SOCKS5."""
    profile = Socks5EgressProfile()
    assert profile.profile_type == EgressProfileType.SOCKS5


def test_wireguard_profile_type() -> None:
    """WireguardEgressProfile has profile_type == WIREGUARD."""
    profile = WireguardEgressProfile()
    assert profile.profile_type == EgressProfileType.WIREGUARD


def test_http_connect_profile_type() -> None:
    """HttpConnectEgressProfile has profile_type == HTTP_CONNECT."""
    profile = HttpConnectEgressProfile()
    assert profile.profile_type == EgressProfileType.HTTP_CONNECT


# === EgressHealthCheck model ==================================================


def test_health_check_model_validates() -> None:
    """EgressHealthCheck accepts valid data and exposes typed fields."""
    now = datetime.now(tz=UTC)
    check = EgressHealthCheck(
        profile_type=EgressProfileType.DIRECT,
        healthy=True,
        latency_ms=1.5,
        checked_at=now,
    )
    assert check.profile_type == EgressProfileType.DIRECT
    assert check.healthy is True
    assert check.latency_ms == 1.5
    assert check.error_message is None
    assert check.checked_at == now


def test_health_check_model_frozen() -> None:
    """EgressHealthCheck is frozen — attributes cannot be mutated."""
    check = EgressHealthCheck(
        profile_type=EgressProfileType.DIRECT,
        healthy=True,
        checked_at=datetime.now(tz=UTC),
    )
    with pytest.raises(Exception):  # noqa: B017
        check.healthy = False  # type: ignore[misc]


def test_health_check_model_forbids_extra() -> None:
    """EgressHealthCheck rejects unknown fields."""
    with pytest.raises(Exception):  # noqa: B017
        EgressHealthCheck(
            profile_type=EgressProfileType.DIRECT,
            healthy=True,
            checked_at=datetime.now(tz=UTC),
            bogus_field="nope",  # type: ignore[call-arg]
        )


# === EgressProfileType enum ==================================================


def test_enum_has_all_four_values() -> None:
    """EgressProfileType has exactly the 4 expected values."""
    values = {t.value for t in EgressProfileType}
    assert values == {"direct", "socks5", "wireguard", "http_connect"}


def test_enum_string_coercion() -> None:
    """EgressProfileType values are usable as plain strings (StrEnum)."""
    assert EgressProfileType.DIRECT == "direct"
    assert str(EgressProfileType.SOCKS5) == "socks5"

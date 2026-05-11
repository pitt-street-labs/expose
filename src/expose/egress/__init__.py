"""Egress profile abstraction for active collector traffic routing (issue #1).

Active (Tier-3) collectors — ``active-dns-resolve`` and
``active-http-fingerprint`` — make outbound connections that could attribute
scanning activity to the operator's infrastructure. The egress profile
abstraction lets deployments route that traffic through controlled exit points
(SOCKS5, WireGuard, HTTP CONNECT) so the operator's IP is not exposed to
targets.

Sub-modules:

- ``base`` — :class:`EgressProfile` ABC, :class:`EgressProfileType` enum,
  :class:`EgressHealthCheck` model.
- ``direct`` — :class:`DirectEgressProfile` (pass-through, default).
- ``socks5`` — :class:`Socks5EgressProfile`.
- ``tor`` — :class:`TorEgressProfile`.
- ``wireguard`` — :class:`WireguardEgressProfile`.
- ``http_connect`` — :class:`HttpConnectEgressProfile`.

Use :func:`create_egress_profile` to instantiate a profile from configuration::

    from expose.egress import create_egress_profile

    profile = create_egress_profile("direct")
    httpx_kwargs = profile.configure_httpx_client()
"""

from __future__ import annotations

from typing import Any

from expose.egress.base import EgressHealthCheck, EgressProfile, EgressProfileType
from expose.egress.direct import DirectEgressProfile
from expose.egress.http_connect import HttpConnectEgressProfile
from expose.egress.socks5 import Socks5EgressProfile
from expose.egress.tor import TorEgressProfile
from expose.egress.wireguard import WireguardEgressProfile

_PROFILE_REGISTRY: dict[EgressProfileType, type[EgressProfile]] = {
    EgressProfileType.DIRECT: DirectEgressProfile,
    EgressProfileType.SOCKS5: Socks5EgressProfile,
    EgressProfileType.TOR: TorEgressProfile,
    EgressProfileType.WIREGUARD: WireguardEgressProfile,
    EgressProfileType.HTTP_CONNECT: HttpConnectEgressProfile,
}


def create_egress_profile(profile_type: str, **config: Any) -> EgressProfile:
    """Factory for egress profiles from configuration.

    Args:
        profile_type: One of the :class:`EgressProfileType` string values
            (``"direct"``, ``"socks5"``, ``"tor"``, ``"wireguard"``,
            ``"http_connect"``).
        **config: Profile-specific configuration kwargs passed to the
            constructor. Currently unused by :class:`DirectEgressProfile`;
            future profiles (SOCKS5 etc.) will accept host/port/auth here.

    Returns:
        An :class:`EgressProfile` instance ready for use by collectors.

    Raises:
        ValueError: If ``profile_type`` is not a recognised profile type.
    """
    try:
        egress_type = EgressProfileType(profile_type)
    except ValueError:
        valid = ", ".join(sorted(t.value for t in EgressProfileType))
        msg = f"Unknown egress profile type {profile_type!r}; valid types: {valid}"
        raise ValueError(msg) from None

    profile_cls = _PROFILE_REGISTRY[egress_type]
    return profile_cls(**config)


__all__ = [
    "DirectEgressProfile",
    "EgressHealthCheck",
    "EgressProfile",
    "EgressProfileType",
    "HttpConnectEgressProfile",
    "Socks5EgressProfile",
    "TorEgressProfile",
    "WireguardEgressProfile",
    "create_egress_profile",
]

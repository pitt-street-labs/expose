"""Tests for SOCKS5, WireGuard, and HTTP CONNECT egress profiles.

Coverage:

 1. SOCKS5 configure_httpx_client returns proxy URL.
 2. SOCKS5 dns_through_proxy rewrites socks5:// to socks5h://.
 3. SOCKS5 dns_through_proxy=False preserves original URL.
 4. SOCKS5 configure_dns_resolver returns empty nameservers when dns_through_proxy=True.
 5. SOCKS5 configure_dns_resolver returns empty dict when dns_through_proxy=False.
 6. SOCKS5 health_check returns healthy=False when proxy unreachable.
 7. HTTP CONNECT configure_httpx_client returns proxy URL.
 8. HTTP CONNECT configure_dns_resolver returns empty dict.
 9. HTTP CONNECT health_check returns healthy=False when proxy unreachable.
10. WireGuard configure_httpx_client with source_address returns transport.
11. WireGuard configure_httpx_client without source_address returns empty dict.
12. WireGuard configure_dns_resolver returns empty dict.
13. WireGuard health_check returns healthy=False when interface missing.
14. WireGuard health_check returns healthy=True when interface is up.
15. WireGuard health_check returns healthy=False when interface is down.
16. WireGuard _check_interface unit tests (sync helper).
17. All profiles have correct profile_type.
18. Direct profile returns empty dicts and healthy=True (cross-check).
19. Factory creates all profile types.

These tests do not require running proxies or WireGuard interfaces. Health
checks against unreachable endpoints verify the error-reporting path. The
WireGuard interface tests mock the ``_check_interface`` helper.
"""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from expose.egress import (
    DirectEgressProfile,
    EgressProfileType,
    HttpConnectEgressProfile,
    Socks5EgressProfile,
    WireguardEgressProfile,
    create_egress_profile,
)
from expose.egress.wireguard import _check_interface

# === SOCKS5 ===================================================================


class TestSocks5EgressProfile:
    """Tests for Socks5EgressProfile."""

    @patch("expose.egress.socks5._socksio_available", return_value=True)
    def test_configure_httpx_client_returns_proxy_url(self, _mock: object) -> None:
        """configure_httpx_client returns the proxy URL in a 'proxy' key."""
        profile = Socks5EgressProfile(proxy_url="socks5://10.0.0.1:9050")
        result = profile.configure_httpx_client()
        assert "proxy" in result

    @patch("expose.egress.socks5._socksio_available", return_value=True)
    def test_dns_through_proxy_rewrites_to_socks5h(self, _mock: object) -> None:
        """dns_through_proxy=True rewrites socks5:// to socks5h://."""
        profile = Socks5EgressProfile(
            proxy_url="socks5://10.0.0.1:9050", dns_through_proxy=True
        )
        result = profile.configure_httpx_client()
        assert result["proxy"] == "socks5h://10.0.0.1:9050"

    @patch("expose.egress.socks5._socksio_available", return_value=True)
    def test_dns_through_proxy_false_preserves_url(self, _mock: object) -> None:
        """dns_through_proxy=False keeps the original socks5:// URL."""
        profile = Socks5EgressProfile(
            proxy_url="socks5://10.0.0.1:9050", dns_through_proxy=False
        )
        result = profile.configure_httpx_client()
        assert result["proxy"] == "socks5://10.0.0.1:9050"

    @patch("expose.egress.socks5._socksio_available", return_value=True)
    def test_socks5h_url_not_double_rewritten(self, _mock: object) -> None:
        """A socks5h:// URL is not rewritten even with dns_through_proxy=True."""
        profile = Socks5EgressProfile(
            proxy_url="socks5h://10.0.0.1:9050", dns_through_proxy=True
        )
        result = profile.configure_httpx_client()
        assert result["proxy"] == "socks5h://10.0.0.1:9050"

    def test_configure_httpx_client_raises_without_socksio(self) -> None:
        """configure_httpx_client raises RuntimeError when socksio is missing."""
        profile = Socks5EgressProfile(proxy_url="socks5://10.0.0.1:9050")
        with patch("expose.egress.socks5._socksio_available", return_value=False):
            with pytest.raises(RuntimeError, match="socksio"):
                profile.configure_httpx_client()

    def test_dns_resolver_returns_empty_nameservers_when_proxied(self) -> None:
        """dns_through_proxy=True returns empty nameservers list."""
        profile = Socks5EgressProfile(dns_through_proxy=True)
        result = profile.configure_dns_resolver()
        assert result == {"nameservers": []}

    def test_dns_resolver_returns_empty_dict_when_not_proxied(self) -> None:
        """dns_through_proxy=False returns empty dict (use system resolver)."""
        profile = Socks5EgressProfile(dns_through_proxy=False)
        result = profile.configure_dns_resolver()
        assert result == {}

    async def test_health_check_unreachable_returns_unhealthy(self) -> None:
        """health_check returns healthy=False when proxy port is closed."""
        # Port 19 (chargen) is almost certainly not listening
        profile = Socks5EgressProfile(proxy_url="socks5://127.0.0.1:19")
        check = await profile.health_check()
        assert check.healthy is False
        assert check.profile_type == EgressProfileType.SOCKS5
        assert check.error_message is not None
        assert check.latency_ms is not None
        assert check.latency_ms >= 0

    def test_profile_type_is_socks5(self) -> None:
        """Profile type is SOCKS5."""
        profile = Socks5EgressProfile()
        assert profile.profile_type == EgressProfileType.SOCKS5


# === HTTP CONNECT =============================================================


class TestHttpConnectEgressProfile:
    """Tests for HttpConnectEgressProfile."""

    def test_configure_httpx_client_returns_proxy_url(self) -> None:
        """configure_httpx_client returns the proxy URL."""
        profile = HttpConnectEgressProfile(proxy_url="http://squid.internal:3128")
        result = profile.configure_httpx_client()
        assert result == {"proxy": "http://squid.internal:3128"}

    def test_configure_dns_resolver_returns_empty(self) -> None:
        """configure_dns_resolver returns empty dict (proxy handles DNS)."""
        profile = HttpConnectEgressProfile()
        result = profile.configure_dns_resolver()
        assert result == {}

    async def test_health_check_unreachable_returns_unhealthy(self) -> None:
        """health_check returns healthy=False when proxy port is closed."""
        profile = HttpConnectEgressProfile(proxy_url="http://127.0.0.1:19")
        check = await profile.health_check()
        assert check.healthy is False
        assert check.profile_type == EgressProfileType.HTTP_CONNECT
        assert check.error_message is not None
        assert check.latency_ms is not None
        assert check.latency_ms >= 0

    def test_profile_type_is_http_connect(self) -> None:
        """Profile type is HTTP_CONNECT."""
        profile = HttpConnectEgressProfile()
        assert profile.profile_type == EgressProfileType.HTTP_CONNECT


# === WireGuard ================================================================


class TestWireguardEgressProfile:
    """Tests for WireguardEgressProfile."""

    def test_configure_httpx_with_source_address(self) -> None:
        """configure_httpx_client with source_address returns a transport."""
        profile = WireguardEgressProfile(
            interface_name="wg0", source_address="10.0.0.2"
        )
        result = profile.configure_httpx_client()
        assert "transport" in result
        assert isinstance(result["transport"], httpx.AsyncHTTPTransport)

    def test_configure_httpx_without_source_address(self) -> None:
        """configure_httpx_client without source_address returns empty dict."""
        profile = WireguardEgressProfile(interface_name="wg0")
        result = profile.configure_httpx_client()
        assert result == {}

    def test_configure_dns_resolver_returns_empty(self) -> None:
        """configure_dns_resolver returns empty dict (OS routing handles DNS)."""
        profile = WireguardEgressProfile()
        result = profile.configure_dns_resolver()
        assert result == {}

    async def test_health_check_missing_interface(self) -> None:
        """health_check returns healthy=False when interface doesn't exist."""
        profile = WireguardEgressProfile(interface_name="wg_nonexistent_test_99")
        check = await profile.health_check()
        assert check.healthy is False
        assert check.profile_type == EgressProfileType.WIREGUARD
        assert "wg_nonexistent_test_99" in (check.error_message or "")
        assert check.latency_ms is not None
        assert check.latency_ms >= 0

    async def test_health_check_interface_up(self) -> None:
        """health_check returns healthy=True when interface is up (mocked)."""
        profile = WireguardEgressProfile(interface_name="wg_test")
        with patch(
            "expose.egress.wireguard._check_interface",
            return_value=(True, None),
        ):
            check = await profile.health_check()

        assert check.healthy is True
        assert check.profile_type == EgressProfileType.WIREGUARD
        assert check.error_message is None

    async def test_health_check_interface_down(self) -> None:
        """health_check returns healthy=False when interface is down (mocked)."""
        profile = WireguardEgressProfile(interface_name="wg_down")
        with patch(
            "expose.egress.wireguard._check_interface",
            return_value=(False, "Interface wg_down is down"),
        ):
            check = await profile.health_check()

        assert check.healthy is False
        assert "down" in (check.error_message or "").lower()

    def test_profile_type_is_wireguard(self) -> None:
        """Profile type is WIREGUARD."""
        profile = WireguardEgressProfile()
        assert profile.profile_type == EgressProfileType.WIREGUARD


class TestCheckInterfaceHelper:
    """Unit tests for the _check_interface sync helper."""

    def test_missing_interface(self, tmp_path: pytest.TempPathFactory) -> None:
        """Returns (False, error) when the sysfs dir doesn't exist."""
        with patch(
            "expose.egress.wireguard.Path",
            return_value=tmp_path / "no_such_iface",  # type: ignore[operator]
        ):
            healthy, error = _check_interface("no_such_iface")
        assert healthy is False
        assert "does not exist" in (error or "")

    def test_interface_up_unknown(self, tmp_path: pytest.TempPathFactory) -> None:
        """Returns (True, None) when operstate is 'unknown' (normal for WG)."""
        iface_dir = tmp_path / "wg_up"  # type: ignore[operator]
        iface_dir.mkdir()
        (iface_dir / "operstate").write_text("unknown\n")

        with patch("expose.egress.wireguard.Path", return_value=iface_dir):
            healthy, error = _check_interface("wg_up")
        assert healthy is True
        assert error is None

    def test_interface_down(self, tmp_path: pytest.TempPathFactory) -> None:
        """Returns (False, error) when operstate is 'down'."""
        iface_dir = tmp_path / "wg_down"  # type: ignore[operator]
        iface_dir.mkdir()
        (iface_dir / "operstate").write_text("down\n")

        with patch("expose.egress.wireguard.Path", return_value=iface_dir):
            healthy, error = _check_interface("wg_down")
        assert healthy is False
        assert "down" in (error or "").lower()

    def test_no_operstate_file(self, tmp_path: pytest.TempPathFactory) -> None:
        """Returns (True, None) when operstate file is missing (defaults to 'unknown')."""
        iface_dir = tmp_path / "wg_noop"  # type: ignore[operator]
        iface_dir.mkdir()
        # No operstate file — should default to "unknown" (healthy)

        with patch("expose.egress.wireguard.Path", return_value=iface_dir):
            healthy, error = _check_interface("wg_noop")
        assert healthy is True
        assert error is None


# === Direct (cross-check) =====================================================


class TestDirectEgressProfileCrossCheck:
    """Cross-check: DirectEgressProfile returns empty dicts + healthy."""

    def test_httpx_empty(self) -> None:
        """configure_httpx_client returns empty dict."""
        assert DirectEgressProfile().configure_httpx_client() == {}

    def test_dns_empty(self) -> None:
        """configure_dns_resolver returns empty dict."""
        assert DirectEgressProfile().configure_dns_resolver() == {}

    async def test_health_always_healthy(self) -> None:
        """health_check always returns healthy=True."""
        check = await DirectEgressProfile().health_check()
        assert check.healthy is True
        assert check.profile_type == EgressProfileType.DIRECT

    def test_profile_type_is_direct(self) -> None:
        """Profile type is DIRECT."""
        assert DirectEgressProfile().profile_type == EgressProfileType.DIRECT


# === Factory integration ======================================================


class TestEgressProfileFactory:
    """Verify the factory can instantiate all implemented profiles."""

    def test_factory_creates_socks5(self) -> None:
        """create_egress_profile('socks5') returns Socks5EgressProfile."""
        profile = create_egress_profile("socks5", proxy_url="socks5://1.2.3.4:1080")
        assert isinstance(profile, Socks5EgressProfile)

    def test_factory_creates_http_connect(self) -> None:
        """create_egress_profile('http_connect') returns HttpConnectEgressProfile."""
        profile = create_egress_profile("http_connect", proxy_url="http://proxy:3128")
        assert isinstance(profile, HttpConnectEgressProfile)

    def test_factory_creates_wireguard(self) -> None:
        """create_egress_profile('wireguard') returns WireguardEgressProfile."""
        profile = create_egress_profile("wireguard", interface_name="wg1")
        assert isinstance(profile, WireguardEgressProfile)

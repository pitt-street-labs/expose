"""Tests for the SSRF IP guard module.

Coverage:

1. RFC 1918 ranges (10.x, 172.16-31.x, 192.168.x) detected as private.
2. Loopback (127.x, ::1) detected as private.
3. Link-local (169.254.x, fe80::) detected as private.
4. IPv6 ULA (fc00::/7) detected as private.
5. Public IPs are not flagged.
6. Invalid/malformed strings return False (safe default).
7. Edge cases: network boundaries, broadcast addresses.
"""

from __future__ import annotations

import pytest

from expose.egress.ip_guard import is_private_ip


# === RFC 1918 private ranges ================================================


class TestRFC1918:
    """RFC 1918 private address ranges."""

    @pytest.mark.parametrize(
        "ip",
        [
            "10.0.0.0",
            "10.0.0.1",
            "10.255.255.255",
            "10.100.50.25",
        ],
    )
    def test_10_slash_8(self, ip: str) -> None:
        assert is_private_ip(ip) is True

    @pytest.mark.parametrize(
        "ip",
        [
            "172.16.0.0",
            "172.16.0.1",
            "172.31.255.255",
            "172.20.10.5",
        ],
    )
    def test_172_16_slash_12(self, ip: str) -> None:
        assert is_private_ip(ip) is True

    @pytest.mark.parametrize(
        "ip",
        [
            "192.168.0.0",
            "192.168.0.1",
            "192.168.255.255",
            "192.168.1.100",
        ],
    )
    def test_192_168_slash_16(self, ip: str) -> None:
        assert is_private_ip(ip) is True


# === Loopback ===============================================================


class TestLoopback:
    """Loopback addresses (127.0.0.0/8, ::1)."""

    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.0",
            "127.0.0.1",
            "127.255.255.255",
            "127.0.0.2",
        ],
    )
    def test_ipv4_loopback(self, ip: str) -> None:
        assert is_private_ip(ip) is True

    def test_ipv6_loopback(self) -> None:
        assert is_private_ip("::1") is True


# === Link-local =============================================================


class TestLinkLocal:
    """Link-local addresses (169.254.0.0/16, fe80::/10)."""

    @pytest.mark.parametrize(
        "ip",
        [
            "169.254.0.0",
            "169.254.0.1",
            "169.254.255.255",
            "169.254.169.254",  # AWS IMDS
        ],
    )
    def test_ipv4_link_local(self, ip: str) -> None:
        assert is_private_ip(ip) is True

    @pytest.mark.parametrize(
        "ip",
        [
            "fe80::1",
            "fe80::dead:beef",
            "feb0::1",  # still in fe80::/10
        ],
    )
    def test_ipv6_link_local(self, ip: str) -> None:
        assert is_private_ip(ip) is True


# === IPv6 ULA ==============================================================


class TestIPv6ULA:
    """IPv6 Unique Local Addresses (fc00::/7)."""

    @pytest.mark.parametrize(
        "ip",
        [
            "fc00::1",
            "fd00::1",
            "fdab:cdef:1234::1",
        ],
    )
    def test_ula(self, ip: str) -> None:
        assert is_private_ip(ip) is True


# === Public IPs (should NOT be flagged) =====================================


class TestPublicIPs:
    """Public IP addresses must not be flagged as private."""

    @pytest.mark.parametrize(
        "ip",
        [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "198.51.100.1",  # TEST-NET-2 (documentation, but not private)
            "203.0.113.1",  # TEST-NET-3
            "11.0.0.1",  # just outside 10.0.0.0/8
            "172.15.255.255",  # just below 172.16.0.0/12
            "172.32.0.0",  # just above 172.31.255.255
            "192.167.255.255",  # just below 192.168.0.0/16
            "192.169.0.0",  # just above 192.168.255.255
            "2607:f8b0:4004:800::200e",  # Google public IPv6
        ],
    )
    def test_public_ip_not_flagged(self, ip: str) -> None:
        assert is_private_ip(ip) is False


# === Invalid/malformed input ================================================


class TestInvalidInput:
    """Invalid strings return False (safe default: do not block)."""

    @pytest.mark.parametrize(
        "val",
        [
            "",
            "not-an-ip",
            "example.com",
            "999.999.999.999",
            "10.0.0",
            "::gg",
        ],
    )
    def test_invalid_returns_false(self, val: str) -> None:
        assert is_private_ip(val) is False


# === Boundary edge cases ====================================================


class TestBoundaries:
    """Network boundary addresses."""

    def test_first_ip_in_10_range(self) -> None:
        assert is_private_ip("10.0.0.0") is True

    def test_last_ip_in_10_range(self) -> None:
        assert is_private_ip("10.255.255.255") is True

    def test_just_outside_10_range(self) -> None:
        assert is_private_ip("11.0.0.0") is False
        assert is_private_ip("9.255.255.255") is False

    def test_first_ip_in_172_16_range(self) -> None:
        assert is_private_ip("172.16.0.0") is True

    def test_last_ip_in_172_16_range(self) -> None:
        assert is_private_ip("172.31.255.255") is True

    def test_just_outside_172_16_range(self) -> None:
        assert is_private_ip("172.15.255.255") is False
        assert is_private_ip("172.32.0.0") is False

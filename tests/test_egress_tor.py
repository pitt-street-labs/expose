"""Tests for the Tor egress profile.

Coverage:

 1. SOCKS5 configuration uses socks5h:// scheme for DNS privacy.
 2. SOCKS5 configuration uses correct host and port.
 3. DNS resolver returns empty nameservers (DNS through Tor circuit).
 4. is_anonymizing is always True.
 5. profile_type is EgressProfileType.TOR.
 6. Circuit rotation sends AUTHENTICATE + SIGNAL NEWNYM (mock control port).
 7. Circuit rotation with password sends quoted password in AUTHENTICATE.
 8. Circuit rotation raises RuntimeError on auth failure.
 9. Circuit rotation raises RuntimeError on NEWNYM failure.
10. Health check succeeds when both SOCKS5 and control ports are reachable.
11. Health check fails when SOCKS5 port is unreachable.
12. Health check fails when control port is unreachable.
13. Health check sets egress_anonymized=True.
14. Auto-rotation counter increments and rotates at threshold.
15. Auto-rotation does nothing when not configured.
16. Auto-rotation resets counter after rotation.
17. Factory creates TorEgressProfile for "tor".
18. socks_url property returns socks5h:// URL.

These tests mock all network I/O -- no running Tor instance required.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from expose.egress import EgressProfileType, TorEgressProfile, create_egress_profile
from expose.egress.base import EgressHealthCheck


# === Helpers ==================================================================


def _mock_socks_health(healthy: bool = True) -> EgressHealthCheck:
    """Build a mock EgressHealthCheck for the inner SOCKS5 profile."""
    from datetime import UTC, datetime

    return EgressHealthCheck(
        profile_type=EgressProfileType.SOCKS5,
        healthy=healthy,
        latency_ms=1.0,
        error_message=None if healthy else "connection refused",
        checked_at=datetime.now(tz=UTC),
    )


class FakeControlPort:
    """Simulates a Tor control port as an asyncio StreamReader/Writer pair.

    Responses are provided as a list of byte strings. Each call to
    ``readline()`` pops the next response. ``write()`` records what was sent.
    """

    def __init__(self, responses: list[bytes]) -> None:
        self._responses = list(responses)
        self.written: list[bytes] = []
        self._closed = False

    async def readline(self) -> bytes:
        if not self._responses:
            return b""
        return self._responses.pop(0)

    def write(self, data: bytes) -> None:
        self.written.append(data)

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self._closed = True

    async def wait_closed(self) -> None:
        pass


# === SOCKS5 configuration ====================================================


class TestTorSocksConfig:
    """Verify the SOCKS5 layer is configured correctly for Tor."""

    @patch("expose.egress.socks5._socksio_available", return_value=True)
    def test_httpx_uses_socks5h_scheme(self, _mock: object) -> None:
        """httpx config must use socks5h:// so DNS resolves through Tor."""
        profile = TorEgressProfile(socks_host="127.0.0.1", socks_port=9050)
        result = profile.configure_httpx_client()
        assert result["proxy"] == "socks5h://127.0.0.1:9050"

    @patch("expose.egress.socks5._socksio_available", return_value=True)
    def test_httpx_custom_host_port(self, _mock: object) -> None:
        """httpx config uses the configured host and port."""
        profile = TorEgressProfile(socks_host="10.0.0.5", socks_port=19050)
        result = profile.configure_httpx_client()
        assert result["proxy"] == "socks5h://10.0.0.5:19050"

    def test_dns_resolver_returns_empty_nameservers(self) -> None:
        """DNS resolver config disables independent resolution (Tor handles it)."""
        profile = TorEgressProfile()
        result = profile.configure_dns_resolver()
        assert result == {"nameservers": []}

    def test_is_anonymizing_always_true(self) -> None:
        """Tor is always anonymizing."""
        profile = TorEgressProfile()
        assert profile.is_anonymizing is True

    def test_profile_type_is_tor(self) -> None:
        """Profile type is TOR."""
        profile = TorEgressProfile()
        assert profile.profile_type == EgressProfileType.TOR

    def test_socks_url_property(self) -> None:
        """socks_url returns socks5h:// URL with configured host/port."""
        profile = TorEgressProfile(socks_host="10.0.0.5", socks_port=19050)
        assert profile.socks_url == "socks5h://10.0.0.5:19050"

    def test_socks_url_default(self) -> None:
        """socks_url default is socks5h://127.0.0.1:9050."""
        profile = TorEgressProfile()
        assert profile.socks_url == "socks5h://127.0.0.1:9050"


# === Circuit rotation =========================================================


class TestCircuitRotation:
    """Test SIGNAL NEWNYM via mocked control port."""

    async def test_rotate_sends_authenticate_and_newnym(self) -> None:
        """rotate_circuit sends AUTHENTICATE then SIGNAL NEWNYM."""
        fake = FakeControlPort([
            b"250 OK\r\n",       # AUTHENTICATE response
            b"250 OK\r\n",       # SIGNAL NEWNYM response
        ])

        async def mock_open_connection(host: str, port: int) -> tuple:
            return fake, fake

        profile = TorEgressProfile()
        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            await profile.rotate_circuit()

        assert len(fake.written) == 2
        assert fake.written[0] == b"AUTHENTICATE\r\n"
        assert fake.written[1] == b"SIGNAL NEWNYM\r\n"

    async def test_rotate_with_password(self) -> None:
        """rotate_circuit sends quoted password in AUTHENTICATE."""
        fake = FakeControlPort([
            b"250 OK\r\n",
            b"250 OK\r\n",
        ])

        async def mock_open_connection(host: str, port: int) -> tuple:
            return fake, fake

        profile = TorEgressProfile(control_password="my_secret")
        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            await profile.rotate_circuit()

        assert fake.written[0] == b'AUTHENTICATE "my_secret"\r\n'
        assert fake.written[1] == b"SIGNAL NEWNYM\r\n"

    async def test_rotate_auth_failure_raises(self) -> None:
        """rotate_circuit raises RuntimeError on AUTHENTICATE failure."""
        fake = FakeControlPort([
            b"515 Bad authentication\r\n",
        ])

        async def mock_open_connection(host: str, port: int) -> tuple:
            return fake, fake

        profile = TorEgressProfile(control_password="wrong_password")
        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            with pytest.raises(RuntimeError, match="AUTHENTICATE failed"):
                await profile.rotate_circuit()

    async def test_rotate_newnym_failure_raises(self) -> None:
        """rotate_circuit raises RuntimeError on SIGNAL NEWNYM failure."""
        fake = FakeControlPort([
            b"250 OK\r\n",
            b"510 Unrecognized command\r\n",
        ])

        async def mock_open_connection(host: str, port: int) -> tuple:
            return fake, fake

        profile = TorEgressProfile()
        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            with pytest.raises(RuntimeError, match="SIGNAL NEWNYM failed"):
                await profile.rotate_circuit()

    async def test_rotate_connection_refused_propagates(self) -> None:
        """rotate_circuit propagates connection errors."""

        async def mock_open_connection(host: str, port: int) -> tuple:
            raise ConnectionRefusedError("Connection refused")

        profile = TorEgressProfile()
        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            with pytest.raises(ConnectionRefusedError):
                await profile.rotate_circuit()


# === Health check =============================================================


class TestHealthCheck:
    """Test combined SOCKS5 + control port health checks."""

    async def test_healthy_when_both_ports_reachable(self) -> None:
        """health_check returns healthy=True when SOCKS5 and control ports work."""
        profile = TorEgressProfile()

        # Mock SOCKS5 health check to succeed
        socks_result = _mock_socks_health(healthy=True)
        profile._socks.health_check = AsyncMock(return_value=socks_result)

        # Mock control port connection to succeed
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch(
            "expose.egress.tor.asyncio.open_connection",
            return_value=(MagicMock(), mock_writer),
        ):
            check = await profile.health_check()

        assert check.healthy is True
        assert check.profile_type == EgressProfileType.TOR
        assert check.egress_anonymized is True
        assert check.latency_ms is not None
        assert check.latency_ms > 0

    async def test_unhealthy_when_socks_unreachable(self) -> None:
        """health_check returns healthy=False when SOCKS5 port is down."""
        profile = TorEgressProfile()

        socks_result = _mock_socks_health(healthy=False)
        profile._socks.health_check = AsyncMock(return_value=socks_result)

        check = await profile.health_check()

        assert check.healthy is False
        assert check.profile_type == EgressProfileType.TOR
        assert check.egress_anonymized is True
        assert "SOCKS5 port unreachable" in (check.error_message or "")

    async def test_unhealthy_when_control_port_unreachable(self) -> None:
        """health_check returns healthy=False when control port is down."""
        profile = TorEgressProfile()

        socks_result = _mock_socks_health(healthy=True)
        profile._socks.health_check = AsyncMock(return_value=socks_result)

        with patch(
            "expose.egress.tor.asyncio.open_connection",
            side_effect=ConnectionRefusedError("Connection refused"),
        ):
            check = await profile.health_check()

        assert check.healthy is False
        assert check.profile_type == EgressProfileType.TOR
        assert check.egress_anonymized is True
        assert "control port unreachable" in (check.error_message or "")

    async def test_health_check_always_sets_anonymized(self) -> None:
        """egress_anonymized is True regardless of health status."""
        profile = TorEgressProfile()

        socks_result = _mock_socks_health(healthy=False)
        profile._socks.health_check = AsyncMock(return_value=socks_result)

        check = await profile.health_check()
        assert check.egress_anonymized is True


# === Auto-rotation ============================================================


class TestAutoRotation:
    """Test the maybe_rotate counter and threshold mechanism."""

    async def test_no_rotation_when_not_configured(self) -> None:
        """maybe_rotate returns False when rotate_every_n_requests is None."""
        profile = TorEgressProfile(rotate_every_n_requests=None)
        result = await profile.maybe_rotate()
        assert result is False
        assert profile.request_counter == 0

    async def test_counter_increments(self) -> None:
        """Counter increments on each call without reaching threshold."""
        fake = FakeControlPort([b"250 OK\r\n", b"250 OK\r\n"])

        profile = TorEgressProfile(rotate_every_n_requests=5)

        for i in range(1, 5):
            result = await profile.maybe_rotate()
            assert result is False
            assert profile.request_counter == i

    async def test_rotates_at_threshold(self) -> None:
        """Circuit rotation triggers when counter reaches threshold."""
        fake = FakeControlPort([b"250 OK\r\n", b"250 OK\r\n"])

        async def mock_open_connection(host: str, port: int) -> tuple:
            return fake, fake

        profile = TorEgressProfile(rotate_every_n_requests=3)

        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            # Calls 1 and 2: no rotation
            assert await profile.maybe_rotate() is False
            assert await profile.maybe_rotate() is False
            assert profile.request_counter == 2

            # Call 3: rotation triggers
            assert await profile.maybe_rotate() is True
            assert profile.request_counter == 0  # reset after rotation

    async def test_counter_resets_after_rotation(self) -> None:
        """Counter resets to 0 after triggering rotation."""
        profile = TorEgressProfile(rotate_every_n_requests=2)

        # First cycle
        with patch.object(profile, "rotate_circuit", new_callable=AsyncMock) as mock_rotate:
            await profile.maybe_rotate()  # counter = 1
            assert mock_rotate.call_count == 0

            await profile.maybe_rotate()  # counter = 2 -> rotate -> counter = 0
            assert mock_rotate.call_count == 1
            assert profile.request_counter == 0

            # Second cycle
            await profile.maybe_rotate()  # counter = 1
            assert mock_rotate.call_count == 1

            await profile.maybe_rotate()  # counter = 2 -> rotate -> counter = 0
            assert mock_rotate.call_count == 2
            assert profile.request_counter == 0

    async def test_rotation_threshold_of_one(self) -> None:
        """rotate_every_n_requests=1 rotates on every call."""
        profile = TorEgressProfile(rotate_every_n_requests=1)

        with patch.object(profile, "rotate_circuit", new_callable=AsyncMock) as mock_rotate:
            for _ in range(5):
                result = await profile.maybe_rotate()
                assert result is True
            assert mock_rotate.call_count == 5


# === Control port authentication =============================================


class TestControlPortAuth:
    """Test AUTHENTICATE command formatting."""

    async def test_no_password_sends_bare_authenticate(self) -> None:
        """No password sends AUTHENTICATE without arguments."""
        fake = FakeControlPort([b"250 OK\r\n", b"250 OK\r\n"])

        async def mock_open_connection(host: str, port: int) -> tuple:
            return fake, fake

        profile = TorEgressProfile(control_password=None)
        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            await profile.rotate_circuit()

        assert fake.written[0] == b"AUTHENTICATE\r\n"

    async def test_password_sends_quoted_authenticate(self) -> None:
        """Password sends AUTHENTICATE "password"."""
        fake = FakeControlPort([b"250 OK\r\n", b"250 OK\r\n"])

        async def mock_open_connection(host: str, port: int) -> tuple:
            return fake, fake

        profile = TorEgressProfile(control_password="s3cret")
        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            await profile.rotate_circuit()

        assert fake.written[0] == b'AUTHENTICATE "s3cret"\r\n'

    async def test_empty_string_password_sends_quoted_empty(self) -> None:
        """Empty string password sends AUTHENTICATE "" (distinct from None)."""
        fake = FakeControlPort([b"250 OK\r\n", b"250 OK\r\n"])

        async def mock_open_connection(host: str, port: int) -> tuple:
            return fake, fake

        profile = TorEgressProfile(control_password="")
        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            await profile.rotate_circuit()

        assert fake.written[0] == b'AUTHENTICATE ""\r\n'


# === Factory integration =====================================================


class TestFactoryIntegration:
    """Verify the factory can create Tor profiles."""

    def test_factory_creates_tor_profile(self) -> None:
        """create_egress_profile('tor') returns a TorEgressProfile."""
        profile = create_egress_profile("tor")
        assert isinstance(profile, TorEgressProfile)
        assert profile.profile_type == EgressProfileType.TOR

    def test_factory_creates_tor_with_kwargs(self) -> None:
        """create_egress_profile('tor', ...) passes kwargs to constructor."""
        profile = create_egress_profile(
            "tor",
            socks_port=19050,
            control_port=19051,
            control_password="test",
            rotate_every_n_requests=10,
        )
        assert isinstance(profile, TorEgressProfile)
        assert profile.socks_url == "socks5h://127.0.0.1:19050"

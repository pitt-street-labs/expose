"""Tests for the active-port-surface collector.

Exercises all code paths with a fully mocked ``asyncio.open_connection`` —
NO live network connections are ever issued.

Coverage:
    1. Happy path — some ports open, some closed, observation yielded
    2. All ports closed — yields observation with empty open_ports list
    3. Non-IP seed skipped
    4. Custom ports via seed.properties
    5. Connection timeout handled gracefully (counted as closed)
    6. Health check success and failure paths
    7. Observation payload has correct counts
    8. Banner grabbing with mock sockets
    9. Port categorization
    10. Service identification
    11. Semaphore bounding (max 50 concurrent)
    12. _collector_id tagging
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

from expose.collectors.base import (
    CollectorConfig,
    CollectorHealthCheck,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.active_port_surface import (
    DEFAULT_PORTS,
    PORT_SERVICE_MAP,
    ActivePortSurfaceCollector,
    _PROBE_SEMAPHORE_LIMIT,
    classify_port,
    identify_service,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

# Synthetic IDs reused across tests (matches project conventions).
TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000E001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000E002")


def _config(**extra: object) -> CollectorConfig:
    """Build a minimal CollectorConfig for test use."""
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        extra=dict(extra),  # type: ignore[arg-type]
    )


def _ip_seed(ip: str = "93.184.216.34", **properties: object) -> Seed:
    """Build an IP seed with optional property overrides."""
    return Seed(
        seed_type=SeedType.IP,
        value=ip,
        properties=dict(properties),  # type: ignore[arg-type]
    )


def _mock_open_connection(
    open_ports: set[int],
    banners: dict[int, bytes] | None = None,
):
    """Return a coroutine factory that simulates open/closed ports.

    Ports in ``open_ports`` succeed (return mock reader/writer); all
    others raise ``ConnectionRefusedError``.  If ``banners`` is provided,
    the mock reader returns the banner bytes for matching ports.
    """
    if banners is None:
        banners = {}

    async def _fake_open_connection(host: str, port: int):
        if port in open_ports:
            reader = AsyncMock()
            banner_data = banners.get(port, b"")
            reader.read = AsyncMock(return_value=banner_data)
            writer = MagicMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()
            return reader, writer
        raise ConnectionRefusedError(f"Connection refused to {host}:{port}")

    return _fake_open_connection


def _mock_open_connection_timeout():
    """Return a coroutine factory that always times out."""

    async def _fake_open_connection(host: str, port: int):
        raise TimeoutError

    return _fake_open_connection


# === Tests ====================================================================


class TestHappyPathSomePortsOpen:
    """Test 1: Some ports open, some closed — correct observation."""

    async def test_some_ports_open(self) -> None:
        open_set = {22, 80, 443, 8080}
        collector = ActivePortSurfaceCollector(_config())

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_mock_open_connection(open_set),
        ):
            seed = _ip_seed()
            observations: list[Observation] = [
                obs async for obs in collector.expand(seed)
            ]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.collector_id == "active-port-surface"
        assert obs.observation_type == ObservationType.PORT_SCAN_RESULT
        assert obs.subject.identifier_type == ExtendedIdentifierType.IP
        assert obs.subject.identifier_value == "93.184.216.34"
        assert obs.tenant_id == TENANT_ID

        payload = obs.structured_payload
        assert sorted(payload["open_ports"]) == sorted(open_set)
        assert payload["total_ports_probed"] == len(DEFAULT_PORTS)
        assert payload["closed_ports_probed"] == len(DEFAULT_PORTS) - len(open_set)


class TestAllPortsClosed:
    """Test 2: All ports closed — yields observation with empty open_ports."""

    async def test_no_open_ports(self) -> None:
        collector = ActivePortSurfaceCollector(_config())

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_mock_open_connection(set()),
        ):
            seed = _ip_seed()
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        obs = observations[0]
        assert obs.structured_payload["open_ports"] == []
        assert obs.structured_payload["closed_ports_probed"] == len(DEFAULT_PORTS)
        assert obs.structured_payload["total_ports_probed"] == len(DEFAULT_PORTS)
        assert obs.structured_payload["banners"] == {}
        assert obs.structured_payload["services"] == {}
        assert obs.structured_payload["port_categories"] == {}


class TestNonIpSeedSkipped:
    """Test 3: Non-IP seeds are silently skipped (with warning log)."""

    async def test_domain_seed_skipped(self) -> None:
        collector = ActivePortSurfaceCollector(_config())
        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_organization_seed_skipped(self) -> None:
        collector = ActivePortSurfaceCollector(_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="ACME Corp")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_cidr_seed_skipped(self) -> None:
        collector = ActivePortSurfaceCollector(_config())
        seed = Seed(seed_type=SeedType.CIDR, value="10.0.0.0/8")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []


class TestCustomPortsViaSeedProperties:
    """Test 4: Custom ports via seed.properties overrides default list."""

    async def test_custom_ports(self) -> None:
        custom_ports = [80, 443, 9999]
        open_set = {443, 9999}
        collector = ActivePortSurfaceCollector(_config())

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_mock_open_connection(open_set),
        ):
            seed = _ip_seed(ports=custom_ports)
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert sorted(payload["open_ports"]) == [443, 9999]
        assert payload["total_ports_probed"] == 3
        assert payload["closed_ports_probed"] == 1


class TestTimeoutHandledGracefully:
    """Test 5: Connection timeout is treated as closed (not an error)."""

    async def test_timeout_counted_as_closed(self) -> None:
        collector = ActivePortSurfaceCollector(_config())

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_mock_open_connection_timeout(),
        ):
            seed = _ip_seed()
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert payload["open_ports"] == []
        assert payload["closed_ports_probed"] == len(DEFAULT_PORTS)


class TestHealthCheck:
    """Test 6: Health check success and failure paths."""

    async def test_health_check_success(self) -> None:
        collector = ActivePortSurfaceCollector(_config())

        with patch(
            "expose.collectors.builtin.active_port_surface._probe_port",
            return_value=(True, None),
        ):
            result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "active-port-surface"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    async def test_health_check_failure_port_closed(self) -> None:
        collector = ActivePortSurfaceCollector(_config())

        with patch(
            "expose.collectors.builtin.active_port_surface._probe_port",
            return_value=(False, None),
        ):
            result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.FAILURE

    async def test_health_check_exception(self) -> None:
        collector = ActivePortSurfaceCollector(_config())

        with patch(
            "expose.collectors.builtin.active_port_surface._probe_port",
            side_effect=RuntimeError("unexpected"),
        ):
            result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "unexpected" in result.error_message


class TestObservationPayloadCounts:
    """Test 7: Observation payload has correct counts for mixed results."""

    async def test_counts_correct(self) -> None:
        # Probe only 5 ports, 2 open.
        custom_ports = [22, 80, 443, 3306, 5432]
        open_set = {80, 443}
        collector = ActivePortSurfaceCollector(_config())

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_mock_open_connection(open_set),
        ):
            seed = _ip_seed(ports=custom_ports)
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert payload["open_ports"] == [80, 443]
        assert payload["closed_ports_probed"] == 3
        assert payload["total_ports_probed"] == 5
        assert payload["probe_timeout_seconds"] == 3.0

    async def test_probe_timeout_configurable(self) -> None:
        """The probe_timeout_seconds value comes from config.extra."""
        collector = ActivePortSurfaceCollector(_config(probe_timeout_seconds=1.5))

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_mock_open_connection({80}),
        ):
            seed = _ip_seed(ports=[80])
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        assert observations[0].structured_payload["probe_timeout_seconds"] == 1.5


class TestRegistration:
    """Verify the collector registers correctly in the default registry."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("active-port-surface")
        cls = DEFAULT_REGISTRY.get("active-port-surface")
        assert cls is ActivePortSurfaceCollector

    def test_metadata_correct(self) -> None:
        assert ActivePortSurfaceCollector.collector_id == "active-port-surface"
        assert ActivePortSurfaceCollector.collector_version == "0.2.0"
        assert ActivePortSurfaceCollector.tier == CollectorTier.TIER_3
        assert ActivePortSurfaceCollector.requires_credentials is False


class TestIPCanonicalization:
    """Verify that IP addresses are canonicalized in the observation subject."""

    async def test_ipv6_canonicalized(self) -> None:
        collector = ActivePortSurfaceCollector(_config())

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_mock_open_connection({80}),
        ):
            seed = Seed(
                seed_type=SeedType.IP,
                value="2001:0db8:0000:0000:0000:0000:0000:0001",
                properties={"ports": [80]},
            )
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        # Canonicalized IPv6 uses compressed form.
        assert observations[0].subject.identifier_value == "2001:db8::1"


class TestGatherExceptionHandling:
    """Verify that unexpected exceptions from asyncio.gather are handled."""

    async def test_unexpected_exception_treated_as_closed(self) -> None:
        """An exception that escapes _probe_port is treated as closed."""

        async def _exploding_open_connection(host: str, port: int):
            raise RuntimeError("kaboom")

        collector = ActivePortSurfaceCollector(_config())

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_exploding_open_connection,
        ):
            seed = _ip_seed(ports=[80, 443])
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        payload = observations[0].structured_payload
        # Both ports should be treated as closed since _probe_port catches
        # OSError (RuntimeError is NOT OSError), but the gather
        # return_exceptions=True path handles it at the result level.
        assert payload["open_ports"] == []
        assert payload["closed_ports_probed"] == 2


# === New test classes for enhanced features ===================================


class TestBannerGrabbing:
    """Test 8: Banner grabbing with mock sockets."""

    async def test_banner_captured_for_open_port(self) -> None:
        """SSH-style banner is captured and sanitized."""
        collector = ActivePortSurfaceCollector(_config())
        banner_text = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_mock_open_connection(
                {22}, banners={22: banner_text}
            ),
        ):
            seed = _ip_seed(ports=[22])
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert "22" in payload["banners"]
        assert "SSH-2.0-OpenSSH" in payload["banners"]["22"]

    async def test_multiple_banners_captured(self) -> None:
        """Multiple service banners are captured independently."""
        collector = ActivePortSurfaceCollector(_config())
        banners_data = {
            22: b"SSH-2.0-OpenSSH_8.9\r\n",
            25: b"220 mail.example.com ESMTP\r\n",
            21: b"220 ProFTPD Server ready.\r\n",
        }

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_mock_open_connection(
                {21, 22, 25}, banners=banners_data
            ),
        ):
            seed = _ip_seed(ports=[21, 22, 25])
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert len(payload["banners"]) == 3
        assert "SSH-2.0-OpenSSH" in payload["banners"]["22"]
        assert "ESMTP" in payload["banners"]["25"]
        assert "ProFTPD" in payload["banners"]["21"]

    async def test_no_banner_port_still_open(self) -> None:
        """Port is still listed as open even when no banner is returned."""
        collector = ActivePortSurfaceCollector(_config())

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_mock_open_connection(
                {443}, banners={443: b""}
            ),
        ):
            seed = _ip_seed(ports=[443])
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert payload["open_ports"] == [443]
        # Empty banner should NOT appear in the banners dict.
        assert 443 not in payload["banners"]
        assert "443" not in payload["banners"]

    async def test_banner_timeout_port_still_open(self) -> None:
        """If banner read times out, port is still recorded as open."""
        collector = ActivePortSurfaceCollector(_config())

        async def _fake_open_connection(host: str, port: int):
            reader = AsyncMock()
            reader.read = AsyncMock(side_effect=TimeoutError)
            writer = MagicMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()
            return reader, writer

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_fake_open_connection,
        ):
            seed = _ip_seed(ports=[80])
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert payload["open_ports"] == [80]
        assert payload["banners"] == {}

    async def test_banner_with_binary_data_decoded_safely(self) -> None:
        """Binary data in banner is decoded with replacement characters."""
        collector = ActivePortSurfaceCollector(_config())
        # Mix of valid ASCII and invalid UTF-8 sequences.
        raw_banner = b"HTTP/1.0 200 OK\xff\xfe\r\n"

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_mock_open_connection(
                {8080}, banners={8080: raw_banner}
            ),
        ):
            seed = _ip_seed(ports=[8080])
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert "8080" in payload["banners"]
        # Invalid bytes should be replaced, not crash.
        assert "HTTP/1.0 200 OK" in payload["banners"]["8080"]


class TestPortCategorization:
    """Test 9: Port risk classification."""

    def test_management_ports(self) -> None:
        management_ports = [22, 23, 2222, 3389, 5900, 10000, 2083, 2087, 135, 139, 445, 161]
        for port in management_ports:
            assert classify_port(port) == "management", (
                f"Port {port} should be classified as management"
            )

    def test_database_ports(self) -> None:
        db_ports = [1433, 1521, 3306, 5432, 6379, 9200, 9042, 11211, 27017, 27018]
        for port in db_ports:
            assert classify_port(port) == "database", (
                f"Port {port} should be classified as database"
            )

    def test_web_ports(self) -> None:
        web_ports = [80, 443, 8080, 8443, 3000, 5601, 9090, 50000]
        for port in web_ports:
            assert classify_port(port) == "web", (
                f"Port {port} should be classified as web"
            )

    def test_other_ports(self) -> None:
        other_ports = [21, 25, 53, 514, 636, 1080, 1883, 5060, 5222, 5672]
        for port in other_ports:
            assert classify_port(port) == "other", (
                f"Port {port} should be classified as other"
            )

    async def test_categories_in_payload(self) -> None:
        """Open ports include their categories in the payload."""
        collector = ActivePortSurfaceCollector(_config())
        open_set = {22, 80, 3306}

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_mock_open_connection(open_set),
        ):
            seed = _ip_seed(ports=[22, 80, 3306])
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        categories = observations[0].structured_payload["port_categories"]
        assert categories["22"] == "management"
        assert categories["80"] == "web"
        assert categories["3306"] == "database"


class TestServiceIdentification:
    """Test 10: Service name mapping."""

    def test_known_services(self) -> None:
        known = {
            22: "ssh", 80: "http", 443: "https", 3306: "mysql",
            5432: "postgresql", 6379: "redis", 27017: "mongodb",
            3389: "rdp", 5900: "vnc", 8080: "alt-http",
            25: "smtp", 21: "ftp", 23: "telnet", 53: "dns",
            110: "pop3", 143: "imap", 993: "imaps", 995: "pop3s",
            1883: "mqtt", 5060: "sip", 5222: "xmpp",
            6443: "k8s-api", 9200: "elasticsearch",
        }
        for port, expected_service in known.items():
            assert identify_service(port) == expected_service, (
                f"Port {port} should map to {expected_service}"
            )

    def test_unknown_port(self) -> None:
        assert identify_service(99999) == "unknown"

    def test_port_service_map_covers_default_ports(self) -> None:
        """Every port in DEFAULT_PORTS has a service mapping."""
        for port in DEFAULT_PORTS:
            assert port in PORT_SERVICE_MAP, (
                f"Port {port} in DEFAULT_PORTS but missing from PORT_SERVICE_MAP"
            )

    async def test_services_in_payload(self) -> None:
        """Open ports include their service names in the payload."""
        collector = ActivePortSurfaceCollector(_config())
        open_set = {22, 443, 6379}

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_mock_open_connection(open_set),
        ):
            seed = _ip_seed(ports=[22, 443, 6379])
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        services = observations[0].structured_payload["services"]
        assert services["22"] == "ssh"
        assert services["443"] == "https"
        assert services["6379"] == "redis"


class TestSemaphoreBounding:
    """Test 11: Semaphore limits concurrent probes to 50."""

    async def test_concurrency_bounded_at_50(self) -> None:
        """Verify no more than 50 probes run concurrently."""
        max_concurrent = 0
        current_concurrent = 0
        lock = asyncio.Lock()

        async def _tracking_open_connection(host: str, port: int):
            nonlocal max_concurrent, current_concurrent
            async with lock:
                current_concurrent += 1
                if current_concurrent > max_concurrent:
                    max_concurrent = current_concurrent

            # Simulate a brief network delay so overlap is possible.
            await asyncio.sleep(0.001)

            async with lock:
                current_concurrent -= 1

            reader = AsyncMock()
            reader.read = AsyncMock(return_value=b"")
            writer = MagicMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()
            return reader, writer

        collector = ActivePortSurfaceCollector(_config())

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_tracking_open_connection,
        ):
            seed = _ip_seed()
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        # With the full DEFAULT_PORTS list (60+ ports), the semaphore
        # must keep concurrency at or below the limit.
        assert max_concurrent <= _PROBE_SEMAPHORE_LIMIT, (
            f"Max concurrent probes ({max_concurrent}) exceeded "
            f"semaphore limit ({_PROBE_SEMAPHORE_LIMIT})"
        )
        # Also verify the semaphore actually constrained something —
        # the default port list is larger than the limit.
        assert len(DEFAULT_PORTS) > _PROBE_SEMAPHORE_LIMIT, (
            "DEFAULT_PORTS must be larger than semaphore limit for "
            "this test to be meaningful"
        )

    def test_semaphore_limit_is_50(self) -> None:
        """The constant is exactly 50."""
        assert _PROBE_SEMAPHORE_LIMIT == 50


class TestCollectorIdTagging:
    """Test 12: _collector_id tagging in payload."""

    async def test_collector_id_in_payload(self) -> None:
        """Payload contains _collector_id for lead scoring."""
        collector = ActivePortSurfaceCollector(_config())

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_mock_open_connection({80}),
        ):
            seed = _ip_seed(ports=[80])
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert payload["_collector_id"] == "active-port-surface"

    async def test_collector_id_present_when_no_open_ports(self) -> None:
        """_collector_id is present even when all ports are closed."""
        collector = ActivePortSurfaceCollector(_config())

        with patch(
            "expose.collectors.builtin.active_port_surface.asyncio.open_connection",
            side_effect=_mock_open_connection(set()),
        ):
            seed = _ip_seed(ports=[80, 443])
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        assert observations[0].structured_payload["_collector_id"] == "active-port-surface"


class TestExpandedPortList:
    """Verify the expanded port list includes all required ports."""

    def test_original_ports_preserved(self) -> None:
        """All 27 original ports are still present."""
        original = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
            993, 995, 1433, 1521, 2222, 3306, 3389, 5432,
            5900, 6379, 8080, 8443, 8888, 9090, 9200, 9443,
            27017,
        ]
        for port in original:
            assert port in DEFAULT_PORTS, f"Original port {port} missing"

    def test_new_ports_added(self) -> None:
        """All requested new ports are present."""
        new_ports = [
            135, 139, 161, 389, 514, 636, 1080, 1883, 2049,
            2083, 2087, 3000, 4443, 5000, 5060, 5222, 5601,
            5672, 6443, 7443, 8000, 8081, 8181, 8444, 8880,
            9000, 9042, 9100, 10000, 11211, 15672, 27018, 50000,
        ]
        for port in new_ports:
            assert port in DEFAULT_PORTS, f"New port {port} missing"

    def test_ports_sorted(self) -> None:
        """Port list is sorted ascending."""
        assert DEFAULT_PORTS == sorted(DEFAULT_PORTS)

    def test_no_duplicates(self) -> None:
        """No duplicate ports in the list."""
        assert len(DEFAULT_PORTS) == len(set(DEFAULT_PORTS))

    def test_port_count_at_least_60(self) -> None:
        """Expanded list has at least 60 ports (27 original + 33 new)."""
        assert len(DEFAULT_PORTS) >= 60


class TestVersionBump:
    """Verify the collector version was bumped for the enhancement."""

    def test_version_is_0_2_0(self) -> None:
        assert ActivePortSurfaceCollector.collector_version == "0.2.0"

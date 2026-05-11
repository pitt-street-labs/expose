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
"""

from __future__ import annotations

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
    ActivePortSurfaceCollector,
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


def _mock_open_connection(open_ports: set[int]):
    """Return a coroutine factory that simulates open/closed ports.

    Ports in ``open_ports`` succeed (return mock reader/writer); all
    others raise ``ConnectionRefusedError``.
    """

    async def _fake_open_connection(host: str, port: int):
        if port in open_ports:
            reader = MagicMock()
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
            return_value=True,
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
            return_value=False,
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
        assert ActivePortSurfaceCollector.collector_version == "0.1.0"
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

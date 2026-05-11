"""End-to-end tests for Phase 1 distributed dispatch, scheduler, tenant config, and egress.

Covers:

- **NatsDispatcher round-trip** -- AsyncMock NATS client, verify result round-trip
- **NatsDispatcher timeout** -- no worker replies, verify timeout result
- **Scheduler CRUD** -- add, remove, get, list operations on RunScheduler
- **CronExpression matching** -- verify cron expressions match expected times
- **Scheduler triggers callback** -- schedule fires and invokes the on_run_trigger callback
- **Tenant config via API** -- POST/PUT and GET tenant config
- **Tenant config PATCH** -- partial update preserves unchanged fields
- **Tenant config independence** -- two tenants have independent configs
- **Egress profile factory** -- create all 4 profile types via factory
- **Egress SOCKS5 DNS through proxy** -- socks5h:// rewriting
- **Egress health check (direct)** -- DirectEgressProfile reports healthy
- **Egress health check (SOCKS5 unreachable)** -- SOCKS5 to unused port reports unhealthy
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nats.errors import TimeoutError as NatsTimeoutError

from expose.api.tenant_config import _configs
from expose.api.tenant_config import router as tenant_config_router
from expose.collectors.base import (
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.egress import create_egress_profile
from expose.egress.base import EgressProfileType
from expose.egress.direct import DirectEgressProfile
from expose.egress.http_connect import HttpConnectEgressProfile
from expose.egress.socks5 import Socks5EgressProfile
from expose.egress.wireguard import WireguardEgressProfile
from expose.pipeline.nats_dispatcher import (
    NatsDispatcher,
    NatsDispatcherResult,
)
from expose.pipeline.run_executor import DispatchJob
from expose.pipeline.scheduler import CronExpression, RunScheduler
from expose.types.canonical import IdentifierType

# === Deterministic synthetic IDs (UUIDv7-style, greppable) ====================

TENANT_A = UUID("018f1f00-0000-7000-8000-00000000da01")
TENANT_B = UUID("018f1f00-0000-7000-8000-00000000da02")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000da03")

# === Helpers ==================================================================


def _make_observation() -> dict[str, Any]:
    """Build a minimal Observation dict for wire format."""
    return Observation(
        collector_id="ct-crtsh",
        collector_version="0.1.0",
        tenant_id=TENANT_A,
        observation_type=ObservationType.CT_LOG_ENTRY,
        subject=ObservationSubject(
            identifier_type=IdentifierType.DOMAIN,
            identifier_value="example.com",
        ),
        observed_at=datetime.now(UTC),
        structured_payload={"issuer": "R3"},
    ).model_dump(mode="json")


def _make_dispatch_job() -> DispatchJob:
    """Build a standard DispatchJob for testing."""
    return DispatchJob(
        collector_id="ct-crtsh",
        seed=Seed(seed_type=SeedType.DOMAIN, value="example.com"),
        run_id=RUN_ID,
        tenant_id=TENANT_A,
    )


# === 1. NatsDispatcher round-trip =============================================


async def test_nats_dispatcher_round_trip() -> None:
    """Dispatch a job via mocked NATS request-reply, verify result comes back."""
    wire_result = NatsDispatcherResult(
        status="completed",
        observations=[_make_observation()],
        error_message=None,
        duration_ms=42.0,
    )

    mock_response = MagicMock()
    mock_response.data = wire_result.to_bytes()

    raw_nats = AsyncMock()
    raw_nats.request = AsyncMock(return_value=mock_response)

    mock_client = MagicMock()
    mock_client._client = raw_nats

    dispatcher = NatsDispatcher(mock_client, timeout_seconds=10.0)
    job = _make_dispatch_job()

    result = await dispatcher.dispatch(job)

    assert result.status == "completed"
    assert len(result.observations) == 1
    assert result.observations[0].collector_id == "ct-crtsh"
    assert result.error_message is None

    raw_nats.request.assert_called_once()
    call_args = raw_nats.request.call_args
    assert f"{TENANT_A}" in call_args[0][0]
    assert "ct-crtsh" in call_args[0][0]


# === 2. NatsDispatcher timeout ================================================


async def test_nats_dispatcher_timeout() -> None:
    """Dispatch to a subject with no worker, verify timeout error result."""

    async def _raise_timeout(*args: Any, **kwargs: Any) -> None:
        raise NatsTimeoutError("NATS request timeout")

    raw_nats = AsyncMock()
    raw_nats.request = _raise_timeout

    mock_client = MagicMock()
    mock_client._client = raw_nats

    dispatcher = NatsDispatcher(mock_client, timeout_seconds=0.1)
    job = _make_dispatch_job()

    result = await dispatcher.dispatch(job)

    assert result.status == "collector_error"
    assert result.error_message == "timeout"
    assert result.observations == []
    assert result.duration_ms > 0


# === 3. Scheduler add/remove/list =============================================


async def test_scheduler_crud() -> None:
    """Add, get, list, and remove schedules."""
    callback = AsyncMock()
    scheduler = RunScheduler(on_run_trigger=callback)

    # Add
    entry = scheduler.add_schedule(
        tenant_id=TENANT_A,
        cron_expression="0 2 * * *",
        collector_ids=["ct-crtsh", "rdap-whois"],
        seeds=[{"seed_type": "domain", "value": "example.com"}],
    )
    assert entry.tenant_id == TENANT_A
    assert entry.cron_expression == "0 2 * * *"
    assert entry.enabled is True
    assert entry.next_run_at is not None

    # Get
    fetched = scheduler.get_schedule(TENANT_A)
    assert fetched is not None
    assert fetched.tenant_id == TENANT_A

    # List
    all_entries = scheduler.list_schedules()
    assert len(all_entries) == 1

    # Add second
    scheduler.add_schedule(
        tenant_id=TENANT_B,
        cron_expression="*/30 * * * *",
        collector_ids=["rdap-whois"],
        seeds=[],
    )
    assert len(scheduler.list_schedules()) == 2

    # Remove
    removed = scheduler.remove_schedule(TENANT_A)
    assert removed is True
    assert scheduler.get_schedule(TENANT_A) is None
    assert len(scheduler.list_schedules()) == 1

    # Remove non-existent
    removed_again = scheduler.remove_schedule(TENANT_A)
    assert removed_again is False


# === 4. CronExpression matching ===============================================


async def test_cron_expression_matching() -> None:
    """Verify CronExpression matches expected times and rejects non-matching."""
    cron = CronExpression("30 2 * * 1")  # 02:30 every Monday

    # Monday 2026-05-11 02:30 UTC (Monday, isoweekday=1)
    monday_match = datetime(2026, 5, 11, 2, 30, 0, tzinfo=UTC)
    assert cron.matches(monday_match) is True

    # Monday 2026-05-11 02:31 UTC -- wrong minute
    monday_wrong_minute = datetime(2026, 5, 11, 2, 31, 0, tzinfo=UTC)
    assert cron.matches(monday_wrong_minute) is False

    # Monday 2026-05-11 03:30 UTC -- wrong hour
    monday_wrong_hour = datetime(2026, 5, 11, 3, 30, 0, tzinfo=UTC)
    assert cron.matches(monday_wrong_hour) is False

    # Tuesday 2026-05-12 02:30 UTC -- wrong day of week
    tuesday = datetime(2026, 5, 12, 2, 30, 0, tzinfo=UTC)
    assert cron.matches(tuesday) is False

    # Every-minute wildcard
    every_minute = CronExpression("* * * * *")
    assert every_minute.matches(datetime(2026, 1, 1, 0, 0, tzinfo=UTC)) is True
    assert every_minute.matches(datetime(2026, 12, 31, 23, 59, tzinfo=UTC)) is True

    # Step expression: every 15 minutes
    every_15 = CronExpression("*/15 * * * *")
    assert every_15.matches(datetime(2026, 1, 1, 0, 0, tzinfo=UTC)) is True
    assert every_15.matches(datetime(2026, 1, 1, 0, 15, tzinfo=UTC)) is True
    assert every_15.matches(datetime(2026, 1, 1, 0, 30, tzinfo=UTC)) is True
    assert every_15.matches(datetime(2026, 1, 1, 0, 7, tzinfo=UTC)) is False


# === 5. CronExpression next_occurrence ========================================


async def test_cron_next_occurrence() -> None:
    """Verify next_occurrence returns the correct next matching time."""
    cron = CronExpression("0 3 * * *")  # Daily at 03:00

    now = datetime(2026, 5, 10, 2, 0, 0, tzinfo=UTC)
    next_time = cron.next_occurrence(now)
    assert next_time == datetime(2026, 5, 10, 3, 0, 0, tzinfo=UTC)

    # When already past today's 03:00, should be tomorrow
    after = datetime(2026, 5, 10, 4, 0, 0, tzinfo=UTC)
    next_after = cron.next_occurrence(after)
    assert next_after == datetime(2026, 5, 11, 3, 0, 0, tzinfo=UTC)


# === 6. Scheduler triggers callback ==========================================


async def test_scheduler_triggers_callback() -> None:
    """Schedule at current time, verify callback fires during scheduler loop."""
    callback = AsyncMock()
    scheduler = RunScheduler(on_run_trigger=callback)

    # Add a schedule whose next_run_at is in the past so the loop fires it
    # immediately.
    now = datetime.now(UTC)
    scheduler.add_schedule(
        tenant_id=TENANT_A,
        cron_expression="* * * * *",  # every minute
        collector_ids=["ct-crtsh"],
        seeds=[{"seed_type": "domain", "value": "example.com"}],
    )

    # Patch the entry's next_run_at to be in the past so the scheduler fires it.
    entry = scheduler.get_schedule(TENANT_A)
    assert entry is not None
    past_entry = entry.model_copy(
        update={"next_run_at": now - timedelta(minutes=1)}
    )
    scheduler._schedules[TENANT_A] = past_entry

    # Run the scheduler briefly and then shut it down.
    shutdown = asyncio.Event()

    async def _run_briefly() -> None:
        # Let the scheduler run one iteration then stop.
        await asyncio.sleep(0.05)
        shutdown.set()

    await asyncio.gather(
        scheduler.run(shutdown),
        _run_briefly(),
    )

    callback.assert_called_once()
    call_args = callback.call_args
    assert call_args[0][0] == TENANT_A
    assert call_args[0][1] == ["ct-crtsh"]

    # Verify next_run_at was advanced.
    updated_entry = scheduler.get_schedule(TENANT_A)
    assert updated_entry is not None
    assert updated_entry.last_run_at is not None
    assert updated_entry.next_run_at is not None
    assert updated_entry.next_run_at > now


# === 7. Tenant config via API -- PUT and GET ==================================


def _make_tenant_config_app() -> Any:
    """Build a minimal FastAPI app with the tenant config router."""
    # Clear module-level config store between tests.
    _configs.clear()

    app = FastAPI(title="EXPOSE Tenant Config (test)")
    app.include_router(tenant_config_router)
    return app


async def test_tenant_config_put_and_get() -> None:
    """PUT a tenant config, GET it back, verify fields match."""
    app = _make_tenant_config_app()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # PUT a config
        put_resp = await client.put(
            f"/v1/tenants/{TENANT_A}/config/",
            json={
                "scope_rules": [
                    {"rule_type": "apex_domain", "value": "example.com"}
                ],
                "enabled_collectors": ["ct-crtsh", "rdap-whois"],
                "egress_profile": "direct",
                "llm_enabled": True,
                "llm_provider": "anthropic",
                "llm_cost_ceiling_per_run": 5.0,
            },
        )
        assert put_resp.status_code == 200
        put_data = put_resp.json()
        assert put_data["tenant_id"] == str(TENANT_A)
        assert len(put_data["scope_rules"]) == 1
        assert put_data["enabled_collectors"] == ["ct-crtsh", "rdap-whois"]
        assert put_data["egress_profile"] == "direct"
        assert put_data["llm_enabled"] is True
        assert put_data["llm_provider"] == "anthropic"
        assert put_data["llm_cost_ceiling_per_run"] == 5.0

        # GET the config back
        get_resp = await client.get(f"/v1/tenants/{TENANT_A}/config/")
        assert get_resp.status_code == 200
        get_data = get_resp.json()
        assert get_data["tenant_id"] == str(TENANT_A)
        assert get_data["enabled_collectors"] == ["ct-crtsh", "rdap-whois"]
        assert get_data["llm_enabled"] is True
        assert get_data["llm_cost_ceiling_per_run"] == 5.0


# === 8. Tenant config PATCH ===================================================


async def test_tenant_config_patch() -> None:
    """PATCH updates only the specified fields; others are preserved."""
    app = _make_tenant_config_app()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # PUT initial config
        await client.put(
            f"/v1/tenants/{TENANT_A}/config/",
            json={
                "enabled_collectors": ["ct-crtsh", "rdap-whois"],
                "egress_profile": "direct",
                "llm_enabled": False,
                "llm_cost_ceiling_per_run": 10.0,
            },
        )

        # PATCH only llm_enabled
        patch_resp = await client.patch(
            f"/v1/tenants/{TENANT_A}/config/",
            json={"llm_enabled": True},
        )
        assert patch_resp.status_code == 200
        patch_data = patch_resp.json()

        # Changed field
        assert patch_data["llm_enabled"] is True

        # Preserved fields
        assert patch_data["enabled_collectors"] == ["ct-crtsh", "rdap-whois"]
        assert patch_data["egress_profile"] == "direct"
        assert patch_data["llm_cost_ceiling_per_run"] == 10.0


# === 9. Tenant config independence ============================================


async def test_tenant_config_independence() -> None:
    """Two tenants have independent configurations."""
    app = _make_tenant_config_app()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # PUT config for tenant A
        await client.put(
            f"/v1/tenants/{TENANT_A}/config/",
            json={"llm_enabled": True, "egress_profile": "socks5"},
        )

        # PUT config for tenant B
        await client.put(
            f"/v1/tenants/{TENANT_B}/config/",
            json={"llm_enabled": False, "egress_profile": "direct"},
        )

        # Verify independence
        a_resp = await client.get(f"/v1/tenants/{TENANT_A}/config/")
        b_resp = await client.get(f"/v1/tenants/{TENANT_B}/config/")

        a_data = a_resp.json()
        b_data = b_resp.json()

        assert a_data["llm_enabled"] is True
        assert a_data["egress_profile"] == "socks5"

        assert b_data["llm_enabled"] is False
        assert b_data["egress_profile"] == "direct"


# === 10. Egress profile factory ===============================================


async def test_egress_profile_factory() -> None:
    """Create all 4 profile types via the factory, verify types."""
    direct = create_egress_profile("direct")
    assert isinstance(direct, DirectEgressProfile)
    assert direct.profile_type == EgressProfileType.DIRECT

    socks5 = create_egress_profile("socks5", proxy_url="socks5://10.0.0.1:1080")
    assert isinstance(socks5, Socks5EgressProfile)
    assert socks5.profile_type == EgressProfileType.SOCKS5

    wireguard = create_egress_profile("wireguard", interface_name="wg0")
    assert isinstance(wireguard, WireguardEgressProfile)
    assert wireguard.profile_type == EgressProfileType.WIREGUARD

    http_connect = create_egress_profile(
        "http_connect", proxy_url="http://proxy:3128"
    )
    assert isinstance(http_connect, HttpConnectEgressProfile)
    assert http_connect.profile_type == EgressProfileType.HTTP_CONNECT

    # Invalid type raises ValueError
    with pytest.raises(ValueError, match="Unknown egress profile type"):
        create_egress_profile("nonexistent")


# === 11. Egress SOCKS5 DNS through proxy ======================================


@patch("expose.egress.socks5._socksio_available", return_value=True)
async def test_egress_socks5_dns_rewriting(_mock_socksio: Any) -> None:
    """Verify socks5:// is rewritten to socks5h:// when dns_through_proxy=True."""
    profile = Socks5EgressProfile(
        proxy_url="socks5://10.0.0.1:1080",
        dns_through_proxy=True,
    )
    kwargs = profile.configure_httpx_client()
    assert kwargs["proxy"] == "socks5h://10.0.0.1:1080"

    # DNS resolver should signal skip (empty nameservers)
    dns_kwargs = profile.configure_dns_resolver()
    assert dns_kwargs["nameservers"] == []

    # With dns_through_proxy=False, scheme stays as-is
    profile_no_dns = Socks5EgressProfile(
        proxy_url="socks5://10.0.0.1:1080",
        dns_through_proxy=False,
    )
    kwargs_no_dns = profile_no_dns.configure_httpx_client()
    assert kwargs_no_dns["proxy"] == "socks5://10.0.0.1:1080"

    dns_kwargs_no = profile_no_dns.configure_dns_resolver()
    assert dns_kwargs_no == {}


# === 12. Egress health check (direct) ========================================


async def test_egress_direct_health_check() -> None:
    """DirectEgressProfile health check returns healthy."""
    profile = DirectEgressProfile()
    health = await profile.health_check()

    assert health.healthy is True
    assert health.profile_type == EgressProfileType.DIRECT
    assert health.error_message is None
    assert health.latency_ms is not None
    assert health.checked_at is not None


# === 13. Egress health check (SOCKS5 unreachable) ============================


async def test_egress_socks5_health_check_unreachable() -> None:
    """SOCKS5 profile pointing at an unused port reports unhealthy."""
    profile = Socks5EgressProfile(
        proxy_url="socks5://127.0.0.1:19999",  # unlikely to have a listener
        dns_through_proxy=True,
    )
    health = await profile.health_check()

    assert health.healthy is False
    assert health.profile_type == EgressProfileType.SOCKS5
    assert health.error_message is not None
    assert health.checked_at is not None


# === 14. NatsDispatcherResult serialization ===================================


async def test_nats_dispatcher_result_round_trip() -> None:
    """NatsDispatcherResult serializes to bytes and back."""
    original = NatsDispatcherResult(
        status="completed",
        observations=[_make_observation()],
        error_message=None,
        duration_ms=55.5,
    )
    wire_bytes = original.to_bytes()
    restored = NatsDispatcherResult.from_bytes(wire_bytes)

    assert restored.status == original.status
    assert len(restored.observations) == 1
    assert restored.duration_ms == original.duration_ms
    assert restored.error_message is None


# === 15. NatsDispatcher deserialization error ==================================


async def test_nats_dispatcher_bad_response() -> None:
    """If the worker sends unparseable bytes, dispatcher returns an error result."""
    mock_response = MagicMock()
    mock_response.data = b"not valid json at all"

    raw_nats = AsyncMock()
    raw_nats.request = AsyncMock(return_value=mock_response)

    mock_client = MagicMock()
    mock_client._client = raw_nats

    dispatcher = NatsDispatcher(mock_client, timeout_seconds=10.0)
    job = _make_dispatch_job()

    result = await dispatcher.dispatch(job)

    assert result.status == "collector_error"
    assert "deserialization failed" in (result.error_message or "")

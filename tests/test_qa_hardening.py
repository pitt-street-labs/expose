"""QA Gate 1 hardening tests — verifying fixes for the silent failure audit.

Covers the highest-priority findings from the audit:

NATS dispatcher (Findings 1, 3):
1. Dropped observations downgrade wire status to "partial" when all dropped.
2. Dropped observations include drop count in error_message.
3. Timeout exception returns a proper timeout result.
4. asyncio.CancelledError propagates (not swallowed).

Scheduler (Finding 5):
5. consecutive_failures incremented on callback failure.
6. Auto-disable after 5 consecutive failures.
7. Success resets consecutive_failures and last_error.
8. last_error populated on failure.
9. last_run_at NOT set on failure (only last_attempted_at).

Tenant config (Finding 7):
10. Invalid cron expression returns 422 on PUT.
11. Invalid cron expression returns 422 on PATCH.
12. Valid cron expression accepted on PUT.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from nats.errors import TimeoutError as NatsTimeoutError

from expose.api import tenant_config
from expose.collectors.base import (
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.pipeline.nats_dispatcher import (
    NatsDispatcher,
    NatsDispatcherResult,
)
from expose.pipeline.run_executor import DispatchJob
from expose.pipeline.scheduler import RunScheduler, ScheduleEntry
from expose.types.canonical import ExtendedIdentifierType

# Suppress testcontainers DeprecationWarnings (consistent with test_broker.py).
pytestmark = [
    pytest.mark.filterwarnings("default::DeprecationWarning"),
]

# === Synthetic IDs ============================================================

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000F001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000F002")
TENANT_A = UUID("018f1f00-0000-7000-8000-00000000F003")

_NOW = datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)


# === NATS dispatcher helpers ==================================================


def _make_seed() -> Seed:
    return Seed(seed_type=SeedType.DOMAIN, value="acme.example")


def _make_dispatch_job() -> DispatchJob:
    return DispatchJob(
        collector_id="ct-crtsh",
        seed=_make_seed(),
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
    )


def _make_observation() -> Observation:
    return Observation(
        collector_id="ct-crtsh",
        collector_version="1.0.0",
        tenant_id=TENANT_ID,
        observation_type=ObservationType.CT_LOG_ENTRY,
        subject=ObservationSubject(
            identifier_type=ExtendedIdentifierType.DOMAIN,
            identifier_value="acme.example",
        ),
        observed_at=_NOW,
    )


def _mock_broker_client(*, response_data: bytes | None = None) -> MagicMock:
    mock_client = MagicMock()
    mock_raw = AsyncMock()
    mock_client._client = mock_raw
    if response_data is not None:
        reply_msg = SimpleNamespace(data=response_data)
        mock_raw.request = AsyncMock(return_value=reply_msg)
    return mock_client


# === NATS dispatcher: dropped observations (Finding 1) ========================


class TestNatsDispatcherDroppedObservations:
    """Verify that dropped observations are tracked and status is downgraded."""

    async def test_all_dropped_downgrades_to_partial(self) -> None:
        """When ALL observations fail validation and wire status was 'success',
        the result status should be downgraded to 'partial'."""
        # Build a wire result with an invalid observation dict (missing required fields).
        wire_result = NatsDispatcherResult(
            status="success",
            observations=[{"bad_key": "bad_value"}],
            duration_ms=10.0,
        )
        mock_client = _mock_broker_client(response_data=wire_result.to_bytes())
        dispatcher = NatsDispatcher(mock_client, timeout_seconds=5.0)

        job = _make_dispatch_job()
        result = await dispatcher.dispatch(job)

        assert result.status == "partial"
        assert result.observations == []
        assert result.error_message is not None
        assert "dropped" in result.error_message
        assert "1" in result.error_message

    async def test_some_dropped_preserves_status(self) -> None:
        """When SOME observations drop but not all, status stays as wire status
        but error_message includes the drop count."""
        good_obs = _make_observation().model_dump(mode="json")
        wire_result = NatsDispatcherResult(
            status="success",
            observations=[good_obs, {"bad_key": "bad_value"}],
            duration_ms=10.0,
        )
        mock_client = _mock_broker_client(response_data=wire_result.to_bytes())
        dispatcher = NatsDispatcher(mock_client, timeout_seconds=5.0)

        job = _make_dispatch_job()
        result = await dispatcher.dispatch(job)

        # Status stays "success" because not ALL were dropped.
        assert result.status == "success"
        assert len(result.observations) == 1
        assert result.error_message is not None
        assert "dropped 1" in result.error_message

    async def test_all_dropped_returns_collector_error_when_wire_not_success(self) -> None:
        """When wire status was already not 'success' and all drop,
        the wire status is preserved (not downgraded further)."""
        wire_result = NatsDispatcherResult(
            status="collector_error",
            observations=[{"bad_key": "bad_value"}],
            error_message="upstream failure",
            duration_ms=10.0,
        )
        mock_client = _mock_broker_client(response_data=wire_result.to_bytes())
        dispatcher = NatsDispatcher(mock_client, timeout_seconds=5.0)

        job = _make_dispatch_job()
        result = await dispatcher.dispatch(job)

        assert result.status == "collector_error"
        assert result.error_message is not None
        assert "upstream failure" in result.error_message
        assert "dropped" in result.error_message


# === NATS dispatcher: specific exception types (Finding 3) ====================


class TestNatsDispatcherExceptionHandling:
    """Verify that specific NATS exception types produce correct results."""

    async def test_timeout_exception_returns_timeout_result(self) -> None:
        """NatsTimeoutError should produce a result with error_message='timeout'."""
        mock_client = _mock_broker_client()
        mock_client._client.request = AsyncMock(side_effect=NatsTimeoutError)
        dispatcher = NatsDispatcher(mock_client, timeout_seconds=0.1)

        job = _make_dispatch_job()
        result = await dispatcher.dispatch(job)

        assert result.status == "collector_error"
        assert result.error_message == "timeout"
        assert result.duration_ms > 0

    async def test_cancelled_error_propagates(self) -> None:
        """asyncio.CancelledError must propagate, not be caught."""
        mock_client = _mock_broker_client()
        mock_client._client.request = AsyncMock(side_effect=asyncio.CancelledError)
        dispatcher = NatsDispatcher(mock_client, timeout_seconds=5.0)

        job = _make_dispatch_job()
        with pytest.raises(asyncio.CancelledError):
            await dispatcher.dispatch(job)

    async def test_connection_error_returns_error_result(self) -> None:
        """Connection-level errors should produce a collector_error result."""
        mock_client = _mock_broker_client()
        mock_client._client.request = AsyncMock(
            side_effect=ConnectionError("connection refused"),
        )
        dispatcher = NatsDispatcher(mock_client, timeout_seconds=5.0)

        job = _make_dispatch_job()
        result = await dispatcher.dispatch(job)

        assert result.status == "collector_error"
        assert "connection refused" in result.error_message


# === Scheduler: failure tracking (Finding 5) ==================================


class TestSchedulerFailureTracking:
    """Verify that ScheduleEntry tracks consecutive failures correctly."""

    def _make_scheduler(self, callback: AsyncMock | None = None) -> RunScheduler:
        return RunScheduler(on_run_trigger=callback or AsyncMock())

    def test_schedule_entry_has_failure_fields(self) -> None:
        """ScheduleEntry should have consecutive_failures and last_error fields."""
        entry = ScheduleEntry(
            tenant_id=TENANT_A,
            cron_expression="0 2 * * *",
        )
        assert entry.consecutive_failures == 0
        assert entry.last_error is None
        assert entry.last_attempted_at is None

    async def test_consecutive_failures_incremented(self) -> None:
        """When the callback fails, consecutive_failures should increment."""
        callback = AsyncMock(side_effect=RuntimeError("boom"))
        sched = self._make_scheduler(callback)

        sched.add_schedule(TENANT_A, "0 2 * * *", ["whois"], [])

        # Force next_run_at into the past so it fires immediately.
        entry = sched.get_schedule(TENANT_A)
        assert entry is not None
        sched._schedules[TENANT_A] = entry.model_copy(
            update={"next_run_at": datetime(2026, 5, 10, 2, 0, 0, tzinfo=UTC)},
        )

        shutdown = asyncio.Event()

        async def stop_soon() -> None:
            await asyncio.sleep(0.05)
            shutdown.set()

        with patch("expose.pipeline.scheduler._CHECK_INTERVAL_SECONDS", 0.01):
            await asyncio.gather(sched.run(shutdown), stop_soon())

        updated = sched.get_schedule(TENANT_A)
        assert updated is not None
        assert updated.consecutive_failures == 1
        assert updated.last_error == "boom"

    async def test_last_run_at_not_set_on_failure(self) -> None:
        """On failure, last_run_at should NOT be updated (only last_attempted_at)."""
        callback = AsyncMock(side_effect=RuntimeError("oops"))
        sched = self._make_scheduler(callback)

        sched.add_schedule(TENANT_A, "0 2 * * *", ["whois"], [])

        entry = sched.get_schedule(TENANT_A)
        assert entry is not None
        sched._schedules[TENANT_A] = entry.model_copy(
            update={"next_run_at": datetime(2026, 5, 10, 2, 0, 0, tzinfo=UTC)},
        )

        shutdown = asyncio.Event()

        async def stop_soon() -> None:
            await asyncio.sleep(0.05)
            shutdown.set()

        with patch("expose.pipeline.scheduler._CHECK_INTERVAL_SECONDS", 0.01):
            await asyncio.gather(sched.run(shutdown), stop_soon())

        updated = sched.get_schedule(TENANT_A)
        assert updated is not None
        assert updated.last_run_at is None
        assert updated.last_attempted_at is not None

    async def test_auto_disable_after_5_failures(self) -> None:
        """After 5 consecutive failures, the schedule should be auto-disabled."""
        callback = AsyncMock(side_effect=RuntimeError("persistent failure"))
        sched = self._make_scheduler(callback)

        sched.add_schedule(TENANT_A, "0 2 * * *", ["whois"], [])

        # Pre-load 4 failures so the next one triggers the auto-disable.
        entry = sched.get_schedule(TENANT_A)
        assert entry is not None
        sched._schedules[TENANT_A] = entry.model_copy(
            update={
                "next_run_at": datetime(2026, 5, 10, 2, 0, 0, tzinfo=UTC),
                "consecutive_failures": 4,
            },
        )

        shutdown = asyncio.Event()

        async def stop_soon() -> None:
            await asyncio.sleep(0.05)
            shutdown.set()

        with patch("expose.pipeline.scheduler._CHECK_INTERVAL_SECONDS", 0.01):
            await asyncio.gather(sched.run(shutdown), stop_soon())

        updated = sched.get_schedule(TENANT_A)
        assert updated is not None
        assert updated.enabled is False
        assert updated.consecutive_failures == 5

    async def test_success_resets_consecutive_failures(self) -> None:
        """Successful callback should reset consecutive_failures to 0."""
        callback = AsyncMock()
        sched = self._make_scheduler(callback)

        sched.add_schedule(TENANT_A, "0 2 * * *", ["whois"], [])

        # Pre-load some failures.
        entry = sched.get_schedule(TENANT_A)
        assert entry is not None
        sched._schedules[TENANT_A] = entry.model_copy(
            update={
                "next_run_at": datetime(2026, 5, 10, 2, 0, 0, tzinfo=UTC),
                "consecutive_failures": 3,
                "last_error": "previous error",
            },
        )

        shutdown = asyncio.Event()

        async def stop_soon() -> None:
            await asyncio.sleep(0.05)
            shutdown.set()

        with patch("expose.pipeline.scheduler._CHECK_INTERVAL_SECONDS", 0.01):
            await asyncio.gather(sched.run(shutdown), stop_soon())

        updated = sched.get_schedule(TENANT_A)
        assert updated is not None
        assert updated.consecutive_failures == 0
        assert updated.last_error is None
        assert updated.last_run_at is not None


# === Tenant config: cron validation (Finding 7) ===============================


def _make_app() -> Any:
    from fastapi import FastAPI  # noqa: PLC0415

    app = FastAPI()
    app.include_router(tenant_config.router)
    return app


@pytest.fixture
def _clear_config_store() -> None:
    tenant_config._configs.clear()


@pytest.fixture
async def config_client(_clear_config_store: None) -> AsyncClient:
    app = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac  # type: ignore[misc]


class TestTenantConfigCronValidation:
    """Verify that invalid cron expressions are rejected with 422."""

    async def test_invalid_cron_put_returns_422(
        self, config_client: AsyncClient
    ) -> None:
        tid = uuid4()
        resp = await config_client.put(
            f"/v1/tenants/{tid}/config/",
            json={"schedule_cron": "not a cron"},
        )
        assert resp.status_code == 422
        assert "cron" in resp.json()["detail"].lower()

    async def test_invalid_cron_patch_returns_422(
        self, config_client: AsyncClient
    ) -> None:
        tid = uuid4()
        resp = await config_client.patch(
            f"/v1/tenants/{tid}/config/",
            json={"schedule_cron": "* * *"},
        )
        assert resp.status_code == 422

    async def test_valid_cron_accepted_put(
        self, config_client: AsyncClient
    ) -> None:
        tid = uuid4()
        resp = await config_client.put(
            f"/v1/tenants/{tid}/config/",
            json={"schedule_cron": "0 2 * * *"},
        )
        assert resp.status_code == 200
        assert resp.json()["schedule_cron"] == "0 2 * * *"

    async def test_valid_cron_accepted_patch(
        self, config_client: AsyncClient
    ) -> None:
        tid = uuid4()
        resp = await config_client.patch(
            f"/v1/tenants/{tid}/config/",
            json={"schedule_cron": "*/5 * * * *"},
        )
        assert resp.status_code == 200
        assert resp.json()["schedule_cron"] == "*/5 * * * *"

"""Tests for the run log accumulator and API endpoint.

Coverage:

1.  emit_log stores entries keyed by run_id.
2.  get_run_log_entries returns entries since offset.
3.  get_run_log_entries returns empty list for unknown run_id.
4.  Log entries are capped at MAX_ENTRIES_PER_RUN.
5.  clear_run_log removes all entries.
6.  make_log_sink creates a callable bound to a run_id.
7.  Log entries have correct structure (ts, level, msg).
8.  API endpoint returns correct response format.
9.  API endpoint since parameter filters entries.
10. RunExecutor with log_sink emits log entries during execution.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient

from expose.api.run_log import (
    _MAX_ENTRIES_PER_RUN,
    _run_logs,
    clear_run_log,
    emit_log,
    get_run_log_entries,
    make_log_sink,
)
from expose.collectors.base import (
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.pipeline.run_executor import (
    DispatchResult,
    RunExecutor,
)
from expose.types.canonical import IdentifierType

# === Synthetic IDs ============================================================

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000B001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000B002")
OBSERVED = datetime(2026, 5, 11, 10, 0, 0, tzinfo=UTC)


# === Fixtures =================================================================


@pytest.fixture(autouse=True)
def _clean_run_logs():
    """Ensure module-level storage is empty before/after each test."""
    _run_logs.clear()
    yield
    _run_logs.clear()


# === Unit tests — emit_log / get_run_log_entries / clear_run_log =============


def test_emit_log_stores_entry() -> None:
    """emit_log appends an entry with ts, level, and msg."""
    emit_log("run-1", "info", "test message")
    entries, total = get_run_log_entries("run-1")
    assert total == 1
    assert len(entries) == 1
    assert entries[0]["level"] == "info"
    assert entries[0]["msg"] == "test message"
    assert "ts" in entries[0]


def test_emit_log_multiple_entries() -> None:
    """Multiple emit_log calls accumulate in order."""
    emit_log("run-1", "info", "first")
    emit_log("run-1", "warn", "second")
    emit_log("run-1", "error", "third")
    entries, total = get_run_log_entries("run-1")
    assert total == 3
    assert [e["msg"] for e in entries] == ["first", "second", "third"]
    assert [e["level"] for e in entries] == ["info", "warn", "error"]


def test_get_run_log_entries_since_offset() -> None:
    """since parameter returns only entries after the offset."""
    for i in range(5):
        emit_log("run-1", "info", f"msg-{i}")

    entries, total = get_run_log_entries("run-1", since=3)
    assert total == 5
    assert len(entries) == 2
    assert entries[0]["msg"] == "msg-3"
    assert entries[1]["msg"] == "msg-4"


def test_get_run_log_entries_since_beyond_total() -> None:
    """When since >= total, returns empty list."""
    emit_log("run-1", "info", "only one")
    entries, total = get_run_log_entries("run-1", since=5)
    assert total == 1
    assert entries == []


def test_get_run_log_entries_unknown_run() -> None:
    """Unknown run_id returns empty list with total=0."""
    entries, total = get_run_log_entries("nonexistent-run")
    assert total == 0
    assert entries == []


def test_emit_log_cap_at_max_entries() -> None:
    """Entries are capped at _MAX_ENTRIES_PER_RUN, dropping oldest."""
    for i in range(_MAX_ENTRIES_PER_RUN + 50):
        emit_log("run-1", "info", f"msg-{i}")

    entries, total = get_run_log_entries("run-1")
    assert total == _MAX_ENTRIES_PER_RUN
    # Oldest 50 entries should have been dropped
    assert entries[0]["msg"] == "msg-50"
    assert entries[-1]["msg"] == f"msg-{_MAX_ENTRIES_PER_RUN + 49}"


def test_clear_run_log() -> None:
    """clear_run_log removes all entries for a run."""
    emit_log("run-1", "info", "test")
    assert get_run_log_entries("run-1")[1] == 1

    clear_run_log("run-1")
    entries, total = get_run_log_entries("run-1")
    assert total == 0
    assert entries == []


def test_clear_run_log_idempotent() -> None:
    """clear_run_log on non-existent run does not raise."""
    clear_run_log("never-existed")  # should not raise


def test_separate_run_ids_isolated() -> None:
    """Entries for different run_ids do not interfere."""
    emit_log("run-a", "info", "alpha")
    emit_log("run-b", "warn", "beta")

    a_entries, a_total = get_run_log_entries("run-a")
    b_entries, b_total = get_run_log_entries("run-b")
    assert a_total == 1
    assert b_total == 1
    assert a_entries[0]["msg"] == "alpha"
    assert b_entries[0]["msg"] == "beta"


# === make_log_sink tests =====================================================


def test_make_log_sink_creates_callable() -> None:
    """make_log_sink returns a callable that appends to the correct run."""
    sink = make_log_sink(RUN_ID)
    sink("info", "sink test")
    entries, total = get_run_log_entries(str(RUN_ID))
    assert total == 1
    assert entries[0]["msg"] == "sink test"


def test_make_log_sink_accepts_uuid() -> None:
    """make_log_sink accepts a UUID object and converts to str internally."""
    sink = make_log_sink(RUN_ID)
    sink("warn", "warning from uuid")
    entries, _ = get_run_log_entries(str(RUN_ID))
    assert entries[0]["level"] == "warn"


# === Entry structure tests ====================================================


def test_entry_ts_is_iso_format() -> None:
    """Log entry ts field is a valid ISO 8601 timestamp."""
    emit_log("run-1", "info", "timestamp test")
    entries, _ = get_run_log_entries("run-1")
    ts = entries[0]["ts"]
    # Should parse without error
    parsed = datetime.fromisoformat(ts)
    assert parsed.tzinfo is not None  # UTC timezone aware


# === API endpoint tests (via TestClient) ======================================


@pytest.fixture
def _app():
    """Create a minimal FastAPI app with the run_log router."""
    from fastapi import FastAPI

    from expose.api.run_log import router

    app = FastAPI()
    app.include_router(router)
    return app


async def test_api_endpoint_returns_entries(_app) -> None:
    """GET /v1/tenants/{tid}/runs/{rid}/log returns entries."""
    emit_log(str(RUN_ID), "info", "api test")

    async with AsyncClient(
        transport=ASGITransport(app=_app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            f"/v1/tenants/{TENANT_ID}/runs/{RUN_ID}/log"
        )

    assert resp.status_code == 200
    data = resp.json()
    assert "entries" in data
    assert "total" in data
    assert data["total"] == 1
    assert len(data["entries"]) == 1
    assert data["entries"][0]["msg"] == "api test"


async def test_api_endpoint_since_param(_app) -> None:
    """GET /log?since=N returns only entries after offset N."""
    for i in range(5):
        emit_log(str(RUN_ID), "info", f"entry-{i}")

    async with AsyncClient(
        transport=ASGITransport(app=_app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            f"/v1/tenants/{TENANT_ID}/runs/{RUN_ID}/log?since=3"
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5
    assert len(data["entries"]) == 2
    assert data["entries"][0]["msg"] == "entry-3"


async def test_api_endpoint_empty_run(_app) -> None:
    """GET /log for a run with no entries returns empty list."""
    async with AsyncClient(
        transport=ASGITransport(app=_app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            f"/v1/tenants/{TENANT_ID}/runs/{RUN_ID}/log"
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["entries"] == []
    assert data["total"] == 0


# === Integration: RunExecutor with log_sink ==================================


def _make_observation(
    identifier_value: str = "example.com",
) -> Observation:
    return Observation(
        collector_id="test-collector",
        collector_version="1.0.0",
        tenant_id=TENANT_ID,
        observation_type=ObservationType.DNS_RESOLUTION,
        subject=ObservationSubject(
            identifier_type=IdentifierType.DOMAIN,
            identifier_value=identifier_value,
        ),
        observed_at=OBSERVED,
        structured_payload={"resolved_ip": "93.184.216.34"},
    )


def _make_run_row(state: str = "pending") -> MagicMock:
    row = MagicMock()
    row.id = RUN_ID
    row.tenant_id = TENANT_ID
    row.state = state
    return row


async def test_executor_emits_log_entries_with_sink() -> None:
    """RunExecutor with a log_sink emits structured log entries during execution."""
    log_sink = make_log_sink(RUN_ID)

    disp = AsyncMock()
    obs = _make_observation()
    disp.dispatch = AsyncMock(
        return_value=DispatchResult(
            status="success",
            observations=[obs],
            duration_ms=100.0,
        )
    )

    r_repo = AsyncMock()
    r_repo.get_by_id = AsyncMock(return_value=_make_run_row("pending"))
    r_repo.update_state = AsyncMock()

    e_repo = AsyncMock()
    e_repo.create_or_update = AsyncMock(return_value=MagicMock())

    executor = RunExecutor(
        dispatcher=disp,
        run_repo=r_repo,
        entity_repo=e_repo,
        log_sink=log_sink,
    )

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["test-collector"],
    )

    assert result.final_state == "completed"

    entries, total = get_run_log_entries(str(RUN_ID))
    assert total > 0

    # Verify key log entry types are present
    messages = [e["msg"] for e in entries]
    # Should have: run started, seed expansion, dispatching, completed, entity, run completed
    assert any("Run started" in m for m in messages)
    assert any("Seed expansion" in m for m in messages)
    assert any("Dispatching" in m for m in messages)
    assert any("completed" in m.lower() for m in messages)
    assert any("New entity" in m for m in messages)

    # All entries should be "info" level for a successful run
    levels = {e["level"] for e in entries}
    assert levels == {"info"}


async def test_executor_without_log_sink_works_normally() -> None:
    """RunExecutor without log_sink works exactly as before (backward compat)."""
    disp = AsyncMock()
    disp.dispatch = AsyncMock(
        return_value=DispatchResult(
            status="success",
            observations=[_make_observation()],
            duration_ms=50.0,
        )
    )

    r_repo = AsyncMock()
    r_repo.get_by_id = AsyncMock(return_value=_make_run_row("pending"))
    r_repo.update_state = AsyncMock()

    e_repo = AsyncMock()
    e_repo.create_or_update = AsyncMock(return_value=MagicMock())

    executor = RunExecutor(
        dispatcher=disp,
        run_repo=r_repo,
        entity_repo=e_repo,
        # No log_sink — should work without errors
    )

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["test-collector"],
    )

    assert result.final_state == "completed"
    # No entries should have been stored (no sink)
    entries, total = get_run_log_entries(str(RUN_ID))
    assert total == 0


async def test_executor_logs_dispatch_failure() -> None:
    """RunExecutor logs failures with warn/error level via log_sink."""
    log_sink = make_log_sink(RUN_ID)

    disp = AsyncMock()
    disp.dispatch = AsyncMock(
        return_value=DispatchResult(
            status="collector_error",
            error_message="timeout connecting",
            duration_ms=5000.0,
        )
    )

    r_repo = AsyncMock()
    r_repo.get_by_id = AsyncMock(return_value=_make_run_row("pending"))
    r_repo.update_state = AsyncMock()

    e_repo = AsyncMock()
    e_repo.create_or_update = AsyncMock(return_value=MagicMock())

    executor = RunExecutor(
        dispatcher=disp,
        run_repo=r_repo,
        entity_repo=e_repo,
        log_sink=log_sink,
    )

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["test-collector"],
    )

    assert result.final_state == "failed"

    entries, total = get_run_log_entries(str(RUN_ID))
    assert total > 0

    # Should have a "warn" level entry for the failure
    warn_entries = [e for e in entries if e["level"] == "warn"]
    assert len(warn_entries) >= 1
    assert any("failed" in e["msg"].lower() for e in warn_entries)


async def test_executor_logs_dispatch_exception() -> None:
    """RunExecutor logs dispatcher exceptions as error level."""
    log_sink = make_log_sink(RUN_ID)

    disp = AsyncMock()
    disp.dispatch = AsyncMock(side_effect=RuntimeError("connection refused"))

    r_repo = AsyncMock()
    r_repo.get_by_id = AsyncMock(return_value=_make_run_row("pending"))
    r_repo.update_state = AsyncMock()

    e_repo = AsyncMock()
    e_repo.create_or_update = AsyncMock(return_value=MagicMock())

    executor = RunExecutor(
        dispatcher=disp,
        run_repo=r_repo,
        entity_repo=e_repo,
        log_sink=log_sink,
    )

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["test-collector"],
    )

    assert result.final_state == "failed"

    entries, _ = get_run_log_entries(str(RUN_ID))
    # Dispatch exceptions are logged at "warn" level with "dispatch exception"
    warn_entries = [e for e in entries if e["level"] == "warn"]
    assert len(warn_entries) >= 1
    assert any("dispatch exception" in e["msg"] for e in warn_entries)


# === Scan Estimate endpoint tests =============================================


async def test_scan_estimate_defaults(_app) -> None:
    """GET /v1/admin/scan-estimate with defaults returns expected structure."""
    async with AsyncClient(
        transport=ASGITransport(app=_app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/v1/admin/scan-estimate")

    assert resp.status_code == 200
    data = resp.json()
    assert "estimated_seconds" in data
    assert "total_dispatches" in data
    # Default: 1 seed * 13 collectors = 13 dispatches
    assert data["total_dispatches"] == 13
    # 13 dispatches / 15 parallel = ceil(13/15) = 1 batch * 3.0s = 3.0s
    assert data["estimated_seconds"] == 3.0


async def test_scan_estimate_custom_params(_app) -> None:
    """GET /v1/admin/scan-estimate with custom seed_count and collector_count."""
    async with AsyncClient(
        transport=ASGITransport(app=_app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            "/v1/admin/scan-estimate?seed_count=5&collector_count=20"
        )

    assert resp.status_code == 200
    data = resp.json()
    # 5 seeds * 20 collectors = 100 dispatches
    assert data["total_dispatches"] == 100
    # 100 / 15 = ceil(6.67) = 7 batches * 3.0s = 21.0s
    assert data["estimated_seconds"] == 21.0


async def test_scan_estimate_single_batch(_app) -> None:
    """Scan with dispatches <= parallel_factor fits in a single batch."""
    async with AsyncClient(
        transport=ASGITransport(app=_app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            "/v1/admin/scan-estimate?seed_count=1&collector_count=15"
        )

    assert resp.status_code == 200
    data = resp.json()
    # 15 dispatches / 15 parallel = exactly 1 batch
    assert data["total_dispatches"] == 15
    assert data["estimated_seconds"] == 3.0


async def test_scan_estimate_large_scan(_app) -> None:
    """Large scan with many seeds and collectors."""
    async with AsyncClient(
        transport=ASGITransport(app=_app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            "/v1/admin/scan-estimate?seed_count=10&collector_count=29"
        )

    assert resp.status_code == 200
    data = resp.json()
    # 10 * 29 = 290 dispatches
    assert data["total_dispatches"] == 290
    # ceil(290/15) = 20 batches * 3.0s = 60.0s
    assert data["estimated_seconds"] == 60.0

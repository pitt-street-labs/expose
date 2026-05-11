"""Tests for the RunExecutor pipeline orchestrator.

All tests use ``unittest.mock.AsyncMock`` for the dispatcher, run repository,
and entity repository — the executor is tested in isolation from real databases
and real dispatchers.

Coverage:

1.  Happy path: seeds dispatched, observations upserted, run completed.
2.  Partial failure: some dispatches fail -> run state = ``partial``.
3.  All dispatches fail -> run state = ``failed``.
4.  Tier-3 denied dispatches counted separately.
5.  State machine: ``pending -> running -> completed``.
6.  Duration measured (non-zero).
7.  Seed expansion integrated: ``www.domain`` generated.
8.  Empty seeds: run completes immediately with zero stats.
9.  Verify ``entity_repo.create_or_update`` called for each observation.
10. Dispatcher exception: counted as failure, does not crash the run.
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest

from expose.collectors.base import (
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.compliance.misuse_detection import (
    MisuseAlert,
    MisuseDetector,
    MisuseIndicator,
)
from expose.pipeline.run_executor import (
    DispatchResult,
    RunExecutor,
)
from expose.quotas.models import TenantQuota
from expose.quotas.tracker import QuotaTracker
from expose.types.canonical import IdentifierType

# === Synthetic IDs ============================================================

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000A001")
RUN_ID = UUID("018f1f00-0000-7000-8000-000000000001")
OBSERVED = datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)


# === Fixtures ================================================================


@pytest.fixture(autouse=True)
def _dns_resolve_all(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make all DNS lookups succeed by default so unit tests never hit the network.

    Individual tests that need to control DNS resolution override this by
    monkeypatching ``socket.getaddrinfo`` themselves (the inner monkeypatch
    wins because pytest processes fixtures before test-level patches).
    """
    def _fake_getaddrinfo(host, port, family=0, type_=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)


# === Helpers ==================================================================


def _make_observation(
    collector_id: str = "test-collector",
    identifier_value: str = "example.com",
) -> Observation:
    """Build a minimal valid Observation for tests."""
    return Observation(
        collector_id=collector_id,
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


def _success_result(*observations: Observation) -> DispatchResult:
    """Build a successful DispatchResult."""
    return DispatchResult(
        status="success",
        observations=list(observations),
        duration_ms=10.0,
    )


def _failed_result(msg: str = "collector error") -> DispatchResult:
    """Build a failed DispatchResult."""
    return DispatchResult(
        status="collector_error",
        error_message=msg,
        duration_ms=5.0,
    )


def _denied_result() -> DispatchResult:
    """Build a denied DispatchResult (Tier-3 gate)."""
    return DispatchResult(
        status="denied",
        error_message="Tier-3 dispatch denied",
        duration_ms=1.0,
    )


def _make_run_row(state: str = "pending") -> MagicMock:
    """Build a mock Run ORM row."""
    row = MagicMock()
    row.id = RUN_ID
    row.tenant_id = TENANT_ID
    row.state = state
    return row


def _build_executor(
    dispatcher: AsyncMock | None = None,
    run_repo: AsyncMock | None = None,
    entity_repo: AsyncMock | None = None,
    run_state: str = "pending",
    quota_tracker: QuotaTracker | None = None,
    misuse_detector: MisuseDetector | None = None,
) -> tuple[RunExecutor, AsyncMock, AsyncMock, AsyncMock]:
    """Wire up a RunExecutor with mocked dependencies.

    Returns (executor, dispatcher_mock, run_repo_mock, entity_repo_mock).
    """
    disp = dispatcher or AsyncMock()
    r_repo = run_repo or AsyncMock()
    e_repo = entity_repo or AsyncMock()

    # Default: get_by_id returns a run row in the requested state
    if not run_repo:
        r_repo.get_by_id = AsyncMock(return_value=_make_run_row(run_state))
        r_repo.update_state = AsyncMock()

    # Default: create_or_update returns a mock entity
    if not entity_repo:
        e_repo.create_or_update = AsyncMock(return_value=MagicMock())

    executor = RunExecutor(
        dispatcher=disp,
        run_repo=r_repo,
        entity_repo=e_repo,
        quota_tracker=quota_tracker,
        misuse_detector=misuse_detector,
    )
    return executor, disp, r_repo, e_repo


# === Tests ====================================================================


async def test_happy_path_completed() -> None:
    """All dispatches succeed -> state = completed, observations upserted."""
    obs = _make_observation()
    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=["dns-resolve"],
    )

    assert result.final_state == "completed"
    assert result.successful_dispatches > 0
    assert result.failed_dispatches == 0
    assert result.total_observations > 0
    assert result.run_id == RUN_ID
    assert result.tenant_id == TENANT_ID


async def test_partial_failure_state() -> None:
    """Some dispatches succeed, some fail -> state = partial."""
    obs = _make_observation()
    executor, disp, _r_repo, _e_repo = _build_executor()
    # Use IP seed (no expansion) with 2 collectors: first succeeds, second fails
    disp.dispatch = AsyncMock(
        side_effect=[_success_result(obs), _failed_result()]
    )

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["passive-dns", "whois"],
    )

    assert result.final_state == "partial"
    assert result.successful_dispatches == 1
    assert result.failed_dispatches == 1


async def test_all_fail_state() -> None:
    """All dispatches fail -> state = failed."""
    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_failed_result())

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    assert result.final_state == "failed"
    assert result.successful_dispatches == 0
    assert result.failed_dispatches == 1


async def test_denied_dispatches_counted_separately() -> None:
    """Tier-3 denied dispatches are counted in denied_dispatches, not failed."""
    obs = _make_observation()
    executor, disp, _r_repo, _e_repo = _build_executor()
    # First succeeds, second denied
    disp.dispatch = AsyncMock(
        side_effect=[_success_result(obs), _denied_result()]
    )

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["passive-dns", "active-tls"],
    )

    assert result.denied_dispatches == 1
    assert result.successful_dispatches == 1
    assert result.failed_dispatches == 0
    # Denied does not count as failure for state calculation — with one success
    # and one denied (no failures), final state is completed.
    assert result.final_state == "completed"


async def test_state_machine_pending_running_completed() -> None:
    """Verify the state machine transitions through pending -> running -> completed."""
    executor, disp, run_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result(_make_observation()))

    await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=["dns-resolve"],
    )

    # Verify update_state was called twice: pending->running, running->completed
    state_calls = run_repo.update_state.call_args_list
    assert len(state_calls) == 2
    assert state_calls[0].kwargs["new_state"] == "running"
    assert state_calls[1].kwargs["new_state"] == "completed"


async def test_duration_measured() -> None:
    """RunResult.duration_ms is a positive number."""
    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result(_make_observation()))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=["dns-resolve"],
    )

    assert result.duration_ms > 0


async def test_seed_expansion_generates_www() -> None:
    """Seed expansion should generate www.example.com from example.com."""
    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result())

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=["dns-resolve"],
    )

    # 2 seeds (example.com + www.example.com) x 1 collector = 2 dispatches
    assert result.expanded_seeds == 2
    assert result.total_seeds == 1
    assert result.total_dispatches == 2

    # Verify dispatch was called with both the original and expanded seed
    dispatch_calls = disp.dispatch.call_args_list
    dispatched_values = {c.args[0].seed.value for c in dispatch_calls}
    assert "example.com" in dispatched_values
    assert "www.example.com" in dispatched_values


async def test_empty_seeds_completes_immediately() -> None:
    """Empty seed list -> run completes with zero stats."""
    executor, disp, _r_repo, _e_repo = _build_executor()

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[],
        collector_ids=["dns-resolve"],
    )

    assert result.final_state == "completed"
    assert result.total_seeds == 0
    assert result.expanded_seeds == 0
    assert result.total_dispatches == 0
    assert result.total_observations == 0
    # Dispatcher should never have been called
    disp.dispatch.assert_not_called()


async def test_entity_upsert_called_for_each_observation() -> None:
    """entity_repo.create_or_update is called once per observation."""
    obs1 = _make_observation(identifier_value="a.example.com")
    obs2 = _make_observation(identifier_value="b.example.com")
    executor, disp, _r_repo, e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result(obs1, obs2))

    await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    # 1 seed x 1 collector = 1 dispatch, yielding 2 observations
    assert e_repo.create_or_update.call_count == 2
    upsert_ids = {
        c.kwargs["canonical_identifier"]
        for c in e_repo.create_or_update.call_args_list
    }
    assert upsert_ids == {"a.example.com", "b.example.com"}


async def test_dispatcher_exception_counted_as_failure() -> None:
    """If dispatcher.dispatch raises, it counts as a failure, not a crash."""
    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(side_effect=RuntimeError("boom"))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    assert result.failed_dispatches == 1
    assert result.successful_dispatches == 0
    assert result.final_state == "failed"


async def test_run_not_found_raises_lookup_error() -> None:
    """If the run row does not exist, LookupError is raised."""
    executor, _disp, r_repo, _e_repo = _build_executor()
    r_repo.get_by_id = AsyncMock(return_value=None)

    with pytest.raises(LookupError, match="No run found"):
        await executor.execute(
            run_id=RUN_ID,
            tenant_id=TENANT_ID,
            seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
            collector_ids=["dns-resolve"],
        )


async def test_invalid_state_transition_raises_value_error() -> None:
    """If the run is not in ``pending`` state, starting it raises ValueError."""
    executor, _disp, r_repo, _e_repo = _build_executor(run_state="completed")
    # Override to return a row in 'completed' state
    r_repo.get_by_id = AsyncMock(return_value=_make_run_row("completed"))

    with pytest.raises(ValueError, match="Invalid run state transition"):
        await executor.execute(
            run_id=RUN_ID,
            tenant_id=TENANT_ID,
            seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
            collector_ids=["dns-resolve"],
        )


async def test_empty_collector_ids_completes_with_zero_dispatches() -> None:
    """Seeds with no collector_ids -> run completes with zero dispatches."""
    executor, disp, _r_repo, _e_repo = _build_executor()

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=[],
    )

    assert result.final_state == "completed"
    assert result.total_dispatches == 0
    assert result.expanded_seeds == 2  # expansion still happened
    disp.dispatch.assert_not_called()


async def test_run_result_is_frozen() -> None:
    """RunResult is immutable (Pydantic frozen=True)."""
    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result())

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[],
        collector_ids=[],
    )

    with pytest.raises(Exception):  # noqa: B017
        result.final_state = "hacked"  # type: ignore[misc]


async def test_all_denied_is_failed_state() -> None:
    """When all dispatches are denied (none succeed), state = failed."""
    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_denied_result())

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["active-tls"],
    )

    assert result.denied_dispatches == 1
    assert result.successful_dispatches == 0
    assert result.final_state == "failed"


# === QuotaTracker integration tests ==========================================


async def test_quota_exceeded_fails_run() -> None:
    """When quota_tracker raises QuotaExceededError, run state = failed with zero stats."""
    tracker = QuotaTracker()
    tracker.set_quota(TenantQuota(tenant_id=TENANT_ID, max_runs_per_day=0))

    executor, disp, run_repo, _e_repo = _build_executor(quota_tracker=tracker)

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=["dns-resolve"],
    )

    assert result.final_state == "failed"
    assert result.total_dispatches == 0
    assert result.total_seeds == 0
    assert result.total_observations == 0
    disp.dispatch.assert_not_called()

    state_calls = run_repo.update_state.call_args_list
    states = [c.kwargs["new_state"] for c in state_calls]
    assert states == ["running", "failed"]


async def test_quota_tracker_records_run_lifecycle() -> None:
    """Verify record_run_start and record_run_complete called on normal run."""
    tracker = QuotaTracker()
    executor, disp, _r_repo, _e_repo = _build_executor(quota_tracker=tracker)
    disp.dispatch = AsyncMock(return_value=_success_result())

    await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    usage = tracker.get_usage(TENANT_ID)
    assert usage.runs_today == 1
    assert usage.active_runs == 0


async def test_quota_tracker_records_entities_added() -> None:
    """Verify record_entities_added called with the count of successfully upserted entities."""
    tracker = QuotaTracker()
    obs1 = _make_observation(identifier_value="a.example.com")
    obs2 = _make_observation(identifier_value="b.example.com")
    executor, disp, _r_repo, _e_repo = _build_executor(quota_tracker=tracker)
    disp.dispatch = AsyncMock(return_value=_success_result(obs1, obs2))

    await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    usage = tracker.get_usage(TENANT_ID)
    assert usage.total_entities == 2


async def test_quota_tracker_entities_excludes_upsert_failures() -> None:
    """Entity count only includes successful upserts, not failures."""
    tracker = QuotaTracker()
    obs1 = _make_observation(identifier_value="a.example.com")
    obs2 = _make_observation(identifier_value="b.example.com")

    e_repo = AsyncMock()
    e_repo.create_or_update = AsyncMock(
        side_effect=[MagicMock(), RuntimeError("db error")]
    )

    executor, disp, _r_repo, _e_repo = _build_executor(
        entity_repo=e_repo, quota_tracker=tracker
    )
    disp.dispatch = AsyncMock(return_value=_success_result(obs1, obs2))

    await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    usage = tracker.get_usage(TENANT_ID)
    assert usage.total_entities == 1


async def test_no_quota_tracker_unchanged() -> None:
    """When quota_tracker=None, existing behavior is preserved (no misuse_alerts)."""
    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result(_make_observation()))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=["dns-resolve"],
    )

    assert result.final_state == "completed"
    assert result.misuse_alerts == []


# === MisuseDetector integration tests ========================================


async def test_misuse_detector_called_after_run() -> None:
    """Verify evaluate_run is called with stats from the run."""
    detector = MagicMock(spec=MisuseDetector)
    detector.evaluate_run = MagicMock(return_value=[])

    executor, disp, _r_repo, _e_repo = _build_executor(misuse_detector=detector)
    disp.dispatch = AsyncMock(return_value=_success_result(_make_observation()))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    detector.evaluate_run.assert_called_once()
    call_kwargs = detector.evaluate_run.call_args.kwargs
    assert call_kwargs["tenant_id"] == TENANT_ID
    assert call_kwargs["run_id"] == RUN_ID
    assert call_kwargs["in_scope"] == 1
    assert call_kwargs["out_of_scope"] == 0
    assert call_kwargs["tier3_dispatches"] == 0
    assert call_kwargs["total_dispatches"] == 1
    assert call_kwargs["denied"] == 0
    assert result.final_state == "completed"


async def test_misuse_alerts_in_run_result() -> None:
    """Verify alerts from the detector appear in RunResult.misuse_alerts."""
    alert = MisuseAlert(
        indicator=MisuseIndicator.HIGH_DENIAL_RATE,
        tenant_id=TENANT_ID,
        severity="warning",
        description="test alert",
        evidence={"denied": 5, "total": 10, "denial_rate": 0.5},
        detected_at=datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
        run_id=RUN_ID,
    )
    detector = MagicMock(spec=MisuseDetector)
    detector.evaluate_run = MagicMock(return_value=[alert])

    executor, disp, _r_repo, _e_repo = _build_executor(misuse_detector=detector)
    disp.dispatch = AsyncMock(return_value=_success_result(_make_observation()))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    assert len(result.misuse_alerts) == 1
    assert result.misuse_alerts[0].indicator == MisuseIndicator.HIGH_DENIAL_RATE
    assert result.misuse_alerts[0].severity == "warning"


async def test_misuse_detector_not_called_when_none() -> None:
    """When misuse_detector=None, no misuse evaluation happens."""
    executor, disp, _r_repo, _e_repo = _build_executor(misuse_detector=None)
    disp.dispatch = AsyncMock(return_value=_success_result(_make_observation()))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    assert result.misuse_alerts == []


# === Multi-pass expansion tests =============================================


def _make_entity_mock(
    entity_type: str = "domain",
    canonical_identifier: str = "sub.example.com",
    properties: dict | None = None,
) -> MagicMock:
    """Build a mock Entity ORM row for multi-pass tests."""
    entity = MagicMock()
    entity.entity_type = entity_type
    entity.canonical_identifier = canonical_identifier
    entity.properties = properties or {}
    return entity


async def test_single_pass_no_new_entities() -> None:
    """When no new entities are discovered, only 1 pass executes."""
    obs = _make_observation()
    executor, disp, _r_repo, e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result(obs))
    # list_for_tenant returns empty -> no new seeds -> single pass
    e_repo.list_for_tenant = AsyncMock(return_value=[])

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    assert result.passes_completed == 1
    assert len(result.entities_discovered_per_pass) == 1
    assert result.final_state == "completed"


async def test_multi_pass_entities_feed_back_as_seeds() -> None:
    """Entities discovered in pass 1 feed back as seeds for pass 2."""
    obs_pass1 = _make_observation(identifier_value="10.0.0.1")
    obs_pass2 = _make_observation(identifier_value="sub.example.com")

    executor, disp, _r_repo, e_repo = _build_executor()

    # Use a default return value so all dispatches succeed.
    # Pass 1: IP seed (1 dispatch), Pass 2: domain seed + www. expansion
    # (2 dispatches). Use return_value for unlimited success responses.
    disp.dispatch = AsyncMock(return_value=_success_result(obs_pass1))

    # After pass 1, list_for_tenant returns a new entity; after pass 2, empty
    new_entity = _make_entity_mock(
        entity_type="domain",
        canonical_identifier="sub.example.com",
    )
    e_repo.list_for_tenant = AsyncMock(side_effect=[[new_entity], []])

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
        max_passes=3,
    )

    assert result.passes_completed == 2
    assert len(result.entities_discovered_per_pass) == 2
    # Pass 1: 1 dispatch (IP), Pass 2: 2 dispatches (domain + www.domain)
    assert result.successful_dispatches == 3
    assert result.final_state == "completed"
    # list_for_tenant should have been called (once after pass 1, once after 2)
    assert e_repo.list_for_tenant.call_count >= 1


async def test_max_passes_limit_reached() -> None:
    """When max_passes is reached, the loop stops even if new entities exist."""
    obs = _make_observation()
    executor, disp, _r_repo, e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    # Always return a new entity (simulating infinite expansion)
    call_count = 0

    async def _list_for_tenant_side_effect(**kwargs):
        nonlocal call_count
        call_count += 1
        return [
            _make_entity_mock(
                entity_type="domain",
                canonical_identifier=f"pass{call_count}.example.com",
            )
        ]

    e_repo.list_for_tenant = AsyncMock(side_effect=_list_for_tenant_side_effect)

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
        max_passes=2,
    )

    assert result.passes_completed == 2
    assert len(result.entities_discovered_per_pass) == 2


async def test_max_passes_default_is_three() -> None:
    """Verify the default max_passes is 3 (no kwarg needed)."""
    obs = _make_observation()
    executor, disp, _r_repo, e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    call_count = 0

    async def _list_for_tenant_always_new(**kwargs):
        nonlocal call_count
        call_count += 1
        return [
            _make_entity_mock(
                entity_type="ip",
                canonical_identifier=f"10.0.0.{call_count}",
            )
        ]

    e_repo.list_for_tenant = AsyncMock(side_effect=_list_for_tenant_always_new)

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.100")],
        collector_ids=["scanner"],
    )

    # Default max_passes=3 means exactly 3 passes
    assert result.passes_completed == 3


async def test_duplicate_seed_collector_pair_not_redispatched() -> None:
    """Same (seed, collector) pair is not dispatched again across passes."""
    obs = _make_observation()
    executor, disp, _r_repo, e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    # Return the SAME entity (same canonical_identifier) after pass 1.
    # Because it matches the original seed, it should be skipped by
    # already_scanned, resulting in no new seeds and a single pass.
    same_entity = _make_entity_mock(
        entity_type="ip",
        canonical_identifier="10.0.0.1",
    )
    e_repo.list_for_tenant = AsyncMock(return_value=[same_entity])

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
        max_passes=3,
    )

    # Entity matches the original seed -> no new seeds -> single pass
    assert result.passes_completed == 1


async def test_multi_pass_org_seeds_from_properties() -> None:
    """Organization seeds extracted from entity properties drive pass 2."""
    obs = _make_observation()
    executor, disp, _r_repo, e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    # After pass 1, return an entity with registrant_org in properties
    entity_with_org = _make_entity_mock(
        entity_type="domain",
        canonical_identifier="10.0.0.1",  # same as original seed type
        properties={"registrant_org": "Acme Corp"},
    )
    # First call returns entity with org, second call returns empty
    e_repo.list_for_tenant = AsyncMock(
        side_effect=[[entity_with_org], []]
    )

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
        max_passes=3,
    )

    # The org seed "Acme Corp" should trigger pass 2
    assert result.passes_completed == 2
    assert result.successful_dispatches >= 2


async def test_entities_discovered_per_pass_tracks_counts() -> None:
    """entities_discovered_per_pass has one entry per pass with entity counts."""
    obs1 = _make_observation(identifier_value="a.example.com")
    obs2 = _make_observation(identifier_value="b.example.com")
    obs3 = _make_observation(identifier_value="c.example.com")

    executor, disp, _r_repo, e_repo = _build_executor()

    # Pass 1: 2 observations, Pass 2: 1 observation
    disp.dispatch = AsyncMock(
        side_effect=[
            _success_result(obs1, obs2),
            _success_result(obs3),
        ]
    )

    new_entity = _make_entity_mock(
        entity_type="domain",
        canonical_identifier="new.example.com",
    )
    e_repo.list_for_tenant = AsyncMock(side_effect=[[new_entity], []])

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
        max_passes=3,
    )

    assert result.passes_completed == 2
    assert len(result.entities_discovered_per_pass) == 2
    # Pass 1: 2 entities (2 obs, 0 upsert failures)
    assert result.entities_discovered_per_pass[0] == 2
    # Pass 2: 1 entity (1 obs, 0 upsert failures)
    assert result.entities_discovered_per_pass[1] == 1


async def test_run_result_backward_compat_defaults() -> None:
    """RunResult's new fields have backward-compatible defaults."""
    from expose.pipeline.run_executor import RunResult

    # Construct a RunResult without the new fields (simulating old callers)
    result = RunResult(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        final_state="completed",
        total_seeds=1,
        expanded_seeds=2,
        total_dispatches=2,
        successful_dispatches=2,
        failed_dispatches=0,
        denied_dispatches=0,
        total_observations=3,
        duration_ms=100.0,
    )

    assert result.passes_completed == 1
    assert result.entities_discovered_per_pass == []


# === Relationship extraction tests ==========================================


def _build_executor_with_rel_repo(
    dispatcher: AsyncMock | None = None,
    run_repo: AsyncMock | None = None,
    entity_repo: AsyncMock | None = None,
    relationship_repo: AsyncMock | None = None,
    run_state: str = "pending",
) -> tuple[RunExecutor, AsyncMock, AsyncMock, AsyncMock, AsyncMock]:
    """Wire up a RunExecutor with mocked dependencies including relationship_repo.

    Returns (executor, dispatcher_mock, run_repo_mock, entity_repo_mock, rel_repo_mock).
    """
    disp = dispatcher or AsyncMock()
    r_repo = run_repo or AsyncMock()
    e_repo = entity_repo or AsyncMock()
    rel_repo = relationship_repo or AsyncMock()

    if not run_repo:
        r_repo.get_by_id = AsyncMock(return_value=_make_run_row(run_state))
        r_repo.update_state = AsyncMock()

    if not entity_repo:
        # Return a mock entity with a unique id for each create_or_update call
        def _make_entity_with_id(**kwargs):
            entity = MagicMock()
            entity.id = UUID("018f1f00-0000-7000-8000-0000000000FF")
            return entity

        e_repo.create_or_update = AsyncMock(side_effect=_make_entity_with_id)

    if not relationship_repo:
        rel_repo.create_or_update = AsyncMock(return_value=MagicMock())

    executor = RunExecutor(
        dispatcher=disp,
        run_repo=r_repo,
        entity_repo=e_repo,
        relationship_repo=rel_repo,
    )
    return executor, disp, r_repo, e_repo, rel_repo


def _make_dns_a_observation(
    identifier_value: str = "example.com",
    ips: list[str] | None = None,
) -> Observation:
    """Build an Observation with A-record structured_payload."""
    return Observation(
        collector_id="active-dns",
        collector_version="1.0.0",
        tenant_id=TENANT_ID,
        observation_type=ObservationType.DNS_RESOLUTION,
        subject=ObservationSubject(
            identifier_type=IdentifierType.DOMAIN,
            identifier_value=identifier_value,
        ),
        observed_at=OBSERVED,
        structured_payload={
            "record_type": "A",
            "values": ips or ["93.184.216.34"],
        },
    )


def _make_subdomain_enum_observation(
    identifier_value: str = "www.example.com",
    resolved_ips: list[str] | None = None,
    cname_chain: list[str] | None = None,
) -> Observation:
    """Build an Observation with dns_subdomain_enum structured_payload."""
    payload: dict = {
        "subdomain": identifier_value,
        "resolved_ips": resolved_ips or ["93.184.216.34"],
    }
    if cname_chain:
        payload["cname_chain"] = cname_chain
    return Observation(
        collector_id="dns-subdomain-enum",
        collector_version="1.0.0",
        tenant_id=TENANT_ID,
        observation_type=ObservationType.DNS_RESOLUTION,
        subject=ObservationSubject(
            identifier_type=IdentifierType.DOMAIN,
            identifier_value=identifier_value,
        ),
        observed_at=OBSERVED,
        structured_payload=payload,
    )


def _make_ns_observation(
    identifier_value: str = "example.com",
    nameservers: list[str] | None = None,
) -> Observation:
    """Build an Observation with NS-record structured_payload."""
    return Observation(
        collector_id="active-dns",
        collector_version="1.0.0",
        tenant_id=TENANT_ID,
        observation_type=ObservationType.DNS_RESOLUTION,
        subject=ObservationSubject(
            identifier_type=IdentifierType.DOMAIN,
            identifier_value=identifier_value,
        ),
        observed_at=OBSERVED,
        structured_payload={
            "record_type": "NS",
            "nameservers": nameservers or ["ns1.example.com", "ns2.example.com"],
        },
    )


def _make_mx_observation(
    identifier_value: str = "example.com",
    exchanges: list[dict] | None = None,
) -> Observation:
    """Build an Observation with MX-record structured_payload."""
    return Observation(
        collector_id="active-dns",
        collector_version="1.0.0",
        tenant_id=TENANT_ID,
        observation_type=ObservationType.DNS_RESOLUTION,
        subject=ObservationSubject(
            identifier_type=IdentifierType.DOMAIN,
            identifier_value=identifier_value,
        ),
        observed_at=OBSERVED,
        structured_payload={
            "record_type": "MX",
            "exchanges": exchanges
            or [
                {"priority": 10, "exchange": "mail.example.com"},
                {"priority": 20, "exchange": "mail2.example.com"},
            ],
        },
    )


def _make_cname_observation(
    identifier_value: str = "www.example.com",
    target: str = "cdn.example.net",
) -> Observation:
    """Build an Observation with CNAME-record structured_payload."""
    return Observation(
        collector_id="active-dns",
        collector_version="1.0.0",
        tenant_id=TENANT_ID,
        observation_type=ObservationType.DNS_RESOLUTION,
        subject=ObservationSubject(
            identifier_type=IdentifierType.DOMAIN,
            identifier_value=identifier_value,
        ),
        observed_at=OBSERVED,
        structured_payload={
            "record_type": "CNAME",
            "target": target,
        },
    )


async def test_relationship_created_for_dns_a_record() -> None:
    """A-record observations create resolves_to relationships to IP entities."""
    obs = _make_dns_a_observation(ips=["93.184.216.34", "93.184.216.35"])
    executor, disp, _r_repo, e_repo, rel_repo = _build_executor_with_rel_repo()
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["active-dns"],
    )

    # entity_repo.create_or_update: 1 for subject + 2 for IPs = 3 calls
    assert e_repo.create_or_update.call_count == 3
    # relationship_repo.create_or_update: 2 relationships (one per IP)
    assert rel_repo.create_or_update.call_count == 2
    edge_types = {
        c.kwargs["edge_type"] for c in rel_repo.create_or_update.call_args_list
    }
    assert edge_types == {"resolves_to"}


async def test_relationship_created_for_ns_records() -> None:
    """NS-record observations create ns_for relationships."""
    obs = _make_ns_observation(nameservers=["ns1.example.com"])
    executor, disp, _r_repo, e_repo, rel_repo = _build_executor_with_rel_repo()
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["active-dns"],
    )

    assert rel_repo.create_or_update.call_count == 1
    call_kwargs = rel_repo.create_or_update.call_args_list[0].kwargs
    assert call_kwargs["edge_type"] == "ns_for"


async def test_relationship_created_for_mx_records() -> None:
    """MX-record observations create mx_for relationships."""
    obs = _make_mx_observation()
    executor, disp, _r_repo, e_repo, rel_repo = _build_executor_with_rel_repo()
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["active-dns"],
    )

    assert rel_repo.create_or_update.call_count == 2
    edge_types = {
        c.kwargs["edge_type"] for c in rel_repo.create_or_update.call_args_list
    }
    assert edge_types == {"mx_for"}


async def test_relationship_created_for_cname_record() -> None:
    """CNAME-record observations create cname_for relationships."""
    obs = _make_cname_observation()
    executor, disp, _r_repo, e_repo, rel_repo = _build_executor_with_rel_repo()
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["active-dns"],
    )

    assert rel_repo.create_or_update.call_count == 1
    call_kwargs = rel_repo.create_or_update.call_args_list[0].kwargs
    assert call_kwargs["edge_type"] == "cname_for"


async def test_relationship_created_for_subdomain_enum_resolved_ips() -> None:
    """Subdomain enum observations with resolved_ips create resolves_to relationships."""
    obs = _make_subdomain_enum_observation(
        resolved_ips=["198.51.100.1", "198.51.100.2"],
    )
    executor, disp, _r_repo, e_repo, rel_repo = _build_executor_with_rel_repo()
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["dns-subdomain-enum"],
    )

    assert rel_repo.create_or_update.call_count == 2
    edge_types = {
        c.kwargs["edge_type"] for c in rel_repo.create_or_update.call_args_list
    }
    assert edge_types == {"resolves_to"}


async def test_relationship_created_for_subdomain_enum_cname_chain() -> None:
    """Subdomain enum observations with cname_chain create cname_for relationships."""
    obs = _make_subdomain_enum_observation(
        resolved_ips=["198.51.100.1"],
        cname_chain=["cdn.example.net"],
    )
    executor, disp, _r_repo, e_repo, rel_repo = _build_executor_with_rel_repo()
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["dns-subdomain-enum"],
    )

    # 1 resolves_to for IP + 1 cname_for for CNAME target = 2 relationships
    assert rel_repo.create_or_update.call_count == 2
    edge_types = {
        c.kwargs["edge_type"] for c in rel_repo.create_or_update.call_args_list
    }
    assert edge_types == {"resolves_to", "cname_for"}


async def test_no_relationships_without_relationship_repo() -> None:
    """When relationship_repo is None, no relationship extraction happens."""
    obs = _make_dns_a_observation(ips=["93.184.216.34"])
    executor, disp, _r_repo, e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["active-dns"],
    )

    # Only the subject entity is upserted (no related entity upserts)
    assert e_repo.create_or_update.call_count == 1
    assert result.final_state == "completed"


async def test_relationship_extraction_failure_does_not_crash_run() -> None:
    """If relationship extraction fails, the run still completes."""
    obs = _make_dns_a_observation(ips=["93.184.216.34"])

    e_repo = AsyncMock()
    entity_mock = MagicMock()
    entity_mock.id = UUID("018f1f00-0000-7000-8000-0000000000FF")
    e_repo.create_or_update = AsyncMock(
        side_effect=[entity_mock, RuntimeError("related entity upsert failed")]
    )

    rel_repo = AsyncMock()
    rel_repo.create_or_update = AsyncMock(return_value=MagicMock())

    executor, disp, _r_repo, _e_repo, _rel_repo = _build_executor_with_rel_repo(
        entity_repo=e_repo,
        relationship_repo=rel_repo,
    )
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["active-dns"],
    )

    # Run completes despite the related entity upsert failure
    assert result.final_state == "completed"
    # The subject entity upsert succeeded; only the related entity failed
    assert result.total_observations == 1


async def test_no_relationships_for_plain_observation() -> None:
    """Observations without recognized payload patterns produce no relationships."""
    obs = _make_observation()  # structured_payload = {"resolved_ip": "93.184.216.34"}
    executor, disp, _r_repo, e_repo, rel_repo = _build_executor_with_rel_repo()
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["test-collector"],
    )

    # No relationship patterns matched -> no relationship upserts
    rel_repo.create_or_update.assert_not_called()
    # Only the subject entity upserted
    assert e_repo.create_or_update.call_count == 1


# === DNS filter tests ========================================================


async def test_dns_filter_removes_nonresolving_domains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-resolving domain seeds are removed; resolving ones and non-domain seeds kept."""

    def _fake_getaddrinfo(host, port, family=0, type_=0):
        if host in ("example.com", "www.example.com"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result())

    # Organization seed "Korlogos" will expand to korlogos.com, korlogos.net,
    # korlogos.org, etc. via multi-TLD expansion. Only the ones that resolve
    # should survive the DNS filter.
    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=["dns-resolve"],
    )

    # example.com and www.example.com both resolve -> 2 seeds dispatched
    assert result.expanded_seeds == 2
    assert result.total_dispatches == 2


async def test_dns_filter_keeps_all_non_domain_seeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IP, CIDR, ORGANIZATION, ASN, ENTITY seeds bypass DNS filter entirely."""

    def _fail_all_dns(host, port, family=0, type_=0):
        raise socket.gaierror("should not be called for non-domain seeds")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_all_dns)

    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result())

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[
            Seed(seed_type=SeedType.IP, value="10.0.0.1"),
            Seed(seed_type=SeedType.CIDR, value="10.0.0.0/24"),
            Seed(seed_type=SeedType.ASN, value="AS64496"),
        ],
        collector_ids=["scanner"],
    )

    # 3 non-domain seeds, no expansion -> 3 dispatches
    assert result.expanded_seeds == 3
    assert result.total_dispatches == 3


async def test_dns_filter_handles_oserror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Domains that raise OSError during DNS lookup are filtered out."""

    def _oserror_getaddrinfo(host, port, family=0, type_=0):
        raise OSError("Network is unreachable")

    monkeypatch.setattr(socket, "getaddrinfo", _oserror_getaddrinfo)

    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result())

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=["dns-resolve"],
    )

    # Both example.com and www.example.com fail -> 0 domain seeds survive
    assert result.expanded_seeds == 0
    assert result.total_dispatches == 0
    assert result.final_state == "completed"


async def test_dns_filter_org_expansion_filters_nonexistent_tlds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Org expansion generates many TLD variants; DNS filter removes non-resolving ones."""

    # Only korlogos.com resolves; all other TLDs fail.
    # Note: www.korlogos.com is NOT generated — the www. expansion only applies
    # to DOMAIN seeds in the original input, not to org-generated domain seeds.
    _resolving = {"korlogos.com"}

    def _selective_getaddrinfo(host, port, family=0, type_=0):
        if host in _resolving:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _selective_getaddrinfo)

    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result())

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.ORGANIZATION, value="Korlogos")],
        collector_ids=["scanner"],
    )

    # Original ORGANIZATION seed + korlogos.com (only resolving domain) = 2 seeds
    # All other TLD variants (korlogos.net, .org, .io, etc.) filtered out
    assert result.expanded_seeds == 2
    # 2 seeds x 1 collector = 2 dispatches
    assert result.total_dispatches == 2

    # Verify that the dispatched seeds are only the resolving ones + org seed
    dispatched_values = {c.args[0].seed.value for c in disp.dispatch.call_args_list}
    assert "Korlogos" in dispatched_values
    assert "korlogos.com" in dispatched_values
    # Non-resolving domains should NOT be dispatched
    assert "korlogos.net" not in dispatched_values
    assert "korlogos.gov" not in dispatched_values
    assert "korlogos.org" not in dispatched_values
    assert "korlogos.io" not in dispatched_values


async def test_dns_filter_all_domains_resolve() -> None:
    """When all domains resolve, none are filtered out (autouse fixture resolves all)."""

    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result())

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=["dns-resolve"],
    )

    # example.com + www.example.com both resolve -> 2 seeds
    assert result.expanded_seeds == 2
    assert result.total_dispatches == 2


async def test_dns_filter_no_domains_resolve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no domains resolve, all domain seeds are removed."""

    def _none_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _none_resolve)

    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result())

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="nonexistent.example")],
        collector_ids=["dns-resolve"],
    )

    # Both nonexistent.example and www.nonexistent.example filtered out -> 0 seeds
    assert result.expanded_seeds == 0
    assert result.total_dispatches == 0
    assert result.final_state == "completed"


# === Batch upsert fallback tests ============================================


def _build_executor_with_batch_repo(
    batch_fails: bool = False,
    enrichment_pipeline: Any = None,
) -> tuple[RunExecutor, AsyncMock, AsyncMock, AsyncMock]:
    """Wire up a RunExecutor with an entity_repo that supports batch_upsert.

    When ``batch_fails`` is True, ``batch_upsert`` raises an exception but
    ``create_or_update`` succeeds — simulating the fallback path.

    Returns (executor, dispatcher_mock, run_repo_mock, entity_repo_mock).
    """
    disp = AsyncMock()
    r_repo = AsyncMock()
    e_repo = AsyncMock()

    r_repo.get_by_id = AsyncMock(return_value=_make_run_row("pending"))
    r_repo.update_state = AsyncMock()

    # Mark as supporting batch upsert (real bool, not Mock)
    e_repo.supports_batch_upsert = True

    if batch_fails:
        e_repo.batch_upsert = AsyncMock(
            side_effect=RuntimeError("ON CONFLICT constraint mismatch")
        )
    else:
        entity_mock = MagicMock()
        entity_mock.canonical_identifier = "example.com"
        entity_mock.entity_type = "domain"
        e_repo.batch_upsert = AsyncMock(return_value=[entity_mock])

    # Fallback per-entity upsert always succeeds
    e_repo.create_or_update = AsyncMock(return_value=MagicMock())
    e_repo.list_for_tenant = AsyncMock(return_value=[])
    e_repo.update_attribution_scores = AsyncMock(return_value=0)

    executor = RunExecutor(
        dispatcher=disp,
        run_repo=r_repo,
        entity_repo=e_repo,
        enrichment_pipeline=enrichment_pipeline,
    )
    return executor, disp, r_repo, e_repo


async def test_batch_upsert_success_path() -> None:
    """When batch_upsert succeeds, create_or_update is NOT called."""
    obs = _make_observation()
    executor, disp, _r_repo, e_repo = _build_executor_with_batch_repo(
        batch_fails=False,
    )
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    assert result.final_state == "completed"
    assert result.total_observations == 1
    # batch_upsert was called, create_or_update was NOT
    e_repo.batch_upsert.assert_called_once()
    e_repo.create_or_update.assert_not_called()


async def test_batch_upsert_failure_falls_back_to_per_entity() -> None:
    """When batch_upsert fails, _flush_batch falls back to per-entity upserts."""
    obs1 = _make_observation(identifier_value="a.example.com")
    obs2 = _make_observation(identifier_value="b.example.com")
    executor, disp, _r_repo, e_repo = _build_executor_with_batch_repo(
        batch_fails=True,
    )
    disp.dispatch = AsyncMock(return_value=_success_result(obs1, obs2))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    assert result.final_state == "completed"
    assert result.total_observations == 2
    # batch_upsert was attempted and failed
    e_repo.batch_upsert.assert_called_once()
    # Fallback: create_or_update called once per observation
    assert e_repo.create_or_update.call_count == 2
    upsert_ids = {
        c.kwargs["canonical_identifier"]
        for c in e_repo.create_or_update.call_args_list
    }
    assert upsert_ids == {"a.example.com", "b.example.com"}
    # No upsert failures since the fallback succeeded
    assert result.entities_discovered_per_pass[0] == 2


async def test_batch_upsert_failure_counts_per_entity_failures() -> None:
    """When batch fails and some per-entity upserts also fail, upsert_failures counted."""
    obs1 = _make_observation(identifier_value="a.example.com")
    obs2 = _make_observation(identifier_value="b.example.com")
    executor, disp, _r_repo, e_repo = _build_executor_with_batch_repo(
        batch_fails=True,
    )
    # One per-entity upsert succeeds, one fails
    e_repo.create_or_update = AsyncMock(
        side_effect=[MagicMock(), RuntimeError("db constraint violation")]
    )
    disp.dispatch = AsyncMock(return_value=_success_result(obs1, obs2))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    # 2 observations, 1 upsert failure -> 1 entity discovered
    assert result.entities_discovered_per_pass[0] == 1
    # Run still completes (upsert failures are not dispatch failures)
    assert result.final_state == "completed"


# === LLM enrichment deduplication tests =====================================


def _build_executor_with_enrichment(
    enrichment_mock: AsyncMock | None = None,
) -> tuple[RunExecutor, AsyncMock, AsyncMock, AsyncMock, AsyncMock]:
    """Wire up a RunExecutor with a mock enrichment pipeline.

    Returns (executor, dispatcher, run_repo, entity_repo, enrichment_mock).
    """
    disp = AsyncMock()
    r_repo = AsyncMock()
    e_repo = AsyncMock()

    r_repo.get_by_id = AsyncMock(return_value=_make_run_row("pending"))
    r_repo.update_state = AsyncMock()
    e_repo.create_or_update = AsyncMock(return_value=MagicMock())
    e_repo.list_for_tenant = AsyncMock(return_value=[])
    e_repo.update_attribution_scores = AsyncMock(return_value=0)

    enrich = enrichment_mock or AsyncMock()
    enrich.enrich_entity = AsyncMock(return_value={"attribution": {}})

    from expose.pipeline.enrichment import EnrichmentPipeline

    executor = RunExecutor(
        dispatcher=disp,
        run_repo=r_repo,
        entity_repo=e_repo,
        enrichment_pipeline=enrich,
    )
    return executor, disp, r_repo, e_repo, enrich


async def test_enrichment_deduplicates_same_entity() -> None:
    """Multiple observations for the same entity result in a single LLM call."""
    # 5 observations all pointing to the same entity
    observations = [_make_observation(identifier_value="example.com") for _ in range(5)]
    executor, disp, _r_repo, _e_repo, enrich = _build_executor_with_enrichment()
    disp.dispatch = AsyncMock(return_value=_success_result(*observations))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    # 5 observations but only 1 unique entity -> 1 enrichment call
    assert enrich.enrich_entity.call_count == 1
    assert result.enrichment_count == 1
    assert result.total_observations == 5


async def test_enrichment_deduplicates_multiple_entities() -> None:
    """Observations for N unique entities result in exactly N LLM calls."""
    observations = [
        _make_observation(identifier_value="a.example.com"),
        _make_observation(identifier_value="b.example.com"),
        _make_observation(identifier_value="a.example.com"),  # duplicate
        _make_observation(identifier_value="c.example.com"),
        _make_observation(identifier_value="b.example.com"),  # duplicate
    ]
    executor, disp, _r_repo, _e_repo, enrich = _build_executor_with_enrichment()
    disp.dispatch = AsyncMock(return_value=_success_result(*observations))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    # 5 observations, 3 unique entities -> 3 enrichment calls
    assert enrich.enrich_entity.call_count == 3
    assert result.enrichment_count == 3
    enriched_ids = {
        c.kwargs["canonical_identifier"]
        for c in enrich.enrich_entity.call_args_list
    }
    assert enriched_ids == {"a.example.com", "b.example.com", "c.example.com"}


async def test_enrichment_cap_limits_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When unique entities exceed the cap, only the first N are enriched."""
    from expose.pipeline import run_executor as mod

    # Set cap to 3 for this test
    monkeypatch.setattr(mod, "_MAX_LLM_ENRICHMENTS_PER_BATCH", 3)

    # 10 unique entities
    observations = [
        _make_observation(identifier_value=f"host{i}.example.com")
        for i in range(10)
    ]
    executor, disp, _r_repo, _e_repo, enrich = _build_executor_with_enrichment()
    disp.dispatch = AsyncMock(return_value=_success_result(*observations))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    # Cap = 3 -> only 3 enrichment calls despite 10 unique entities
    assert enrich.enrich_entity.call_count == 3
    assert result.enrichment_count == 3
    assert result.total_observations == 10


async def test_enrichment_no_enrichment_pipeline() -> None:
    """When enrichment_pipeline is None, enrichment_count is 0."""
    obs = _make_observation()
    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    result = await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        collector_ids=["scanner"],
    )

    assert result.enrichment_count == 0
    assert result.total_observations == 1

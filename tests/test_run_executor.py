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

from datetime import UTC, datetime
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

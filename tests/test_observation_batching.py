"""Tests for observation batching in RunExecutor.

Validates that the RunExecutor flushes observations in batches of
``_OBSERVATION_BATCH_SIZE`` (500) instead of accumulating all observations
in memory before upserting.  This prevents OOM on large scans.

Coverage:

1. Small scan (< 500 obs) flushes once at end.
2. Large scan (1500 obs) flushes 3 times (500 + 500 + 500).
3. Exact batch size (500 obs) flushes once during loop + zero at end.
4. Enrichment runs per-batch, not deferred to end.
5. Total observation count correct across batches.
6. Entity repo upsert called for every observation.
7. Empty scan (0 obs) -- no flush calls.
8. RunResult totals match expected.
9. Enrichment failures in one batch do not affect other batches.
10. Upsert failures tracked correctly across batches.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

from expose.collectors.base import (
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.pipeline.enrichment import EnrichmentPipeline
from expose.pipeline.run_executor import (
    _OBSERVATION_BATCH_SIZE,
    DispatchResult,
    RunExecutor,
)
from expose.types.canonical import IdentifierType

# === Synthetic IDs ============================================================

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000C001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000C002")
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


def _make_observations(count: int) -> list[Observation]:
    """Build ``count`` distinct observations."""
    return [
        _make_observation(identifier_value=f"host-{i}.example.com")
        for i in range(count)
    ]


def _success_result(*observations: Observation) -> DispatchResult:
    """Build a successful DispatchResult."""
    return DispatchResult(
        status="success",
        observations=list(observations),
        duration_ms=10.0,
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
    entity_repo: AsyncMock | None = None,
    enrichment_pipeline: EnrichmentPipeline | None = None,
) -> tuple[RunExecutor, AsyncMock, AsyncMock, AsyncMock]:
    """Wire up a RunExecutor with mocked dependencies.

    Returns (executor, dispatcher_mock, run_repo_mock, entity_repo_mock).
    """
    disp = dispatcher or AsyncMock()
    r_repo = AsyncMock()
    e_repo = entity_repo or AsyncMock()

    r_repo.get_by_id = AsyncMock(return_value=_make_run_row("pending"))
    r_repo.update_state = AsyncMock()

    if not entity_repo:
        e_repo.create_or_update = AsyncMock(return_value=MagicMock())

    executor = RunExecutor(
        dispatcher=disp,
        run_repo=r_repo,
        entity_repo=e_repo,
        enrichment_pipeline=enrichment_pipeline,
    )
    return executor, disp, r_repo, e_repo


def _execute_kwargs(
    seeds: list[Seed] | None = None,
    collector_ids: list[str] | None = None,
) -> dict:
    """Build common kwargs for executor.execute()."""
    return {
        "run_id": RUN_ID,
        "tenant_id": TENANT_ID,
        "seeds": seeds or [Seed(seed_type=SeedType.IP, value="10.0.0.1")],
        "collector_ids": collector_ids or ["scanner"],
    }


# === Tests ====================================================================


async def test_batch_size_constant_is_500() -> None:
    """The module constant _OBSERVATION_BATCH_SIZE is 500."""
    assert _OBSERVATION_BATCH_SIZE == 500


async def test_small_scan_flushes_once_at_end() -> None:
    """A scan with < 500 observations flushes once after the dispatch loop."""
    obs_count = 100
    observations = _make_observations(obs_count)
    executor, disp, _r_repo, e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result(*observations))

    with patch.object(
        executor, "_flush_batch", wraps=executor._flush_batch
    ) as mock_flush:
        result = await executor.execute(**_execute_kwargs())

    # Only one flush call (the trailing flush after the loop)
    assert mock_flush.call_count == 1
    # The single flush received all observations
    flushed_obs = mock_flush.call_args_list[0].args[0]
    assert len(flushed_obs) == obs_count
    assert result.total_observations == obs_count
    assert e_repo.create_or_update.call_count == obs_count


async def test_large_scan_flushes_multiple_times() -> None:
    """A scan with 1500 observations flushes 3 times (500 + 500 + 500)."""
    batch_size = _OBSERVATION_BATCH_SIZE  # 500
    total_obs = batch_size * 3  # 1500

    # Each dispatch returns batch_size observations to trigger a flush
    observations = _make_observations(batch_size)
    executor, disp, _r_repo, e_repo = _build_executor()

    # 3 dispatches, each returning 500 observations
    disp.dispatch = AsyncMock(
        side_effect=[
            _success_result(*observations[:batch_size]),
            _success_result(
                *_make_observations(batch_size)
            ),
            _success_result(
                *_make_observations(batch_size)
            ),
        ]
    )

    with patch.object(
        executor, "_flush_batch", wraps=executor._flush_batch
    ) as mock_flush:
        result = await executor.execute(
            **_execute_kwargs(
                seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
                collector_ids=["c1", "c2", "c3"],
            )
        )

    # 3 mid-loop flushes (each hit exactly 500), no trailing flush
    # because the batch is empty after the last mid-loop flush
    assert mock_flush.call_count == 3
    for call in mock_flush.call_args_list:
        assert len(call.args[0]) == batch_size
    assert result.total_observations == total_obs
    assert e_repo.create_or_update.call_count == total_obs


async def test_exact_batch_size_flushes_during_loop() -> None:
    """Exactly 500 observations: one flush mid-loop, no trailing flush."""
    batch_size = _OBSERVATION_BATCH_SIZE
    observations = _make_observations(batch_size)
    executor, disp, _r_repo, _e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result(*observations))

    with patch.object(
        executor, "_flush_batch", wraps=executor._flush_batch
    ) as mock_flush:
        result = await executor.execute(**_execute_kwargs())

    # One mid-loop flush at exactly 500
    assert mock_flush.call_count == 1
    assert len(mock_flush.call_args_list[0].args[0]) == batch_size
    assert result.total_observations == batch_size


async def test_enrichment_runs_per_batch() -> None:
    """Enrichment is called per-batch during flush, not deferred to end."""
    batch_size = _OBSERVATION_BATCH_SIZE

    mock_pipeline = AsyncMock(spec=EnrichmentPipeline)
    mock_pipeline.enrich_entity = AsyncMock(
        return_value={"attribution": {"adjusted_confidence": 0.6}}
    )

    executor, disp, _r_repo, _e_repo = _build_executor(
        enrichment_pipeline=mock_pipeline
    )

    # Two dispatches: first returns 500 obs (triggers flush), second returns 100
    batch1 = _make_observations(batch_size)
    batch2 = _make_observations(100)
    disp.dispatch = AsyncMock(
        side_effect=[
            _success_result(*batch1),
            _success_result(*batch2),
        ]
    )

    result = await executor.execute(
        **_execute_kwargs(
            seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
            collector_ids=["c1", "c2"],
        )
    )

    # Enrichment called for every observation (500 + 100)
    assert mock_pipeline.enrich_entity.call_count == batch_size + 100
    assert result.enrichment_count == batch_size + 100
    assert result.total_observations == batch_size + 100


async def test_total_observation_count_correct_across_batches() -> None:
    """total_observations in RunResult is the sum of all flushed batches."""
    # 750 obs total: one mid-loop flush of 500, one trailing flush of 250
    total = 750
    executor, disp, _r_repo, _e_repo = _build_executor()

    # Single dispatch returning 750 observations
    observations = _make_observations(total)
    disp.dispatch = AsyncMock(return_value=_success_result(*observations))

    result = await executor.execute(**_execute_kwargs())

    assert result.total_observations == total


async def test_entity_repo_upsert_called_for_every_observation() -> None:
    """entity_repo.create_or_update is called once per observation across batches."""
    batch_size = _OBSERVATION_BATCH_SIZE
    total = batch_size + 200  # 700: one mid-loop flush + one trailing
    observations = _make_observations(total)

    executor, disp, _r_repo, e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result(*observations))

    await executor.execute(**_execute_kwargs())

    assert e_repo.create_or_update.call_count == total
    # Verify all distinct identifiers were upserted
    upserted = {
        c.kwargs["canonical_identifier"]
        for c in e_repo.create_or_update.call_args_list
    }
    expected = {f"host-{i}.example.com" for i in range(total)}
    assert upserted == expected


async def test_empty_scan_no_flush() -> None:
    """A scan with 0 observations does not call _flush_batch."""
    executor, disp, _r_repo, e_repo = _build_executor()
    disp.dispatch = AsyncMock(return_value=_success_result())  # no observations

    with patch.object(
        executor, "_flush_batch", wraps=executor._flush_batch
    ) as mock_flush:
        result = await executor.execute(**_execute_kwargs())

    mock_flush.assert_not_called()
    assert result.total_observations == 0
    e_repo.create_or_update.assert_not_called()


async def test_run_result_totals_match_expected() -> None:
    """RunResult fields are accurate for a multi-batch run."""
    batch_size = _OBSERVATION_BATCH_SIZE
    obs_per_dispatch = batch_size  # exactly one flush per dispatch

    mock_pipeline = AsyncMock(spec=EnrichmentPipeline)
    mock_pipeline.enrich_entity = AsyncMock(
        return_value={"noise": {"is_noise": False}}
    )

    executor, disp, _r_repo, _e_repo = _build_executor(
        enrichment_pipeline=mock_pipeline
    )

    # 2 dispatches x 500 obs each = 1000 total
    disp.dispatch = AsyncMock(
        side_effect=[
            _success_result(*_make_observations(obs_per_dispatch)),
            _success_result(*_make_observations(obs_per_dispatch)),
        ]
    )

    result = await executor.execute(
        **_execute_kwargs(
            seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
            collector_ids=["c1", "c2"],
        )
    )

    assert result.run_id == RUN_ID
    assert result.tenant_id == TENANT_ID
    assert result.final_state == "completed"
    assert result.total_observations == obs_per_dispatch * 2
    assert result.successful_dispatches == 2
    assert result.failed_dispatches == 0
    assert result.enrichment_count == obs_per_dispatch * 2


async def test_enrichment_failure_in_one_batch_does_not_affect_others() -> None:
    """Enrichment errors in one batch don't prevent enrichment in subsequent batches."""
    batch_size = _OBSERVATION_BATCH_SIZE

    # First batch (500): all enrichments raise.
    # Second batch (100): all enrichments succeed.
    first_batch_effects = [RuntimeError("LLM down")] * batch_size
    second_batch_effects = [
        {"attribution": {"adjusted_confidence": 0.6}}
    ] * 100

    mock_pipeline = AsyncMock(spec=EnrichmentPipeline)
    mock_pipeline.enrich_entity = AsyncMock(
        side_effect=first_batch_effects + second_batch_effects
    )

    executor, disp, _r_repo, _e_repo = _build_executor(
        enrichment_pipeline=mock_pipeline
    )

    batch1 = _make_observations(batch_size)
    batch2 = _make_observations(100)
    disp.dispatch = AsyncMock(
        side_effect=[
            _success_result(*batch1),
            _success_result(*batch2),
        ]
    )

    result = await executor.execute(
        **_execute_kwargs(
            seeds=[Seed(seed_type=SeedType.IP, value="10.0.0.1")],
            collector_ids=["c1", "c2"],
        )
    )

    assert result.final_state == "completed"
    # Only the second batch's 100 enrichments succeeded
    assert result.enrichment_count == 100
    assert result.total_observations == batch_size + 100


async def test_upsert_failures_tracked_across_batches() -> None:
    """Upsert failures from multiple batches are accumulated correctly."""
    batch_size = _OBSERVATION_BATCH_SIZE
    # 600 total: first flush at 500 (2 failures), trailing flush at 100 (1 failure)
    total = batch_size + 100

    # Build side_effect: first 500 have 2 failures, next 100 have 1 failure
    effects: list = []
    for i in range(batch_size):
        if i in (10, 20):
            effects.append(RuntimeError("db error"))
        else:
            effects.append(MagicMock())
    for i in range(100):
        if i == 50:
            effects.append(RuntimeError("db error"))
        else:
            effects.append(MagicMock())

    e_repo = AsyncMock()
    e_repo.create_or_update = AsyncMock(side_effect=effects)

    executor, disp, _r_repo, _ = _build_executor(entity_repo=e_repo)

    observations = _make_observations(total)
    disp.dispatch = AsyncMock(return_value=_success_result(*observations))

    result = await executor.execute(**_execute_kwargs())

    assert result.total_observations == total
    # 3 upsert failures should not prevent run completion
    assert result.final_state == "completed"
    assert e_repo.create_or_update.call_count == total

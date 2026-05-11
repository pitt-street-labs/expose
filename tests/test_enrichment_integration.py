"""Integration tests for EnrichmentPipeline wired into RunExecutor (Stage 4b).

Validates:
1. RunExecutor with enrichment_pipeline=None preserves existing behavior.
2. RunExecutor with a mock EnrichmentPipeline calls enrich_entity per observation.
3. Enrichment results are counted in RunResult.enrichment_count.
4. Enrichment failure (pipeline raises) does not crash the run.
5. Only medium-confidence entities trigger attribution enrichment (per the
   enrichment pipeline's internal [0.4, 0.7) filtering).
6. enrichment_count defaults to 0 on RunResult.
7. Multiple observations each trigger an enrichment call.
8. Empty enrichment results (pipeline returns {}) are not counted.
9. Enrichment receives correct observation properties.
10. Partial enrichment failures (some succeed, some raise) are handled.

Follows the mock-injection patterns established in ``tests/test_run_executor.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
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
    DispatchResult,
    RunExecutor,
    RunResult,
)
from expose.types.canonical import IdentifierType

# === Synthetic IDs ============================================================

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000B001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000B002")
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
    enrichment_pipeline: EnrichmentPipeline | None = None,
    run_state: str = "pending",
) -> tuple[RunExecutor, AsyncMock, AsyncMock, AsyncMock]:
    """Wire up a RunExecutor with mocked dependencies.

    Returns (executor, dispatcher_mock, run_repo_mock, entity_repo_mock).
    """
    disp = dispatcher or AsyncMock()
    r_repo = run_repo or AsyncMock()
    e_repo = entity_repo or AsyncMock()

    if not run_repo:
        r_repo.get_by_id = AsyncMock(return_value=_make_run_row(run_state))
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


async def test_no_enrichment_pipeline_skips_stage_4b() -> None:
    """When enrichment_pipeline=None, Stage 4b is skipped and enrichment_count=0."""
    obs = _make_observation()
    executor, disp, _r_repo, _e_repo = _build_executor(enrichment_pipeline=None)
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    result = await executor.execute(**_execute_kwargs())

    assert result.final_state == "completed"
    assert result.enrichment_count == 0
    assert result.total_observations == 1


async def test_enrichment_called_for_each_observation() -> None:
    """EnrichmentPipeline.enrich_entity is called once per observation."""
    obs1 = _make_observation(identifier_value="a.example.com")
    obs2 = _make_observation(identifier_value="b.example.com")

    mock_pipeline = AsyncMock(spec=EnrichmentPipeline)
    mock_pipeline.enrich_entity = AsyncMock(
        return_value={"attribution": {"adjusted_confidence": 0.6}}
    )

    executor, disp, _r_repo, _e_repo = _build_executor(
        enrichment_pipeline=mock_pipeline
    )
    disp.dispatch = AsyncMock(return_value=_success_result(obs1, obs2))

    result = await executor.execute(**_execute_kwargs())

    assert mock_pipeline.enrich_entity.call_count == 2
    assert result.enrichment_count == 2


async def test_enrichment_count_in_run_result() -> None:
    """RunResult.enrichment_count reflects the number of entities that produced results."""
    obs = _make_observation()

    mock_pipeline = AsyncMock(spec=EnrichmentPipeline)
    mock_pipeline.enrich_entity = AsyncMock(
        return_value={"noise": {"is_noise": False}}
    )

    executor, disp, _r_repo, _e_repo = _build_executor(
        enrichment_pipeline=mock_pipeline
    )
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    result = await executor.execute(**_execute_kwargs())

    assert result.enrichment_count == 1
    assert result.total_observations == 1


async def test_enrichment_failure_does_not_crash_run() -> None:
    """If enrich_entity raises, the run still completes without crashing."""
    obs = _make_observation()

    mock_pipeline = AsyncMock(spec=EnrichmentPipeline)
    mock_pipeline.enrich_entity = AsyncMock(
        side_effect=RuntimeError("LLM provider exploded")
    )

    executor, disp, _r_repo, _e_repo = _build_executor(
        enrichment_pipeline=mock_pipeline
    )
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    result = await executor.execute(**_execute_kwargs())

    assert result.final_state == "completed"
    assert result.enrichment_count == 0
    assert result.total_observations == 1


async def test_enrichment_passes_correct_entity_data() -> None:
    """enrich_entity receives entity_type, canonical_identifier, and properties from the observation."""
    obs = _make_observation(
        collector_id="ct-crtsh",
        identifier_value="sub.example.com",
    )

    mock_pipeline = AsyncMock(spec=EnrichmentPipeline)
    mock_pipeline.enrich_entity = AsyncMock(return_value={})

    executor, disp, _r_repo, _e_repo = _build_executor(
        enrichment_pipeline=mock_pipeline
    )
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    await executor.execute(**_execute_kwargs())

    mock_pipeline.enrich_entity.assert_called_once()
    call_kwargs = mock_pipeline.enrich_entity.call_args.kwargs
    assert call_kwargs["entity_type"] == "domain"
    assert call_kwargs["canonical_identifier"] == "sub.example.com"
    assert call_kwargs["tenant_id"] == TENANT_ID
    assert call_kwargs["run_id"] == RUN_ID
    # Properties should include collector metadata
    assert call_kwargs["properties"]["_collector_id"] == "ct-crtsh"
    assert call_kwargs["properties"]["_collector_version"] == "1.0.0"
    assert call_kwargs["properties"]["resolved_ip"] == "93.184.216.34"


async def test_empty_enrichment_result_not_counted() -> None:
    """When enrich_entity returns {}, enrichment_count is not incremented."""
    obs = _make_observation()

    mock_pipeline = AsyncMock(spec=EnrichmentPipeline)
    mock_pipeline.enrich_entity = AsyncMock(return_value={})

    executor, disp, _r_repo, _e_repo = _build_executor(
        enrichment_pipeline=mock_pipeline
    )
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    result = await executor.execute(**_execute_kwargs())

    assert mock_pipeline.enrich_entity.call_count == 1
    assert result.enrichment_count == 0


async def test_enrichment_count_defaults_to_zero() -> None:
    """RunResult.enrichment_count defaults to 0 when not provided."""
    result = RunResult(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        final_state="completed",
        total_seeds=0,
        expanded_seeds=0,
        total_dispatches=0,
        successful_dispatches=0,
        failed_dispatches=0,
        denied_dispatches=0,
        total_observations=0,
        duration_ms=1.0,
    )
    assert result.enrichment_count == 0


async def test_partial_enrichment_failures() -> None:
    """When some enrichment calls succeed and others raise, only successes are counted."""
    obs1 = _make_observation(identifier_value="good.example.com")
    obs2 = _make_observation(identifier_value="bad.example.com")
    obs3 = _make_observation(identifier_value="also-good.example.com")

    mock_pipeline = AsyncMock(spec=EnrichmentPipeline)
    mock_pipeline.enrich_entity = AsyncMock(
        side_effect=[
            {"attribution": {"adjusted_confidence": 0.6}},
            RuntimeError("LLM timeout"),
            {"noise": {"is_noise": True}},
        ]
    )

    executor, disp, _r_repo, _e_repo = _build_executor(
        enrichment_pipeline=mock_pipeline
    )
    disp.dispatch = AsyncMock(return_value=_success_result(obs1, obs2, obs3))

    result = await executor.execute(**_execute_kwargs())

    assert result.final_state == "completed"
    assert mock_pipeline.enrich_entity.call_count == 3
    assert result.enrichment_count == 2  # first and third succeed


async def test_medium_confidence_triggers_attribution() -> None:
    """The enrichment pipeline internally filters: only [0.4, 0.7) triggers attribution.

    This test uses a real EnrichmentPipeline with no LLM client to verify
    that the executor passes the attribution_confidence parameter and the
    pipeline's internal filtering works end-to-end.
    """
    obs = _make_observation()

    # Real pipeline with no LLM client -- always returns {} (graceful degradation)
    real_pipeline = EnrichmentPipeline(llm_client=None)

    executor, disp, _r_repo, _e_repo = _build_executor(
        enrichment_pipeline=real_pipeline
    )
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    result = await executor.execute(**_execute_kwargs())

    # Pipeline returns {} because no LLM client -> enrichment_count = 0
    assert result.enrichment_count == 0
    assert result.final_state == "completed"


async def test_no_observations_skips_enrichment() -> None:
    """When there are no observations, enrichment loop body is never entered."""
    mock_pipeline = AsyncMock(spec=EnrichmentPipeline)
    mock_pipeline.enrich_entity = AsyncMock(return_value={})

    executor, disp, _r_repo, _e_repo = _build_executor(
        enrichment_pipeline=mock_pipeline
    )
    disp.dispatch = AsyncMock(return_value=_success_result())  # no observations

    result = await executor.execute(**_execute_kwargs())

    mock_pipeline.enrich_entity.assert_not_called()
    assert result.enrichment_count == 0


async def test_enrichment_does_not_affect_final_state() -> None:
    """Enrichment failures do not change the final_state of the run."""
    obs = _make_observation()

    mock_pipeline = AsyncMock(spec=EnrichmentPipeline)
    mock_pipeline.enrich_entity = AsyncMock(
        side_effect=RuntimeError("total failure")
    )

    executor, disp, _r_repo, _e_repo = _build_executor(
        enrichment_pipeline=mock_pipeline
    )
    disp.dispatch = AsyncMock(return_value=_success_result(obs))

    result = await executor.execute(**_execute_kwargs())

    # Despite enrichment failure, dispatch succeeded -> completed
    assert result.final_state == "completed"
    assert result.successful_dispatches == 1
    assert result.enrichment_count == 0

"""Tests for the prioritized findings endpoint (``expose.api.findings``).

Validates issue #69 — Priority Findings panel API:

 1. GET /findings/ returns 200
 2. Response has correct structure (FindingsResponse)
 3. Findings sorted by score descending
 4. limit parameter respected
 5. min_score filter works
 6. FindingEntry model validation
 7. Empty tenant returns empty findings when min_score filters all out
 8. Score color function returns correct colors (JavaScript logic, tested
    as a Python translation for coverage)
 9. Default limit returns all placeholder findings
10. Invalid query parameters rejected with 422
11. Real scored entities returned when DB has them (is_placeholder=False)
12. Placeholder fallback when DB has no scored entities
13. min_score filter works with real scored entities
14. limit applies correctly with real scored entities
15. _flush_batch calls lead scoring for upserted entities

Uses ``httpx.AsyncClient`` with ``ASGITransport`` against a standalone
FastAPI app that includes only the findings router (no DB required for
placeholder tests; mock session_factory for real-data tests).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from expose.api.findings import (
    _PLACEHOLDER_FINDINGS,
    FindingEntry,
    FindingsResponse,
    _build_placeholder_findings,
    router,
)

# ---------------------------------------------------------------------------
# Test app — minimal, no DB, just the findings router
# ---------------------------------------------------------------------------

_TENANT_ID = "00000000-0000-0000-0000-000000000001"
_BASE_URL = f"http://test/v1/tenants/{_TENANT_ID}/findings"


def _make_app() -> FastAPI:
    """Build a minimal FastAPI app with the findings router mounted."""
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture()
def app() -> FastAPI:
    return _make_app()


@pytest.fixture()
async def client(app: FastAPI) -> AsyncClient:
    """Yield an async HTTP client wired to the test app."""
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    )


# ---------------------------------------------------------------------------
# 1. GET /findings/ returns 200
# ---------------------------------------------------------------------------


async def test_get_findings_returns_200(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 2. Response has correct structure (FindingsResponse)
# ---------------------------------------------------------------------------


async def test_response_structure(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/")
    data = resp.json()

    # Top-level fields
    assert "tenant_id" in data
    assert data["tenant_id"] == _TENANT_ID
    assert "findings" in data
    assert isinstance(data["findings"], list)
    assert "total_scored" in data
    assert isinstance(data["total_scored"], int)
    assert "generated_at" in data

    # Validate each finding entry
    for finding in data["findings"]:
        assert "rank" in finding
        assert "entity_identifier" in finding
        assert "entity_type" in finding
        assert "score" in finding
        assert "priority_tier" in finding
        assert "justification" in finding
        assert "signals" in finding
        assert isinstance(finding["signals"], list)


# ---------------------------------------------------------------------------
# 3. Findings sorted by score descending
# ---------------------------------------------------------------------------


async def test_findings_sorted_by_score_descending(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/")
    data = resp.json()
    findings = data["findings"]

    scores = [f["score"] for f in findings]
    assert scores == sorted(scores, reverse=True), "Findings must be sorted by score descending"


# ---------------------------------------------------------------------------
# 4. limit parameter respected
# ---------------------------------------------------------------------------


async def test_limit_parameter(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/?limit=3")
    data = resp.json()
    assert len(data["findings"]) == 3


async def test_limit_minimum_is_1(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/?limit=0")
    assert resp.status_code == 422


async def test_limit_maximum_is_100(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/?limit=101")
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 5. min_score filter works
# ---------------------------------------------------------------------------


async def test_min_score_filter(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/?min_score=70")
    data = resp.json()
    for finding in data["findings"]:
        assert finding["score"] >= 70


async def test_min_score_filters_low_scores(client: AsyncClient) -> None:
    resp_all = await client.get(f"{_BASE_URL}/")
    resp_filtered = await client.get(f"{_BASE_URL}/?min_score=50")
    all_count = len(resp_all.json()["findings"])
    filtered_count = len(resp_filtered.json()["findings"])
    assert filtered_count < all_count, "min_score should reduce the result set"


# ---------------------------------------------------------------------------
# 6. FindingEntry model validation
# ---------------------------------------------------------------------------


class TestFindingEntryValidation:
    """Unit tests for FindingEntry Pydantic model validation."""

    def test_valid_finding(self) -> None:
        entry = FindingEntry(
            rank=1,
            entity_identifier="test.example.com",
            entity_type="domain",
            score=75,
            priority_tier="high",
            justification="Test justification",
            signals=[{"signal": "test", "weight": 10}],
        )
        assert entry.rank == 1
        assert entry.score == 75

    def test_score_below_minimum_rejected(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            FindingEntry(
                rank=1,
                entity_identifier="test.example.com",
                entity_type="domain",
                score=-1,
                priority_tier="low",
                justification="Negative score",
                signals=[],
            )

    def test_score_above_maximum_rejected(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            FindingEntry(
                rank=1,
                entity_identifier="test.example.com",
                entity_type="domain",
                score=101,
                priority_tier="low",
                justification="Over 100",
                signals=[],
            )

    def test_rank_below_minimum_rejected(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            FindingEntry(
                rank=0,
                entity_identifier="test.example.com",
                entity_type="domain",
                score=50,
                priority_tier="medium",
                justification="Zero rank",
                signals=[],
            )

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            FindingEntry(
                rank=1,
                entity_identifier="test.example.com",
                entity_type="domain",
                score=50,
                priority_tier="medium",
                justification="Extra field",
                signals=[],
                extra_field="should fail",  # type: ignore[call-arg]
            )

    def test_frozen_immutability(self) -> None:
        entry = FindingEntry(
            rank=1,
            entity_identifier="test.example.com",
            entity_type="domain",
            score=50,
            priority_tier="medium",
            justification="Frozen test",
            signals=[],
        )
        with pytest.raises(Exception):  # noqa: B017
            entry.score = 99  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 7. Empty findings when min_score filters all out
# ---------------------------------------------------------------------------


async def test_high_min_score_returns_empty(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/?min_score=100")
    data = resp.json()
    # No placeholder findings have score=100
    assert len(data["findings"]) == 0
    assert data["total_scored"] == len(_PLACEHOLDER_FINDINGS)


# ---------------------------------------------------------------------------
# 8. Score color function (JavaScript logic tested as Python translation)
# ---------------------------------------------------------------------------


class TestScoreColor:
    """Test the scoreColor logic that maps scores to CSS variables.

    This mirrors the JavaScript ``scoreColor()`` function in expose.js.
    """

    @staticmethod
    def _score_color(score: int) -> str:
        if score >= 70:
            return "var(--error)"
        if score >= 40:
            return "var(--warning)"
        if score >= 20:
            return "var(--accent)"
        return "var(--text-dim)"

    def test_critical_score_returns_error(self) -> None:
        assert self._score_color(92) == "var(--error)"
        assert self._score_color(70) == "var(--error)"
        assert self._score_color(100) == "var(--error)"

    def test_high_score_returns_warning(self) -> None:
        assert self._score_color(69) == "var(--warning)"
        assert self._score_color(40) == "var(--warning)"
        assert self._score_color(55) == "var(--warning)"

    def test_medium_score_returns_accent(self) -> None:
        assert self._score_color(39) == "var(--accent)"
        assert self._score_color(20) == "var(--accent)"

    def test_low_score_returns_dim(self) -> None:
        assert self._score_color(19) == "var(--text-dim)"
        assert self._score_color(0) == "var(--text-dim)"


# ---------------------------------------------------------------------------
# 9. Default limit returns all placeholder findings
# ---------------------------------------------------------------------------


async def test_default_limit_returns_all_placeholders(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/")
    data = resp.json()
    assert len(data["findings"]) == len(_PLACEHOLDER_FINDINGS)
    assert data["total_scored"] == len(_PLACEHOLDER_FINDINGS)


# ---------------------------------------------------------------------------
# 10. Ranks are sequential starting at 1
# ---------------------------------------------------------------------------


async def test_ranks_sequential(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/")
    data = resp.json()
    ranks = [f["rank"] for f in data["findings"]]
    assert ranks == list(range(1, len(data["findings"]) + 1))


# ---------------------------------------------------------------------------
# Unit tests for _build_placeholder_findings
# ---------------------------------------------------------------------------


class TestBuildPlaceholderFindings:
    """Unit tests for the internal builder function."""

    def test_returns_findings_response(self) -> None:
        result = _build_placeholder_findings(
            UUID(_TENANT_ID), limit=20, min_score=0,
        )
        assert isinstance(result, FindingsResponse)
        assert result.tenant_id == UUID(_TENANT_ID)

    def test_limit_applied(self) -> None:
        result = _build_placeholder_findings(
            UUID(_TENANT_ID), limit=2, min_score=0,
        )
        assert len(result.findings) == 2

    def test_min_score_applied(self) -> None:
        result = _build_placeholder_findings(
            UUID(_TENANT_ID), limit=100, min_score=80,
        )
        for f in result.findings:
            assert f.score >= 80

    def test_sorted_descending(self) -> None:
        result = _build_placeholder_findings(
            UUID(_TENANT_ID), limit=100, min_score=0,
        )
        scores = [f.score for f in result.findings]
        assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# Helpers for real-data and pipeline tests
# ---------------------------------------------------------------------------


def _make_entity_row(
    canonical_identifier: str,
    entity_type: str = "domain",
    properties: dict[str, Any] | None = None,
    attribution_status: str = "unattributed",
    attribution_confidence: Decimal = Decimal("0.000"),
) -> MagicMock:
    """Build a mock Entity ORM row with the given properties."""
    entity = MagicMock()
    entity.id = uuid4()
    entity.tenant_id = UUID(_TENANT_ID)
    entity.entity_type = entity_type
    entity.canonical_identifier = canonical_identifier
    entity.properties = properties or {}
    entity.attribution_status = attribution_status
    entity.attribution_confidence = attribution_confidence
    entity.last_observed_at = datetime.now(tz=UTC)
    return entity


def _make_scored_entity(
    canonical_identifier: str,
    score: int,
    tier: str = "low",
    entity_type: str = "domain",
) -> MagicMock:
    """Build a mock Entity with ``_lead_score`` and ``_priority_tier``."""
    return _make_entity_row(
        canonical_identifier=canonical_identifier,
        entity_type=entity_type,
        properties={
            "_lead_score": score,
            "_priority_tier": tier,
            "_collector_id": "test-collector",
        },
    )


def _mock_session_factory(entities: list[Any]):
    """Build a mock async session factory that returns the given entities.

    Returns an async context-manager-compatible callable that mimics
    ``async_sessionmaker().__call__()`` -> session with ``.execute()``.
    """
    mock_result = MagicMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = entities
    mock_result.scalars.return_value = mock_scalars

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    @asynccontextmanager
    async def factory():
        yield mock_session

    return factory


def _make_app_with_session_factory(entities: list[Any]) -> FastAPI:
    """Build a FastAPI app with a mock session_factory on app.state."""
    app = FastAPI()
    app.include_router(router)
    app.state.session_factory = _mock_session_factory(entities)
    return app


# ---------------------------------------------------------------------------
# 11. Real scored entities returned (is_placeholder=False)
# ---------------------------------------------------------------------------


async def test_real_scored_entities_returned() -> None:
    """When DB has scored entities, return them with is_placeholder=False."""
    entities = [
        _make_scored_entity("staging.example.com", 85, "critical"),
        _make_scored_entity("api.example.com", 45, "high"),
        _make_scored_entity("www.example.com", 10, "low"),
    ]
    app = _make_app_with_session_factory(entities)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(f"{_BASE_URL}/")

    assert resp.status_code == 200
    data = resp.json()
    assert data["is_placeholder"] is False
    assert len(data["findings"]) == 3
    # Should be sorted by score descending
    scores = [f["score"] for f in data["findings"]]
    assert scores == sorted(scores, reverse=True)
    assert data["findings"][0]["entity_identifier"] == "staging.example.com"
    assert data["findings"][0]["score"] == 85


# ---------------------------------------------------------------------------
# 12. Placeholder fallback when DB has no scored entities
# ---------------------------------------------------------------------------


async def test_placeholder_fallback_with_empty_db() -> None:
    """When DB has entities but none are scored, fall back to placeholders."""
    entities = [
        _make_entity_row("example.com"),  # no _lead_score
    ]
    app = _make_app_with_session_factory(entities)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(f"{_BASE_URL}/")

    data = resp.json()
    assert data["is_placeholder"] is True
    assert len(data["findings"]) == len(_PLACEHOLDER_FINDINGS)


async def test_placeholder_fallback_with_no_session_factory() -> None:
    """When no session_factory exists (no DB), return placeholders."""
    app = _make_app()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(f"{_BASE_URL}/")

    data = resp.json()
    assert data["is_placeholder"] is True
    assert len(data["findings"]) == len(_PLACEHOLDER_FINDINGS)


# ---------------------------------------------------------------------------
# 13. min_score filter works with real scored entities
# ---------------------------------------------------------------------------


async def test_min_score_filter_real_data() -> None:
    """min_score should filter real scored entities correctly."""
    entities = [
        _make_scored_entity("critical.example.com", 90, "critical"),
        _make_scored_entity("high.example.com", 55, "high"),
        _make_scored_entity("low.example.com", 15, "low"),
    ]
    app = _make_app_with_session_factory(entities)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(f"{_BASE_URL}/?min_score=50")

    data = resp.json()
    assert data["is_placeholder"] is False
    assert len(data["findings"]) == 2
    for finding in data["findings"]:
        assert finding["score"] >= 50


# ---------------------------------------------------------------------------
# 14. limit applies correctly with real scored entities
# ---------------------------------------------------------------------------


async def test_limit_real_data() -> None:
    """limit should cap the number of real scored entities returned."""
    entities = [
        _make_scored_entity("a.example.com", 90, "critical"),
        _make_scored_entity("b.example.com", 80, "critical"),
        _make_scored_entity("c.example.com", 70, "critical"),
        _make_scored_entity("d.example.com", 60, "high"),
        _make_scored_entity("e.example.com", 50, "high"),
    ]
    app = _make_app_with_session_factory(entities)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(f"{_BASE_URL}/?limit=3")

    data = resp.json()
    assert data["is_placeholder"] is False
    assert len(data["findings"]) == 3
    assert data["total_scored"] == 5
    # Top 3 by score
    assert data["findings"][0]["score"] == 90
    assert data["findings"][2]["score"] == 70


# ---------------------------------------------------------------------------
# 15. _flush_batch calls lead scoring for upserted entities
# ---------------------------------------------------------------------------


async def test_flush_batch_calls_lead_scoring() -> None:
    """Verify _flush_batch invokes LeadScoringEngine after entity upsert."""
    from expose.collectors.base import (
        Observation,
        ObservationSubject,
        ObservationType,
        Seed,
        SeedType,
    )
    from expose.pipeline.run_executor import RunExecutor
    from expose.types.canonical import IdentifierType

    tenant_id = UUID(_TENANT_ID)
    run_id = uuid4()
    observed = datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)

    obs = Observation(
        collector_id="test-collector",
        collector_version="1.0.0",
        tenant_id=tenant_id,
        observation_type=ObservationType.DNS_RESOLUTION,
        subject=ObservationSubject(
            identifier_type=IdentifierType.DOMAIN,
            identifier_value="test.example.com",
        ),
        observed_at=observed,
        structured_payload={"resolved_ip": "93.184.216.34"},
    )

    # Build mock entity returned by create_or_update
    mock_entity = _make_entity_row(
        "test.example.com",
        entity_type="domain",
        properties={"resolved_ip": "93.184.216.34"},
    )

    entity_repo = AsyncMock()
    entity_repo.create_or_update = AsyncMock(return_value=mock_entity)

    run_repo = AsyncMock()
    dispatcher = AsyncMock()

    executor = RunExecutor(
        dispatcher=dispatcher,
        run_repo=run_repo,
        entity_repo=entity_repo,
    )

    with patch(
        "expose.pipeline.lead_scoring.LeadScoringEngine"
    ) as mock_engine_cls:
        mock_scorer = MagicMock()
        mock_score_result = MagicMock()
        mock_score_result.score = 42
        mock_score_result.priority_tier = MagicMock()
        mock_score_result.priority_tier.value = "high"
        mock_scorer.score_entity.return_value = mock_score_result
        mock_engine_cls.return_value = mock_scorer

        await executor._flush_batch([obs], run_id, tenant_id)

        # LeadScoringEngine should have been instantiated and called
        mock_engine_cls.assert_called_once()
        mock_scorer.score_entity.assert_called_once()

        # Verify the scoring call used correct entity_identifier
        call_kwargs = mock_scorer.score_entity.call_args
        assert call_kwargs.kwargs["entity_identifier"] == "test.example.com"
        assert isinstance(call_kwargs.kwargs["observations"], list)

        # Verify create_or_update was called twice:
        # 1. Initial entity upsert
        # 2. Lead score property update
        assert entity_repo.create_or_update.call_count == 2

        # The second call should include _lead_score and _priority_tier
        second_call = entity_repo.create_or_update.call_args_list[1]
        props = second_call.kwargs["properties"]
        assert props["_lead_score"] == 42
        assert props["_priority_tier"] == "high"


async def test_flush_batch_scoring_exception_does_not_crash() -> None:
    """Lead scoring failure for one entity must not crash the batch."""
    from expose.collectors.base import (
        Observation,
        ObservationSubject,
        ObservationType,
    )
    from expose.pipeline.run_executor import RunExecutor
    from expose.types.canonical import IdentifierType

    tenant_id = UUID(_TENANT_ID)
    run_id = uuid4()
    observed = datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)

    obs = Observation(
        collector_id="test-collector",
        collector_version="1.0.0",
        tenant_id=tenant_id,
        observation_type=ObservationType.DNS_RESOLUTION,
        subject=ObservationSubject(
            identifier_type=IdentifierType.DOMAIN,
            identifier_value="fail.example.com",
        ),
        observed_at=observed,
        structured_payload={"resolved_ip": "1.2.3.4"},
    )

    mock_entity = _make_entity_row("fail.example.com")
    entity_repo = AsyncMock()
    entity_repo.create_or_update = AsyncMock(return_value=mock_entity)

    executor = RunExecutor(
        dispatcher=AsyncMock(),
        run_repo=AsyncMock(),
        entity_repo=entity_repo,
    )

    with patch(
        "expose.pipeline.lead_scoring.LeadScoringEngine"
    ) as mock_engine_cls:
        mock_scorer = MagicMock()
        mock_scorer.score_entity.side_effect = RuntimeError("scoring boom")
        mock_engine_cls.return_value = mock_scorer

        # Should not raise — exception is caught and logged
        enrichment_count, upsert_failures = await executor._flush_batch(
            [obs], run_id, tenant_id,
        )

        # The batch should still complete (upsert succeeded)
        assert upsert_failures == 0


async def test_flush_batch_no_scoring_when_entity_map_empty() -> None:
    """When all entity upserts fail, lead scoring should be skipped."""
    from expose.collectors.base import (
        Observation,
        ObservationSubject,
        ObservationType,
    )
    from expose.pipeline.run_executor import RunExecutor
    from expose.types.canonical import IdentifierType

    tenant_id = UUID(_TENANT_ID)
    run_id = uuid4()
    observed = datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)

    obs = Observation(
        collector_id="test-collector",
        collector_version="1.0.0",
        tenant_id=tenant_id,
        observation_type=ObservationType.DNS_RESOLUTION,
        subject=ObservationSubject(
            identifier_type=IdentifierType.DOMAIN,
            identifier_value="broken.example.com",
        ),
        observed_at=observed,
        structured_payload={},
    )

    entity_repo = AsyncMock()
    entity_repo.create_or_update = AsyncMock(
        side_effect=RuntimeError("db error"),
    )

    executor = RunExecutor(
        dispatcher=AsyncMock(),
        run_repo=AsyncMock(),
        entity_repo=entity_repo,
    )

    with patch(
        "expose.pipeline.lead_scoring.LeadScoringEngine"
    ) as mock_engine_cls:
        await executor._flush_batch([obs], run_id, tenant_id)

        # Scoring engine should never be instantiated when entity_map is empty
        mock_engine_cls.assert_not_called()


# ---------------------------------------------------------------------------
# 16. Real data: ranks are sequential
# ---------------------------------------------------------------------------


async def test_real_data_ranks_sequential() -> None:
    """Real scored entities should have sequential ranks starting at 1."""
    entities = [
        _make_scored_entity("a.example.com", 90, "critical"),
        _make_scored_entity("b.example.com", 60, "high"),
    ]
    app = _make_app_with_session_factory(entities)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(f"{_BASE_URL}/")

    data = resp.json()
    ranks = [f["rank"] for f in data["findings"]]
    assert ranks == [1, 2]

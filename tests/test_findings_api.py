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

Uses ``httpx.AsyncClient`` with ``ASGITransport`` against a standalone
FastAPI app that includes only the findings router (no DB required).
"""

from __future__ import annotations

from uuid import UUID

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

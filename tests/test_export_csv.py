"""Tests for the CSV export endpoint (``expose.api.export``).

Validates issue #66 — filtered CSV download from the Darkroom dashboard:

 1. GET /export/csv returns 200 with text/csv content-type
 2. Content-Disposition header has filename
 3. CSV has expected column headers
 4. entity_type filter narrows results
 5. attribution_tier filter narrows results
 6. Multiple filters combine (AND logic)
 7. Empty result returns headers-only CSV
 8. Limit parameter respected
 9. Invalid filter values handled gracefully (empty result, not error)
10. collector_id filter narrows results
11. environment filter narrows results
12. Default limit does not exceed 10,000

Uses ``httpx.AsyncClient`` with ``ASGITransport`` against a standalone
FastAPI app that includes only the export router (no DB required — the
export endpoint falls back to placeholder data when no session factory
is available).
"""

from __future__ import annotations

import csv
import io

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from expose.api.export import (
    _CSV_COLUMNS,
    _PLACEHOLDER_ENTITIES,
    _filter_entities,
    _generate_csv,
    router,
)

# ---------------------------------------------------------------------------
# Test app — minimal, no DB, just the export router
# ---------------------------------------------------------------------------

_TENANT_ID = "00000000-0000-0000-0000-000000000001"
_BASE_URL = f"http://test/v1/tenants/{_TENANT_ID}/export"


def _make_app() -> FastAPI:
    """Build a minimal FastAPI app with the export router mounted."""
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


def _parse_csv(text: str) -> list[dict[str, str]]:
    """Parse CSV text into a list of row dicts."""
    reader = csv.DictReader(io.StringIO(text))
    return list(reader)


# ---------------------------------------------------------------------------
# 1. GET /export/csv returns 200 with text/csv content-type
# ---------------------------------------------------------------------------


async def test_export_csv_returns_200_text_csv(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")


# ---------------------------------------------------------------------------
# 2. Content-Disposition header has filename
# ---------------------------------------------------------------------------


async def test_export_csv_content_disposition(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/csv")
    cd = resp.headers["content-disposition"]
    assert "attachment" in cd
    assert "expose-export-" in cd
    assert _TENANT_ID in cd
    assert ".csv" in cd


# ---------------------------------------------------------------------------
# 3. CSV has expected column headers
# ---------------------------------------------------------------------------


async def test_export_csv_column_headers(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/csv")
    rows = _parse_csv(resp.text)
    # At least one row should exist (placeholder data)
    assert len(rows) > 0
    # Every column we expect should be present as a key
    for col in _CSV_COLUMNS:
        assert col in rows[0], f"Missing column: {col}"


# ---------------------------------------------------------------------------
# 4. entity_type filter narrows results
# ---------------------------------------------------------------------------


async def test_entity_type_filter(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/csv?entity_type=ip_address")
    rows = _parse_csv(resp.text)
    assert len(rows) > 0
    for row in rows:
        assert row["entity_type"] == "ip_address"

    # Should be fewer than the unfiltered set
    resp_all = await client.get(f"{_BASE_URL}/csv")
    rows_all = _parse_csv(resp_all.text)
    assert len(rows) < len(rows_all)


# ---------------------------------------------------------------------------
# 5. attribution_tier filter narrows results
# ---------------------------------------------------------------------------


async def test_attribution_tier_filter(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/csv?attribution_tier=confirmed")
    rows = _parse_csv(resp.text)
    assert len(rows) > 0
    for row in rows:
        assert row["attribution_tier"] == "confirmed"

    resp_all = await client.get(f"{_BASE_URL}/csv")
    rows_all = _parse_csv(resp_all.text)
    assert len(rows) < len(rows_all)


# ---------------------------------------------------------------------------
# 6. Multiple filters combine (AND logic)
# ---------------------------------------------------------------------------


async def test_multiple_filters_combine(client: AsyncClient) -> None:
    resp = await client.get(
        f"{_BASE_URL}/csv?entity_type=domain&attribution_tier=confirmed"
    )
    rows = _parse_csv(resp.text)
    for row in rows:
        assert row["entity_type"] == "domain"
        assert row["attribution_tier"] == "confirmed"

    # Combined should be <= either individual filter
    resp_type = await client.get(f"{_BASE_URL}/csv?entity_type=domain")
    resp_tier = await client.get(f"{_BASE_URL}/csv?attribution_tier=confirmed")
    rows_type = _parse_csv(resp_type.text)
    rows_tier = _parse_csv(resp_tier.text)
    assert len(rows) <= len(rows_type)
    assert len(rows) <= len(rows_tier)


# ---------------------------------------------------------------------------
# 7. Empty result returns headers-only CSV
# ---------------------------------------------------------------------------


async def test_empty_result_headers_only(client: AsyncClient) -> None:
    resp = await client.get(
        f"{_BASE_URL}/csv?entity_type=nonexistent_type_xyz"
    )
    assert resp.status_code == 200
    rows = _parse_csv(resp.text)
    assert len(rows) == 0

    # Header row should still be present
    lines = resp.text.strip().split("\n")
    assert len(lines) == 1  # Just the header
    header_cols = lines[0].split(",")
    assert header_cols == _CSV_COLUMNS


# ---------------------------------------------------------------------------
# 8. Limit parameter respected
# ---------------------------------------------------------------------------


async def test_limit_parameter(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/csv?limit=2")
    rows = _parse_csv(resp.text)
    assert len(rows) == 2


async def test_limit_minimum_is_1(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/csv?limit=0")
    assert resp.status_code == 422  # Validation error


async def test_limit_maximum_is_10000(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/csv?limit=10001")
    assert resp.status_code == 422  # Validation error


# ---------------------------------------------------------------------------
# 9. Invalid filter values handled gracefully (empty result, not error)
# ---------------------------------------------------------------------------


async def test_invalid_entity_type_returns_empty(
    client: AsyncClient,
) -> None:
    resp = await client.get(
        f"{_BASE_URL}/csv?entity_type=bogus_does_not_exist"
    )
    assert resp.status_code == 200
    rows = _parse_csv(resp.text)
    assert len(rows) == 0


async def test_invalid_tier_returns_empty(client: AsyncClient) -> None:
    resp = await client.get(
        f"{_BASE_URL}/csv?attribution_tier=nonexistent"
    )
    assert resp.status_code == 200
    rows = _parse_csv(resp.text)
    assert len(rows) == 0


# ---------------------------------------------------------------------------
# 10. collector_id filter narrows results
# ---------------------------------------------------------------------------


async def test_collector_id_filter(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/csv?collector_id=ct_crtsh")
    rows = _parse_csv(resp.text)
    assert len(rows) > 0
    for row in rows:
        assert "ct_crtsh" in row["collectors"]


# ---------------------------------------------------------------------------
# 11. environment filter narrows results
# ---------------------------------------------------------------------------


async def test_environment_filter(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/csv?environment=staging")
    rows = _parse_csv(resp.text)
    assert len(rows) > 0
    for row in rows:
        assert row["environment"] == "staging"


# ---------------------------------------------------------------------------
# Unit tests for internal helper functions
# ---------------------------------------------------------------------------


class TestFilterEntities:
    """Unit tests for ``_filter_entities``."""

    def test_no_filters_returns_all(self) -> None:
        result = _filter_entities(
            list(_PLACEHOLDER_ENTITIES),
            entity_type=None,
            attribution_tier=None,
            collector_id=None,
            environment=None,
        )
        assert len(result) == len(_PLACEHOLDER_ENTITIES)

    def test_entity_type_filter(self) -> None:
        result = _filter_entities(
            list(_PLACEHOLDER_ENTITIES),
            entity_type="ip_address",
            attribution_tier=None,
            collector_id=None,
            environment=None,
        )
        assert all(e["entity_type"] == "ip_address" for e in result)
        assert len(result) > 0

    def test_all_filters_combine(self) -> None:
        result = _filter_entities(
            list(_PLACEHOLDER_ENTITIES),
            entity_type="domain",
            attribution_tier="confirmed",
            collector_id=None,
            environment="production",
        )
        for e in result:
            assert e["entity_type"] == "domain"
            assert e["attribution_tier"] == "confirmed"
            assert e["environment"] == "production"


class TestGenerateCsv:
    """Unit tests for ``_generate_csv``."""

    def test_empty_list_produces_header_only(self) -> None:
        output = _generate_csv([])
        lines = output.strip().split("\n")
        assert len(lines) == 1
        assert lines[0] == ",".join(_CSV_COLUMNS)

    def test_rows_are_written(self) -> None:
        output = _generate_csv(_PLACEHOLDER_ENTITIES[:2])
        rows = _parse_csv(output)
        assert len(rows) == 2
        assert rows[0]["entity_identifier"] == "example.com"

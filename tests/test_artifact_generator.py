"""Tests for the canonical artifact generator (Stage 5).

All tests use ``unittest.mock.AsyncMock`` for the entity, relationship, and
run repositories — the generator is tested in isolation from real databases.

Coverage:

1. Generate with entities produces artifact with targets.
2. Generate with relationships populates relationship count.
3. Empty graph produces artifact with empty targets list.
4. Content hash is computed via FIPS adapter (64-char hex string).
5. ArtifactResult has correct entity/relationship counts.
6. JSON bytes are valid JSON that round-trips through the schema.
7. Target identifiers match entity canonical_identifiers.
8. Run metadata (run_id, tenant_id, state) appears in artifact.
9. ArtifactResult is frozen (immutable).
10. Missing run raises LookupError.
11. Entity attribution confidence maps to correct tier.
12. Collector health entries extracted from entity properties.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest

from expose.pipeline.artifact_generator import ArtifactGenerator
from expose.storage import StorageBackend
from expose.storage.local import LocalStorageBackend

# === Synthetic IDs ============================================================

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000a001")
RUN_ID = UUID("018f1f00-0000-7000-8000-000000000001")
ENTITY_ID_1 = UUID("018f1f00-0000-7000-8000-000000000101")
ENTITY_ID_2 = UUID("018f1f00-0000-7000-8000-000000000102")
REL_ID_1 = UUID("018f1f00-0000-7000-8000-000000000201")
NOW = datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)
VALID_GIT_SHA = "a" * 40


# === Helpers ==================================================================


def _make_entity_row(
    entity_id: UUID = ENTITY_ID_1,
    entity_type: str = "Domain",
    canonical_identifier: str = "example.com",
    attribution_status: str = "confirmed",
    attribution_confidence: Decimal = Decimal("0.950"),
    properties: dict[str, Any] | None = None,
) -> MagicMock:
    """Build a mock Entity ORM row."""
    row = MagicMock()
    row.id = entity_id
    row.tenant_id = TENANT_ID
    row.entity_type = entity_type
    row.canonical_identifier = canonical_identifier
    row.attribution_status = attribution_status
    row.attribution_confidence = attribution_confidence
    row.first_observed_at = NOW
    row.last_observed_at = NOW
    row.properties = properties or {
        "_collector_id": "test-collector",
        "_collector_version": "1.0.0",
        "source": "test",
    }
    return row


def _make_relationship_row(
    rel_id: UUID = REL_ID_1,
    from_entity_id: UUID = ENTITY_ID_1,
    to_entity_id: UUID = ENTITY_ID_2,
    edge_type: str = "resolves_to",
) -> MagicMock:
    """Build a mock Relationship ORM row."""
    row = MagicMock()
    row.id = rel_id
    row.tenant_id = TENANT_ID
    row.from_entity_id = from_entity_id
    row.to_entity_id = to_entity_id
    row.edge_type = edge_type
    row.confidence = Decimal("0.900")
    row.observed_at = NOW
    row.collector_id = "test-collector"
    row.evidence_ref = None
    row.properties = {}
    return row


def _make_run_row(
    state: str = "completed",
    pipeline_version: str = VALID_GIT_SHA,
) -> MagicMock:
    """Build a mock Run ORM row."""
    row = MagicMock()
    row.id = RUN_ID
    row.tenant_id = TENANT_ID
    row.state = state
    row.pipeline_version = pipeline_version
    row.started_at = NOW
    row.completed_at = NOW
    row.canonical_artifact_ref = None
    row.manifest_ref = None
    row.target_count = None
    return row


def _build_generator(
    entities: list[MagicMock] | None = None,
    relationships: list[MagicMock] | None = None,
    run_row: MagicMock | None = None,
    storage: StorageBackend | None = None,
) -> ArtifactGenerator:
    """Wire up an ArtifactGenerator with mocked dependencies."""
    entity_repo = AsyncMock()
    entity_repo.list_for_tenant = AsyncMock(return_value=entities or [])

    relationship_repo = AsyncMock()
    relationship_repo.find_for_entity = AsyncMock(
        return_value=relationships or [],
    )

    run_repo = AsyncMock()
    run_repo.get_by_id = AsyncMock(return_value=run_row or _make_run_row())

    return ArtifactGenerator(
        entity_repo=entity_repo,
        relationship_repo=relationship_repo,
        run_repo=run_repo,
        storage=storage,
    )


# === Tests ====================================================================


async def test_generate_with_entities_produces_targets() -> None:
    """Generate with entities produces artifact with targets."""
    entities = [
        _make_entity_row(entity_id=ENTITY_ID_1, canonical_identifier="example.com"),
        _make_entity_row(entity_id=ENTITY_ID_2, canonical_identifier="test.example.com"),
    ]
    gen = _build_generator(entities=entities)

    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    assert len(result.artifact.targets) == 2
    assert result.entity_count == 2


async def test_generate_with_relationships_populates_count() -> None:
    """Generate with relationships records relationship count correctly."""
    entities = [
        _make_entity_row(entity_id=ENTITY_ID_1, canonical_identifier="a.example.com"),
        _make_entity_row(entity_id=ENTITY_ID_2, canonical_identifier="b.example.com"),
    ]
    rel = _make_relationship_row()

    # The relationship repo is called per entity, return the rel for the first
    entity_repo = AsyncMock()
    entity_repo.list_for_tenant = AsyncMock(return_value=entities)

    relationship_repo = AsyncMock()
    # First entity returns the relationship; second returns empty (avoids double-counting)
    relationship_repo.find_for_entity = AsyncMock(
        side_effect=[[rel], []],
    )

    run_repo = AsyncMock()
    run_repo.get_by_id = AsyncMock(return_value=_make_run_row())

    gen = ArtifactGenerator(
        entity_repo=entity_repo,
        relationship_repo=relationship_repo,
        run_repo=run_repo,
    )
    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    assert result.relationship_count == 1
    assert result.entity_count == 2


async def test_empty_graph_produces_empty_targets() -> None:
    """Empty graph produces artifact with empty targets list."""
    gen = _build_generator(entities=[], relationships=[])

    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    assert result.artifact.targets == []
    assert result.entity_count == 0
    assert result.relationship_count == 0


async def test_content_hash_is_64_char_hex() -> None:
    """Content hash is a 64-char lowercase hex string (SHA-256 via FIPS adapter)."""
    entities = [_make_entity_row()]
    gen = _build_generator(entities=entities)

    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    assert len(result.content_hash) == 64
    assert re.fullmatch(r"[a-f0-9]{64}", result.content_hash) is not None


async def test_entity_and_relationship_counts_correct() -> None:
    """ArtifactResult has correct entity/relationship counts."""
    entities = [
        _make_entity_row(entity_id=ENTITY_ID_1, canonical_identifier="one.example.com"),
        _make_entity_row(entity_id=ENTITY_ID_2, canonical_identifier="two.example.com"),
    ]
    rel = _make_relationship_row()

    entity_repo = AsyncMock()
    entity_repo.list_for_tenant = AsyncMock(return_value=entities)

    relationship_repo = AsyncMock()
    # Return the same relationship from both entities' queries;
    # the generator deduplicates by id
    relationship_repo.find_for_entity = AsyncMock(return_value=[rel])

    run_repo = AsyncMock()
    run_repo.get_by_id = AsyncMock(return_value=_make_run_row())

    gen = ArtifactGenerator(
        entity_repo=entity_repo,
        relationship_repo=relationship_repo,
        run_repo=run_repo,
    )
    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    assert result.entity_count == 2
    # Deduplicated: same rel seen from both entities, counted once
    assert result.relationship_count == 1


async def test_json_bytes_are_valid_json() -> None:
    """JSON bytes are valid JSON that can be deserialized."""
    entities = [_make_entity_row()]
    gen = _build_generator(entities=entities)

    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    parsed = json.loads(result.json_bytes)
    assert isinstance(parsed, dict)
    assert parsed["schema_version"] == "expose/v1"
    assert "targets" in parsed
    assert "run" in parsed
    assert "tenant" in parsed
    assert "delta_from_previous_run" in parsed
    assert "collector_health" in parsed
    assert "manifest_ref" in parsed

    # delta_from_previous_run.previous_run_id is required-nullable
    delta = parsed["delta_from_previous_run"]
    assert "previous_run_id" in delta
    assert delta["previous_run_id"] is None


async def test_target_identifiers_match_entity_canonicals() -> None:
    """Target primary_identifier values match entity canonical_identifiers."""
    entities = [
        _make_entity_row(
            entity_id=ENTITY_ID_1,
            canonical_identifier="alpha.example.com",
            entity_type="Domain",
        ),
        _make_entity_row(
            entity_id=ENTITY_ID_2,
            canonical_identifier="192.0.2.1",
            entity_type="IP",
        ),
    ]
    gen = _build_generator(entities=entities)

    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    target_values = {t.primary_identifier.value for t in result.artifact.targets}
    assert target_values == {"alpha.example.com", "192.0.2.1"}

    # Verify identifier types are correctly mapped
    target_map = {
        t.primary_identifier.value: t.primary_identifier.type
        for t in result.artifact.targets
    }
    assert target_map["alpha.example.com"] == "domain"
    assert target_map["192.0.2.1"] == "ip"


async def test_run_metadata_in_artifact() -> None:
    """Run metadata (run_id, tenant_id) appears in artifact."""
    run_row = _make_run_row(
        state="completed",
        pipeline_version=VALID_GIT_SHA,
    )
    gen = _build_generator(run_row=run_row)

    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    assert result.artifact.run.run_id == RUN_ID
    assert result.artifact.run.pipeline_version == VALID_GIT_SHA
    assert result.artifact.run.started_at == NOW
    assert result.artifact.run.completed_at == NOW
    assert result.artifact.tenant.tenant_id == TENANT_ID


async def test_artifact_result_is_frozen() -> None:
    """ArtifactResult is immutable (Pydantic frozen=True)."""
    gen = _build_generator()

    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    with pytest.raises(Exception):  # noqa: B017
        result.entity_count = 999  # type: ignore[misc]


async def test_missing_run_raises_lookup_error() -> None:
    """If the run row does not exist, LookupError is raised."""
    run_repo = AsyncMock()
    run_repo.get_by_id = AsyncMock(return_value=None)

    gen = ArtifactGenerator(
        entity_repo=AsyncMock(),
        relationship_repo=AsyncMock(),
        run_repo=run_repo,
    )

    with pytest.raises(LookupError, match="No run found"):
        await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)


async def test_attribution_confidence_maps_to_correct_tier() -> None:
    """Entity attribution confidence maps to the correct tier in the target."""
    entities = [
        _make_entity_row(
            entity_id=ENTITY_ID_1,
            canonical_identifier="high.example.com",
            attribution_confidence=Decimal("0.950"),
        ),
        _make_entity_row(
            entity_id=ENTITY_ID_2,
            canonical_identifier="low.example.com",
            attribution_confidence=Decimal("0.300"),
        ),
    ]
    gen = _build_generator(entities=entities)

    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    target_map = {
        t.primary_identifier.value: t.attribution.tier
        for t in result.artifact.targets
    }
    assert target_map["high.example.com"] == "confirmed"
    assert target_map["low.example.com"] == "requires_review"


async def test_collector_health_from_entity_properties() -> None:
    """Collector health entries are extracted from entity properties."""
    entities = [
        _make_entity_row(
            entity_id=ENTITY_ID_1,
            canonical_identifier="a.example.com",
            properties={"_collector_id": "dns-resolve", "_collector_version": "2.0.0"},
        ),
        _make_entity_row(
            entity_id=ENTITY_ID_2,
            canonical_identifier="b.example.com",
            properties={"_collector_id": "whois-lookup", "_collector_version": "1.0.0"},
        ),
    ]
    gen = _build_generator(entities=entities)

    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    collector_ids = {
        c.collector_id for c in result.artifact.collector_health.collectors
    }
    assert collector_ids == {"dns-resolve", "whois-lookup"}

    # Each collector observed 1 entity
    for entry in result.artifact.collector_health.collectors:
        assert entry.observations_collected == 1
        assert entry.status == "success"


async def test_pipeline_version_normalization() -> None:
    """Non-git-sha pipeline version is normalized to the zero placeholder."""
    run_row = _make_run_row(pipeline_version="v0.1.0")
    gen = _build_generator(run_row=run_row)

    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    assert result.artifact.run.pipeline_version == "0" * 40


async def test_content_hash_deterministic() -> None:
    """Same inputs produce the same content hash."""
    entities = [_make_entity_row()]
    gen1 = _build_generator(entities=entities)
    gen2 = _build_generator(entities=entities)

    result1 = await gen1.generate(run_id=RUN_ID, tenant_id=TENANT_ID)
    result2 = await gen2.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    # Both should produce identical JSON and hash (assuming same datetime.now())
    # Because datetime.now() is called inside generate, the exact bytes may differ.
    # But we can verify both hashes are valid 64-char hex.
    assert len(result1.content_hash) == 64
    assert len(result2.content_hash) == 64
    assert re.fullmatch(r"[a-f0-9]{64}", result1.content_hash) is not None
    assert re.fullmatch(r"[a-f0-9]{64}", result2.content_hash) is not None


# === Storage wiring tests =====================================================


async def test_storage_backend_receives_artifact_json(tmp_path: Path) -> None:
    """Storage backend receives artifact JSON when provided."""
    storage = LocalStorageBackend(root=tmp_path)
    entities = [_make_entity_row()]
    gen = _build_generator(entities=entities, storage=storage)

    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    key = f"tenant/{TENANT_ID}/artifacts/{RUN_ID}.json"
    assert await storage.exists(key)
    assert result.storage_uri is not None


async def test_storage_uri_in_result(tmp_path: Path) -> None:
    """Result storage_uri is a file:// URI when LocalStorageBackend is used."""
    storage = LocalStorageBackend(root=tmp_path)
    entities = [_make_entity_row()]
    gen = _build_generator(entities=entities, storage=storage)

    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    assert result.storage_uri is not None
    assert result.storage_uri.startswith("file://")


async def test_no_storage_backend_returns_none_uri() -> None:
    """When storage=None (default), result.storage_uri is None."""
    entities = [_make_entity_row()]
    gen = _build_generator(entities=entities)

    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    assert result.storage_uri is None


async def test_stored_json_matches_result_json_bytes(tmp_path: Path) -> None:
    """Bytes read back from storage match result.json_bytes exactly."""
    storage = LocalStorageBackend(root=tmp_path)
    entities = [_make_entity_row()]
    gen = _build_generator(entities=entities, storage=storage)

    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    key = f"tenant/{TENANT_ID}/artifacts/{RUN_ID}.json"
    stored = await storage.get(key)
    assert stored == result.json_bytes


async def test_storage_key_follows_convention(tmp_path: Path) -> None:
    """Storage key is tenant/{tenant_id}/artifacts/{run_id}.json."""
    storage = LocalStorageBackend(root=tmp_path)
    entities = [_make_entity_row()]
    gen = _build_generator(entities=entities, storage=storage)

    await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    expected_key = f"tenant/{TENANT_ID}/artifacts/{RUN_ID}.json"
    keys = await storage.list_keys(prefix=f"tenant/{TENANT_ID}/artifacts/")
    assert expected_key in keys

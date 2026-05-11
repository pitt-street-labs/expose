"""End-to-end artifact lifecycle tests.

Combines pipeline execution (via RunExecutor with respx-mocked collectors)
with ArtifactGenerator to verify the full seed -> collect -> upsert -> artifact
lifecycle.

Flow for each test:
1. Run the pipeline (respx + AsyncMock repos).
2. Collect the entities that were upserted (capture from
   ``entity_repo.create_or_update.call_args_list``).
3. Build mock entity/run rows from the captured data.
4. Pass to ArtifactGenerator.
5. Verify the artifact.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import httpx
import pytest
import respx

from expose.collectors.base import Seed, SeedType
from expose.collectors.builtin.ct_crtsh import CrtShCollector
from expose.collectors.registry import CollectorRegistry
from expose.collectors.tiers import TenantAuthorizationScope
from expose.pipeline.artifact_generator import ArtifactGenerator
from expose.pipeline.dispatcher import PipelineDispatcher
from expose.pipeline.run_executor import RunExecutor
from expose.storage.local import LocalStorageBackend

# === Deterministic synthetic IDs ==============================================

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000e301")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000e302")
NOW = datetime(2026, 5, 10, 14, 0, 0, tzinfo=UTC)
VALID_GIT_SHA = "b" * 40

# Minimal crt.sh JSON response with two certificates / three hostnames.
CRT_SH_RESPONSE = '[{"issuer_ca_id":16418,"issuer_name":"C=US, O=Let\'s Encrypt, CN=R3","common_name":"example.com","name_value":"example.com\\nwww.example.com","id":1111111111,"entry_timestamp":"2025-01-15T10:30:00.000","not_before":"2025-01-15T00:00:00","not_after":"2025-04-15T00:00:00","serial_number":"aabb0011223344556677889900aabbcc"},{"issuer_ca_id":185756,"issuer_name":"C=US, O=Amazon, CN=Amazon RSA 2048 M01","common_name":"api.example.com","name_value":"api.example.com","id":2222222222,"entry_timestamp":"2025-02-20T14:45:00.000","not_before":"2025-02-20T00:00:00","not_after":"2025-05-20T00:00:00","serial_number":"ccdd0011223344556677889900aabbee"}]'


# === Helpers ==================================================================


def _make_executor_run_row(state: str = "pending") -> MagicMock:
    """Build a mock Run ORM row for the RunExecutor (pending state)."""
    row = MagicMock()
    row.id = RUN_ID
    row.tenant_id = TENANT_ID
    row.state = state
    return row


def _make_generator_run_row(state: str = "completed") -> MagicMock:
    """Build a mock Run ORM row for the ArtifactGenerator (completed state)."""
    row = MagicMock()
    row.id = RUN_ID
    row.tenant_id = TENANT_ID
    row.state = state
    row.pipeline_version = VALID_GIT_SHA
    row.started_at = NOW
    row.completed_at = NOW
    row.canonical_artifact_ref = None
    row.manifest_ref = None
    row.target_count = None
    return row


def _build_registry() -> CollectorRegistry:
    """Build a registry with ct-crtsh only (sufficient for artifact tests)."""
    reg = CollectorRegistry()
    reg.register(CrtShCollector)
    return reg


def _build_dispatcher(registry: CollectorRegistry) -> PipelineDispatcher:
    """Build a PipelineDispatcher with example.com in scope."""
    scope = TenantAuthorizationScope(
        explicit_entity_identifiers=frozenset({"example.com"}),
    )
    return PipelineDispatcher(registry, scope, TENANT_ID)


def _build_executor_mocks() -> tuple[AsyncMock, AsyncMock]:
    """Build mock run and entity repos for the RunExecutor.

    Returns (run_repo, entity_repo).
    """
    run_repo = AsyncMock()
    run_repo.get_by_id = AsyncMock(return_value=_make_executor_run_row("pending"))
    run_repo.update_state = AsyncMock()

    entity_repo = AsyncMock()
    entity_repo.create_or_update = AsyncMock(return_value=MagicMock())

    return run_repo, entity_repo


def _setup_crtsh_routes() -> None:
    """Register respx routes for ct-crtsh with a successful response."""
    respx.get("https://crt.sh/", params__contains={"output": "json"}).mock(
        return_value=httpx.Response(200, text=CRT_SH_RESPONSE),
    )
    respx.head("https://crt.sh/").mock(
        return_value=httpx.Response(200),
    )


def _extract_entities_from_upserts(entity_repo: AsyncMock) -> list[MagicMock]:
    """Build mock entity rows from captured create_or_update calls.

    Each call to ``entity_repo.create_or_update`` provides the kwargs
    ``entity_type``, ``canonical_identifier``, ``properties``, etc. We
    build mock entity rows matching what ArtifactGenerator expects.
    """
    entities: list[MagicMock] = []
    seen_identifiers: set[str] = set()

    for i, call in enumerate(entity_repo.create_or_update.call_args_list):
        kwargs = call.kwargs
        canonical_id = kwargs["canonical_identifier"]

        # Deduplicate — the pipeline may upsert the same entity multiple
        # times from different collector results.
        if canonical_id in seen_identifiers:
            continue
        seen_identifiers.add(canonical_id)

        row = MagicMock()
        row.id = UUID(f"018f1f00-0000-7000-8000-0000000{i:05d}")
        row.tenant_id = TENANT_ID
        row.entity_type = kwargs["entity_type"]
        row.canonical_identifier = canonical_id
        row.attribution_status = kwargs.get("attribution_status", "unattributed")
        row.attribution_confidence = kwargs.get(
            "attribution_confidence", Decimal("0.500"),
        )
        row.first_observed_at = NOW
        row.last_observed_at = NOW
        row.properties = kwargs.get("properties", {})

        entities.append(row)

    return entities


def _build_artifact_generator(
    entities: list[MagicMock],
    storage: LocalStorageBackend | None = None,
) -> ArtifactGenerator:
    """Wire up an ArtifactGenerator with mock repos seeded from pipeline entities."""
    entity_repo = AsyncMock()
    entity_repo.list_for_tenant = AsyncMock(return_value=entities)

    relationship_repo = AsyncMock()
    relationship_repo.find_for_entity = AsyncMock(return_value=[])

    run_repo = AsyncMock()
    run_repo.get_by_id = AsyncMock(return_value=_make_generator_run_row())

    return ArtifactGenerator(
        entity_repo=entity_repo,
        relationship_repo=relationship_repo,
        run_repo=run_repo,
        storage=storage,
    )


async def _run_pipeline_and_collect_entities() -> list[MagicMock]:
    """Execute the pipeline and return mock entity rows from upserted data.

    Shared setup for tests that need real pipeline output flowing into
    the artifact generator.
    """
    _setup_crtsh_routes()

    registry = _build_registry()
    dispatcher = _build_dispatcher(registry)
    run_repo, entity_repo = _build_executor_mocks()

    executor = RunExecutor(
        dispatcher=dispatcher,
        run_repo=run_repo,
        entity_repo=entity_repo,
    )

    await executor.execute(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        seeds=[Seed(seed_type=SeedType.DOMAIN, value="example.com")],
        collector_ids=["ct-crtsh"],
    )

    return _extract_entities_from_upserts(entity_repo)


# === Tests ====================================================================


@pytest.mark.integration
@respx.mock
async def test_pipeline_to_artifact_with_targets() -> None:
    """Run pipeline against example.com with ct-crtsh, then generate artifact.

    Verifies that entities upserted during the pipeline run produce an
    artifact with at least one target.
    """
    entities = await _run_pipeline_and_collect_entities()
    assert len(entities) > 0, "Pipeline should have upserted at least one entity"

    gen = _build_artifact_generator(entities)
    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    assert len(result.artifact.targets) > 0


@pytest.mark.integration
@respx.mock
async def test_artifact_content_hash_format() -> None:
    """Generate an artifact and verify the content hash is 64-char lowercase hex."""
    entities = await _run_pipeline_and_collect_entities()
    gen = _build_artifact_generator(entities)
    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    assert len(result.content_hash) == 64
    assert re.fullmatch(r"[a-f0-9]{64}", result.content_hash) is not None


@pytest.mark.integration
@respx.mock
async def test_artifact_stored_to_local_backend(tmp_path: Path) -> None:
    """Create a LocalStorageBackend and verify the artifact is persisted."""
    entities = await _run_pipeline_and_collect_entities()
    storage = LocalStorageBackend(root=tmp_path)
    gen = _build_artifact_generator(entities, storage=storage)

    await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    key = f"tenant/{TENANT_ID}/artifacts/{RUN_ID}.json"
    assert await storage.exists(key)


@pytest.mark.integration
@respx.mock
async def test_artifact_targets_match_entities() -> None:
    """Verify that artifact target identifiers match the entity canonical IDs."""
    entities = await _run_pipeline_and_collect_entities()
    gen = _build_artifact_generator(entities)
    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    target_values = {
        t.primary_identifier.value for t in result.artifact.targets
    }
    entity_identifiers = {e.canonical_identifier for e in entities}

    assert target_values == entity_identifiers


@pytest.mark.integration
@respx.mock
async def test_first_run_delta_has_no_previous() -> None:
    """First-run artifact delta must have previous_run_id = None."""
    entities = await _run_pipeline_and_collect_entities()
    gen = _build_artifact_generator(entities)
    result = await gen.generate(run_id=RUN_ID, tenant_id=TENANT_ID)

    assert result.artifact.delta_from_previous_run.previous_run_id is None

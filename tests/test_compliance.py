"""Tests for GDPR/CCPA compliance module (issue #26).

Coverage:

 1. DataExporter returns complete export with all data.
 2. Export of tenant with no data returns empty lists.
 3. Export metadata has correct counts.
 4. Export is tenant-scoped (tenant B data not included).
 5. DeletionRequest defaults to dry_run=True.
 6. Dry run counts deletions without modifying data.
 7. Real deletion removes all tenant entities.
 8. Real deletion removes all tenant relationships.
 9. Real deletion removes all tenant runs.
10. Litigation hold blocks deletion (raises LitigationHoldError).
11. Litigation hold can be overridden.
12. DeletionResult has correct counts.
13. Evidence refs are counted in deletion result.
14. Deletion logs at WARNING level with audit context.

All repos are ``AsyncMock``-ed -- no real database needed.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID

import pytest

from expose.compliance import (
    DataDeleter,
    DataExporter,
    DeletionRequest,
    DeletionResult,
    ExportMetadata,
    TenantDataExport,
)
from expose.compliance.data_deletion import LitigationHoldError
from expose.maintenance.retention_policy import RetentionPolicy

# Synthetic tenant UUIDs matching the pattern in test_tenant_isolation.py.
TENANT_A = UUID("018f1f00-0000-7000-8000-00000000A001")
TENANT_B = UUID("018f1f00-0000-7000-8000-00000000B002")


# ---------------------------------------------------------------------------
# Fake ORM rows (SimpleNamespace with __table__ for _row_to_dict)
# ---------------------------------------------------------------------------

def _fake_table(columns: list[str]) -> Any:
    """Build a minimal __table__ with .columns that have .key attributes."""
    cols = [SimpleNamespace(key=k) for k in columns]
    return SimpleNamespace(columns=cols)


_ENTITY_TABLE = _fake_table([
    "id", "tenant_id", "entity_type", "canonical_identifier",
    "properties", "attribution_status", "attribution_confidence",
    "first_observed_at", "last_observed_at",
])

_RELATIONSHIP_TABLE = _fake_table([
    "id", "tenant_id", "from_entity_id", "to_entity_id",
    "edge_type", "confidence", "observed_at", "collector_id",
    "evidence_ref", "properties",
])

_RUN_TABLE = _fake_table([
    "id", "tenant_id", "pipeline_version", "started_at",
    "completed_at", "state", "canonical_artifact_ref",
    "manifest_ref", "target_count",
])


def _make_entity(
    entity_id: UUID,
    tenant_id: UUID = TENANT_A,
    entity_type: str = "Domain",
    canonical_identifier: str = "example.com",
) -> SimpleNamespace:
    return SimpleNamespace(
        __table__=_ENTITY_TABLE,
        id=entity_id,
        tenant_id=tenant_id,
        entity_type=entity_type,
        canonical_identifier=canonical_identifier,
        properties={"registrar": "test-rar"},
        attribution_status="confirmed",
        attribution_confidence=Decimal("0.95"),
        first_observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        last_observed_at=datetime(2026, 5, 1, tzinfo=UTC),
    )


def _make_relationship(
    rel_id: UUID,
    from_entity_id: UUID,
    to_entity_id: UUID,
    tenant_id: UUID = TENANT_A,
    evidence_ref: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        __table__=_RELATIONSHIP_TABLE,
        id=rel_id,
        tenant_id=tenant_id,
        from_entity_id=from_entity_id,
        to_entity_id=to_entity_id,
        edge_type="resolves_to",
        confidence=Decimal("0.9"),
        observed_at=datetime(2026, 3, 1, tzinfo=UTC),
        collector_id="dns-passive",
        evidence_ref=evidence_ref,
        properties={},
    )


def _make_run(
    run_id: UUID,
    tenant_id: UUID = TENANT_A,
) -> SimpleNamespace:
    return SimpleNamespace(
        __table__=_RUN_TABLE,
        id=run_id,
        tenant_id=tenant_id,
        pipeline_version="0.1.0",
        started_at=datetime(2026, 4, 1, tzinfo=UTC),
        completed_at=datetime(2026, 4, 1, 0, 30, tzinfo=UTC),
        state="completed",
        canonical_artifact_ref="sha256:abc123",
        manifest_ref="sha256:def456",
        target_count=10,
    )


# Deterministic IDs for test data.
_E1 = UUID("00000000-0000-0000-0000-000000000001")
_E2 = UUID("00000000-0000-0000-0000-000000000002")
_R1 = UUID("00000000-0000-0000-0000-0000000000A1")
_R2 = UUID("00000000-0000-0000-0000-0000000000A2")
_RUN1 = UUID("00000000-0000-0000-0000-000000000B01")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def entity_repo() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def relationship_repo() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def run_repo() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def session() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def exporter(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
) -> DataExporter:
    return DataExporter(entity_repo, relationship_repo, run_repo)


@pytest.fixture
def deleter(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
    session: AsyncMock,
) -> DataDeleter:
    return DataDeleter(entity_repo, relationship_repo, run_repo, session)


def _setup_repos_with_data(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
) -> None:
    """Wire up mocks to return standard test data for TENANT_A."""
    e1 = _make_entity(_E1, TENANT_A, "Domain", "example.com")
    e2 = _make_entity(_E2, TENANT_A, "IP", "1.2.3.4")
    r1 = _make_relationship(_R1, _E1, _E2, TENANT_A, evidence_ref="s3://bucket/ev1")
    run1 = _make_run(_RUN1, TENANT_A)

    entity_repo.list_for_tenant.return_value = [e1, e2]

    def _find_for_entity(
        *, tenant_id: UUID, entity_id: UUID, direction: str, limit: int
    ) -> list[SimpleNamespace]:
        if entity_id == _E1:
            return [r1]
        return []

    relationship_repo.find_for_entity.side_effect = _find_for_entity
    run_repo.list_for_tenant.return_value = [run1]


# ---------------------------------------------------------------------------
# DataExporter tests
# ---------------------------------------------------------------------------


async def test_export_returns_complete_data(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
    exporter: DataExporter,
) -> None:
    """1. DataExporter returns complete export with all data."""
    _setup_repos_with_data(entity_repo, relationship_repo, run_repo)

    result = await exporter.export_tenant(TENANT_A, requested_by="admin@test")

    assert isinstance(result, TenantDataExport)
    assert result.tenant_id == TENANT_A
    assert len(result.entities) == 2
    assert len(result.relationships) == 1
    assert len(result.runs) == 1
    # Check that entity data is serialized properly.
    assert result.entities[0]["entity_type"] in {"Domain", "IP"}


async def test_export_empty_tenant(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
    exporter: DataExporter,
) -> None:
    """2. Export of tenant with no data returns empty lists."""
    entity_repo.list_for_tenant.return_value = []
    relationship_repo.find_for_entity.return_value = []
    run_repo.list_for_tenant.return_value = []

    result = await exporter.export_tenant(TENANT_A, requested_by="admin@test")

    assert result.entities == []
    assert result.relationships == []
    assert result.runs == []


async def test_export_metadata_counts(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
    exporter: DataExporter,
) -> None:
    """3. Export metadata has correct counts."""
    _setup_repos_with_data(entity_repo, relationship_repo, run_repo)

    result = await exporter.export_tenant(TENANT_A, requested_by="dpo@test")

    assert isinstance(result.metadata, ExportMetadata)
    assert result.metadata.entity_count == 2
    assert result.metadata.relationship_count == 1
    assert result.metadata.run_count == 1
    assert result.metadata.export_requested_by == "dpo@test"
    assert result.metadata.format_version == "1.0"


async def test_export_tenant_scoped(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
    exporter: DataExporter,
) -> None:
    """4. Export is tenant-scoped (tenant B data not included).

    The exporter passes tenant_id to every repo call. We verify the
    correct tenant_id is forwarded (the repo itself enforces scoping).
    """
    entity_repo.list_for_tenant.return_value = []
    relationship_repo.find_for_entity.return_value = []
    run_repo.list_for_tenant.return_value = []

    await exporter.export_tenant(TENANT_B, requested_by="admin@test")

    # Verify tenant B was passed to the repo, not tenant A.
    call_kwargs = entity_repo.list_for_tenant.call_args
    assert call_kwargs.kwargs["tenant_id"] == TENANT_B

    call_kwargs = run_repo.list_for_tenant.call_args
    assert call_kwargs.kwargs["tenant_id"] == TENANT_B


# ---------------------------------------------------------------------------
# DeletionRequest model tests
# ---------------------------------------------------------------------------


def test_deletion_request_defaults_to_dry_run() -> None:
    """5. DeletionRequest defaults to dry_run=True."""
    req = DeletionRequest(
        tenant_id=TENANT_A,
        requested_by="admin@test",
    )
    assert req.dry_run is True
    assert req.override_litigation_hold is False


# ---------------------------------------------------------------------------
# DataDeleter tests
# ---------------------------------------------------------------------------


async def test_dry_run_counts_without_modifying(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
    session: AsyncMock,
    deleter: DataDeleter,
) -> None:
    """6. Dry run counts deletions without modifying data."""
    _setup_repos_with_data(entity_repo, relationship_repo, run_repo)

    req = DeletionRequest(
        tenant_id=TENANT_A,
        requested_by="admin@test",
        dry_run=True,
    )
    result = await deleter.delete_tenant_data(req)

    assert result.entities_deleted == 2
    assert result.relationships_deleted == 1
    assert result.runs_deleted == 1
    # Crucially, session.delete was never called.
    session.delete.assert_not_awaited()
    session.flush.assert_not_awaited()


async def test_real_deletion_removes_entities(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
    session: AsyncMock,
    deleter: DataDeleter,
) -> None:
    """7. Real deletion removes all tenant entities."""
    _setup_repos_with_data(entity_repo, relationship_repo, run_repo)

    req = DeletionRequest(
        tenant_id=TENANT_A,
        requested_by="admin@test",
        dry_run=False,
    )
    result = await deleter.delete_tenant_data(req)

    assert result.entities_deleted == 2
    # session.delete should have been called for each entity.
    deleted_objects = [call.args[0] for call in session.delete.call_args_list]
    entity_ids = {
        obj.id for obj in deleted_objects
        if getattr(obj, "entity_type", None) is not None
    }
    assert _E1 in entity_ids
    assert _E2 in entity_ids


async def test_real_deletion_removes_relationships(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
    session: AsyncMock,
    deleter: DataDeleter,
) -> None:
    """8. Real deletion removes all tenant relationships."""
    _setup_repos_with_data(entity_repo, relationship_repo, run_repo)

    req = DeletionRequest(
        tenant_id=TENANT_A,
        requested_by="admin@test",
        dry_run=False,
    )
    result = await deleter.delete_tenant_data(req)

    assert result.relationships_deleted == 1
    deleted_objects = [call.args[0] for call in session.delete.call_args_list]
    rel_ids = {
        obj.id for obj in deleted_objects
        if getattr(obj, "edge_type", None) is not None
    }
    assert _R1 in rel_ids


async def test_real_deletion_removes_runs(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
    session: AsyncMock,
    deleter: DataDeleter,
) -> None:
    """9. Real deletion removes all tenant runs."""
    _setup_repos_with_data(entity_repo, relationship_repo, run_repo)

    req = DeletionRequest(
        tenant_id=TENANT_A,
        requested_by="admin@test",
        dry_run=False,
    )
    result = await deleter.delete_tenant_data(req)

    assert result.runs_deleted == 1
    deleted_objects = [call.args[0] for call in session.delete.call_args_list]
    run_ids = {
        obj.id for obj in deleted_objects
        if getattr(obj, "pipeline_version", None) is not None
    }
    assert _RUN1 in run_ids


async def test_litigation_hold_blocks_deletion(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
    session: AsyncMock,
) -> None:
    """10. Litigation hold blocks deletion (raises LitigationHoldError)."""
    policy = RetentionPolicy(tenant_id=TENANT_A, litigation_hold=True)
    deleter = DataDeleter(
        entity_repo, relationship_repo, run_repo, session,
        retention_policy=policy,
    )

    req = DeletionRequest(
        tenant_id=TENANT_A,
        requested_by="admin@test",
        dry_run=False,
    )

    with pytest.raises(LitigationHoldError, match="Litigation hold active"):
        await deleter.delete_tenant_data(req)

    # No data was touched.
    session.delete.assert_not_awaited()


async def test_litigation_hold_override(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
    session: AsyncMock,
) -> None:
    """11. Litigation hold can be overridden."""
    _setup_repos_with_data(entity_repo, relationship_repo, run_repo)
    policy = RetentionPolicy(tenant_id=TENANT_A, litigation_hold=True)
    deleter = DataDeleter(
        entity_repo, relationship_repo, run_repo, session,
        retention_policy=policy,
    )

    req = DeletionRequest(
        tenant_id=TENANT_A,
        requested_by="legal-counsel@test",
        override_litigation_hold=True,
        dry_run=False,
    )
    result = await deleter.delete_tenant_data(req)

    assert result.retention_override is True
    assert result.entities_deleted == 2
    # session.delete was called (data was actually removed).
    assert session.delete.await_count > 0


async def test_deletion_result_counts(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
    session: AsyncMock,
    deleter: DataDeleter,
) -> None:
    """12. DeletionResult has correct counts."""
    _setup_repos_with_data(entity_repo, relationship_repo, run_repo)

    req = DeletionRequest(
        tenant_id=TENANT_A,
        requested_by="admin@test",
        dry_run=False,
    )
    result = await deleter.delete_tenant_data(req)

    assert isinstance(result, DeletionResult)
    assert result.tenant_id == TENANT_A
    assert result.entities_deleted == 2
    assert result.relationships_deleted == 1
    assert result.runs_deleted == 1
    assert result.evidence_refs_deleted == 1  # _R1 has evidence_ref set
    assert result.retention_override is False


async def test_evidence_refs_counted(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
    session: AsyncMock,
    deleter: DataDeleter,
) -> None:
    """13. Evidence refs are counted in deletion result."""
    e1 = _make_entity(_E1)
    r1 = _make_relationship(_R1, _E1, _E2, evidence_ref="s3://bucket/ev1")
    r2 = _make_relationship(_R2, _E1, _E2, evidence_ref="s3://bucket/ev2")

    entity_repo.list_for_tenant.return_value = [e1]
    relationship_repo.find_for_entity.return_value = [r1, r2]
    run_repo.list_for_tenant.return_value = []

    req = DeletionRequest(
        tenant_id=TENANT_A,
        requested_by="admin@test",
        dry_run=True,
    )
    result = await deleter.delete_tenant_data(req)

    assert result.evidence_refs_deleted == 2


async def test_deletion_logs_warning(
    entity_repo: AsyncMock,
    relationship_repo: AsyncMock,
    run_repo: AsyncMock,
    session: AsyncMock,
    deleter: DataDeleter,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """14. Deletion logs at WARNING level with audit context."""
    _setup_repos_with_data(entity_repo, relationship_repo, run_repo)

    req = DeletionRequest(
        tenant_id=TENANT_A,
        requested_by="compliance-officer@test",
        dry_run=False,
    )

    with caplog.at_level(logging.WARNING, logger="expose.compliance.data_deletion"):
        await deleter.delete_tenant_data(req)

    warning_messages = [
        r.message for r in caplog.records if r.levelno >= logging.WARNING
    ]
    assert len(warning_messages) >= 2  # start + complete
    assert any("Deleting all tenant data" in m for m in warning_messages)
    assert any("Tenant data deletion complete" in m for m in warning_messages)

"""Tenant data export for GDPR Article 20 (data portability).

Gathers all entities, relationships, and runs for a single tenant into a
portable ``TenantDataExport`` envelope that can be serialized to JSON and
handed to the data subject.

The exporter delegates to the tenant-scoped repositories (per ADR-007) so
cross-tenant data leakage is impossible by construction -- each repository
method includes ``tenant_id`` in its WHERE clause.

Design notes:

- **Limit handling**: the default ``list_for_tenant`` limit on each
  repository is 100. For a full export the exporter passes
  ``limit=_EXPORT_PAGE_SIZE`` (10 000) to ensure all data is captured.
  Tenants with >10 000 entities/relationships/runs will need cursor-based
  pagination in a follow-up (filed as a backlog item).

- **Serialization**: ORM rows are converted to plain dicts via column
  inspection so the export is ORM-independent and JSON-serializable.
  ``datetime`` and ``Decimal`` fields are stringified; ``UUID`` fields
  become RFC 4122 strings.

References:
    - GDPR Article 20: Right to data portability
    - ADR-007: Multi-tenancy (tenant scoping)
    - Issue #26: GDPR/CCPA tenant data export and deletion
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)

# Large page size for full-tenant export.  Repositories default to 100;
# we override to capture everything in a single pass.  Tenants exceeding
# this threshold need cursor-based pagination (backlog item).
_EXPORT_PAGE_SIZE: int = 10_000


class ExportMetadata(BaseModel):
    """Metadata envelope for a tenant data export."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str = "1.0"
    entity_count: int
    relationship_count: int
    run_count: int
    export_requested_by: str


class TenantDataExport(BaseModel):
    """Complete export of all tenant data in a portable format.

    Designed to be serialized to JSON (``model_dump_json()``) and handed
    to the data subject per GDPR Article 20.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    exported_at: datetime
    entities: list[dict[str, Any]]
    relationships: list[dict[str, Any]]
    runs: list[dict[str, Any]]
    metadata: ExportMetadata


def _serialize_value(value: object) -> object:
    """Convert ORM column values to JSON-safe primitives."""
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    return value


def _row_to_dict(row: object) -> dict[str, Any]:
    """Convert a SQLAlchemy ORM instance to a plain dict.

    Uses ``__table__.columns`` so only mapped DB columns are included
    (no relationship proxies, no internal SA state).
    """
    table = getattr(row, "__table__", None)
    if table is None:
        return {}
    return {
        col.key: _serialize_value(getattr(row, col.key))
        for col in table.columns
    }


class _EntityRepoLike(Protocol):
    async def list_for_tenant(
        self, *, tenant_id: Any, limit: int = 100
    ) -> Any: ...


class _RelationshipRepoLike(Protocol):
    async def find_for_entity(
        self, *, tenant_id: Any, entity_id: Any, direction: str, limit: int
    ) -> Any: ...


class _RunRepoLike(Protocol):
    async def list_for_tenant(
        self, *, tenant_id: Any, limit: int = 50
    ) -> Any: ...


class DataExporter:
    """Exports all tenant data into a portable ``TenantDataExport``.

    Constructor accepts the three tenant-scoped repositories.  The exporter
    itself is stateless -- each ``export_tenant`` call is independent.
    """

    def __init__(
        self,
        entity_repo: _EntityRepoLike,
        relationship_repo: _RelationshipRepoLike,
        run_repo: _RunRepoLike,
    ) -> None:
        self._entity_repo = entity_repo
        self._relationship_repo = relationship_repo
        self._run_repo = run_repo

    async def export_tenant(
        self,
        tenant_id: UUID,
        requested_by: str,
    ) -> TenantDataExport:
        """Gather all tenant data into an export package.

        Args:
            tenant_id: The tenant whose data is being exported.
            requested_by: Audit trail -- who requested the export.

        Returns:
            A ``TenantDataExport`` containing all entities, relationships,
            and runs for the tenant plus metadata.
        """
        logger.info(
            "Starting tenant data export",
            extra={
                "tenant_id": str(tenant_id),
                "requested_by": requested_by,
            },
        )

        entities = await self._entity_repo.list_for_tenant(
            tenant_id=tenant_id, limit=_EXPORT_PAGE_SIZE
        )

        # Relationships are queried per-entity (the repository API exposes
        # find_for_entity, not list_for_tenant).  Collect all relationships
        # for all entities, deduplicating by id.
        seen_rel_ids: set[str] = set()
        all_relationships: list[dict[str, Any]] = []
        for entity in entities:
            rels = await self._relationship_repo.find_for_entity(
                tenant_id=tenant_id,
                entity_id=entity.id,
                direction="both",
                limit=_EXPORT_PAGE_SIZE,
            )
            for rel in rels:
                rel_dict = _row_to_dict(rel)
                rel_id = str(rel_dict.get("id", ""))
                if rel_id not in seen_rel_ids:
                    seen_rel_ids.add(rel_id)
                    all_relationships.append(rel_dict)

        runs = await self._run_repo.list_for_tenant(
            tenant_id=tenant_id, limit=_EXPORT_PAGE_SIZE
        )

        entity_dicts = [_row_to_dict(e) for e in entities]
        run_dicts = [_row_to_dict(r) for r in runs]

        metadata = ExportMetadata(
            entity_count=len(entity_dicts),
            relationship_count=len(all_relationships),
            run_count=len(run_dicts),
            export_requested_by=requested_by,
        )

        export = TenantDataExport(
            tenant_id=tenant_id,
            exported_at=datetime.now(UTC),
            entities=entity_dicts,
            relationships=all_relationships,
            runs=run_dicts,
            metadata=metadata,
        )

        logger.info(
            "Tenant data export complete",
            extra={
                "tenant_id": str(tenant_id),
                "entity_count": metadata.entity_count,
                "relationship_count": metadata.relationship_count,
                "run_count": metadata.run_count,
            },
        )

        return export

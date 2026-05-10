"""Tenant data deletion for GDPR Article 17 (right to erasure).

Handles complete deletion of all tenant data from the observation graph.
Supports dry-run mode (default) for safety, litigation-hold enforcement,
and evidence-reference counting for downstream blob cleanup.

All deletion operations are logged at WARNING level with full audit context
per the project's compliance logging requirements.

Design notes:

- **Dry-run default**: ``DeletionRequest.dry_run`` defaults to ``True``
  so accidental calls never destroy data.  The caller must explicitly set
  ``dry_run=False`` to perform a real deletion.

- **Litigation hold**: When a tenant's retention policy has
  ``litigation_hold=True``, deletion is blocked unless the request
  explicitly overrides with ``override_litigation_hold=True``.  This
  satisfies FRCP / GDPR Art. 17(3)(e) obligations.

- **Evidence references**: The deleter counts ``evidence_ref`` values on
  relationships so the caller knows how many object-storage blobs need
  downstream cleanup.  Actual blob deletion is out of scope (per ADR-004,
  object storage lifecycle is a separate concern).

- **Transaction control**: The deleter does not commit -- the caller owns
  the session and transaction boundary.

References:
    - GDPR Article 17: Right to erasure
    - GDPR Article 17(3)(e): Litigation hold exception
    - CCPA Section 1798.105: Right to deletion
    - ADR-007: Multi-tenancy (tenant scoping)
    - ADR-008: Data minimization
    - Issue #26: GDPR/CCPA tenant data export and deletion
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from expose.maintenance.retention_policy import RetentionPolicy

logger = logging.getLogger(__name__)


class DeletionRequest(BaseModel):
    """Request to delete all data for a tenant."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    requested_by: str
    override_litigation_hold: bool = False
    dry_run: bool = True


class DeletionResult(BaseModel):
    """Result of a tenant data deletion (or dry-run count)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    deleted_at: datetime
    entities_deleted: int
    relationships_deleted: int
    runs_deleted: int
    evidence_refs_deleted: int
    retention_override: bool


class LitigationHoldError(Exception):
    """Raised when deletion is blocked by an active litigation hold."""


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


class _SessionLike(Protocol):
    async def delete(self, instance: Any) -> None: ...
    async def flush(self) -> None: ...


# Page size for gathering all tenant data before deletion.
_DELETE_PAGE_SIZE: int = 10_000


class DataDeleter:
    """Handles GDPR Article 17 right-to-erasure for a tenant.

    Constructor accepts the three tenant-scoped repositories and an
    optional ``RetentionPolicy`` for litigation-hold checks.

    The ``session`` parameter is required so the deleter can issue ORM
    ``session.delete()`` calls.  The caller owns commit/rollback.
    """

    def __init__(
        self,
        entity_repo: _EntityRepoLike,
        relationship_repo: _RelationshipRepoLike,
        run_repo: _RunRepoLike,
        session: _SessionLike,
        retention_policy: RetentionPolicy | None = None,
    ) -> None:
        self._entity_repo = entity_repo
        self._relationship_repo = relationship_repo
        self._run_repo = run_repo
        self._session = session
        self._retention_policy = retention_policy

    async def delete_tenant_data(
        self, request: DeletionRequest
    ) -> DeletionResult:
        """Delete all data for a tenant.

        If ``dry_run=True``, counts what would be deleted without
        modifying data.

        If a litigation hold is active on the tenant's retention policy
        and ``override_litigation_hold`` is ``False``, raises
        ``LitigationHoldError``.

        Args:
            request: The deletion request specifying tenant, requester,
                and safety flags.

        Returns:
            A ``DeletionResult`` with counts of deleted (or
            would-be-deleted) records.

        Raises:
            LitigationHoldError: If a litigation hold blocks deletion.
        """
        # Check litigation hold before doing any work.
        hold_active = (
            self._retention_policy is not None
            and self._retention_policy.litigation_hold
        )
        if hold_active and not request.override_litigation_hold:
            logger.warning(
                "Tenant data deletion blocked by litigation hold",
                extra={
                    "tenant_id": str(request.tenant_id),
                    "requested_by": request.requested_by,
                },
            )
            raise LitigationHoldError(
                f"Litigation hold active for tenant {request.tenant_id}; "
                f"set override_litigation_hold=True to proceed"
            )

        retention_override = hold_active and request.override_litigation_hold

        # Gather all tenant data.
        entities = await self._entity_repo.list_for_tenant(
            tenant_id=request.tenant_id, limit=_DELETE_PAGE_SIZE
        )

        # Collect all relationships (deduped) and count evidence refs.
        seen_rel_ids: set[object] = set()
        all_relationships: list[Any] = []
        evidence_ref_count = 0
        for entity in entities:
            rels = await self._relationship_repo.find_for_entity(
                tenant_id=request.tenant_id,
                entity_id=entity.id,
                direction="both",
                limit=_DELETE_PAGE_SIZE,
            )
            for rel in rels:
                if rel.id not in seen_rel_ids:
                    seen_rel_ids.add(rel.id)
                    all_relationships.append(rel)
                    if getattr(rel, "evidence_ref", None) is not None:
                        evidence_ref_count += 1

        runs = await self._run_repo.list_for_tenant(
            tenant_id=request.tenant_id, limit=_DELETE_PAGE_SIZE
        )

        entity_count = len(list(entities))
        relationship_count = len(all_relationships)
        run_count = len(list(runs))

        if not request.dry_run:
            logger.warning(
                "Deleting all tenant data (GDPR Article 17 erasure)",
                extra={
                    "tenant_id": str(request.tenant_id),
                    "requested_by": request.requested_by,
                    "entity_count": entity_count,
                    "relationship_count": relationship_count,
                    "run_count": run_count,
                    "evidence_refs": evidence_ref_count,
                    "retention_override": retention_override,
                },
            )

            # Delete relationships first (FK constraints).
            for rel in all_relationships:
                await self._session.delete(rel)

            # Delete entities.
            for entity in entities:
                await self._session.delete(entity)

            # Delete runs.
            for run in runs:
                await self._session.delete(run)

            await self._session.flush()

            logger.warning(
                "Tenant data deletion complete",
                extra={
                    "tenant_id": str(request.tenant_id),
                    "requested_by": request.requested_by,
                    "entities_deleted": entity_count,
                    "relationships_deleted": relationship_count,
                    "runs_deleted": run_count,
                    "evidence_refs_deleted": evidence_ref_count,
                },
            )
        else:
            logger.info(
                "Tenant data deletion dry run complete",
                extra={
                    "tenant_id": str(request.tenant_id),
                    "requested_by": request.requested_by,
                    "entities_would_delete": entity_count,
                    "relationships_would_delete": relationship_count,
                    "runs_would_delete": run_count,
                    "evidence_refs_would_delete": evidence_ref_count,
                },
            )

        return DeletionResult(
            tenant_id=request.tenant_id,
            deleted_at=datetime.now(UTC),
            entities_deleted=entity_count,
            relationships_deleted=relationship_count,
            runs_deleted=run_count,
            evidence_refs_deleted=evidence_ref_count,
            retention_override=retention_override,
        )

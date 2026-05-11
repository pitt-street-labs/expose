"""Pydantic request / response models for the EXPOSE REST API.

Frozen response models prevent accidental mutation after serialisation.
Request models (``TenantCreate``, ``TenantUpdate``) are mutable so FastAPI
can populate them from the inbound JSON body.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Allowed tenant states (kept as a module-level set for validation).
# ---------------------------------------------------------------------------
VALID_STATES: frozenset[str] = frozenset({"active", "suspended", "pending_deletion"})
PATCHABLE_STATES: frozenset[str] = frozenset({"active", "suspended"})


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class TenantCreate(BaseModel):
    """Body for ``POST /v1/tenants/``."""

    name: str = Field(min_length=1, max_length=255)


class TenantUpdate(BaseModel):
    """Body for ``PATCH /v1/tenants/{tenant_id}``.

    Only ``name`` and ``state`` may be patched.  State transitions are
    restricted to ``active <-> suspended``; setting ``pending_deletion`` via
    PATCH is rejected (use ``DELETE`` instead).
    """

    name: str | None = Field(default=None, min_length=1, max_length=255)
    state: str | None = None


# ---------------------------------------------------------------------------
# Response models (frozen — immutable once built)
# ---------------------------------------------------------------------------


class TenantResponse(BaseModel, frozen=True):
    """Single-tenant representation returned by all tenant endpoints."""

    id: UUID
    name: str
    state: str
    created_at: datetime


class TenantList(BaseModel, frozen=True):
    """Paginated (future) list wrapper returned by ``GET /v1/tenants/``."""

    tenants: list[TenantResponse]
    total: int


# ---------------------------------------------------------------------------
# Run response models (issue #10 — run results API)
# ---------------------------------------------------------------------------


class RunResponse(BaseModel):
    """Single-run representation returned by run endpoints."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    tenant_id: UUID
    state: str
    started_at: datetime | None
    completed_at: datetime | None
    pipeline_version: str | None
    enforcement_refusal_count: int | None = None


class RunList(BaseModel):
    """Paginated (future) list wrapper returned by ``GET /v1/tenants/{tid}/runs``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    runs: list[RunResponse]
    total: int


# ---------------------------------------------------------------------------
# Entity response models (issue #10 — run results API)
# ---------------------------------------------------------------------------


class EntityResponse(BaseModel):
    """Single-entity representation returned by entity endpoints."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    tenant_id: UUID
    entity_type: str
    canonical_identifier: str
    properties: dict[str, Any]
    attribution_status: str
    first_observed_at: datetime | None
    last_observed_at: datetime | None


class EntityList(BaseModel):
    """Paginated (future) list wrapper returned by ``GET /v1/tenants/{tid}/entities``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entities: list[EntityResponse]
    total: int


# ---------------------------------------------------------------------------
# Run trigger request / response models (run trigger API)
# ---------------------------------------------------------------------------


class RunCreate(BaseModel):
    """Body for ``POST /v1/tenants/{tenant_id}/runs``.

    The ``seeds`` field contains domain/IP/CIDR seeds (at least one required
    unless ``organization_seeds`` is provided). The optional
    ``organization_seeds`` field accepts organization names for org-name-based
    discovery (M&A shadow IT, crt.sh org search).

    At least one of ``seeds`` or ``organization_seeds`` must be non-empty.
    """

    model_config = ConfigDict(extra="forbid")

    seeds: list[str] = Field(default_factory=list)
    seed_type: str | None = None
    organization_seeds: list[str] = Field(default_factory=list)
    collector_ids: list[str] | None = None

    def model_post_init(self, __context: object) -> None:
        """Validate that at least one seed is provided."""
        if not self.seeds and not self.organization_seeds:
            msg = "At least one of 'seeds' or 'organization_seeds' must be non-empty."
            raise ValueError(msg)


class RunStarted(BaseModel):
    """Response for ``POST /v1/tenants/{tenant_id}/runs`` — 202 Accepted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: UUID
    tenant_id: UUID
    state: str
    seeds: list[str]
    organization_seeds: list[str] = Field(default_factory=list)
    collector_ids: list[str]
    message: str

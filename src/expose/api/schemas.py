"""Pydantic request / response models for the EXPOSE REST API.

Frozen response models prevent accidental mutation after serialisation.
Request models (``TenantCreate``, ``TenantUpdate``) are mutable so FastAPI
can populate them from the inbound JSON body.
"""

from __future__ import annotations

from datetime import datetime
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
    attribution_status: str
    first_observed_at: datetime | None
    last_observed_at: datetime | None


class EntityList(BaseModel):
    """Paginated (future) list wrapper returned by ``GET /v1/tenants/{tid}/entities``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entities: list[EntityResponse]
    total: int

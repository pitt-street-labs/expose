"""Pydantic request / response models for the tenant lifecycle API.

Frozen response models prevent accidental mutation after serialisation.
Request models (``TenantCreate``, ``TenantUpdate``) are mutable so FastAPI
can populate them from the inbound JSON body.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

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

"""FastAPI router for tenant CRUD operations.

Implements the tenant lifecycle described in issue #23:

* **Create** — ``POST /v1/tenants/`` → 201
* **Get**    — ``GET  /v1/tenants/{tenant_id}`` → 200 | 404
* **List**   — ``GET  /v1/tenants/`` → 200
* **Update** — ``PATCH /v1/tenants/{tenant_id}`` → 200 | 404 | 422
* **Delete** — ``DELETE /v1/tenants/{tenant_id}`` → 204 | 404

State is persisted inside the ``config_jsonb`` column (key ``"state"``)
rather than a dedicated column, which avoids altering the locked ORM model
(``Tenant`` in ``expose.db.models``).

The ``get_session`` dependency is a placeholder that **must** be overridden
at application startup (or in tests) to inject a real ``AsyncSession``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from expose.api.schemas import (
    PATCHABLE_STATES,
    TenantCreate,
    TenantList,
    TenantResponse,
    TenantUpdate,
)
from expose.db.models import Tenant

# ---------------------------------------------------------------------------
# Session dependency — wired at app-level; tests override via
# ``app.dependency_overrides[get_session]``.
# ---------------------------------------------------------------------------

_DEFAULT_STATE = "active"


async def get_session() -> AsyncIterator[AsyncSession]:  # pragma: no cover
    """Placeholder — override in the FastAPI app lifespan or tests."""
    raise NotImplementedError("Wire up via app lifespan")
    # yield is required so the signature is ``AsyncIterator``, satisfying
    # FastAPI's dependency-injection machinery even though it is unreachable.
    yield  # type: ignore[unreachable]


# Annotated type alias — avoids B008 by hoisting Depends() out of the
# function signature default.
SessionDep = Annotated[AsyncSession, Depends(get_session)]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tenant_state(tenant: Tenant) -> str:
    """Extract state from ``config_jsonb``, defaulting to ``active``."""
    cfg: dict[str, object] = tenant.config_jsonb or {}
    raw = cfg.get("state", _DEFAULT_STATE)
    return str(raw)


def _to_response(tenant: Tenant) -> TenantResponse:
    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        state=_tenant_state(tenant),
        created_at=tenant.created_at,
    )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/v1/tenants", tags=["tenants"])


@router.post("/", status_code=201, response_model=TenantResponse)
async def create_tenant(
    body: TenantCreate,
    session: SessionDep,
) -> TenantResponse:
    """Create a new tenant in *active* state."""
    tenant = Tenant(
        id=uuid4(),
        name=body.name,
        created_at=datetime.now(UTC),
        config_jsonb={"state": _DEFAULT_STATE},
    )
    session.add(tenant)
    await session.flush()
    return _to_response(tenant)


@router.get("/{tenant_id}", response_model=TenantResponse)
async def get_tenant(
    tenant_id: UUID,
    session: SessionDep,
) -> TenantResponse:
    """Return a single tenant or 404."""
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return _to_response(tenant)


@router.get("/", response_model=TenantList)
async def list_tenants(
    session: SessionDep,
) -> TenantList:
    """Return all tenants (pagination deferred)."""
    result = await session.execute(select(Tenant))
    tenants = list(result.scalars().all())
    return TenantList(
        tenants=[_to_response(t) for t in tenants],
        total=len(tenants),
    )


@router.patch("/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: UUID,
    body: TenantUpdate,
    session: SessionDep,
) -> TenantResponse:
    """Partial update — only ``name`` and ``state`` (active <-> suspended)."""
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")

    if body.state is not None:
        if body.state not in PATCHABLE_STATES:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Invalid state transition: only {sorted(PATCHABLE_STATES)} "
                    "are allowed via PATCH. Use DELETE for pending_deletion."
                ),
            )
        current = _tenant_state(tenant)
        if current == "pending_deletion":
            raise HTTPException(
                status_code=422,
                detail="Cannot modify a tenant in pending_deletion state.",
            )
        cfg = dict(tenant.config_jsonb or {})
        cfg["state"] = body.state
        tenant.config_jsonb = cfg

    if body.name is not None:
        tenant.name = body.name

    await session.flush()
    return _to_response(tenant)


@router.delete("/{tenant_id}", status_code=204)
async def delete_tenant(
    tenant_id: UUID,
    session: SessionDep,
) -> None:
    """Two-phase delete: set state to ``pending_deletion`` without removing the row."""
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")

    cfg = dict(tenant.config_jsonb or {})
    cfg["state"] = "pending_deletion"
    tenant.config_jsonb = cfg
    await session.flush()

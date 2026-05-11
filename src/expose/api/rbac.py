"""Role-based access control for the EXPOSE API.

Provides tenant-scoped RBAC with three built-in roles:

* **Admin** -- full access to all operations within a tenant.
* **Operator** -- can execute scans, view results, and read configs but
  cannot modify tenant settings or manage users.
* **Viewer** -- read-only access to scan results, configs, and exports.

Phase 1 stores role assignments in memory.  Production deployments should
back ``RBACEnforcer`` with a database table (see ADR-007 multi-tenancy).

The ``require()`` function produces a FastAPI dependency that enforces a
permission check on every request, reading the user identity from the
``Authorization: Bearer <token>`` header or the ``X-User-Id`` header.

Backwards compatibility: when no role assignment exists for a user+tenant
pair the dependency does **not** reject the request, keeping RBAC opt-in
for endpoints that have not yet been migrated.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Role(StrEnum):
    """Tenant-scoped user role."""

    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class Permission(StrEnum):
    """Fine-grained permission checked by ``require()``."""

    TENANT_READ = "tenant:read"
    TENANT_WRITE = "tenant:write"
    TENANT_DELETE = "tenant:delete"
    CONFIG_READ = "config:read"
    CONFIG_WRITE = "config:write"
    RUN_READ = "run:read"
    RUN_WRITE = "run:write"
    CREDENTIAL_READ = "credential:read"
    CREDENTIAL_WRITE = "credential:write"
    EXPORT = "export"
    WEBHOOK_READ = "webhook:read"
    WEBHOOK_WRITE = "webhook:write"
    USER_MANAGE = "user:manage"


# ---------------------------------------------------------------------------
# Role -> Permission mapping
# ---------------------------------------------------------------------------

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: frozenset(Permission),
    Role.OPERATOR: frozenset(
        {
            Permission.TENANT_READ,
            Permission.CONFIG_READ,
            Permission.RUN_READ,
            Permission.RUN_WRITE,
            Permission.CREDENTIAL_READ,
            Permission.EXPORT,
            Permission.WEBHOOK_READ,
        }
    ),
    Role.VIEWER: frozenset(
        {
            Permission.TENANT_READ,
            Permission.CONFIG_READ,
            Permission.RUN_READ,
            Permission.EXPORT,
        }
    ),
}

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TenantUser(BaseModel):
    """A user's role assignment within a specific tenant."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: str = Field(min_length=1)
    tenant_id: UUID
    role: Role
    created_at: datetime


class TenantUserCreate(BaseModel):
    """Request body for assigning a user to a tenant."""

    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1)
    role: Role


class TenantUserPermissions(BaseModel):
    """Response showing the effective permissions for a user."""

    model_config = ConfigDict(extra="forbid")

    user_id: str
    tenant_id: UUID
    role: Role
    permissions: list[str]


# ---------------------------------------------------------------------------
# Enforcer
# ---------------------------------------------------------------------------


class RBACEnforcer:
    """In-memory RBAC enforcement for Phase 1.

    Role assignments are keyed by ``(user_id, tenant_id)`` pairs so the
    same user can hold different roles in different tenants.
    """

    def __init__(self) -> None:
        self._users: dict[tuple[str, UUID], TenantUser] = {}

    # -- mutations -----------------------------------------------------------

    def assign_role(self, user_id: str, tenant_id: UUID, role: Role) -> TenantUser:
        """Create or update a role assignment for *user_id* in *tenant_id*."""
        tu = TenantUser(
            user_id=user_id,
            tenant_id=tenant_id,
            role=role,
            created_at=datetime.now(UTC),
        )
        self._users[(user_id, tenant_id)] = tu
        return tu

    def remove_user(self, user_id: str, tenant_id: UUID) -> bool:
        """Remove a role assignment.  Returns ``True`` if found and removed."""
        return self._users.pop((user_id, tenant_id), None) is not None

    # -- queries -------------------------------------------------------------

    def get_role(self, user_id: str, tenant_id: UUID) -> Role | None:
        """Return the role for *user_id* in *tenant_id*, or ``None``."""
        tu = self._users.get((user_id, tenant_id))
        return tu.role if tu is not None else None

    def check_permission(self, user_id: str, tenant_id: UUID, permission: Permission) -> bool:
        """Return ``True`` if *user_id* holds *permission* in *tenant_id*."""
        role = self.get_role(user_id, tenant_id)
        if role is None:
            return False
        return permission in ROLE_PERMISSIONS[role]

    def require_permission(self, user_id: str, tenant_id: UUID, permission: Permission) -> None:
        """Raise ``HTTPException(403)`` if *user_id* lacks *permission*."""
        if not self.check_permission(user_id, tenant_id, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: {permission}",
            )

    def list_users(self, tenant_id: UUID) -> list[TenantUser]:
        """Return all role assignments for *tenant_id*."""
        return [tu for tu in self._users.values() if tu.tenant_id == tenant_id]


# ---------------------------------------------------------------------------
# Module-level enforcer (shared across the API)
# ---------------------------------------------------------------------------

_enforcer = RBACEnforcer()


def get_enforcer() -> RBACEnforcer:
    """Return the module-level ``RBACEnforcer`` singleton.

    Tests can override via ``app.dependency_overrides[get_enforcer]``.
    """
    return _enforcer


EnforcerDep = Annotated[RBACEnforcer, Depends(get_enforcer)]


# ---------------------------------------------------------------------------
# FastAPI dependency factory
# ---------------------------------------------------------------------------


def _extract_user_id(request: Request) -> str | None:
    """Extract a user identifier from the request.

    Checks ``Authorization: Bearer <token>`` first (uses the raw token as
    the user id in Phase 1), then falls back to ``X-User-Id``.
    """
    auth_header: str = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.removeprefix("Bearer ")

    user_header = request.headers.get("x-user-id")
    if user_header:
        return user_header

    return None


def _extract_tenant_id(request: Request) -> UUID | None:
    """Extract ``tenant_id`` from the URL path parameters."""
    raw = request.path_params.get("tenant_id")
    if raw is None:
        return None
    try:
        return UUID(str(raw))
    except ValueError:
        return None


def require(permission: Permission) -> Callable:
    """Create a FastAPI dependency that enforces *permission*.

    The dependency is opt-in: if the user has no role assignment the request
    is allowed through (backward compatible).  Once a role **is** assigned,
    the permission check is enforced.

    Usage::

        @router.get("/things", dependencies=[require(Permission.THING_READ)])
        async def list_things(): ...
    """

    async def _check(
        request: Request,
        enforcer: EnforcerDep,
    ) -> None:
        user_id = _extract_user_id(request)
        if user_id is None:
            # No user identity -> skip RBAC (backward compat).
            return

        tenant_id = _extract_tenant_id(request)
        if tenant_id is None:
            # No tenant in path -> skip RBAC.
            return

        role = enforcer.get_role(user_id, tenant_id)
        if role is None:
            # User has no role assignment -> opt-in: allow.
            return

        enforcer.require_permission(user_id, tenant_id, permission)

    return Depends(_check)


# ---------------------------------------------------------------------------
# User management router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/v1/tenants/{tenant_id}/users", tags=["users"])


@router.get(
    "/",
    response_model=list[TenantUser],
    dependencies=[require(Permission.USER_MANAGE)],
)
async def list_users(
    tenant_id: UUID,
    enforcer: EnforcerDep,
) -> list[TenantUser]:
    """List all user role assignments for a tenant."""
    return enforcer.list_users(tenant_id)


@router.post(
    "/",
    status_code=201,
    response_model=TenantUser,
    dependencies=[require(Permission.USER_MANAGE)],
)
async def create_user(
    tenant_id: UUID,
    body: TenantUserCreate,
    enforcer: EnforcerDep,
) -> TenantUser:
    """Assign a role to a user within this tenant."""
    return enforcer.assign_role(body.user_id, tenant_id, body.role)


@router.delete(
    "/{user_id}",
    status_code=204,
    dependencies=[require(Permission.USER_MANAGE)],
)
async def delete_user(
    tenant_id: UUID,
    user_id: str,
    enforcer: EnforcerDep,
) -> None:
    """Remove a user's role assignment from this tenant."""
    if not enforcer.remove_user(user_id, tenant_id):
        raise HTTPException(status_code=404, detail="User not found in tenant")


@router.get(
    "/{user_id}/permissions",
    response_model=TenantUserPermissions,
    dependencies=[require(Permission.TENANT_READ)],
)
async def get_user_permissions(
    tenant_id: UUID,
    user_id: str,
    enforcer: EnforcerDep,
) -> TenantUserPermissions:
    """Return the effective permissions for a user in this tenant."""
    role = enforcer.get_role(user_id, tenant_id)
    if role is None:
        raise HTTPException(status_code=404, detail="User not found in tenant")
    perms = sorted(str(p) for p in ROLE_PERMISSIONS[role])
    return TenantUserPermissions(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        permissions=perms,
    )

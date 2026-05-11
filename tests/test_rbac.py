"""Tests for role-based access control.

Covers:
 1. Role enum values
 2. Permission enum values
 3. ROLE_PERMISSIONS: admin has all permissions
 4. ROLE_PERMISSIONS: viewer is a strict subset
 5. ROLE_PERMISSIONS: operator is a strict subset
 6. assign_role creates TenantUser
 7. check_permission returns True for allowed
 8. check_permission returns False for denied
 9. require_permission raises 403 for denied
10. require_permission passes for allowed
11. Admin can do everything
12. Operator can run:write but not config:write
13. Viewer can run:read but not run:write
14. list_users returns correct set
15. remove_user works
16. remove_user returns False for unknown
17. Unknown user returns None role
18. TenantUser model validation rejects extra fields
19. TenantUser model validation rejects empty user_id
20. Multi-tenant isolation (same user, different tenants)
21. User management: list users via API
22. User management: create user via API
23. User management: delete user via API
24. User management: get permissions via API
25. User management: delete unknown user returns 404
26. require() dependency allows request when no role assigned (opt-in)
"""

from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from expose.api.rbac import (
    ROLE_PERMISSIONS,
    Permission,
    RBACEnforcer,
    Role,
    TenantUser,
    get_enforcer,
    router,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def enforcer() -> RBACEnforcer:
    """Fresh in-memory RBAC enforcer."""
    return RBACEnforcer()


@pytest.fixture
def tenant_id() -> UUID:
    """Deterministic tenant UUID for test assertions."""
    return uuid4()


@pytest.fixture
def other_tenant_id() -> UUID:
    """Second tenant UUID for multi-tenant isolation tests."""
    return uuid4()


# ---------------------------------------------------------------------------
# 1. Role enum values
# ---------------------------------------------------------------------------


def test_role_enum_values() -> None:
    assert Role.ADMIN == "admin"
    assert Role.OPERATOR == "operator"
    assert Role.VIEWER == "viewer"
    assert len(Role) == 3


# ---------------------------------------------------------------------------
# 2. Permission enum values
# ---------------------------------------------------------------------------


def test_permission_enum_values() -> None:
    expected = {
        "tenant:read",
        "tenant:write",
        "tenant:delete",
        "config:read",
        "config:write",
        "run:read",
        "run:write",
        "credential:read",
        "credential:write",
        "export",
        "webhook:read",
        "webhook:write",
        "user:manage",
    }
    actual = {str(p) for p in Permission}
    assert actual == expected
    assert len(Permission) == 13


# ---------------------------------------------------------------------------
# 3. ROLE_PERMISSIONS: admin has all permissions
# ---------------------------------------------------------------------------


def test_admin_has_all_permissions() -> None:
    admin_perms = ROLE_PERMISSIONS[Role.ADMIN]
    all_perms = frozenset(Permission)
    assert admin_perms == all_perms


# ---------------------------------------------------------------------------
# 4. ROLE_PERMISSIONS: viewer is a strict subset
# ---------------------------------------------------------------------------


def test_viewer_is_strict_subset_of_admin() -> None:
    assert ROLE_PERMISSIONS[Role.VIEWER] < ROLE_PERMISSIONS[Role.ADMIN]


# ---------------------------------------------------------------------------
# 5. ROLE_PERMISSIONS: operator is a strict subset
# ---------------------------------------------------------------------------


def test_operator_is_strict_subset_of_admin() -> None:
    assert ROLE_PERMISSIONS[Role.OPERATOR] < ROLE_PERMISSIONS[Role.ADMIN]


def test_viewer_is_strict_subset_of_operator() -> None:
    assert ROLE_PERMISSIONS[Role.VIEWER] < ROLE_PERMISSIONS[Role.OPERATOR]


# ---------------------------------------------------------------------------
# 6. assign_role creates TenantUser
# ---------------------------------------------------------------------------


def test_assign_role_creates_tenant_user(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    tu = enforcer.assign_role("alice", tenant_id, Role.ADMIN)
    assert isinstance(tu, TenantUser)
    assert tu.user_id == "alice"
    assert tu.tenant_id == tenant_id
    assert tu.role == Role.ADMIN
    assert tu.created_at is not None


# ---------------------------------------------------------------------------
# 7. check_permission returns True for allowed
# ---------------------------------------------------------------------------


def test_check_permission_allowed(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    enforcer.assign_role("alice", tenant_id, Role.ADMIN)
    assert enforcer.check_permission("alice", tenant_id, Permission.TENANT_WRITE) is True


# ---------------------------------------------------------------------------
# 8. check_permission returns False for denied
# ---------------------------------------------------------------------------


def test_check_permission_denied(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    enforcer.assign_role("bob", tenant_id, Role.VIEWER)
    assert enforcer.check_permission("bob", tenant_id, Permission.TENANT_WRITE) is False


# ---------------------------------------------------------------------------
# 9. require_permission raises 403 for denied
# ---------------------------------------------------------------------------


def test_require_permission_raises_403(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    enforcer.assign_role("bob", tenant_id, Role.VIEWER)

    with pytest.raises(HTTPException) as exc_info:
        enforcer.require_permission("bob", tenant_id, Permission.CONFIG_WRITE)
    assert exc_info.value.status_code == 403
    assert "Permission denied" in str(exc_info.value.detail)


# ---------------------------------------------------------------------------
# 10. require_permission passes for allowed
# ---------------------------------------------------------------------------


def test_require_permission_passes(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    enforcer.assign_role("alice", tenant_id, Role.ADMIN)
    # Should not raise
    enforcer.require_permission("alice", tenant_id, Permission.USER_MANAGE)


# ---------------------------------------------------------------------------
# 11. Admin can do everything
# ---------------------------------------------------------------------------


def test_admin_can_do_everything(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    enforcer.assign_role("alice", tenant_id, Role.ADMIN)
    for perm in Permission:
        assert enforcer.check_permission("alice", tenant_id, perm) is True, (
            f"Admin should have {perm}"
        )


# ---------------------------------------------------------------------------
# 12. Operator can run:write but not config:write
# ---------------------------------------------------------------------------


def test_operator_permissions(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    enforcer.assign_role("ops", tenant_id, Role.OPERATOR)
    assert enforcer.check_permission("ops", tenant_id, Permission.RUN_WRITE) is True
    assert enforcer.check_permission("ops", tenant_id, Permission.CONFIG_WRITE) is False
    assert enforcer.check_permission("ops", tenant_id, Permission.USER_MANAGE) is False
    assert enforcer.check_permission("ops", tenant_id, Permission.TENANT_WRITE) is False


# ---------------------------------------------------------------------------
# 13. Viewer can run:read but not run:write
# ---------------------------------------------------------------------------


def test_viewer_permissions(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    enforcer.assign_role("viewer", tenant_id, Role.VIEWER)
    assert enforcer.check_permission("viewer", tenant_id, Permission.RUN_READ) is True
    assert enforcer.check_permission("viewer", tenant_id, Permission.RUN_WRITE) is False
    assert enforcer.check_permission("viewer", tenant_id, Permission.CREDENTIAL_READ) is False


# ---------------------------------------------------------------------------
# 14. list_users returns correct set
# ---------------------------------------------------------------------------


def test_list_users(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    enforcer.assign_role("alice", tenant_id, Role.ADMIN)
    enforcer.assign_role("bob", tenant_id, Role.VIEWER)

    users = enforcer.list_users(tenant_id)
    assert len(users) == 2
    user_ids = {u.user_id for u in users}
    assert user_ids == {"alice", "bob"}


# ---------------------------------------------------------------------------
# 15. remove_user works
# ---------------------------------------------------------------------------


def test_remove_user(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    enforcer.assign_role("alice", tenant_id, Role.ADMIN)
    assert enforcer.remove_user("alice", tenant_id) is True
    assert enforcer.get_role("alice", tenant_id) is None
    assert enforcer.list_users(tenant_id) == []


# ---------------------------------------------------------------------------
# 16. remove_user returns False for unknown
# ---------------------------------------------------------------------------


def test_remove_user_unknown(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    assert enforcer.remove_user("ghost", tenant_id) is False


# ---------------------------------------------------------------------------
# 17. Unknown user returns None role
# ---------------------------------------------------------------------------


def test_unknown_user_returns_none(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    assert enforcer.get_role("nobody", tenant_id) is None


# ---------------------------------------------------------------------------
# 18. TenantUser model validation rejects extra fields
# ---------------------------------------------------------------------------


def test_tenant_user_rejects_extra_fields(tenant_id: UUID) -> None:
    with pytest.raises(ValidationError):
        TenantUser(
            user_id="alice",
            tenant_id=tenant_id,
            role=Role.ADMIN,
            created_at="2026-01-01T00:00:00Z",
            bonus="nope",  # type: ignore[call-arg]
        )


# ---------------------------------------------------------------------------
# 19. TenantUser model validation rejects empty user_id
# ---------------------------------------------------------------------------


def test_tenant_user_rejects_empty_user_id(tenant_id: UUID) -> None:
    with pytest.raises(ValidationError):
        TenantUser(
            user_id="",
            tenant_id=tenant_id,
            role=Role.ADMIN,
            created_at="2026-01-01T00:00:00Z",
        )


# ---------------------------------------------------------------------------
# 20. Multi-tenant isolation (same user, different tenants)
# ---------------------------------------------------------------------------


def test_multi_tenant_isolation(
    enforcer: RBACEnforcer,
    tenant_id: UUID,
    other_tenant_id: UUID,
) -> None:
    enforcer.assign_role("alice", tenant_id, Role.ADMIN)
    enforcer.assign_role("alice", other_tenant_id, Role.VIEWER)

    assert enforcer.get_role("alice", tenant_id) == Role.ADMIN
    assert enforcer.get_role("alice", other_tenant_id) == Role.VIEWER

    # Admin in tenant A can manage users
    assert enforcer.check_permission("alice", tenant_id, Permission.USER_MANAGE) is True
    # Viewer in tenant B cannot
    assert enforcer.check_permission("alice", other_tenant_id, Permission.USER_MANAGE) is False

    # list_users is tenant-scoped
    assert len(enforcer.list_users(tenant_id)) == 1
    assert len(enforcer.list_users(other_tenant_id)) == 1


# ---------------------------------------------------------------------------
# API integration helpers
# ---------------------------------------------------------------------------


def _make_user_mgmt_app(enforcer: RBACEnforcer) -> FastAPI:
    """Build a minimal FastAPI app with the RBAC user management router."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_enforcer] = lambda: enforcer
    return app


# ---------------------------------------------------------------------------
# 21. User management: list users via API
# ---------------------------------------------------------------------------


async def test_api_list_users(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    enforcer.assign_role("admin-user", tenant_id, Role.ADMIN)
    enforcer.assign_role("viewer-user", tenant_id, Role.VIEWER)
    app = _make_user_mgmt_app(enforcer)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            f"/v1/tenants/{tenant_id}/users/",
            headers={"X-User-Id": "admin-user"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2


# ---------------------------------------------------------------------------
# 22. User management: create user via API
# ---------------------------------------------------------------------------


async def test_api_create_user(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    enforcer.assign_role("admin-user", tenant_id, Role.ADMIN)
    app = _make_user_mgmt_app(enforcer)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.post(
            f"/v1/tenants/{tenant_id}/users/",
            json={"user_id": "new-operator", "role": "operator"},
            headers={"X-User-Id": "admin-user"},
        )
    assert resp.status_code == 201
    data = resp.json()
    assert data["user_id"] == "new-operator"
    assert data["role"] == "operator"
    assert data["tenant_id"] == str(tenant_id)


# ---------------------------------------------------------------------------
# 23. User management: delete user via API
# ---------------------------------------------------------------------------


async def test_api_delete_user(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    enforcer.assign_role("admin-user", tenant_id, Role.ADMIN)
    enforcer.assign_role("doomed", tenant_id, Role.VIEWER)
    app = _make_user_mgmt_app(enforcer)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.delete(
            f"/v1/tenants/{tenant_id}/users/doomed",
            headers={"X-User-Id": "admin-user"},
        )
    assert resp.status_code == 204
    assert enforcer.get_role("doomed", tenant_id) is None


# ---------------------------------------------------------------------------
# 24. User management: get permissions via API
# ---------------------------------------------------------------------------


async def test_api_get_permissions(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    enforcer.assign_role("alice", tenant_id, Role.VIEWER)
    app = _make_user_mgmt_app(enforcer)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            f"/v1/tenants/{tenant_id}/users/alice/permissions",
            headers={"X-User-Id": "alice"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["role"] == "viewer"
    assert "run:read" in data["permissions"]
    assert "run:write" not in data["permissions"]
    assert len(data["permissions"]) == len(ROLE_PERMISSIONS[Role.VIEWER])


# ---------------------------------------------------------------------------
# 25. User management: delete unknown user returns 404
# ---------------------------------------------------------------------------


async def test_api_delete_unknown_user(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    app = _make_user_mgmt_app(enforcer)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.delete(
            f"/v1/tenants/{tenant_id}/users/ghost",
        )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 26. require() dependency allows request when no role assigned (opt-in)
# ---------------------------------------------------------------------------


async def test_require_allows_unassigned_user(enforcer: RBACEnforcer, tenant_id: UUID) -> None:
    """An unknown user (no role assignment) is allowed through -- RBAC is opt-in."""
    app = _make_user_mgmt_app(enforcer)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        # No role assigned for "stranger", but the opt-in policy lets them through
        resp = await client.get(
            f"/v1/tenants/{tenant_id}/users/",
            headers={"X-User-Id": "stranger"},
        )
    assert resp.status_code == 200

"""Tests for bearer token authentication middleware.

Covers:
 1. create_token returns valid APIToken
 2. validate_token returns payload for valid token
 3. validate_token returns None for unknown token
 4. validate_token returns None for expired token
 5. revoke_token removes the token
 6. revoke_token returns False for unknown token
 7. AuthDependency extracts Bearer token correctly
 8. AuthDependency rejects missing header -> 401
 9. AuthDependency rejects invalid token -> 401
10. AuthDependency rejects expired token -> 401
11. AuthDependency checks scopes -> 403 on missing scope
12. Token is tenant-scoped (payload.tenant_id matches)
13. create_token with custom scopes
14. create_token with explicit expiry in the future
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from expose.api.auth import APIToken, AuthDependency, TokenPayload, TokenStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store() -> TokenStore:
    """Fresh in-memory token store."""
    return TokenStore()


@pytest.fixture
def tenant_id() -> UUID:
    """Deterministic tenant UUID for test assertions."""
    return uuid4()


# ---------------------------------------------------------------------------
# 1. create_token returns valid APIToken
# ---------------------------------------------------------------------------


def test_create_token_returns_api_token(store: TokenStore, tenant_id: UUID) -> None:
    result = store.create_token(tenant_id)
    assert isinstance(result, APIToken)
    assert isinstance(result.token, str)
    assert len(result.token) == 32  # uuid4().hex is 32 hex chars
    assert isinstance(result.payload, TokenPayload)
    assert result.payload.tenant_id == tenant_id
    assert result.payload.scopes == ["read", "write"]
    assert result.payload.issued_at <= datetime.now(UTC)
    assert result.payload.expires_at is None


# ---------------------------------------------------------------------------
# 2. validate_token returns payload for valid token
# ---------------------------------------------------------------------------


def test_validate_token_returns_payload(store: TokenStore, tenant_id: UUID) -> None:
    api_token = store.create_token(tenant_id)
    payload = store.validate_token(api_token.token)
    assert payload is not None
    assert payload.tenant_id == tenant_id
    assert payload.scopes == ["read", "write"]


# ---------------------------------------------------------------------------
# 3. validate_token returns None for unknown token
# ---------------------------------------------------------------------------


def test_validate_token_unknown_returns_none(store: TokenStore) -> None:
    assert store.validate_token("nonexistent-token-value") is None


# ---------------------------------------------------------------------------
# 4. validate_token returns None for expired token
# ---------------------------------------------------------------------------


def test_validate_token_expired_returns_none(store: TokenStore, tenant_id: UUID) -> None:
    expired = datetime.now(UTC) - timedelta(hours=1)
    api_token = store.create_token(tenant_id, expires_at=expired)
    assert store.validate_token(api_token.token) is None


# ---------------------------------------------------------------------------
# 5. revoke_token removes the token
# ---------------------------------------------------------------------------


def test_revoke_token_removes(store: TokenStore, tenant_id: UUID) -> None:
    api_token = store.create_token(tenant_id)
    assert store.revoke_token(api_token.token) is True
    # Token should no longer validate
    assert store.validate_token(api_token.token) is None


# ---------------------------------------------------------------------------
# 6. revoke_token returns False for unknown token
# ---------------------------------------------------------------------------


def test_revoke_token_unknown_returns_false(store: TokenStore) -> None:
    assert store.revoke_token("does-not-exist") is False


# ---------------------------------------------------------------------------
# 7. AuthDependency extracts Bearer token correctly
# ---------------------------------------------------------------------------


async def test_auth_dependency_extracts_token(store: TokenStore, tenant_id: UUID) -> None:
    api_token = store.create_token(tenant_id)
    app = _make_protected_app(store)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            "/protected",
            headers={"Authorization": f"Bearer {api_token.token}"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["tenant_id"] == str(tenant_id)


# ---------------------------------------------------------------------------
# 8. AuthDependency rejects missing header -> 401
# ---------------------------------------------------------------------------


async def test_auth_dependency_rejects_missing_header(store: TokenStore) -> None:
    app = _make_protected_app(store)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/protected")
    assert resp.status_code == 401
    assert "Missing or invalid" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 9. AuthDependency rejects invalid token -> 401
# ---------------------------------------------------------------------------


async def test_auth_dependency_rejects_invalid_token(store: TokenStore) -> None:
    app = _make_protected_app(store)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            "/protected",
            headers={"Authorization": "Bearer bogus-token-value"},
        )
    assert resp.status_code == 401
    assert "Invalid or expired" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 10. AuthDependency rejects expired token -> 401
# ---------------------------------------------------------------------------


async def test_auth_dependency_rejects_expired_token(
    store: TokenStore, tenant_id: UUID
) -> None:
    expired = datetime.now(UTC) - timedelta(seconds=10)
    api_token = store.create_token(tenant_id, expires_at=expired)
    app = _make_protected_app(store)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            "/protected",
            headers={"Authorization": f"Bearer {api_token.token}"},
        )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 11. AuthDependency checks scopes -> 403 on missing scope
# ---------------------------------------------------------------------------


async def test_auth_dependency_rejects_missing_scope(
    store: TokenStore, tenant_id: UUID
) -> None:
    # Token with only "read" scope trying to hit a "write"-scoped endpoint
    api_token = store.create_token(tenant_id, scopes=["read"])
    app = _make_protected_app(store, required_scope="write")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            "/protected",
            headers={"Authorization": f"Bearer {api_token.token}"},
        )
    assert resp.status_code == 403
    assert "Token lacks required scope" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 12. Token is tenant-scoped (payload.tenant_id matches)
# ---------------------------------------------------------------------------


def test_token_is_tenant_scoped(store: TokenStore) -> None:
    tenant_a = uuid4()
    tenant_b = uuid4()
    token_a = store.create_token(tenant_a)
    token_b = store.create_token(tenant_b)

    payload_a = store.validate_token(token_a.token)
    payload_b = store.validate_token(token_b.token)

    assert payload_a is not None
    assert payload_b is not None
    assert payload_a.tenant_id == tenant_a
    assert payload_b.tenant_id == tenant_b
    assert payload_a.tenant_id != payload_b.tenant_id


# ---------------------------------------------------------------------------
# 13. create_token with custom scopes
# ---------------------------------------------------------------------------


def test_create_token_custom_scopes(store: TokenStore, tenant_id: UUID) -> None:
    api_token = store.create_token(tenant_id, scopes=["read"])
    assert api_token.payload.scopes == ["read"]


# ---------------------------------------------------------------------------
# 14. create_token with explicit future expiry
# ---------------------------------------------------------------------------


def test_create_token_future_expiry(store: TokenStore, tenant_id: UUID) -> None:
    future = datetime.now(UTC) + timedelta(hours=24)
    api_token = store.create_token(tenant_id, expires_at=future)
    assert api_token.payload.expires_at == future
    # Should still be valid
    payload = store.validate_token(api_token.token)
    assert payload is not None
    assert payload.tenant_id == tenant_id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_protected_app(
    store: TokenStore,
    required_scope: str = "read",
) -> FastAPI:
    """Build a minimal FastAPI app with a single protected endpoint."""
    app = FastAPI()
    auth = AuthDependency(store, required_scope=required_scope)

    @app.get("/protected")
    async def protected(
        payload: TokenPayload = Depends(auth),  # noqa: B008
    ) -> dict[str, str]:
        return {"tenant_id": str(payload.tenant_id)}

    return app

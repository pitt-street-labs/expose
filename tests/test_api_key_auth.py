"""Tests for the global API-key authentication middleware.

Covers:
 1. No EXPOSE_API_KEY set → all requests pass (dev mode)
 2. EXPOSE_API_KEY set → unauthenticated request to protected path → 401
 3. EXPOSE_API_KEY set → wrong key → 403
 4. EXPOSE_API_KEY set → correct key via Authorization: Bearer → 200
 5. EXPOSE_API_KEY set → correct key via X-API-Key → 200
 6. /healthz is always exempt (with and without key)
 7. Empty EXPOSE_API_KEY treated as unset (dev mode)
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

# We need to reimport the module after patching the env var, so tests
# manipulate the module-level _API_KEY directly.
import expose.api.auth_middleware as auth_mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_app(api_key: str | None) -> FastAPI:
    """Build a minimal FastAPI app with the global API-key dependency.

    Patches ``_API_KEY`` in the middleware module for the duration of the
    test (caller is responsible for restoring via the fixture below).
    """
    @asynccontextmanager
    async def _noop_lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield

    app = FastAPI(
        lifespan=_noop_lifespan,
        dependencies=[Depends(auth_mod.require_api_key)],
    )

    @app.get("/v1/test")
    async def _test_endpoint() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/healthz")
    async def _healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


@pytest.fixture(autouse=True)
def _restore_api_key() -> AsyncIterator[None]:
    """Ensure _API_KEY is restored after each test."""
    original = auth_mod._API_KEY
    yield  # type: ignore[misc]
    auth_mod._API_KEY = original


# ---------------------------------------------------------------------------
# 1. Dev mode — no key set, all requests pass
# ---------------------------------------------------------------------------


async def test_dev_mode_no_key_all_pass() -> None:
    auth_mod._API_KEY = None
    app = _make_app(api_key=None)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/test")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 2. Key set — unauthenticated request → 401
# ---------------------------------------------------------------------------


async def test_missing_key_returns_401() -> None:
    auth_mod._API_KEY = "test-secret-key"
    app = _make_app(api_key="test-secret-key")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/test")
    assert resp.status_code == 401
    assert "API key required" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 3. Key set — wrong key → 403
# ---------------------------------------------------------------------------


async def test_wrong_key_returns_403() -> None:
    auth_mod._API_KEY = "test-secret-key"
    app = _make_app(api_key="test-secret-key")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/test",
            headers={"Authorization": "Bearer wrong-key"},
        )
    assert resp.status_code == 403
    assert "Invalid API key" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 4. Correct key via Authorization: Bearer → 200
# ---------------------------------------------------------------------------


async def test_correct_bearer_key_returns_200() -> None:
    auth_mod._API_KEY = "test-secret-key"
    app = _make_app(api_key="test-secret-key")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/test",
            headers={"Authorization": "Bearer test-secret-key"},
        )
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# 5. Correct key via X-API-Key → 200
# ---------------------------------------------------------------------------


async def test_correct_x_api_key_returns_200() -> None:
    auth_mod._API_KEY = "test-secret-key"
    app = _make_app(api_key="test-secret-key")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/v1/test",
            headers={"X-API-Key": "test-secret-key"},
        )
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# 6. /healthz always exempt
# ---------------------------------------------------------------------------


async def test_healthz_exempt_without_key() -> None:
    auth_mod._API_KEY = None
    app = _make_app(api_key=None)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/healthz")
    assert resp.status_code == 200


async def test_healthz_exempt_with_key() -> None:
    auth_mod._API_KEY = "test-secret-key"
    app = _make_app(api_key="test-secret-key")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # No auth header — healthz should still work
        resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# 7. Empty string treated as unset (dev mode)
# ---------------------------------------------------------------------------


async def test_empty_string_key_is_dev_mode() -> None:
    auth_mod._API_KEY = None  # Simulates empty env var → or None
    app = _make_app(api_key=None)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/test")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 8. Bearer token takes precedence over X-API-Key
# ---------------------------------------------------------------------------


async def test_bearer_takes_precedence_over_x_api_key() -> None:
    auth_mod._API_KEY = "correct-key"
    app = _make_app(api_key="correct-key")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Bearer is correct, X-API-Key is wrong — should succeed
        resp = await client.get(
            "/v1/test",
            headers={
                "Authorization": "Bearer correct-key",
                "X-API-Key": "wrong-key",
            },
        )
    assert resp.status_code == 200

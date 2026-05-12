"""Global API-key authentication middleware for the EXPOSE API.

When the ``EXPOSE_API_KEY`` environment variable is set, every request
(except explicitly exempted paths like ``/healthz``) must present the key
via either:

- ``Authorization: Bearer <key>``
- ``X-API-Key: <key>``

When ``EXPOSE_API_KEY`` is **not** set the API runs in unauthenticated
dev mode — no key required, all requests pass through.

This is a simple shared-secret gate intended as the first layer of
defence while the tenant-scoped token system (``auth.py``) matures.
"""

from __future__ import annotations

import os

from fastapi import HTTPException, Request

# Read once at import time — no hot-reload needed for a static secret.
_API_KEY: str | None = os.environ.get("EXPOSE_API_KEY") or None

# Paths that bypass API-key authentication unconditionally.
# /healthz is used by Podman health checks and monitoring.
# /docs, /redoc, /openapi.json are development conveniences
# (only exposed when API key is unset or explicitly allowed).
_PUBLIC_PATHS: frozenset[str] = frozenset({
    "/healthz",
})

# Dev-mode-only paths — exempt when EXPOSE_API_KEY is unset, but
# still gated when a key is configured (prevent leaking schema in prod).
_DEV_ONLY_PATHS: frozenset[str] = frozenset({
    "/docs",
    "/redoc",
    "/openapi.json",
})


async def require_api_key(request: Request) -> None:
    """FastAPI dependency that enforces API-key authentication.

    Designed to be applied globally via
    ``FastAPI(dependencies=[Depends(require_api_key)])``.
    """
    path = request.url.path

    # Always allow health checks — they carry no sensitive data.
    if path in _PUBLIC_PATHS:
        return

    # Dev mode — no key configured, everything passes.
    if _API_KEY is None:
        return

    # In authenticated mode, docs endpoints are locked too.
    # (They're already allowed above when _API_KEY is None.)

    # --- Extract token from headers ---
    auth_header = request.headers.get("Authorization", "")
    api_key_header = request.headers.get("X-API-Key", "")

    token: str | None = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    elif api_key_header:
        token = api_key_header

    if token is None:
        raise HTTPException(
            status_code=401,
            detail="API key required — provide via Authorization: Bearer <key> "
            "or X-API-Key: <key> header",
        )

    if token != _API_KEY:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key",
        )

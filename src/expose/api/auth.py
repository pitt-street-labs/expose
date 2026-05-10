"""Bearer token authentication middleware for the EXPOSE API.

Provides tenant-scoped API token management and a FastAPI dependency for
protecting endpoints with ``Authorization: Bearer <token>`` headers.

Token generation uses ``uuid.uuid4().hex`` rather than ``hashlib`` or
``secrets`` to stay within the FIPS gate (ADR-010). Production deployments
should replace ``TokenStore`` with a database-backed or JWT-based validator.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi import Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TokenPayload(BaseModel):
    """Claims embedded in an API token."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    scopes: list[str] = Field(default_factory=lambda: ["read", "write"])
    issued_at: datetime
    expires_at: datetime | None = None


class APIToken(BaseModel):
    """An issued API token with its decoded payload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    token: str
    payload: TokenPayload


# ---------------------------------------------------------------------------
# Token store
# ---------------------------------------------------------------------------


class TokenStore:
    """In-memory token store.

    Production: backed by a database table or JWT validation per ADR-008.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, TokenPayload] = {}

    def create_token(
        self,
        tenant_id: UUID,
        scopes: list[str] | None = None,
        *,
        expires_at: datetime | None = None,
    ) -> APIToken:
        """Generate a new API token for a tenant.

        Uses ``uuid4().hex`` for the token value (no ``hashlib`` or
        ``secrets`` — FIPS gate).
        """
        token = uuid4().hex
        effective_scopes = scopes if scopes is not None else ["read", "write"]
        payload = TokenPayload(
            tenant_id=tenant_id,
            scopes=effective_scopes,
            issued_at=datetime.now(UTC),
            expires_at=expires_at,
        )
        self._tokens[token] = payload
        return APIToken(token=token, payload=payload)

    def validate_token(self, token: str) -> TokenPayload | None:
        """Validate a token and return its payload, or ``None`` if invalid/expired."""
        payload = self._tokens.get(token)
        if payload is None:
            return None
        if payload.expires_at is not None and payload.expires_at <= datetime.now(UTC):
            # Expired — remove and reject.
            del self._tokens[token]
            return None
        return payload

    def revoke_token(self, token: str) -> bool:
        """Revoke a token. Returns ``True`` if found and revoked."""
        return self._tokens.pop(token, None) is not None


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


class AuthDependency:
    """FastAPI dependency for bearer token authentication.

    Usage::

        auth = AuthDependency(token_store)

        @router.get("/protected")
        async def protected(payload: TokenPayload = Depends(auth)):
            ...
    """

    def __init__(
        self,
        token_store: TokenStore,
        required_scope: str = "read",
    ) -> None:
        self._store = token_store
        self._scope = required_scope

    async def __call__(
        self,
        authorization: str = Header(default=""),
    ) -> TokenPayload:
        """Extract and validate a ``Bearer`` token from the ``Authorization`` header."""
        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid Authorization header",
            )
        token = authorization.removeprefix("Bearer ")
        payload = self._store.validate_token(token)
        if payload is None:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        if self._scope not in payload.scopes:
            raise HTTPException(
                status_code=403,
                detail=f"Token lacks required scope: {self._scope}",
            )
        return payload

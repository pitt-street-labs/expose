"""Read-only bucket credential issuance for artifact retrieval (issue #11).

Downstream consumers (analysts, SIEM integrations, CTEM platforms) need
scoped, time-limited read-only access to retrieve scan artifacts from object
storage.  This module issues credentials that grant ``s3:GetObject`` and
``s3:ListBucket`` permissions within a single tenant's artifact prefix.

Phase 1 (this implementation) generates credentials locally — no actual
AWS STS or MinIO policy calls.  The :class:`ReadOnlyCredential` model and
:class:`CredentialIssuer` interface are designed so Phase 3 can swap in
real STS ``AssumeRole`` or MinIO service-account integration without
changing the consumer-facing API.

Credential IDs are derived via :func:`expose.crypto.fips_adapter.compute_sha256_hex`
(FIPS-compliant per ADR-010) from the tenant ID and issuance timestamp,
producing deterministic identifiers for the same inputs.

Credential lifecycle:

1. **Issue** — :meth:`CredentialIssuer.issue` creates a
   :class:`ReadOnlyCredential` scoped to ``{bucket}/{tenant_id}/artifacts/*``.
2. **Validate** — :meth:`CredentialIssuer.validate` checks expiry and
   revocation status.
3. **Revoke** — :meth:`CredentialIssuer.revoke` adds the credential ID to
   an in-memory revocation set (Phase 1).  Phase 3 will integrate with
   STS token revocation or MinIO policy deletion.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from expose.crypto.fips_adapter import compute_sha256_hex


class ReadOnlyCredential(BaseModel):
    """Time-limited, scope-restricted credential for artifact retrieval.

    All fields are frozen after construction — credentials are immutable
    value objects.  Revocation is tracked externally by the issuer, not
    by mutating the credential.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    credential_id: str = Field(min_length=1)
    tenant_id: UUID
    bucket: str = Field(min_length=1)
    prefix: str  # scope to tenant's artifact prefix
    access_key: str = Field(min_length=1)
    secret_key: str  # empty for token-based auth
    session_token: str | None = None
    endpoint: str | None = None
    region: str = "us-east-1"
    expires_at: datetime
    issued_at: datetime
    permissions: frozenset[str] = frozenset({"s3:GetObject", "s3:ListBucket"})


class CredentialRequest(BaseModel):
    """Request for a read-only credential.

    ``duration_hours`` is clamped to [1, 168] (1 hour to 7 days) to limit
    exposure window.  ``prefix_override`` allows narrowing the scope below
    the default tenant-level prefix.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    duration_hours: int = Field(default=24, ge=1, le=168)  # 1h to 7d
    prefix_override: str | None = None  # narrow scope further


class CredentialIssuer:
    """Issues scoped, time-limited read-only credentials for artifact storage.

    Phase 1: credentials are locally generated deterministic tokens.
    Phase 3: swap in STS AssumeRole or MinIO service-account integration.
    """

    def __init__(
        self,
        *,
        bucket: str,
        endpoint: str | None = None,
        region: str = "us-east-1",
    ) -> None:
        self._bucket = bucket
        self._endpoint = endpoint
        self._region = region
        self._revoked: set[str] = set()

    def _compute_prefix(self, request: CredentialRequest) -> str:
        """Derive the storage prefix for the credential scope.

        Default: ``tenant/{tenant_id}/artifacts``.
        If ``prefix_override`` is set, it is appended to narrow the scope.
        """
        base = f"tenant/{request.tenant_id}/artifacts"
        if request.prefix_override:
            return f"{base}/{request.prefix_override}"
        return base

    def _generate_credential_id(self, tenant_id: UUID, issued_at: datetime) -> str:
        """Derive a deterministic credential ID from tenant + timestamp.

        Uses FIPS-compliant SHA-256 (per ADR-010) so the ID is reproducible
        for the same inputs — useful for idempotent issuance and audit trails.
        """
        # Canonical input: tenant UUID + ISO-8601 timestamp in UTC.
        canonical = f"{tenant_id}:{issued_at.isoformat()}"
        return compute_sha256_hex(canonical.encode())

    def _generate_access_key(self, credential_id: str) -> str:
        """Derive an access key from the credential ID.

        Phase 1: deterministic derivation.  Phase 3: replaced by STS-issued keys.
        """
        return compute_sha256_hex(f"access:{credential_id}".encode())[:20]

    def _generate_secret_key(self, credential_id: str) -> str:
        """Derive a secret key from the credential ID.

        Phase 1: deterministic derivation.  Phase 3: replaced by STS-issued keys.
        """
        return compute_sha256_hex(f"secret:{credential_id}".encode())[:40]

    def issue(self, request: CredentialRequest) -> ReadOnlyCredential:
        """Issue a read-only credential scoped to the tenant's prefix.

        Phase 1: generates a deterministic credential from tenant_id + timestamp.
        Phase 3: integrates with AWS STS AssumeRole or MinIO policy.
        """
        now = datetime.now(tz=UTC)
        credential_id = self._generate_credential_id(request.tenant_id, now)
        prefix = self._compute_prefix(request)

        return ReadOnlyCredential(
            credential_id=credential_id,
            tenant_id=request.tenant_id,
            bucket=self._bucket,
            prefix=prefix,
            access_key=self._generate_access_key(credential_id),
            secret_key=self._generate_secret_key(credential_id),
            session_token=None,
            endpoint=self._endpoint,
            region=self._region,
            expires_at=now + timedelta(hours=request.duration_hours),
            issued_at=now,
            permissions=frozenset({"s3:GetObject", "s3:ListBucket"}),
        )

    def validate(self, credential: ReadOnlyCredential) -> bool:
        """Check if a credential is still valid (not expired and not revoked)."""
        if credential.credential_id in self._revoked:
            return False
        return credential.expires_at > datetime.now(tz=UTC)

    def revoke(self, credential_id: str) -> bool:
        """Revoke a credential by adding it to the in-memory revocation set.

        Returns ``True`` if the credential was newly revoked, ``False`` if
        it was already in the revocation set (idempotent).

        Phase 1: in-memory revocation list.
        Phase 3: STS token revocation or MinIO policy deletion.
        """
        if credential_id in self._revoked:
            return False
        self._revoked.add(credential_id)
        return True


__all__ = [
    "CredentialIssuer",
    "CredentialRequest",
    "ReadOnlyCredential",
]

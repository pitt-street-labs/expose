"""Tests for read-only bucket credential issuance (issue #11).

Coverage:

1.  Issue credential with default duration (24h).
2.  Issue credential with custom duration.
3.  Credential scoped to tenant prefix.
4.  Credential expires_at is correct.
5.  Validate returns True for fresh credential.
6.  Validate returns False for expired credential.
7.  Revoke marks credential as invalid.
8.  Duration bounds enforced (1h min, 168h max).
9.  ReadOnlyCredential model validation (frozen, min_length).
10. CredentialRequest model validation.
11. Permissions are read-only only.
12. Multiple tenants get independent credentials.
13. Credential ID is deterministic for same inputs.
14. Revoke is idempotent.
15. Prefix override narrows scope.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from pydantic import ValidationError

from expose.storage.credentials import (
    CredentialIssuer,
    CredentialRequest,
    ReadOnlyCredential,
)

# Synthetic tenant UUIDs matching the project convention.
TENANT_A = UUID("018f1f00-0000-7000-8000-00000000A001")
TENANT_B = UUID("018f1f00-0000-7000-8000-00000000B002")


@pytest.fixture
def issuer() -> CredentialIssuer:
    """Fresh credential issuer per test."""
    return CredentialIssuer(bucket="expose-artifacts", region="us-east-1")


# ---------------------------------------------------------------------------
# 1. Issue credential with default duration (24h)
# ---------------------------------------------------------------------------
def test_issue_default_duration(issuer: CredentialIssuer) -> None:
    """Default duration is 24 hours."""
    request = CredentialRequest(tenant_id=TENANT_A)
    cred = issuer.issue(request)

    assert cred.tenant_id == TENANT_A
    assert cred.bucket == "expose-artifacts"
    assert cred.region == "us-east-1"
    # expires_at should be ~24h from issued_at
    delta = cred.expires_at - cred.issued_at
    assert delta == timedelta(hours=24)


# ---------------------------------------------------------------------------
# 2. Issue credential with custom duration
# ---------------------------------------------------------------------------
def test_issue_custom_duration(issuer: CredentialIssuer) -> None:
    """Custom duration is respected."""
    request = CredentialRequest(tenant_id=TENANT_A, duration_hours=72)
    cred = issuer.issue(request)

    delta = cred.expires_at - cred.issued_at
    assert delta == timedelta(hours=72)


# ---------------------------------------------------------------------------
# 3. Credential scoped to tenant prefix
# ---------------------------------------------------------------------------
def test_credential_scoped_to_tenant_prefix(issuer: CredentialIssuer) -> None:
    """Credential prefix includes the tenant ID for isolation."""
    request = CredentialRequest(tenant_id=TENANT_A)
    cred = issuer.issue(request)

    assert cred.prefix == f"tenant/{TENANT_A}/artifacts"
    assert str(TENANT_A) in cred.prefix


# ---------------------------------------------------------------------------
# 4. Credential expires_at is correct
# ---------------------------------------------------------------------------
def test_expires_at_is_future(issuer: CredentialIssuer) -> None:
    """expires_at is in the future from the point of issuance."""
    request = CredentialRequest(tenant_id=TENANT_A, duration_hours=1)
    before = datetime.now(tz=UTC)
    cred = issuer.issue(request)
    after = datetime.now(tz=UTC)

    # expires_at should be between (before + 1h) and (after + 1h)
    assert cred.expires_at >= before + timedelta(hours=1)
    assert cred.expires_at <= after + timedelta(hours=1)
    # issued_at should be between before and after
    assert cred.issued_at >= before
    assert cred.issued_at <= after


# ---------------------------------------------------------------------------
# 5. Validate returns True for fresh credential
# ---------------------------------------------------------------------------
def test_validate_fresh_credential(issuer: CredentialIssuer) -> None:
    """A freshly issued credential passes validation."""
    request = CredentialRequest(tenant_id=TENANT_A)
    cred = issuer.issue(request)

    assert issuer.validate(cred) is True


# ---------------------------------------------------------------------------
# 6. Validate returns False for expired credential
# ---------------------------------------------------------------------------
def test_validate_expired_credential(issuer: CredentialIssuer) -> None:
    """An expired credential fails validation."""
    # Build a credential that already expired.
    now = datetime.now(tz=UTC)
    cred = ReadOnlyCredential(
        credential_id="expired-test-id",
        tenant_id=TENANT_A,
        bucket="expose-artifacts",
        prefix=f"tenant/{TENANT_A}/artifacts",
        access_key="access-key-12345678",
        secret_key="secret-key-value",  # noqa: S106
        region="us-east-1",
        expires_at=now - timedelta(hours=1),
        issued_at=now - timedelta(hours=25),
    )

    assert issuer.validate(cred) is False


# ---------------------------------------------------------------------------
# 7. Revoke marks credential as invalid
# ---------------------------------------------------------------------------
def test_revoke_marks_invalid(issuer: CredentialIssuer) -> None:
    """A revoked credential fails validation even if not expired."""
    request = CredentialRequest(tenant_id=TENANT_A)
    cred = issuer.issue(request)

    assert issuer.validate(cred) is True
    result = issuer.revoke(cred.credential_id)
    assert result is True
    assert issuer.validate(cred) is False


# ---------------------------------------------------------------------------
# 8. Duration bounds enforced (1h min, 168h max)
# ---------------------------------------------------------------------------
def test_duration_bounds_min() -> None:
    """duration_hours below 1 is rejected by pydantic validation."""
    with pytest.raises(ValidationError, match="duration_hours"):
        CredentialRequest(tenant_id=TENANT_A, duration_hours=0)


def test_duration_bounds_max() -> None:
    """duration_hours above 168 is rejected by pydantic validation."""
    with pytest.raises(ValidationError, match="duration_hours"):
        CredentialRequest(tenant_id=TENANT_A, duration_hours=169)


def test_duration_bounds_edge_valid() -> None:
    """Boundary values 1 and 168 are accepted."""
    req_min = CredentialRequest(tenant_id=TENANT_A, duration_hours=1)
    assert req_min.duration_hours == 1
    req_max = CredentialRequest(tenant_id=TENANT_A, duration_hours=168)
    assert req_max.duration_hours == 168


# ---------------------------------------------------------------------------
# 9. ReadOnlyCredential model validation (frozen, min_length, extra=forbid)
# ---------------------------------------------------------------------------
def test_credential_frozen() -> None:
    """ReadOnlyCredential instances are immutable (frozen)."""
    now = datetime.now(tz=UTC)
    cred = ReadOnlyCredential(
        credential_id="frozen-test-id",
        tenant_id=TENANT_A,
        bucket="test-bucket",
        prefix=f"tenant/{TENANT_A}/artifacts",
        access_key="access-key-12345678",
        secret_key="",
        region="us-east-1",
        expires_at=now + timedelta(hours=1),
        issued_at=now,
    )
    with pytest.raises(ValidationError, match="frozen"):
        cred.credential_id = "mutated"  # type: ignore[misc]


def test_credential_min_length_validation() -> None:
    """credential_id, bucket, and access_key reject empty strings."""
    now = datetime.now(tz=UTC)
    with pytest.raises(ValidationError, match="credential_id"):
        ReadOnlyCredential(
            credential_id="",
            tenant_id=TENANT_A,
            bucket="test-bucket",
            prefix="prefix",
            access_key="key",
            secret_key="secret",  # noqa: S106
            expires_at=now + timedelta(hours=1),
            issued_at=now,
        )
    with pytest.raises(ValidationError, match="bucket"):
        ReadOnlyCredential(
            credential_id="cred-id",
            tenant_id=TENANT_A,
            bucket="",
            prefix="prefix",
            access_key="key",
            secret_key="secret",  # noqa: S106
            expires_at=now + timedelta(hours=1),
            issued_at=now,
        )
    with pytest.raises(ValidationError, match="access_key"):
        ReadOnlyCredential(
            credential_id="cred-id",
            tenant_id=TENANT_A,
            bucket="test-bucket",
            prefix="prefix",
            access_key="",
            secret_key="secret",  # noqa: S106
            expires_at=now + timedelta(hours=1),
            issued_at=now,
        )


def test_credential_extra_forbid() -> None:
    """Extra fields are rejected on ReadOnlyCredential."""
    now = datetime.now(tz=UTC)
    with pytest.raises(ValidationError, match="extra_field"):
        ReadOnlyCredential(
            credential_id="cred-id",
            tenant_id=TENANT_A,
            bucket="test-bucket",
            prefix="prefix",
            access_key="key",
            secret_key="secret",  # noqa: S106
            expires_at=now + timedelta(hours=1),
            issued_at=now,
            extra_field="not allowed",  # type: ignore[call-arg]
        )


# ---------------------------------------------------------------------------
# 10. CredentialRequest model validation
# ---------------------------------------------------------------------------
def test_request_extra_forbid() -> None:
    """Extra fields are rejected on CredentialRequest."""
    with pytest.raises(ValidationError, match="bogus"):
        CredentialRequest(
            tenant_id=TENANT_A,
            bogus="nope",  # type: ignore[call-arg]
        )


def test_request_frozen() -> None:
    """CredentialRequest instances are immutable (frozen)."""
    req = CredentialRequest(tenant_id=TENANT_A)
    with pytest.raises(ValidationError, match="frozen"):
        req.duration_hours = 48  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 11. Permissions are read-only only
# ---------------------------------------------------------------------------
def test_permissions_default_read_only(issuer: CredentialIssuer) -> None:
    """Issued credentials have exactly the read-only permission set."""
    request = CredentialRequest(tenant_id=TENANT_A)
    cred = issuer.issue(request)

    assert cred.permissions == frozenset({"s3:GetObject", "s3:ListBucket"})
    # Write operations must not be present.
    assert "s3:PutObject" not in cred.permissions
    assert "s3:DeleteObject" not in cred.permissions


# ---------------------------------------------------------------------------
# 12. Multiple tenants get independent credentials
# ---------------------------------------------------------------------------
def test_multiple_tenants_independent(issuer: CredentialIssuer) -> None:
    """Different tenants receive credentials with distinct IDs and prefixes."""
    req_a = CredentialRequest(tenant_id=TENANT_A)
    req_b = CredentialRequest(tenant_id=TENANT_B)
    cred_a = issuer.issue(req_a)
    cred_b = issuer.issue(req_b)

    # Different credential IDs.
    assert cred_a.credential_id != cred_b.credential_id
    # Different prefixes.
    assert cred_a.prefix != cred_b.prefix
    assert str(TENANT_A) in cred_a.prefix
    assert str(TENANT_B) in cred_b.prefix
    # Different access keys.
    assert cred_a.access_key != cred_b.access_key


# ---------------------------------------------------------------------------
# 13. Credential ID is deterministic for same inputs
# ---------------------------------------------------------------------------
def test_credential_id_deterministic() -> None:
    """The same tenant_id + timestamp produces the same credential ID."""
    issuer = CredentialIssuer(bucket="expose-artifacts")
    tenant = TENANT_A
    timestamp = datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)

    cred_id_1 = issuer._generate_credential_id(tenant, timestamp)
    cred_id_2 = issuer._generate_credential_id(tenant, timestamp)

    assert cred_id_1 == cred_id_2
    # SHA-256 hex is 64 chars.
    assert len(cred_id_1) == 64


# ---------------------------------------------------------------------------
# 14. Revoke is idempotent
# ---------------------------------------------------------------------------
def test_revoke_idempotent(issuer: CredentialIssuer) -> None:
    """Revoking the same credential ID twice returns False the second time."""
    request = CredentialRequest(tenant_id=TENANT_A)
    cred = issuer.issue(request)

    assert issuer.revoke(cred.credential_id) is True
    assert issuer.revoke(cred.credential_id) is False
    # Still invalid after double revoke.
    assert issuer.validate(cred) is False


# ---------------------------------------------------------------------------
# 15. Prefix override narrows scope
# ---------------------------------------------------------------------------
def test_prefix_override_narrows_scope(issuer: CredentialIssuer) -> None:
    """prefix_override appends to the base tenant prefix."""
    request = CredentialRequest(
        tenant_id=TENANT_A,
        prefix_override="2026/05",
    )
    cred = issuer.issue(request)

    assert cred.prefix == f"tenant/{TENANT_A}/artifacts/2026/05"


# ---------------------------------------------------------------------------
# 16. Endpoint passthrough
# ---------------------------------------------------------------------------
def test_endpoint_passthrough() -> None:
    """Custom endpoint (e.g., MinIO) is propagated to credentials."""
    issuer = CredentialIssuer(
        bucket="expose-artifacts",
        endpoint="https://minio.internal:9000",
    )
    request = CredentialRequest(tenant_id=TENANT_A)
    cred = issuer.issue(request)

    assert cred.endpoint == "https://minio.internal:9000"


def test_endpoint_default_none(issuer: CredentialIssuer) -> None:
    """Default endpoint is None (AWS S3 default)."""
    request = CredentialRequest(tenant_id=TENANT_A)
    cred = issuer.issue(request)

    assert cred.endpoint is None

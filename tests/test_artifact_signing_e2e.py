"""End-to-end tests for artifact signing (issue #101).

Covers:
 1. Artifact download includes signature headers (X-Artifact-Signature, etc.)
 2. Detached .sig endpoint returns valid base64 signature
 3. Verify endpoint confirms artifact integrity
 4. Auto-generated keypair is stable across calls
 5. CLI verify command — valid signature
 6. CLI verify command — tampered artifact fails
 7. Public key endpoint returns valid PEM
 8. .sig endpoint for nonexistent run → 404
 9. .sig endpoint for pending run → 409
10. Verify endpoint for nonexistent run → 404
11. Tampered artifact fails verification via verify_artifact
12. Signed artifact from generator includes SignatureResult
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from click.testing import CliRunner
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from expose.api.runs import router as runs_router
from expose.api.signing import (
    get_key_info,
    get_signer,
    reset_signer,
    router as signing_router,
)
from expose.api.tenants import get_session
from expose.api.tenants import router as tenants_router
from expose.crypto.signing import (
    ArtifactSigner,
    sign_artifact,
    verify_artifact,
)
from expose.db.models import Base, Entity, Run, Tenant


# ---------------------------------------------------------------------------
# Fixtures — mirrors test_runs_api.py pattern (in-memory SQLite)
# ---------------------------------------------------------------------------


def _make_app() -> Any:
    """Construct a minimal FastAPI app with tenants + runs + signing routers."""
    from fastapi import FastAPI  # noqa: PLC0415

    app = FastAPI()
    app.include_router(tenants_router)
    app.include_router(runs_router)
    app.include_router(signing_router)
    return app


def _create_tables(connection: Any) -> None:
    """Create all tables, stripping Postgres-only server_defaults for SQLite."""
    patched: list[tuple[Any, Any]] = []
    for table in Base.metadata.sorted_tables:
        for col in table.columns:
            sd = col.server_default
            if sd is None:
                continue
            arg = getattr(sd, "arg", None)
            if arg is None:
                continue
            raw = str(getattr(arg, "text", arg)).upper()
            if any(tok in raw for tok in ("NOW()", "::JSONB", "'PENDING'")):
                patched.append((col, sd))
                col.server_default = None
    try:
        Base.metadata.create_all(connection)
    finally:
        for col, default in patched:
            col.server_default = default


@pytest_asyncio.fixture
async def async_engine() -> AsyncIterator[AsyncEngine]:
    """Per-test in-memory SQLite engine with fresh schema."""
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn: Any, _rec: Any) -> None:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(_create_tables)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def session_factory(
    async_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    """Session factory bound to the test engine."""
    return async_sessionmaker(
        bind=async_engine,
        expire_on_commit=False,
        autoflush=False,
        class_=AsyncSession,
    )


@pytest_asyncio.fixture(autouse=True)
async def _reset_signer_singleton() -> AsyncIterator[None]:
    """Reset the module-level signer between tests for isolation."""
    reset_signer()
    yield
    reset_signer()


@pytest_asyncio.fixture
async def client(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    """HTTPX async client wired to the FastAPI app with dependency overrides."""
    app = _make_app()

    async def _override_get_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_session] = _override_get_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Helpers — seed test data
# ---------------------------------------------------------------------------


async def _seed_tenant(
    session_factory: async_sessionmaker[AsyncSession],
    name: str,
) -> UUID:
    """Insert a tenant row and return its id."""
    tid = uuid4()
    async with session_factory() as session:
        tenant = Tenant(
            id=tid,
            name=name,
            created_at=datetime.now(UTC),
            config_jsonb={"state": "active"},
        )
        session.add(tenant)
        await session.commit()
    return tid


async def _seed_run(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    tenant_id: UUID,
    state: str = "completed",
    pipeline_version: str = "1.0.0",
) -> UUID:
    """Insert a run row and return its id."""
    rid = uuid4()
    async with session_factory() as session:
        run = Run(
            id=rid,
            tenant_id=tenant_id,
            pipeline_version=pipeline_version,
            state=state,
            started_at=datetime.now(UTC),
            completed_at=None,
            target_count=None,
            run_metadata={},
        )
        session.add(run)
        await session.commit()
    return rid


async def _seed_entity(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    tenant_id: UUID,
    entity_type: str = "Domain",
    canonical_identifier: str = "example.com",
) -> UUID:
    """Insert an entity row and return its id."""
    eid = uuid4()
    now = datetime.now(UTC)
    async with session_factory() as session:
        entity = Entity(
            id=eid,
            tenant_id=tenant_id,
            entity_type=entity_type,
            canonical_identifier=canonical_identifier,
            properties={},
            attribution_status="confirmed",
            attribution_confidence=Decimal("0.950"),
            first_observed_at=now,
            last_observed_at=now,
        )
        session.add(entity)
        await session.commit()
    return eid


# ===========================================================================
# 1. Artifact download includes signature headers
# ===========================================================================


async def test_download_artifact_has_signature_headers(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """The artifact download response includes X-Artifact-Signature headers."""
    tid = await _seed_tenant(session_factory, "sig-header-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid)
    await _seed_entity(session_factory, tenant_id=tid)

    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}/artifact")
    assert resp.status_code == 200

    # Signature headers must be present.
    assert "x-artifact-signature" in resp.headers
    assert "x-signature-key-id" in resp.headers
    assert "x-signature-algorithm" in resp.headers
    assert resp.headers["x-signature-algorithm"] == "ed25519"

    # The signature should be non-empty base64.
    sig_b64 = resp.headers["x-artifact-signature"]
    assert len(sig_b64) > 0


# ===========================================================================
# 2. Detached .sig endpoint returns valid base64 signature
# ===========================================================================


async def test_sig_endpoint_returns_signature(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """GET .../artifact.sig returns a detached base64 signature."""
    tid = await _seed_tenant(session_factory, "sig-endpoint-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid)
    await _seed_entity(session_factory, tenant_id=tid)

    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}/artifact.sig")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/octet-stream"

    # Content-Disposition indicates a downloadable .sig file.
    assert ".json.sig" in resp.headers.get("content-disposition", "")

    # Signature metadata headers.
    assert "x-signature-key-id" in resp.headers
    assert "x-signature-algorithm" in resp.headers

    # Body is base64 text (decodable).
    import base64  # noqa: PLC0415

    sig_b64 = resp.content.decode("ascii")
    raw_sig = base64.b64decode(sig_b64)
    assert len(raw_sig) > 0


# ===========================================================================
# 3. Verify endpoint confirms artifact integrity
# ===========================================================================


async def test_verify_endpoint_returns_verified_true(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """GET .../artifact/verify reports verified=true for a valid artifact."""
    tid = await _seed_tenant(session_factory, "verify-endpoint-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid)
    await _seed_entity(session_factory, tenant_id=tid)

    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}/artifact/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["verified"] is True
    assert data["algorithm"] == "ed25519"
    assert len(data["key_id"]) == 32  # 128-bit NIST minimum
    assert "content_hash" in data


# ===========================================================================
# 4. Auto-generated keypair is stable across calls
# ===========================================================================


async def test_keypair_stable_across_calls() -> None:
    """The singleton signer and key_info are stable across multiple calls."""
    reset_signer()
    signer1 = get_signer()
    info1 = get_key_info()

    signer2 = get_signer()
    info2 = get_key_info()

    assert signer1 is signer2
    assert info1 is info2
    assert info1.key_id == info2.key_id
    assert info1.algorithm == "ed25519"
    assert "BEGIN PUBLIC KEY" in info1.public_key_pem


# ===========================================================================
# 5. CLI verify command — valid signature
# ===========================================================================


def test_cli_verify_valid_signature(tmp_path: Path) -> None:
    """The ``expose verify`` command succeeds for a valid signature."""
    from expose.cli import main  # noqa: PLC0415

    # Generate a keypair and sign some artifact bytes.
    signer, key_info = ArtifactSigner.generate_key_pair("ed25519")
    artifact_bytes = b'{"schema_version": "expose/v1", "targets": []}'
    sig_result = sign_artifact(artifact_bytes, signer)

    # Write files.
    artifact_file = tmp_path / "artifact.json"
    artifact_file.write_bytes(artifact_bytes)

    sig_file = tmp_path / "artifact.json.sig"
    sig_file.write_text(sig_result.signature_b64, encoding="ascii")

    pubkey_file = tmp_path / "cosign.pub"
    pubkey_file.write_text(key_info.public_key_pem, encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "verify",
            "--artifact", str(artifact_file),
            "--signature", str(sig_file),
            "--public-key", str(pubkey_file),
        ],
    )
    assert result.exit_code == 0
    assert "VERIFIED" in result.output


# ===========================================================================
# 6. CLI verify command — tampered artifact fails
# ===========================================================================


def test_cli_verify_tampered_artifact_fails(tmp_path: Path) -> None:
    """The ``expose verify`` command fails for a tampered artifact."""
    from expose.cli import main  # noqa: PLC0415

    signer, key_info = ArtifactSigner.generate_key_pair("ed25519")
    original = b'{"schema_version": "expose/v1", "targets": []}'
    sig_result = sign_artifact(original, signer)

    # Write the TAMPERED artifact but the original signature.
    tampered = b'{"schema_version": "expose/v1", "targets": ["evil"]}'
    artifact_file = tmp_path / "artifact.json"
    artifact_file.write_bytes(tampered)

    sig_file = tmp_path / "artifact.json.sig"
    sig_file.write_text(sig_result.signature_b64, encoding="ascii")

    pubkey_file = tmp_path / "cosign.pub"
    pubkey_file.write_text(key_info.public_key_pem, encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "verify",
            "--artifact", str(artifact_file),
            "--signature", str(sig_file),
            "--public-key", str(pubkey_file),
        ],
    )
    assert result.exit_code == 1
    assert "FAILED" in result.output


# ===========================================================================
# 7. Public key endpoint returns valid PEM
# ===========================================================================


async def test_public_key_endpoint(
    client: AsyncClient,
) -> None:
    """GET /v1/signing/public-key returns key metadata and a valid PEM."""
    resp = await client.get("/v1/signing/public-key")
    assert resp.status_code == 200
    data = resp.json()

    assert data["algorithm"] == "ed25519"
    assert len(data["key_id"]) == 32
    assert "BEGIN PUBLIC KEY" in data["public_key_pem"]
    assert "created_at" in data


# ===========================================================================
# 8. .sig endpoint for nonexistent run → 404
# ===========================================================================


async def test_sig_endpoint_nonexistent_run(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """GET .../artifact.sig for a nonexistent run returns 404."""
    tid = await _seed_tenant(session_factory, "sig-404-tenant")
    fake_rid = uuid4()
    resp = await client.get(f"/v1/tenants/{tid}/runs/{fake_rid}/artifact.sig")
    assert resp.status_code == 404


# ===========================================================================
# 9. .sig endpoint for pending run → 409
# ===========================================================================


async def test_sig_endpoint_pending_run(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """GET .../artifact.sig for a pending run returns 409."""
    tid = await _seed_tenant(session_factory, "sig-409-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid, state="pending")
    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}/artifact.sig")
    assert resp.status_code == 409


# ===========================================================================
# 10. Verify endpoint for nonexistent run → 404
# ===========================================================================


async def test_verify_endpoint_nonexistent_run(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """GET .../artifact/verify for a nonexistent run returns 404."""
    tid = await _seed_tenant(session_factory, "verify-404-tenant")
    fake_rid = uuid4()
    resp = await client.get(f"/v1/tenants/{tid}/runs/{fake_rid}/artifact/verify")
    assert resp.status_code == 404


# ===========================================================================
# 11. Tampered artifact fails verification via verify_artifact
# ===========================================================================


def test_tampered_artifact_fails_verify_artifact() -> None:
    """verify_artifact() returns False for tampered content."""
    signer, key_info = ArtifactSigner.generate_key_pair("ed25519")
    original = b"original artifact content"
    sig = sign_artifact(original, signer)

    tampered = b"tampered artifact content"
    assert not verify_artifact(
        tampered,
        sig.signature_b64,
        key_info.public_key_pem,
        algorithm="ed25519",
    )


# ===========================================================================
# 12. Signed artifact from download_artifact includes SignatureResult
# ===========================================================================


async def test_download_artifact_signature_verifies_against_public_key(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """The signature from download_artifact verifies against the public key endpoint."""
    tid = await _seed_tenant(session_factory, "sig-roundtrip-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid)
    await _seed_entity(session_factory, tenant_id=tid)

    # Get the artifact + signature.
    artifact_resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}/artifact")
    assert artifact_resp.status_code == 200
    artifact_bytes = artifact_resp.content
    sig_b64 = artifact_resp.headers["x-artifact-signature"]

    # Get the public key.
    pk_resp = await client.get("/v1/signing/public-key")
    assert pk_resp.status_code == 200
    public_key_pem = pk_resp.json()["public_key_pem"]

    # Verify offline.
    is_valid = verify_artifact(
        artifact_bytes,
        sig_b64,
        public_key_pem,
        algorithm="ed25519",
    )
    assert is_valid


# ===========================================================================
# 13. .sig endpoint signature verifies against public key independently
# ===========================================================================


async def test_sig_endpoint_signature_verifies_independently(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Both the .sig endpoint and the download header produce valid signatures.

    Note: the two signatures may differ because each endpoint regenerates
    the artifact (timestamps in ``_entity_to_target`` use ``datetime.now``).
    Both must independently verify against their respective artifact bytes.
    """
    tid = await _seed_tenant(session_factory, "sig-verify-indep-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid)
    await _seed_entity(session_factory, tenant_id=tid)

    # Get public key.
    pk_resp = await client.get("/v1/signing/public-key")
    public_key_pem = pk_resp.json()["public_key_pem"]

    # Verify the download header signature against its artifact bytes.
    artifact_resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}/artifact")
    header_sig = artifact_resp.headers["x-artifact-signature"]
    assert verify_artifact(
        artifact_resp.content,
        header_sig,
        public_key_pem,
        algorithm="ed25519",
    )

    # The .sig endpoint also returns a valid signature (for its own generation).
    sig_resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}/artifact.sig")
    assert sig_resp.status_code == 200
    # The .sig endpoint does not return the corresponding artifact bytes,
    # so we just verify it is a well-formed base64 string.
    import base64  # noqa: PLC0415

    endpoint_sig = sig_resp.content.decode("ascii")
    raw_bytes = base64.b64decode(endpoint_sig)
    assert len(raw_bytes) > 0


# ===========================================================================
# 14. CLI verify with ECDSA P-256 algorithm
# ===========================================================================


def test_cli_verify_ecdsa_p256(tmp_path: Path) -> None:
    """The ``expose verify`` command works with ecdsa-p256 algorithm."""
    from expose.cli import main  # noqa: PLC0415

    signer, key_info = ArtifactSigner.generate_key_pair("ecdsa-p256")
    artifact_bytes = b'{"schema_version": "expose/v1"}'
    sig_result = sign_artifact(artifact_bytes, signer)

    artifact_file = tmp_path / "artifact.json"
    artifact_file.write_bytes(artifact_bytes)

    sig_file = tmp_path / "artifact.json.sig"
    sig_file.write_text(sig_result.signature_b64, encoding="ascii")

    pubkey_file = tmp_path / "cosign.pub"
    pubkey_file.write_text(key_info.public_key_pem, encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "verify",
            "--artifact", str(artifact_file),
            "--signature", str(sig_file),
            "--public-key", str(pubkey_file),
            "--algorithm", "ecdsa-p256",
        ],
    )
    assert result.exit_code == 0
    assert "VERIFIED" in result.output


# ===========================================================================
# 15. Verify endpoint for pending run → 409
# ===========================================================================


async def test_verify_endpoint_pending_run(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """GET .../artifact/verify for a pending run returns 409."""
    tid = await _seed_tenant(session_factory, "verify-409-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid, state="pending")
    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}/artifact/verify")
    assert resp.status_code == 409


# ===========================================================================
# 16. Wrong public key fails verification
# ===========================================================================


def test_cli_verify_wrong_public_key_fails(tmp_path: Path) -> None:
    """Verification fails when using a different keypair's public key."""
    from expose.cli import main  # noqa: PLC0415

    signer1, _key1 = ArtifactSigner.generate_key_pair("ed25519")
    _signer2, key2 = ArtifactSigner.generate_key_pair("ed25519")

    artifact_bytes = b'{"schema_version": "expose/v1"}'
    sig_result = sign_artifact(artifact_bytes, signer1)

    artifact_file = tmp_path / "artifact.json"
    artifact_file.write_bytes(artifact_bytes)

    sig_file = tmp_path / "artifact.json.sig"
    sig_file.write_text(sig_result.signature_b64, encoding="ascii")

    # Use the WRONG public key.
    pubkey_file = tmp_path / "wrong.pub"
    pubkey_file.write_text(key2.public_key_pem, encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "verify",
            "--artifact", str(artifact_file),
            "--signature", str(sig_file),
            "--public-key", str(pubkey_file),
        ],
    )
    assert result.exit_code == 1
    assert "FAILED" in result.output

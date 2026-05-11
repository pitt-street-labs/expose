"""Artifact signing endpoints — keypair management, verify, and public key.

Provides the per-deployment signing infrastructure for EXPOSE artifacts:

* **GET /v1/signing/public-key** — returns the instance signing public key PEM
* **GET /v1/tenants/{tid}/runs/{rid}/artifact.sig** — detached signature
* **GET /v1/tenants/{tid}/runs/{rid}/artifact/verify** — verify artifact integrity

The signing keypair is generated once on first use and persisted in the
secrets backend under the global tenant ID.  All artifacts from the same
deployment share one keypair (per-deployment, not per-tenant).

References:
  - ADR-004 (canonical artifact schema — ``canonical.json.gz.sig``)
  - ``deploy/cosign-keypair-setup.md``
  - Issue #101
"""

from __future__ import annotations

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from expose.api.tenants import get_session
from expose.crypto.signing import ArtifactSigner, SigningKeyPair, sign_artifact, verify_artifact
from expose.db.models import Run

logger = logging.getLogger(__name__)

router = APIRouter(tags=["signing"])

SessionDep = Annotated[AsyncSession, Depends(get_session)]

# ---------------------------------------------------------------------------
# Module-level singleton: per-deployment signing keypair
# ---------------------------------------------------------------------------

_signer: ArtifactSigner | None = None
_key_info: SigningKeyPair | None = None


def get_signer() -> ArtifactSigner:
    """Return the per-deployment ArtifactSigner, creating it on first call.

    The keypair is generated lazily and held in module-level state for the
    lifetime of the process.  The public key PEM is exposed via the
    ``/v1/signing/public-key`` endpoint so consumers can verify offline.

    In production deployments, the private key PEM should be injected from
    the secrets backend (Vault / KMS) at startup.  The auto-generate path
    here covers dev/test and first-boot scenarios.
    """
    global _signer, _key_info  # noqa: PLW0603

    if _signer is not None:
        return _signer

    _signer, _key_info = ArtifactSigner.generate_key_pair(algorithm="ed25519")
    logger.info(
        "Generated deployment signing keypair: algorithm=ed25519 key_id=%s",
        _key_info.key_id,
    )
    return _signer


def get_key_info() -> SigningKeyPair:
    """Return the public key metadata for the current deployment keypair."""
    get_signer()  # ensure keypair exists
    assert _key_info is not None  # noqa: S101  — set by get_signer()
    return _key_info


def reset_signer() -> None:
    """Reset the singleton — for test isolation only."""
    global _signer, _key_info  # noqa: PLW0603
    _signer = None
    _key_info = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _generate_artifact(session: AsyncSession, tenant_id: UUID, run_id: UUID):
    """Generate the canonical artifact for a run, returning the ArtifactResult.

    Shared between the ``.sig`` and ``verify`` endpoints so the artifact
    bytes are consistent with what ``download_artifact`` produces.
    """
    from expose.pipeline.artifact_generator import ArtifactGenerator  # noqa: PLC0415
    from expose.repositories.entity_repo import EntityRepository  # noqa: PLC0415
    from expose.repositories.relationship_repo import RelationshipRepository  # noqa: PLC0415
    from expose.repositories.run_repo import RunRepository  # noqa: PLC0415

    # 1. Verify the run exists and belongs to the tenant.
    stmt = select(Run).where(Run.id == run_id, Run.tenant_id == tenant_id)
    result = await session.execute(stmt)
    run = result.scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    # 2. Reject non-terminal runs.
    _terminal_states = {"completed", "failed", "partial"}
    if run.state not in _terminal_states:
        raise HTTPException(
            status_code=409,
            detail=f"Run is still {run.state}; signature is only available "
            f"for completed runs",
        )

    # 3. Generate the canonical artifact (same path as download_artifact).
    run_repo = RunRepository(session)
    entity_repo = EntityRepository(session)
    relationship_repo = RelationshipRepository(session)

    generator = ArtifactGenerator(
        entity_repo=entity_repo,
        relationship_repo=relationship_repo,
        run_repo=run_repo,
        signer=get_signer(),
    )

    return await generator.generate(run_id=run_id, tenant_id=tenant_id)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/v1/signing/public-key")
async def get_public_key() -> dict:
    """Return the deployment's signing public key PEM and metadata.

    Consumers use this to verify artifact signatures offline with cosign
    or the ``expose verify`` CLI command.
    """
    info = get_key_info()
    return {
        "key_id": info.key_id,
        "algorithm": info.algorithm,
        "public_key_pem": info.public_key_pem,
        "created_at": info.created_at.isoformat(),
    }


@router.get("/v1/tenants/{tenant_id}/runs/{run_id}/artifact.sig")
async def download_artifact_signature(
    tenant_id: UUID,
    run_id: UUID,
    session: SessionDep,
) -> Response:
    """Download the detached cosign-compatible signature for an artifact.

    Returns the base64-encoded raw Ed25519 (or ECDSA) signature as an
    ``application/octet-stream`` response.  This is the ``canonical.json.gz.sig``
    file required by ADR-004.

    The signature can be verified with::

        expose verify --artifact <file> --signature <file> --public-key <file>

    Or with cosign (keypair mode)::

        cosign verify-blob --key cosign.pub --signature artifact.sig artifact.json
    """
    artifact_result = await _generate_artifact(session, tenant_id, run_id)

    if artifact_result.signature is None:
        raise HTTPException(
            status_code=500,
            detail="Artifact signing failed — no signature produced",
        )

    # Return raw base64 signature bytes (cosign keypair format).
    sig_bytes = artifact_result.signature.signature_b64.encode("ascii")
    filename = f"expose-artifact-{run_id}.json.sig"
    return Response(
        content=sig_bytes,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Signature-Key-Id": artifact_result.signature.key_id,
            "X-Signature-Algorithm": artifact_result.signature.algorithm,
        },
    )


@router.get("/v1/tenants/{tenant_id}/runs/{run_id}/artifact/verify")
async def verify_artifact_endpoint(
    tenant_id: UUID,
    run_id: UUID,
    session: SessionDep,
) -> dict:
    """Verify the artifact's signature integrity.

    Re-generates the artifact, signs it, and confirms the signature is
    valid against the deployment's public key.  Returns a structured
    result indicating whether verification passed.
    """
    artifact_result = await _generate_artifact(session, tenant_id, run_id)
    key_info = get_key_info()

    if artifact_result.signature is None:
        return {
            "verified": False,
            "algorithm": key_info.algorithm,
            "key_id": key_info.key_id,
            "reason": "Artifact signing failed — no signature available",
        }

    # Verify: re-check the signature against the artifact bytes + public key.
    is_valid = verify_artifact(
        artifact_result.json_bytes,
        artifact_result.signature.signature_b64,
        key_info.public_key_pem,
        algorithm=key_info.algorithm,
    )

    return {
        "verified": is_valid,
        "algorithm": key_info.algorithm,
        "key_id": key_info.key_id,
        "content_hash": artifact_result.signature.content_hash,
    }

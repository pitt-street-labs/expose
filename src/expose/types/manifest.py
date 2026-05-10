"""Pydantic models mirroring `schemas/manifest-v1.json`.

The manifest is the smaller companion file accompanying every canonical artifact —
it contains run provenance, signing metadata, and integrity hashes for quick
inspection without parsing the full canonical artifact.

Schema sync is verified by `tests/test_schema_sync.py`. Any change here must be
mirrored in `schemas/manifest-v1.json` (or vice versa).
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

# Match the schema regex `^[0-9a-f]{40}$` — git commit SHA-1 hash.
GitSha1 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]

# Match `^sha256:[a-f0-9]{64}$` — content-addressable hash references.
Sha256Ref = Annotated[str, StringConstraints(pattern=r"^sha256:[a-f0-9]{64}$")]


class EnforcementMode(str, Enum):
    """Authorization scope enforcement mode (per ADR-008 layer 2)."""

    SOFT = "soft"
    MEDIUM = "medium"  # v1 default
    HARD = "hard"


class LLMProvider(str, Enum):
    """LLM provider used for enrichment (per ADR-005)."""

    OLLAMA = "ollama"
    ANTHROPIC_DIRECT = "anthropic_direct"
    OPENAI = "openai"
    GEMINI = "gemini"
    NONE = "none"


class SignatureFormat(str, Enum):
    """Artifact signing format (per ADR-004 §9.4)."""

    COSIGN_KEYLESS = "cosign-keyless"
    COSIGN_KEYPAIR = "cosign-keypair"
    UNSIGNED = "unsigned"


class StrictModel(BaseModel):
    """Base for all manifest sub-models — disallow extra fields per schema."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )


class ManifestRulePack(StrictModel):
    """Rule pack identification (`rule_pack` object in schema)."""

    pack_id: str
    pack_version: str
    pack_hash: Sha256Ref | None = None


class ManifestScope(StrictModel):
    """Authorization scope identification (`scope` object in schema)."""

    scope_version: str | None = None
    scope_hash: Sha256Ref | None = None
    enforcement_mode: EnforcementMode | None = None


class ManifestLLMProviderUsed(StrictModel):
    """LLM provider used during the run (`llm_provider_used` object in schema)."""

    primary_provider: LLMProvider | None = None
    primary_model: str | None = None
    tie_breaker_provider: str | None = None
    tie_breaker_model: str | None = None
    tie_breaker_invocations: int | None = Field(default=None, ge=0)


class ManifestSignature(StrictModel):
    """Signature metadata (`signature_metadata` object in schema)."""

    signature_format: SignatureFormat
    signed_by: str
    signature_filename: str = "canonical.json.gz.sig"
    transparency_log_entry: str | None = None


# Forward declarations to satisfy schema definitions from canonical-artifact-v1.
class ManifestRun(StrictModel):
    """Run identifier and timing — present here for re-use by canonical artifact."""

    run_id: UUID
    started_at: datetime
    completed_at: datetime
    pipeline_version: GitSha1


class ManifestPipeline(StrictModel):
    """Pipeline identification — present here for re-use by canonical artifact."""

    pipeline_version: GitSha1
    deployment_id: str | None = None


class ManifestArtifact(StrictModel):
    """Per-artifact integrity (the file the manifest accompanies)."""

    canonical_artifact_hash: Sha256Ref
    canonical_artifact_filename: str = "canonical.json.gz"
    target_count: int | None = Field(default=None, ge=0)


class Manifest(StrictModel):
    """Run manifest accompanying every canonical artifact.

    Mirrors `schemas/manifest-v1.json`. Verified by `tests/test_schema_sync.py`.
    """

    schema_version: Literal["expose-manifest/v1"] = "expose-manifest/v1"

    run_id: UUID
    tenant_id: UUID
    tenant_name: str | None = None
    deployment_id: str | None = None

    generated_at: datetime
    pipeline_version: GitSha1

    canonical_artifact_hash: Sha256Ref
    canonical_artifact_filename: str = "canonical.json.gz"

    target_count: int | None = Field(default=None, ge=0)

    rule_pack: ManifestRulePack | None = None
    scope: ManifestScope | None = None
    llm_provider_used: ManifestLLMProviderUsed | None = None

    collectors_enabled: list[str] | None = None
    feature_flags: dict[str, bool] | None = None

    signature_metadata: ManifestSignature

    previous_run_id: UUID | None = None
    next_scheduled_run_at: datetime | None = None

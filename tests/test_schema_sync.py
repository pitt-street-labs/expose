"""Verify the JSON Schemas in `schemas/` parse and that the example rule pack validates.

Pydantic-to-Schema sync (Sprint 5+ when more models land) will be added here as the
canonical artifact and rulepack models are written. For Sprint 1-2 the manifest model
exists; this test verifies it round-trips a minimal manifest example.
"""
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import jsonschema
import pytest

from expose.types import (
    Manifest,
    ManifestArtifact,
    ManifestSignature,
    ManifestRun,
    ManifestPipeline,
)
from expose.types.manifest import (
    EnforcementMode,
    LLMProvider,
    SignatureFormat,
)

pytestmark = pytest.mark.schema_sync


def test_canonical_artifact_schema_parses(schemas_dir: Path) -> None:
    schema_path = schemas_dir / "canonical-artifact-v1.json"
    schema = json.loads(schema_path.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["$id"].endswith("canonical-artifact-v1.json")


def test_manifest_schema_parses(schemas_dir: Path) -> None:
    schema_path = schemas_dir / "manifest-v1.json"
    schema = json.loads(schema_path.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["$id"].endswith("manifest-v1.json")


def test_rulepack_schema_parses(schemas_dir: Path) -> None:
    schema_path = schemas_dir / "rulepack-v1.json"
    schema = json.loads(schema_path.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["$id"].endswith("rulepack-v1.json")


def test_example_rulepack_validates_against_schema(
    schemas_dir: Path,
    examples_dir: Path,
) -> None:
    schema = json.loads((schemas_dir / "rulepack-v1.json").read_text())
    rulepack = json.loads((examples_dir / "rulepacks" / "example-baseline.json").read_text())
    jsonschema.validate(instance=rulepack, schema=schema)


def test_manifest_pydantic_round_trips_through_schema(schemas_dir: Path) -> None:
    """A Pydantic-built manifest must validate against the published schema and back."""
    manifest = Manifest(
        run_id=UUID("018f1f00-0000-7000-8000-000000000000"),
        tenant_id=UUID("018f1f00-0000-7000-8000-000000000001"),
        generated_at=datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
        pipeline_version="0" * 40,
        canonical_artifact_hash="sha256:" + "0" * 64,
        signature_metadata=ManifestSignature(
            signature_format=SignatureFormat.UNSIGNED,
            signed_by="lab-operator (no signing in v1 lab)",
        ),
    )
    schema = json.loads((schemas_dir / "manifest-v1.json").read_text())
    payload = manifest.model_dump(mode="json", exclude_none=True)
    jsonschema.validate(instance=payload, schema=schema)

    rebuilt = Manifest.model_validate(payload)
    assert rebuilt == manifest


def test_manifest_rejects_unknown_field() -> None:
    """The model must forbid extra fields per schema `additionalProperties: false`."""
    base = {
        "schema_version": "expose-manifest/v1",
        "run_id": "018f1f00-0000-7000-8000-000000000000",
        "tenant_id": "018f1f00-0000-7000-8000-000000000001",
        "generated_at": "2026-05-10T12:00:00Z",
        "pipeline_version": "0" * 40,
        "canonical_artifact_hash": "sha256:" + "0" * 64,
        "signature_metadata": {
            "signature_format": "unsigned",
            "signed_by": "lab-operator",
        },
        "totally_made_up_field": "boom",
    }
    with pytest.raises(ValueError, match=r"totally_made_up_field"):
        Manifest.model_validate(base)


def test_manifest_signature_format_accepts_known_values() -> None:
    for fmt in SignatureFormat:
        sig = ManifestSignature(signature_format=fmt, signed_by="ci")
        assert sig.signature_format is fmt


def test_manifest_enforcement_mode_accepts_known_values() -> None:
    for mode in EnforcementMode:
        # Just constructing exercises the enum membership.
        assert EnforcementMode(mode.value) is mode


def test_manifest_llm_provider_accepts_known_values() -> None:
    for provider in LLMProvider:
        assert LLMProvider(provider.value) is provider


def test_manifest_helper_classes_importable() -> None:
    """Forward-declared helpers re-exported via expose.types are available."""
    assert ManifestArtifact is not None
    assert ManifestRun is not None
    assert ManifestPipeline is not None

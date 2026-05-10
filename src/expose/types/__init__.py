"""Pydantic models mirroring the JSON Schemas in `schemas/`.

The schemas in `schemas/canonical-artifact-v1.json`, `schemas/manifest-v1.json`, and
`schemas/rulepack-v1.json` are the authoritative wire format. The Pydantic models here
mirror them for typed in-process use; CI verifies the two stay in sync (see
`tests/test_schema_sync.py`).

Sprint 1-2 lands the Manifest model end-to-end. Canonical artifact and rulepack models
follow as Sprint 5-7 lands the attribution engine and artifact generator.
"""
from expose.types.manifest import (
    Manifest,
    ManifestArtifact,
    ManifestSignature,
    ManifestRun,
    ManifestPipeline,
)
from expose.types.shared import EntityId, RunId, TenantId

__all__ = [
    "EntityId",
    "Manifest",
    "ManifestArtifact",
    "ManifestPipeline",
    "ManifestRun",
    "ManifestSignature",
    "RunId",
    "TenantId",
]

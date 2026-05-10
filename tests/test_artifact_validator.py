"""Tests for the artifact validation framework.

Coverage:

1.  Valid artifact passes all checks.
2.  Invalid JSON -> ERROR finding.
3.  Schema violation (missing required field) -> ERROR.
4.  Schema violation (extra field with additionalProperties:false) -> ERROR.
5.  Duplicate target identifiers -> WARNING.
6.  Orphaned delta added reference -> WARNING.
7.  Hash mismatch -> ERROR.
8.  Hash match -> no integrity findings.
9.  Run completed_at < started_at -> WARNING.
10. validate() combines all finding types.
11. ValidationResult.valid is False when any ERROR exists.
12. ValidationResult.valid is True with only WARNINGs.
13. validate_artifact_file reads from disk.
14. error_count and warning_count properties work.
15. FIPS adapter sha256: prefix stripped from expected hash.
16. Collector health vs. provenance mismatch -> WARNING.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from expose.crypto.fips_adapter import compute_sha256_hex
from expose.pipeline.artifact_validator import (
    ArtifactValidator,
    ValidationFinding,
    ValidationResult,
    ValidationSeverity,
    validate_artifact_file,
)

# === Helpers ==================================================================

NOW_ISO = "2026-05-10T12:00:00Z"
VALID_GIT_SHA = "a" * 40


def _minimal_valid_artifact(
    *,
    targets: list[dict[str, Any]] | None = None,
    delta: dict[str, Any] | None = None,
    collector_health: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a minimal artifact dict that passes schema validation.

    Caller can override specific sections to introduce test-specific mutations.
    """
    target_id = str(uuid4())
    collector_id = "test-collector"

    default_target: dict[str, Any] = {
        "target_id": target_id,
        "primary_identifier": {"type": "domain", "value": "example.com"},
        "attribution": {
            "tier": "confirmed",
            "confidence": 0.95,
            "reasoning": "Automated test attribution",
            "decision_path": [
                {
                    "rule_id": "test-rule",
                    "rule_version": "1.0.0",
                    "outcome": "matched_promote",
                    "confidence_contribution": 0.95,
                },
            ],
        },
        "exposure": {},
        "provenance": {
            "sources": [
                {
                    "collector_id": collector_id,
                    "first_observed_at": NOW_ISO,
                    "last_observed_at": NOW_ISO,
                },
            ],
            "evidence_refs": [],
        },
        "first_observed_at": NOW_ISO,
        "last_observed_at": NOW_ISO,
    }

    default_collector_health: dict[str, Any] = {
        "collectors": [
            {
                "collector_id": collector_id,
                "status": "success",
                "started_at": NOW_ISO,
                "completed_at": NOW_ISO,
            },
        ],
    }

    default_delta: dict[str, Any] = {
        "previous_run_id": None,
        "added": [],
        "removed": [],
        "changed": [],
    }

    return {
        "schema_version": "expose/v1",
        "run": {
            "run_id": str(uuid4()),
            "started_at": NOW_ISO,
            "completed_at": NOW_ISO,
            "pipeline_version": VALID_GIT_SHA,
        },
        "tenant": {
            "tenant_id": str(uuid4()),
            "tenant_name": "Test Tenant",
        },
        "targets": targets if targets is not None else [default_target],
        "delta_from_previous_run": delta if delta is not None else default_delta,
        "collector_health": (
            collector_health if collector_health is not None else default_collector_health
        ),
        "manifest_ref": "manifest.json",
    }


def _to_bytes(artifact: dict[str, Any]) -> bytes:
    """Serialize an artifact dict to JSON bytes."""
    return json.dumps(artifact, sort_keys=True).encode("utf-8")


# === Tests ====================================================================


class TestValidArtifact:
    """1. Valid artifact passes all checks."""

    def test_valid_artifact_passes(self) -> None:
        artifact = _minimal_valid_artifact()
        artifact_bytes = _to_bytes(artifact)
        content_hash = compute_sha256_hex(artifact_bytes)

        validator = ArtifactValidator()
        result = validator.validate(artifact_bytes, expected_hash=content_hash)

        assert result.valid is True
        assert result.error_count == 0
        assert result.schema_version == "expose/v1"


class TestInvalidJSON:
    """2. Invalid JSON -> ERROR finding."""

    def test_invalid_json_produces_error(self) -> None:
        validator = ArtifactValidator()
        result = validator.validate(b"{{not valid json}}")

        assert result.valid is False
        assert result.error_count >= 1
        codes = [f.code for f in result.findings]
        assert "INVALID_JSON" in codes


class TestSchemaViolationMissingField:
    """3. Schema violation (missing required field) -> ERROR."""

    def test_missing_required_field(self) -> None:
        artifact = _minimal_valid_artifact()
        del artifact["run"]
        artifact_bytes = _to_bytes(artifact)

        validator = ArtifactValidator()
        result = validator.validate(artifact_bytes)

        assert result.valid is False
        schema_errors = [f for f in result.findings if f.code == "SCHEMA_INVALID"]
        assert len(schema_errors) >= 1
        # The error message should mention 'run' as a required property
        assert any("run" in f.message for f in schema_errors)


class TestSchemaViolationExtraField:
    """4. Schema violation (extra field with additionalProperties:false) -> ERROR."""

    def test_extra_field_rejected(self) -> None:
        artifact = _minimal_valid_artifact()
        artifact["bogus_extra_field"] = "should not be here"
        artifact_bytes = _to_bytes(artifact)

        validator = ArtifactValidator()
        result = validator.validate(artifact_bytes)

        assert result.valid is False
        schema_errors = [f for f in result.findings if f.code == "SCHEMA_INVALID"]
        assert len(schema_errors) >= 1
        assert any("bogus_extra_field" in f.message for f in schema_errors)


class TestDuplicateTargetIds:
    """5. Duplicate target identifiers -> WARNING."""

    def test_duplicate_target_id_warning(self) -> None:
        shared_id = str(uuid4())
        collector_id = "test-collector"
        target_template: dict[str, Any] = {
            "target_id": shared_id,
            "primary_identifier": {"type": "domain", "value": "dup.example.com"},
            "attribution": {
                "tier": "confirmed",
                "confidence": 0.95,
                "reasoning": "test",
                "decision_path": [
                    {
                        "rule_id": "r1",
                        "rule_version": "1.0.0",
                        "outcome": "matched_promote",
                        "confidence_contribution": 0.95,
                    },
                ],
            },
            "exposure": {},
            "provenance": {
                "sources": [
                    {
                        "collector_id": collector_id,
                        "first_observed_at": NOW_ISO,
                        "last_observed_at": NOW_ISO,
                    },
                ],
                "evidence_refs": [],
            },
            "first_observed_at": NOW_ISO,
            "last_observed_at": NOW_ISO,
        }
        targets = [target_template, target_template]
        artifact = _minimal_valid_artifact(
            targets=targets,
            collector_health={
                "collectors": [
                    {
                        "collector_id": collector_id,
                        "status": "success",
                        "started_at": NOW_ISO,
                        "completed_at": NOW_ISO,
                    },
                ],
            },
        )

        validator = ArtifactValidator()
        findings = validator.validate_consistency(artifact)

        dup_findings = [f for f in findings if f.code == "DUPLICATE_TARGET_ID"]
        assert len(dup_findings) >= 1


class TestOrphanedDeltaRef:
    """6. Orphaned delta added reference -> WARNING."""

    def test_orphaned_delta_ref_warning(self) -> None:
        orphan_id = str(uuid4())
        delta: dict[str, Any] = {
            "previous_run_id": None,
            "added": [
                {
                    "target_id": orphan_id,
                    "primary_identifier": {"type": "domain", "value": "ghost.example.com"},
                    "discovery_path": ["dns-resolve"],
                },
            ],
            "removed": [],
            "changed": [],
        }
        artifact = _minimal_valid_artifact(delta=delta)

        validator = ArtifactValidator()
        findings = validator.validate_consistency(artifact)

        orphan_findings = [f for f in findings if f.code == "ORPHANED_DELTA_REF"]
        assert len(orphan_findings) >= 1
        assert orphan_id in orphan_findings[0].message


class TestHashMismatch:
    """7. Hash mismatch -> ERROR."""

    def test_hash_mismatch_error(self) -> None:
        artifact = _minimal_valid_artifact()
        artifact_bytes = _to_bytes(artifact)
        wrong_hash = "0" * 64

        validator = ArtifactValidator()
        findings = validator.validate_integrity(artifact_bytes, wrong_hash)

        assert len(findings) == 1
        assert findings[0].severity == ValidationSeverity.ERROR
        assert findings[0].code == "HASH_MISMATCH"


class TestHashMatch:
    """8. Hash match -> no integrity findings."""

    def test_hash_match_no_findings(self) -> None:
        artifact = _minimal_valid_artifact()
        artifact_bytes = _to_bytes(artifact)
        correct_hash = compute_sha256_hex(artifact_bytes)

        validator = ArtifactValidator()
        findings = validator.validate_integrity(artifact_bytes, correct_hash)

        assert len(findings) == 0


class TestRunTimeOrder:
    """9. Run completed_at < started_at -> WARNING."""

    def test_run_time_order_warning(self) -> None:
        artifact = _minimal_valid_artifact()
        artifact["run"]["started_at"] = "2026-05-10T14:00:00Z"
        artifact["run"]["completed_at"] = "2026-05-10T12:00:00Z"

        validator = ArtifactValidator()
        findings = validator.validate_consistency(artifact)

        time_findings = [f for f in findings if f.code == "RUN_TIME_ORDER"]
        assert len(time_findings) == 1
        assert time_findings[0].severity == ValidationSeverity.WARNING


class TestValidateCombinesAllFindings:
    """10. validate() combines all finding types."""

    def test_validate_combines_findings(self) -> None:
        artifact = _minimal_valid_artifact()
        # Add an extra field to trigger a schema error
        artifact["bogus_field"] = True
        artifact_bytes = _to_bytes(artifact)
        wrong_hash = "f" * 64

        validator = ArtifactValidator()
        result = validator.validate(artifact_bytes, expected_hash=wrong_hash)

        assert result.valid is False
        codes = {f.code for f in result.findings}
        # Should have both schema errors and hash mismatch
        assert "SCHEMA_INVALID" in codes
        assert "HASH_MISMATCH" in codes


class TestValidFalseWithErrors:
    """11. ValidationResult.valid is False when any ERROR exists."""

    def test_valid_false_with_errors(self) -> None:
        result = ValidationResult(
            valid=False,
            findings=[
                ValidationFinding(
                    severity=ValidationSeverity.ERROR,
                    code="TEST_ERROR",
                    message="test error",
                ),
                ValidationFinding(
                    severity=ValidationSeverity.WARNING,
                    code="TEST_WARNING",
                    message="test warning",
                ),
            ],
            schema_version="expose/v1",
            validated_at=datetime.now(UTC),
        )
        assert result.valid is False
        assert result.error_count == 1


class TestValidTrueWithWarningsOnly:
    """12. ValidationResult.valid is True with only WARNINGs."""

    def test_valid_true_warnings_only(self) -> None:
        artifact = _minimal_valid_artifact()
        # Produce a duplicate target id (WARNING) but no schema errors
        target = artifact["targets"][0]
        artifact["targets"] = [target, target]
        artifact_bytes = _to_bytes(artifact)

        validator = ArtifactValidator()
        result = validator.validate(artifact_bytes)

        # Should have warnings but still be valid (no schema errors because
        # the schema does not enforce uniqueItems on targets)
        assert result.valid is True
        assert result.warning_count >= 1
        assert result.error_count == 0


class TestValidateArtifactFile:
    """13. validate_artifact_file reads from disk."""

    def test_validate_artifact_file_from_disk(self, tmp_path: Path) -> None:
        artifact = _minimal_valid_artifact()
        artifact_bytes = _to_bytes(artifact)
        content_hash = compute_sha256_hex(artifact_bytes)

        artifact_path = tmp_path / "canonical.json"
        artifact_path.write_bytes(artifact_bytes)

        result = validate_artifact_file(artifact_path, expected_hash=content_hash)

        assert result.valid is True
        assert result.error_count == 0

    def test_validate_artifact_file_not_found(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.json"

        with pytest.raises(FileNotFoundError, match="Artifact file not found"):
            validate_artifact_file(missing)


class TestErrorAndWarningCounts:
    """14. error_count and warning_count properties work."""

    def test_error_and_warning_counts(self) -> None:
        findings = [
            ValidationFinding(
                severity=ValidationSeverity.ERROR,
                code="E1",
                message="error one",
            ),
            ValidationFinding(
                severity=ValidationSeverity.ERROR,
                code="E2",
                message="error two",
            ),
            ValidationFinding(
                severity=ValidationSeverity.WARNING,
                code="W1",
                message="warning one",
            ),
            ValidationFinding(
                severity=ValidationSeverity.INFO,
                code="I1",
                message="info one",
            ),
        ]
        result = ValidationResult(
            valid=False,
            findings=findings,
            schema_version="expose/v1",
            validated_at=datetime.now(UTC),
        )
        assert result.error_count == 2
        assert result.warning_count == 1


class TestHashPrefixStripping:
    """15. FIPS adapter sha256: prefix stripped from expected hash."""

    def test_sha256_prefix_stripped(self) -> None:
        artifact = _minimal_valid_artifact()
        artifact_bytes = _to_bytes(artifact)
        bare_hash = compute_sha256_hex(artifact_bytes)
        prefixed_hash = f"sha256:{bare_hash}"

        validator = ArtifactValidator()
        findings = validator.validate_integrity(artifact_bytes, prefixed_hash)

        assert len(findings) == 0


class TestCollectorHealthProvenance:
    """16. Collector health vs. provenance mismatch -> WARNING."""

    def test_health_collector_without_provenance(self) -> None:
        """Health entry exists but no target's provenance uses that collector."""
        collector_id = "ghost-collector"
        real_collector_id = "real-collector"
        artifact = _minimal_valid_artifact(
            collector_health={
                "collectors": [
                    {
                        "collector_id": collector_id,
                        "status": "success",
                        "started_at": NOW_ISO,
                        "completed_at": NOW_ISO,
                    },
                    {
                        "collector_id": real_collector_id,
                        "status": "success",
                        "started_at": NOW_ISO,
                        "completed_at": NOW_ISO,
                    },
                ],
            },
        )
        # Update target provenance to only reference real_collector_id
        artifact["targets"][0]["provenance"]["sources"][0]["collector_id"] = real_collector_id

        validator = ArtifactValidator()
        findings = validator.validate_consistency(artifact)

        health_findings = [f for f in findings if f.code == "COLLECTOR_HEALTH_NO_PROVENANCE"]
        assert len(health_findings) >= 1
        assert collector_id in health_findings[0].message

    def test_provenance_collector_without_health(self) -> None:
        """Target provenance references a collector that is not in health."""
        artifact = _minimal_valid_artifact(
            collector_health={"collectors": []},
        )

        validator = ArtifactValidator()
        findings = validator.validate_consistency(artifact)

        prov_findings = [f for f in findings if f.code == "PROVENANCE_NO_COLLECTOR_HEALTH"]
        assert len(prov_findings) >= 1

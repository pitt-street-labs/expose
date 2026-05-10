"""Artifact validation framework for canonical artifacts.

Validates generated canonical artifacts against the JSON Schema, checks
internal consistency rules not expressible in schema alone, and verifies
content integrity via the FIPS adapter.

This module is the single validation entry point for pipeline Stage 6
(artifact signing and publication) — no artifact passes to consumers
without a green :meth:`ArtifactValidator.validate` result.

Content hashing uses exclusively :func:`expose.crypto.fips_adapter.compute_sha256_hex`
per ADR-010 FIPS mandate.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import jsonschema  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict

from expose.crypto.fips_adapter import compute_sha256_hex

logger = logging.getLogger(__name__)

# Path to the canonical artifact JSON Schema, relative to project root.
# The schema lives alongside the source in the published sdist/wheel
# (see pyproject.toml [tool.hatch.build.targets.sdist] include list).
_SCHEMA_DIR = Path(__file__).resolve().parents[3] / "schemas"
_CANONICAL_SCHEMA_FILE = _SCHEMA_DIR / "canonical-artifact-v1.json"


class ValidationSeverity(StrEnum):
    """Severity level for a validation finding."""

    ERROR = "error"  # artifact is invalid, must not be published
    WARNING = "warning"  # artifact is valid but has quality issues
    INFO = "info"  # informational findings


class ValidationFinding(BaseModel):
    """A single finding from artifact validation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    severity: ValidationSeverity
    code: str  # machine-readable code, e.g. "SCHEMA_INVALID", "HASH_MISMATCH"
    message: str
    path: str | None = None  # JSON path to the issue, e.g. "targets[0].identifiers"


class ValidationResult(BaseModel):
    """Aggregated result of all validation checks on a single artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool  # True only if zero ERROR findings
    findings: list[ValidationFinding]
    schema_version: str
    validated_at: datetime

    @property
    def error_count(self) -> int:
        """Number of ERROR-severity findings."""
        return sum(1 for f in self.findings if f.severity == ValidationSeverity.ERROR)

    @property
    def warning_count(self) -> int:
        """Number of WARNING-severity findings."""
        return sum(1 for f in self.findings if f.severity == ValidationSeverity.WARNING)


class ArtifactValidator:
    """Validates canonical artifacts for schema compliance, consistency, and integrity."""

    def __init__(self) -> None:
        self._schema = self._load_schema()

    @staticmethod
    def _load_schema() -> dict[str, Any]:
        """Load canonical-artifact-v1.json from the schemas/ directory."""
        if not _CANONICAL_SCHEMA_FILE.is_file():
            msg = f"Schema file not found: {_CANONICAL_SCHEMA_FILE}"
            raise FileNotFoundError(msg)
        raw = _CANONICAL_SCHEMA_FILE.read_text(encoding="utf-8")
        schema: dict[str, Any] = json.loads(raw)
        return schema

    def validate_schema(self, artifact_json: dict[str, Any]) -> list[ValidationFinding]:
        """Validate the artifact dict against the JSON Schema.

        Returns a list of findings; each ``jsonschema.ValidationError``
        becomes an ERROR finding with the JSON path to the offending field.
        """
        findings: list[ValidationFinding] = []
        validator = jsonschema.Draft202012Validator(self._schema)

        for error in validator.iter_errors(artifact_json):
            json_path = ".".join(str(p) for p in error.absolute_path) or "(root)"
            findings.append(
                ValidationFinding(
                    severity=ValidationSeverity.ERROR,
                    code="SCHEMA_INVALID",
                    message=error.message,
                    path=json_path,
                )
            )

        return findings

    def validate_consistency(self, artifact_json: dict[str, Any]) -> list[ValidationFinding]:
        """Check internal consistency rules not expressible in JSON Schema.

        Rules checked:
          - All delta added ``target_id`` values reference existing target
            IDs in the ``targets`` array.
          - No duplicate ``target_id`` values across targets.
          - Collector health entries have IDs that match collectors
            referenced in target provenance sources.
          - Run timing: warn if ``completed_at < started_at``.
        """
        findings: list[ValidationFinding] = []

        targets: list[dict[str, Any]] = artifact_json.get("targets", [])
        target_ids: list[str] = [t.get("target_id", "") for t in targets]
        target_id_set = set(target_ids)

        findings.extend(self._check_duplicate_targets(target_ids))
        findings.extend(self._check_delta_refs(artifact_json, target_id_set))
        findings.extend(self._check_collector_provenance(artifact_json, targets))
        findings.extend(self._check_run_timing(artifact_json))

        return findings

    @staticmethod
    def _check_duplicate_targets(
        target_ids: list[str],
    ) -> list[ValidationFinding]:
        """Detect duplicate target_id values."""
        findings: list[ValidationFinding] = []
        seen: set[str] = set()
        for idx, tid in enumerate(target_ids):
            if tid in seen:
                findings.append(
                    ValidationFinding(
                        severity=ValidationSeverity.WARNING,
                        code="DUPLICATE_TARGET_ID",
                        message=f"Duplicate target_id: {tid}",
                        path=f"targets[{idx}].target_id",
                    )
                )
            seen.add(tid)
        return findings

    @staticmethod
    def _check_delta_refs(
        artifact_json: dict[str, Any],
        target_id_set: set[str],
    ) -> list[ValidationFinding]:
        """Detect delta.added entries that reference targets not in the artifact."""
        findings: list[ValidationFinding] = []
        delta: dict[str, Any] = artifact_json.get("delta_from_previous_run", {})
        entries: list[dict[str, Any]] = delta.get("added", [])
        for idx, entry in enumerate(entries):
            ref_id = entry.get("target_id", "")
            if ref_id not in target_id_set:
                findings.append(
                    ValidationFinding(
                        severity=ValidationSeverity.WARNING,
                        code="ORPHANED_DELTA_REF",
                        message=(
                            f"Delta added[{idx}] references target_id {ref_id} not found in targets"
                        ),
                        path=f"delta_from_previous_run.added[{idx}].target_id",
                    )
                )
        return findings

    @staticmethod
    def _check_collector_provenance(
        artifact_json: dict[str, Any],
        targets: list[dict[str, Any]],
    ) -> list[ValidationFinding]:
        """Cross-check collector health entries against provenance sources."""
        findings: list[ValidationFinding] = []
        health: dict[str, Any] = artifact_json.get("collector_health", {})
        health_collector_ids: set[str] = {
            c.get("collector_id", "") for c in health.get("collectors", []) if c.get("collector_id")
        }

        provenance_collector_ids: set[str] = set()
        for target in targets:
            prov: dict[str, Any] = target.get("provenance", {})
            for source in prov.get("sources", []):
                cid = source.get("collector_id", "")
                if cid:
                    provenance_collector_ids.add(cid)

        for cid in sorted(health_collector_ids - provenance_collector_ids):
            findings.append(
                ValidationFinding(
                    severity=ValidationSeverity.WARNING,
                    code="COLLECTOR_HEALTH_NO_PROVENANCE",
                    message=(
                        f"Collector health entry '{cid}' has no matching "
                        f"provenance source in any target"
                    ),
                    path="collector_health.collectors",
                )
            )

        for cid in sorted(provenance_collector_ids - health_collector_ids):
            findings.append(
                ValidationFinding(
                    severity=ValidationSeverity.WARNING,
                    code="PROVENANCE_NO_COLLECTOR_HEALTH",
                    message=(f"Provenance source '{cid}' has no matching collector health entry"),
                    path="collector_health.collectors",
                )
            )

        return findings

    @staticmethod
    def _check_run_timing(
        artifact_json: dict[str, Any],
    ) -> list[ValidationFinding]:
        """Warn if completed_at precedes started_at."""
        findings: list[ValidationFinding] = []
        run: dict[str, Any] = artifact_json.get("run", {})
        started = run.get("started_at", "")
        completed = run.get("completed_at", "")
        if started and completed and completed < started:
            findings.append(
                ValidationFinding(
                    severity=ValidationSeverity.WARNING,
                    code="RUN_TIME_ORDER",
                    message="run.completed_at is earlier than run.started_at",
                    path="run.completed_at",
                )
            )
        return findings

    def validate_integrity(
        self, artifact_bytes: bytes, expected_hash: str
    ) -> list[ValidationFinding]:
        """Verify content hash matches artifact bytes.

        Uses the FIPS adapter SHA-256 (per ADR-010) to compute the actual
        hash and compare against ``expected_hash``. The expected hash may
        optionally carry the ``sha256:`` prefix (manifest format); it is
        stripped before comparison.
        """
        findings: list[ValidationFinding] = []

        actual_hash = compute_sha256_hex(artifact_bytes)

        # Strip optional sha256: prefix from expected_hash.
        normalized_expected = expected_hash
        if normalized_expected.startswith("sha256:"):
            normalized_expected = normalized_expected[len("sha256:") :]

        if actual_hash != normalized_expected:
            findings.append(
                ValidationFinding(
                    severity=ValidationSeverity.ERROR,
                    code="HASH_MISMATCH",
                    message=(
                        f"Content hash mismatch: expected {normalized_expected}, got {actual_hash}"
                    ),
                )
            )

        return findings

    def validate(
        self,
        artifact_bytes: bytes,
        expected_hash: str | None = None,
    ) -> ValidationResult:
        """Run all validation checks and return a combined result.

        Steps:
          1. Parse JSON from bytes.
          2. Schema validation.
          3. Consistency checks.
          4. Integrity check (if ``expected_hash`` is provided).
          5. Combine all findings and determine overall validity.
        """
        findings: list[ValidationFinding] = []
        schema_version = "unknown"

        # 1. Parse JSON
        try:
            artifact_json: dict[str, Any] = json.loads(artifact_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            findings.append(
                ValidationFinding(
                    severity=ValidationSeverity.ERROR,
                    code="INVALID_JSON",
                    message=f"Failed to parse artifact as JSON: {exc}",
                )
            )
            return ValidationResult(
                valid=False,
                findings=findings,
                schema_version=schema_version,
                validated_at=datetime.now(UTC),
            )

        schema_version = str(artifact_json.get("schema_version", "unknown"))

        # 2. Schema validation
        findings.extend(self.validate_schema(artifact_json))

        # 3. Consistency checks
        findings.extend(self.validate_consistency(artifact_json))

        # 4. Integrity check
        if expected_hash is not None:
            findings.extend(self.validate_integrity(artifact_bytes, expected_hash))

        # 5. Combine
        has_errors = any(f.severity == ValidationSeverity.ERROR for f in findings)

        return ValidationResult(
            valid=not has_errors,
            findings=findings,
            schema_version=schema_version,
            validated_at=datetime.now(UTC),
        )


def validate_artifact_file(
    path: Path,
    expected_hash: str | None = None,
) -> ValidationResult:
    """Validate an artifact JSON file from disk.

    Convenience function that reads the file, instantiates a validator,
    and runs the full validation pipeline.

    Args:
        path: Path to the canonical artifact JSON file.
        expected_hash: Optional expected SHA-256 hash for integrity check.

    Returns:
        A :class:`ValidationResult` with all findings.

    Raises:
        FileNotFoundError: If the artifact file does not exist.
    """
    if not path.is_file():
        msg = f"Artifact file not found: {path}"
        raise FileNotFoundError(msg)

    artifact_bytes = path.read_bytes()

    validator = ArtifactValidator()
    return validator.validate(artifact_bytes, expected_hash=expected_hash)


__all__ = [
    "ArtifactValidator",
    "ValidationFinding",
    "ValidationResult",
    "ValidationSeverity",
    "validate_artifact_file",
]

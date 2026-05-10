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
    Attribution,
    AttributionTier,
    CanonicalArtifact,
    CanonicalRun,
    CanonicalTenant,
    CollectorHealth,
    Delta,
    DeltaAdded,
    Exposure,
    Manifest,
    ManifestArtifact,
    ManifestPipeline,
    ManifestRun,
    ManifestSignature,
    PrimaryIdentifier,
    Provenance,
    Target,
)
from expose.types.canonical import (
    AttributionRuleApplication,
    AttributionRuleOutcome,
    CollectorHealthEntry,
    CollectorStatus,
    IdentifierType,
    ProvenanceSource,
)
from expose.types.manifest import (
    EnforcementMode,
    LLMProvider,
    SignatureFormat,
)
from expose.types.rulepack import (
    Action,
    AttributionRule,
    LeadScoreFormula,
    LeadScoreWeights,
    Outcome,
    Predicate,
    PredicateCondition,
    RuleCategory,
    RulePack,
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


def _build_minimal_canonical_artifact() -> CanonicalArtifact:
    """Construct the smallest valid CanonicalArtifact — used by multiple tests."""
    started = datetime(2026, 5, 10, 2, 0, 0, tzinfo=UTC)
    completed = datetime(2026, 5, 10, 2, 5, 0, tzinfo=UTC)
    target_id = UUID("018f1f00-0000-7000-8000-000000001001")
    return CanonicalArtifact(
        run=CanonicalRun(
            run_id=UUID("018f1f00-0000-7000-8000-000000000000"),
            started_at=started,
            completed_at=completed,
            pipeline_version="0" * 40,
        ),
        tenant=CanonicalTenant(
            tenant_id=UUID("00000000-0000-0000-0000-000000000000"),
            tenant_name="default",
        ),
        targets=[
            Target(
                target_id=target_id,
                primary_identifier=PrimaryIdentifier(
                    type=IdentifierType.DOMAIN, value="acme.example"
                ),
                attribution=Attribution(
                    tier=AttributionTier.CONFIRMED,
                    confidence=0.99,
                    reasoning="Cloud-account-authoritative match",
                    decision_path=[
                        AttributionRuleApplication(
                            rule_id="cloud-account-authoritative",
                            rule_version="1.0",
                            outcome=AttributionRuleOutcome.MATCHED_PROMOTE,
                            confidence_contribution=0.5,
                        )
                    ],
                ),
                exposure=Exposure(),
                provenance=Provenance(
                    sources=[
                        ProvenanceSource(
                            collector_id="cloud-aws-ranges",
                            first_observed_at=started,
                            last_observed_at=started,
                        )
                    ],
                    evidence_refs=["sha256:" + "a" * 64],
                ),
                first_observed_at=started,
                last_observed_at=started,
            )
        ],
        delta_from_previous_run=Delta(
            previous_run_id=None,
            added=[
                DeltaAdded(
                    target_id=target_id,
                    primary_identifier=PrimaryIdentifier(
                        type=IdentifierType.DOMAIN, value="acme.example"
                    ),
                    discovery_path=[
                        "cloud-aws-ranges",
                        "cloud-account-authoritative",
                    ],
                )
            ],
            removed=[],
            changed=[],
        ),
        collector_health=CollectorHealth(
            collectors=[
                CollectorHealthEntry(
                    collector_id="cloud-aws-ranges",
                    status=CollectorStatus.SUCCESS,
                    started_at=started,
                    completed_at=datetime(
                        2026, 5, 10, 2, 0, 30, tzinfo=UTC
                    ),
                )
            ]
        ),
        manifest_ref="manifest.json",
    )


def test_canonical_artifact_pydantic_validates_against_schema(
    schemas_dir: Path,
) -> None:
    """A Pydantic-built canonical artifact must validate against the schema."""
    art = _build_minimal_canonical_artifact()
    schema = json.loads((schemas_dir / "canonical-artifact-v1.json").read_text())
    payload = art.to_dict_for_artifact()
    jsonschema.validate(instance=payload, schema=schema)


def test_canonical_artifact_round_trips(schemas_dir: Path) -> None:
    """model_validate(to_dict_for_artifact()) == original."""
    art = _build_minimal_canonical_artifact()
    payload = art.to_dict_for_artifact()
    rebuilt = CanonicalArtifact.model_validate(payload)
    assert rebuilt == art


def test_canonical_artifact_rejects_unknown_field() -> None:
    """The top-level model must forbid extra fields per schema."""
    art = _build_minimal_canonical_artifact()
    payload = art.to_dict_for_artifact()
    payload["totally_made_up"] = "boom"
    with pytest.raises(ValueError, match=r"totally_made_up"):
        CanonicalArtifact.model_validate(payload)


def test_canonical_artifact_delta_previous_run_id_serialized_when_null() -> None:
    """Required-nullable field must always be present in serialized payload."""
    art = _build_minimal_canonical_artifact()
    payload = art.to_dict_for_artifact()
    assert "previous_run_id" in payload["delta_from_previous_run"]
    assert payload["delta_from_previous_run"]["previous_run_id"] is None


def test_canonical_artifact_optional_fields_omitted_when_none() -> None:
    """Optional non-nullable fields must be omitted from the payload (not null)."""
    art = _build_minimal_canonical_artifact()
    payload = art.to_dict_for_artifact()
    assert "tenant_quota_warnings" not in payload
    assert "outside_authorized_scope_summary" not in payload


# === RulePack tests =========================================================
def _build_minimal_rulepack() -> RulePack:
    """Construct the smallest valid RulePack — used by multiple tests."""
    return RulePack(
        pack_id="example-baseline",
        pack_version="0.1.0",
        description="Test pack",
        attribution_rules=[
            AttributionRule(
                rule_id="cloud-account-authoritative",
                rule_version="1.0.0",
                description="Cloud account authoritative match",
                category=RuleCategory.CLOUD_AUTHORITATIVE,
                when=PredicateCondition(
                    predicate=Predicate.TARGET_IP_IN_AUTHORIZED_CLOUD_ACCOUNT_RANGE
                ),
                then=Action(outcome=Outcome.PROMOTE, confidence_delta=0.5),
            ),
        ],
        lead_score_formula=LeadScoreFormula(
            formula_version="1.0.0",
            weights=LeadScoreWeights(),
            modifiers=[],
        ),
    )


def test_rulepack_pydantic_validates_against_schema(schemas_dir: Path) -> None:
    pack = _build_minimal_rulepack()
    schema = json.loads((schemas_dir / "rulepack-v1.json").read_text())
    payload = pack.model_dump(mode="json", exclude_none=True, by_alias=True)
    jsonschema.validate(instance=payload, schema=schema)


def test_rulepack_round_trips() -> None:
    pack = _build_minimal_rulepack()
    payload = pack.model_dump(mode="json", exclude_none=True, by_alias=True)
    rebuilt = RulePack.model_validate(payload)
    assert rebuilt == pack


def test_rulepack_action_promote_requires_confidence_delta() -> None:
    """An action with outcome=promote MUST set confidence_delta."""
    from pydantic import ValidationError  # noqa: PLC0415  (test-local import is fine)

    with pytest.raises(ValidationError, match=r"confidence_delta"):
        Action(outcome=Outcome.PROMOTE)


def test_rulepack_action_demote_requires_confidence_delta() -> None:
    """An action with outcome=demote MUST set confidence_delta."""
    from pydantic import ValidationError  # noqa: PLC0415  (test-local import is fine)

    with pytest.raises(ValidationError, match=r"confidence_delta"):
        Action(outcome=Outcome.DEMOTE)


def test_rulepack_action_neutral_does_not_require_delta() -> None:
    """Neutral and reject outcomes don't need a confidence_delta."""
    Action(outcome=Outcome.NEUTRAL)
    Action(outcome=Outcome.REJECT)


def test_rulepack_predicate_vocabulary_is_closed() -> None:
    """A rule referencing a predicate not in the enum is rejected."""
    from pydantic import ValidationError  # noqa: PLC0415  (test-local import is fine)

    with pytest.raises(ValidationError):
        PredicateCondition.model_validate({"predicate": "made_up_predicate"})


def test_rulepack_id_pattern_enforced() -> None:
    """pack_id and rule_id must match the lowercase-slug pattern."""
    from pydantic import ValidationError  # noqa: PLC0415  (test-local import is fine)

    with pytest.raises(ValidationError):
        RulePack(
            pack_id="UPPERCASE_BAD",  # uppercase + underscore — not allowed
            pack_version="0.1.0",
            attribution_rules=[],
            lead_score_formula=LeadScoreFormula(
                formula_version="1.0.0",
                weights=LeadScoreWeights(),
                modifiers=[],
            ),
        )

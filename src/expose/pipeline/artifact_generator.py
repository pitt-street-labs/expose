"""Stage 5 — Canonical artifact generator.

Assembles a :class:`~expose.types.canonical.CanonicalArtifact` from the
observation graph stored in the database, then serializes it to JSON and
computes a FIPS-validated content hash.

The generator reads entities, relationships, and run metadata via the
async repository layer (ADR-002 / ADR-007) and maps them into the
canonical schema types defined in :mod:`expose.types.canonical`.  The
resulting artifact is the sole deliverable of an EXPOSE pipeline run
(per ADR-004 / SPEC §2.2 Stage 6).

Content hashing is done exclusively through the FIPS adapter
(:func:`expose.crypto.fips_adapter.compute_sha256_hex`) per ADR-010.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from expose.crypto.fips_adapter import compute_sha256_hex
from expose.crypto.signing import ArtifactSigner, SignatureResult, sign_artifact
from expose.db.models import Entity as EntityRow
from expose.db.models import Relationship as RelationshipRow
from expose.db.models import Run as RunRow
from expose.repositories.entity_repo import EntityRepository
from expose.repositories.relationship_repo import RelationshipRepository
from expose.repositories.run_repo import RunRepository
from expose.storage.base import StorageBackend
from expose.types.canonical import (
    Attribution,
    AttributionRuleApplication,
    AttributionRuleOutcome,
    AttributionTier,
    CanonicalArtifact,
    CollectorHealth,
    CollectorHealthEntry,
    CollectorStatus,
    Delta,
    Exposure,
    IdentifierType,
    LeadScore,
    LeadScoreCategory,
    LeadScoreInputs,
    PrimaryIdentifier,
    Provenance,
    ProvenanceSource,
    Run,
    Target,
    Tenant,
)
from expose.types.shared import RunId, TenantId

logger = logging.getLogger(__name__)

# Default pipeline version placeholder when the run row has a non-40-char
# value (e.g., a semantic version string used in tests).  The canonical
# schema requires a 40-char lowercase hex git sha-1.
_GIT_SHA1_LENGTH = 40
_DEFAULT_GIT_SHA1 = "0" * _GIT_SHA1_LENGTH

# v1 lead-score formula identifier.
_LEAD_SCORE_FORMULA_VERSION = "expose/lead-score/v1"

# Attribution confidence thresholds for tier assignment.
_TIER_CONFIRMED_THRESHOLD = 0.9
_TIER_HIGH_THRESHOLD = 0.7
_TIER_MEDIUM_THRESHOLD = 0.4

# Lead-score category thresholds (0-100 scale).
_SCORE_CRITICAL_THRESHOLD = 90.0
_SCORE_HIGH_THRESHOLD = 70.0
_SCORE_MEDIUM_THRESHOLD = 40.0
_SCORE_LOW_THRESHOLD = 20.0


class ArtifactResult(BaseModel):
    """Outcome of :meth:`ArtifactGenerator.generate`.

    Bundles the Pydantic artifact model, its JSON serialization, and the
    FIPS-validated SHA-256 content hash together with summary counts.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact: CanonicalArtifact
    json_bytes: bytes
    content_hash: str  # SHA-256 hex via FIPS adapter
    entity_count: int
    relationship_count: int
    storage_uri: str | None = None
    signature: SignatureResult | None = None


class ArtifactGenerator:
    """Assembles a CanonicalArtifact from the observation graph.

    Reads entities + relationships from repos, maps to the canonical
    schema types (Target, Identifier, Provenance, Attribution, etc.),
    and produces a serializable CanonicalArtifact.
    """

    def __init__(
        self,
        entity_repo: EntityRepository,
        relationship_repo: RelationshipRepository,
        run_repo: RunRepository,
        storage: StorageBackend | None = None,
        signer: ArtifactSigner | None = None,
    ) -> None:
        self._entity_repo = entity_repo
        self._relationship_repo = relationship_repo
        self._run_repo = run_repo
        self._storage = storage
        self._signer = signer

    async def generate(
        self,
        *,
        run_id: UUID,
        tenant_id: UUID,
    ) -> ArtifactResult:
        """Build a canonical artifact for the given run.

        Steps:
          1. Fetch the Run row.
          2. Fetch all entities for the tenant.
          3. Fetch relationships for each entity.
          4. Map entities to Target objects.
          5. Build CollectorHealth from run metadata.
          6. Assemble the CanonicalArtifact.
          7. Serialize to JSON and compute the FIPS content hash.
        """
        tid = TenantId(tenant_id)
        rid = RunId(run_id)

        # 1. Fetch the Run row
        run_row = await self._run_repo.get_by_id(tenant_id=tid, run_id=rid)
        if run_row is None:
            msg = f"No run found for tenant_id={tenant_id} run_id={run_id}"
            raise LookupError(msg)

        # 2. Fetch all entities for the tenant
        entities = await self._entity_repo.list_for_tenant(
            tenant_id=tid,
            limit=10000,
        )

        # 3. Gather relationships per entity
        all_relationships: list[RelationshipRow] = []
        seen_rel_ids: set[UUID] = set()
        for entity in entities:
            rels = await self._relationship_repo.find_for_entity(
                tenant_id=tid,
                entity_id=entity.id,  # type: ignore[arg-type]
                direction="both",
                limit=1000,
            )
            for rel in rels:
                if rel.id not in seen_rel_ids:
                    seen_rel_ids.add(rel.id)
                    all_relationships.append(rel)

        # 4. Map entities -> Targets
        targets = [_entity_to_target(e) for e in entities]

        # 5. Build Run metadata for the artifact
        artifact_run = _build_run(run_row)

        # 6. Build Tenant metadata
        artifact_tenant = Tenant(
            tenant_id=tenant_id,
            tenant_name=f"tenant-{tenant_id}",
        )

        # 7. Build CollectorHealth
        collector_health = _build_collector_health(entities)

        # 8. Build the empty delta (first-run default)
        delta = Delta(
            previous_run_id=None,
            added=[],
            removed=[],
            changed=[],
        )

        # 9. Assemble the artifact
        artifact = CanonicalArtifact(
            schema_version="expose/v1",
            run=artifact_run,
            tenant=artifact_tenant,
            targets=targets,
            delta_from_previous_run=delta,
            collector_health=collector_health,
            manifest_ref=f"manifest-{run_id}.json",
        )

        # 10. Serialize and hash
        payload = artifact.to_dict_for_artifact()
        json_bytes = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        content_hash = compute_sha256_hex(json_bytes)

        # 11. Sign the serialized artifact when a signer is configured
        signature: SignatureResult | None = None
        if self._signer is not None:
            try:
                signature = sign_artifact(json_bytes, self._signer)
                logger.info(
                    "Artifact signed: algorithm=%s key_id=%s",
                    signature.algorithm,
                    signature.key_id,
                )
            except Exception:
                logger.warning(
                    "Artifact signing failed; producing unsigned artifact",
                    exc_info=True,
                )

        # 12. Persist to object storage when a backend is configured
        storage_uri: str | None = None
        if self._storage is not None:
            artifact_key = f"tenant/{tenant_id}/artifacts/{run_id}.json"
            storage_uri = await self._storage.put(
                artifact_key,
                json_bytes,
                content_type="application/json",
            )

        return ArtifactResult(
            artifact=artifact,
            json_bytes=json_bytes,
            content_hash=content_hash,
            entity_count=len(entities),
            relationship_count=len(all_relationships),
            storage_uri=storage_uri,
            signature=signature,
        )


# === Private helpers =========================================================


def _normalize_pipeline_version(raw: str) -> str:
    """Ensure the pipeline version is a valid 40-char hex git sha-1.

    Run rows may carry semantic versions (e.g. ``v0.1.0``) in dev/test;
    the canonical schema requires a 40-char hex string.
    """
    if len(raw) == _GIT_SHA1_LENGTH and all(c in "0123456789abcdef" for c in raw):
        return raw
    return _DEFAULT_GIT_SHA1


def _build_run(run_row: RunRow) -> Run:
    """Map a Run ORM row to the canonical Run model."""
    now = datetime.now(UTC)
    return Run(
        run_id=run_row.id,
        started_at=run_row.started_at or now,
        completed_at=run_row.completed_at or now,
        pipeline_version=_normalize_pipeline_version(run_row.pipeline_version),
    )


def _entity_type_to_identifier_type(entity_type: str) -> IdentifierType:
    """Map an entity_type string to an IdentifierType enum value.

    Falls back to ``IdentifierType.DOMAIN`` for unrecognized types.
    """
    mapping: dict[str, IdentifierType] = {
        "Domain": IdentifierType.DOMAIN,
        "domain": IdentifierType.DOMAIN,
        "Subdomain": IdentifierType.SUBDOMAIN,
        "subdomain": IdentifierType.SUBDOMAIN,
        "IP": IdentifierType.IP,
        "ip": IdentifierType.IP,
        "CIDR": IdentifierType.CIDR,
        "cidr": IdentifierType.CIDR,
        "CloudResource": IdentifierType.CLOUD_RESOURCE_ID,
        "cloud_resource_id": IdentifierType.CLOUD_RESOURCE_ID,
        "URL": IdentifierType.URL,
        "url": IdentifierType.URL,
    }
    return mapping.get(entity_type, IdentifierType.DOMAIN)


def _entity_to_target(entity: EntityRow) -> Target:
    """Map an Entity ORM row to a canonical Target model.

    Uses sensible defaults for fields that don't have data yet in the
    early pipeline (e.g. ``exposure`` is empty, ``tech_stack`` is None).
    """
    now = datetime.now(UTC)

    identifier_type = _entity_type_to_identifier_type(entity.entity_type)

    primary_identifier = PrimaryIdentifier(
        type=identifier_type,
        value=entity.canonical_identifier,
    )

    # Attribution: map from entity columns
    confidence = float(entity.attribution_confidence)
    tier = _confidence_to_tier(confidence)

    attribution = Attribution(
        tier=tier,
        confidence=confidence,
        reasoning=f"Attributed via {entity.attribution_status}",
        decision_path=[
            AttributionRuleApplication(
                rule_id="entity-attribution-status",
                rule_version="1.0.0",
                outcome=AttributionRuleOutcome.MATCHED_PROMOTE,
                confidence_contribution=confidence,
            ),
        ],
    )

    # Provenance: derive from entity properties if available
    props: dict[str, Any] = entity.properties or {}
    collector_id = str(props.get("_collector_id", "unknown"))
    collector_version = str(props.get("_collector_version", "1.0.0"))

    provenance = Provenance(
        sources=[
            ProvenanceSource(
                collector_id=collector_id,
                collector_version=collector_version,
                first_observed_at=entity.first_observed_at or now,
                last_observed_at=entity.last_observed_at or now,
                observation_count=1,
            ),
        ],
        evidence_refs=[],
    )

    # Exposure: empty for now (populated in later pipeline stages)
    exposure = Exposure()

    # LeadScore: basic score derived from attribution confidence
    lead_score = LeadScore(
        score=round(confidence * 100.0, 1),
        formula_version=_LEAD_SCORE_FORMULA_VERSION,
        inputs=LeadScoreInputs(
            attribution_confidence=confidence,
        ),
        category=_score_to_category(confidence * 100.0),
    )

    return Target(
        target_id=entity.id,
        primary_identifier=primary_identifier,
        attribution=attribution,
        exposure=exposure,
        provenance=provenance,
        first_observed_at=entity.first_observed_at or now,
        last_observed_at=entity.last_observed_at or now,
        lead_score=lead_score,
    )


def _confidence_to_tier(confidence: float) -> AttributionTier:
    """Map a numeric confidence to an attribution tier.

    Thresholds:
      - >= 0.9 -> confirmed
      - >= 0.7 -> high
      - >= 0.4 -> medium
      - <  0.4 -> requires_review
    """
    if confidence >= _TIER_CONFIRMED_THRESHOLD:
        return AttributionTier.CONFIRMED
    if confidence >= _TIER_HIGH_THRESHOLD:
        return AttributionTier.HIGH
    if confidence >= _TIER_MEDIUM_THRESHOLD:
        return AttributionTier.MEDIUM
    return AttributionTier.REQUIRES_REVIEW


def _score_to_category(score: float) -> LeadScoreCategory:
    """Map a numeric lead score (0-100) to a category."""
    if score >= _SCORE_CRITICAL_THRESHOLD:
        return LeadScoreCategory.CRITICAL_PRIORITY
    if score >= _SCORE_HIGH_THRESHOLD:
        return LeadScoreCategory.HIGH_PRIORITY
    if score >= _SCORE_MEDIUM_THRESHOLD:
        return LeadScoreCategory.MEDIUM_PRIORITY
    if score >= _SCORE_LOW_THRESHOLD:
        return LeadScoreCategory.LOW_PRIORITY
    return LeadScoreCategory.INFORMATIONAL


def _build_collector_health(entities: Sequence[EntityRow]) -> CollectorHealth:
    """Build a CollectorHealth summary from entity properties.

    Extracts distinct collector IDs from entity properties and creates a
    health entry for each.
    """
    now = datetime.now(UTC)
    collector_ids: set[str] = set()
    for entity in entities:
        props: dict[str, Any] = entity.properties or {}
        cid = props.get("_collector_id")
        if cid is not None:
            collector_ids.add(str(cid))

    if not collector_ids:
        # Even an empty run needs a collectors list (required by schema).
        return CollectorHealth(collectors=[])

    entries = [
        CollectorHealthEntry(
            collector_id=cid,
            status=CollectorStatus.SUCCESS,
            started_at=now,
            completed_at=now,
            observations_collected=sum(
                1
                for e in entities
                if (e.properties or {}).get("_collector_id") == cid
            ),
        )
        for cid in sorted(collector_ids)
    ]
    return CollectorHealth(collectors=entries)


__all__ = [
    "ArtifactGenerator",
    "ArtifactResult",
]

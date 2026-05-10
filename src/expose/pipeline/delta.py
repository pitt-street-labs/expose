"""Delta computation engine — compute what changed between consecutive scan runs.

Given two sets of entity snapshots (previous and current), ``compute_delta``
determines which entities were added, removed, or changed. Entities are matched
by the composite key ``(canonical_identifier, entity_type)`` — UUID identity is
deliberately excluded from matching so that re-discovered entities with new UUIDs
are still recognized as the same logical entity.

This module is pure — no database access, no I/O, no side effects. All models
are Pydantic frozen for immutability.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class FieldChange(BaseModel):
    """A single field that differs between the previous and current snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: str
    old_value: Any
    new_value: Any


class ChangedEntity(BaseModel):
    """An entity present in both snapshots but with differing attributes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entity_id: UUID
    canonical_identifier: str
    entity_type: str
    changes: list[FieldChange]


class EntitySnapshot(BaseModel):
    """Point-in-time snapshot of an entity for diffing."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entity_id: UUID
    canonical_identifier: str
    entity_type: str
    attribution_status: str
    attribution_confidence: float
    properties: dict[str, Any] = Field(default_factory=dict)


class DeltaResult(BaseModel):
    """Result of computing the diff between two entity snapshot sets."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    added: list[EntitySnapshot]
    removed: list[EntitySnapshot]
    changed: list[ChangedEntity]

    @property
    def total_changes(self) -> int:
        """Total number of entities that were added, removed, or changed."""
        return len(self.added) + len(self.removed) + len(self.changed)


# Type alias for the composite match key.
_MatchKey = tuple[str, str]


def _match_key(snapshot: EntitySnapshot) -> _MatchKey:
    """Return the composite key used to match entities across snapshots."""
    return (snapshot.canonical_identifier, snapshot.entity_type)


def _diff_fields(
    previous: EntitySnapshot,
    current: EntitySnapshot,
) -> list[FieldChange]:
    """Compare diffable fields between two snapshots of the same entity.

    Compared fields: ``attribution_status``, ``attribution_confidence``,
    ``properties``. Identity fields (``entity_id``, ``canonical_identifier``,
    ``entity_type``) are excluded — they are either the match key or may
    legitimately differ across runs.
    """
    changes: list[FieldChange] = []

    if previous.attribution_status != current.attribution_status:
        changes.append(
            FieldChange(
                field="attribution_status",
                old_value=previous.attribution_status,
                new_value=current.attribution_status,
            )
        )

    if previous.attribution_confidence != current.attribution_confidence:
        changes.append(
            FieldChange(
                field="attribution_confidence",
                old_value=previous.attribution_confidence,
                new_value=current.attribution_confidence,
            )
        )

    if previous.properties != current.properties:
        changes.append(
            FieldChange(
                field="properties",
                old_value=previous.properties,
                new_value=current.properties,
            )
        )

    return changes


def compute_delta(
    previous: list[EntitySnapshot],
    current: list[EntitySnapshot],
) -> DeltaResult:
    """Compute the diff between two sets of entity snapshots.

    Entities are matched by ``(canonical_identifier, entity_type)``.

    - **Added:** present in *current* but not in *previous*.
    - **Removed:** present in *previous* but not in *current*.
    - **Changed:** present in both, but ``attribution_status``,
      ``attribution_confidence``, or ``properties`` differ.

    Entities present in both sets with identical diffable fields are omitted
    from all three lists.

    This function is pure — no I/O, no side effects.
    """
    prev_by_key: dict[_MatchKey, EntitySnapshot] = {
        _match_key(s): s for s in previous
    }
    curr_by_key: dict[_MatchKey, EntitySnapshot] = {
        _match_key(s): s for s in current
    }

    prev_keys = set(prev_by_key.keys())
    curr_keys = set(curr_by_key.keys())

    added = [curr_by_key[k] for k in curr_keys - prev_keys]
    removed = [prev_by_key[k] for k in prev_keys - curr_keys]

    changed: list[ChangedEntity] = []
    for key in prev_keys & curr_keys:
        field_changes = _diff_fields(prev_by_key[key], curr_by_key[key])
        if field_changes:
            current_snap = curr_by_key[key]
            changed.append(
                ChangedEntity(
                    entity_id=current_snap.entity_id,
                    canonical_identifier=current_snap.canonical_identifier,
                    entity_type=current_snap.entity_type,
                    changes=field_changes,
                )
            )

    return DeltaResult(added=added, removed=removed, changed=changed)


__all__ = [
    "ChangedEntity",
    "DeltaResult",
    "EntitySnapshot",
    "FieldChange",
    "compute_delta",
]

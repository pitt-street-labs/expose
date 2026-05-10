"""Tests for the delta computation engine (expose.pipeline.delta)."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from expose.pipeline.delta import (
    ChangedEntity,
    DeltaResult,
    EntitySnapshot,
    FieldChange,
    compute_delta,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snap(
    *,
    canonical_identifier: str = "example.com",
    entity_type: str = "domain",
    attribution_status: str = "confirmed",
    attribution_confidence: float = 0.95,
    properties: dict[str, object] | None = None,
    entity_id: UUID | None = None,
) -> EntitySnapshot:
    """Build an EntitySnapshot with sensible defaults."""
    return EntitySnapshot(
        entity_id=entity_id or uuid4(),
        canonical_identifier=canonical_identifier,
        entity_type=entity_type,
        attribution_status=attribution_status,
        attribution_confidence=attribution_confidence,
        properties=properties or {},
    )


# ---------------------------------------------------------------------------
# 1. No changes -> empty delta
# ---------------------------------------------------------------------------

def test_no_changes_returns_empty_delta() -> None:
    """Identical previous and current snapshots produce an empty delta."""
    entity_id = uuid4()
    snap = _snap(entity_id=entity_id)
    # Build a second snapshot with the same values and same match key
    snap_copy = _snap(
        entity_id=entity_id,
        canonical_identifier=snap.canonical_identifier,
        entity_type=snap.entity_type,
        attribution_status=snap.attribution_status,
        attribution_confidence=snap.attribution_confidence,
        properties=dict(snap.properties),
    )
    result = compute_delta([snap], [snap_copy])

    assert result.added == []
    assert result.removed == []
    assert result.changed == []
    assert result.total_changes == 0


# ---------------------------------------------------------------------------
# 2. New entity -> in added
# ---------------------------------------------------------------------------

def test_new_entity_in_added() -> None:
    """An entity present only in current shows up in added."""
    new = _snap(canonical_identifier="new.example.com")
    result = compute_delta([], [new])

    assert len(result.added) == 1
    assert result.added[0].canonical_identifier == "new.example.com"
    assert result.removed == []
    assert result.changed == []


# ---------------------------------------------------------------------------
# 3. Removed entity -> in removed
# ---------------------------------------------------------------------------

def test_removed_entity_in_removed() -> None:
    """An entity present only in previous shows up in removed."""
    old = _snap(canonical_identifier="gone.example.com")
    result = compute_delta([old], [])

    assert len(result.removed) == 1
    assert result.removed[0].canonical_identifier == "gone.example.com"
    assert result.added == []
    assert result.changed == []


# ---------------------------------------------------------------------------
# 4. Changed attribution_status -> in changed with correct FieldChange
# ---------------------------------------------------------------------------

def test_changed_attribution_status() -> None:
    """A change in attribution_status is detected with the right field name."""
    prev = _snap(attribution_status="requires_review")
    curr = _snap(attribution_status="confirmed")

    result = compute_delta([prev], [curr])

    assert len(result.changed) == 1
    changes = result.changed[0].changes
    status_changes = [c for c in changes if c.field == "attribution_status"]
    assert len(status_changes) == 1
    assert status_changes[0].old_value == "requires_review"
    assert status_changes[0].new_value == "confirmed"


# ---------------------------------------------------------------------------
# 5. Changed attribution_confidence -> detected
# ---------------------------------------------------------------------------

def test_changed_attribution_confidence() -> None:
    """A change in attribution_confidence is detected."""
    prev = _snap(attribution_confidence=0.5)
    curr = _snap(attribution_confidence=0.9)

    result = compute_delta([prev], [curr])

    assert len(result.changed) == 1
    changes = result.changed[0].changes
    conf_changes = [c for c in changes if c.field == "attribution_confidence"]
    assert len(conf_changes) == 1
    assert conf_changes[0].old_value == 0.5
    assert conf_changes[0].new_value == 0.9


# ---------------------------------------------------------------------------
# 6. Changed properties -> detected
# ---------------------------------------------------------------------------

def test_changed_properties() -> None:
    """A change in the properties dict is detected."""
    prev = _snap(properties={"server": "nginx/1.18"})
    curr = _snap(properties={"server": "nginx/1.20"})

    result = compute_delta([prev], [curr])

    assert len(result.changed) == 1
    changes = result.changed[0].changes
    prop_changes = [c for c in changes if c.field == "properties"]
    assert len(prop_changes) == 1
    assert prop_changes[0].old_value == {"server": "nginx/1.18"}
    assert prop_changes[0].new_value == {"server": "nginx/1.20"}


# ---------------------------------------------------------------------------
# 7. Multiple simultaneous adds/removes/changes
# ---------------------------------------------------------------------------

def test_multiple_adds_removes_changes() -> None:
    """A mix of added, removed, and changed entities in a single delta."""
    stable = _snap(canonical_identifier="stable.example.com")
    stable_copy = _snap(
        canonical_identifier="stable.example.com",
        attribution_status=stable.attribution_status,
        attribution_confidence=stable.attribution_confidence,
    )

    removed_entity = _snap(canonical_identifier="old.example.com")

    changed_prev = _snap(
        canonical_identifier="drift.example.com",
        attribution_confidence=0.6,
    )
    changed_curr = _snap(
        canonical_identifier="drift.example.com",
        attribution_confidence=0.9,
    )

    added_entity = _snap(canonical_identifier="brand-new.example.com")

    previous = [stable, removed_entity, changed_prev]
    current = [stable_copy, changed_curr, added_entity]

    result = compute_delta(previous, current)

    assert len(result.added) == 1
    assert result.added[0].canonical_identifier == "brand-new.example.com"

    assert len(result.removed) == 1
    assert result.removed[0].canonical_identifier == "old.example.com"

    assert len(result.changed) == 1
    assert result.changed[0].canonical_identifier == "drift.example.com"


# ---------------------------------------------------------------------------
# 8. Same entity unchanged -> not in any list
# ---------------------------------------------------------------------------

def test_unchanged_entity_not_in_any_list() -> None:
    """An entity with identical fields in both snapshots appears nowhere."""
    entity_id = uuid4()
    prev = _snap(
        entity_id=entity_id,
        canonical_identifier="static.example.com",
        attribution_status="confirmed",
        attribution_confidence=0.99,
        properties={"key": "value"},
    )
    curr = _snap(
        entity_id=entity_id,
        canonical_identifier="static.example.com",
        attribution_status="confirmed",
        attribution_confidence=0.99,
        properties={"key": "value"},
    )
    result = compute_delta([prev], [curr])

    assert result.total_changes == 0


# ---------------------------------------------------------------------------
# 9. DeltaResult.total_changes counts correctly
# ---------------------------------------------------------------------------

def test_total_changes_counts_correctly() -> None:
    """total_changes is the sum of added + removed + changed lengths."""
    prev_only_1 = _snap(canonical_identifier="r1.example.com")
    prev_only_2 = _snap(canonical_identifier="r2.example.com")

    curr_only = _snap(canonical_identifier="a1.example.com")

    changed_prev = _snap(
        canonical_identifier="c1.example.com",
        attribution_status="medium",
    )
    changed_curr = _snap(
        canonical_identifier="c1.example.com",
        attribution_status="confirmed",
    )

    result = compute_delta(
        [prev_only_1, prev_only_2, changed_prev],
        [curr_only, changed_curr],
    )

    assert len(result.added) == 1
    assert len(result.removed) == 2
    assert len(result.changed) == 1
    assert result.total_changes == 4


# ---------------------------------------------------------------------------
# 10. Entity matched by (identifier, type) not by UUID
# ---------------------------------------------------------------------------

def test_matching_by_identifier_and_type_not_uuid() -> None:
    """Two snapshots with different UUIDs but same (identifier, type) are matched."""
    prev = _snap(
        entity_id=UUID("00000000-0000-0000-0000-000000000001"),
        canonical_identifier="matched.example.com",
        entity_type="domain",
        attribution_status="medium",
    )
    curr = _snap(
        entity_id=UUID("00000000-0000-0000-0000-000000000002"),
        canonical_identifier="matched.example.com",
        entity_type="domain",
        attribution_status="confirmed",
    )
    result = compute_delta([prev], [curr])

    # Should not be in added or removed — same logical entity
    assert result.added == []
    assert result.removed == []
    # Should be in changed because attribution_status differs
    assert len(result.changed) == 1
    assert result.changed[0].canonical_identifier == "matched.example.com"


# ---------------------------------------------------------------------------
# 11. Empty previous (first run) -> all current are "added"
# ---------------------------------------------------------------------------

def test_empty_previous_all_added() -> None:
    """When there is no previous run, every current entity is added."""
    entities = [
        _snap(canonical_identifier="a.example.com"),
        _snap(canonical_identifier="b.example.com"),
        _snap(canonical_identifier="c.example.com"),
    ]
    result = compute_delta([], entities)

    assert len(result.added) == 3
    assert result.removed == []
    assert result.changed == []
    added_ids = {s.canonical_identifier for s in result.added}
    assert added_ids == {"a.example.com", "b.example.com", "c.example.com"}


# ---------------------------------------------------------------------------
# 12. Empty current (everything removed) -> all previous are "removed"
# ---------------------------------------------------------------------------

def test_empty_current_all_removed() -> None:
    """When current is empty, every previous entity is removed."""
    entities = [
        _snap(canonical_identifier="x.example.com"),
        _snap(canonical_identifier="y.example.com"),
    ]
    result = compute_delta(entities, [])

    assert result.added == []
    assert len(result.removed) == 2
    assert result.changed == []
    removed_ids = {s.canonical_identifier for s in result.removed}
    assert removed_ids == {"x.example.com", "y.example.com"}


# ---------------------------------------------------------------------------
# 13. Same identifier different type -> treated as different entities
# ---------------------------------------------------------------------------

def test_same_identifier_different_type_are_distinct() -> None:
    """(identifier, type) is the full key; same identifier with different types
    are independent entities."""
    prev = _snap(canonical_identifier="192.168.1.1", entity_type="ip")
    curr = _snap(canonical_identifier="192.168.1.1", entity_type="cloud_resource")

    result = compute_delta([prev], [curr])

    # The IP entity was "removed" and the cloud_resource entity was "added"
    assert len(result.removed) == 1
    assert result.removed[0].entity_type == "ip"
    assert len(result.added) == 1
    assert result.added[0].entity_type == "cloud_resource"
    assert result.changed == []


# ---------------------------------------------------------------------------
# 14. Multiple field changes on one entity -> all enumerated
# ---------------------------------------------------------------------------

def test_multiple_field_changes_enumerated() -> None:
    """When multiple fields change, each is listed as a separate FieldChange."""
    prev = _snap(
        canonical_identifier="multi.example.com",
        attribution_status="requires_review",
        attribution_confidence=0.3,
        properties={"version": "1"},
    )
    curr = _snap(
        canonical_identifier="multi.example.com",
        attribution_status="confirmed",
        attribution_confidence=0.95,
        properties={"version": "2"},
    )

    result = compute_delta([prev], [curr])

    assert len(result.changed) == 1
    changed_fields = {c.field for c in result.changed[0].changes}
    assert changed_fields == {"attribution_status", "attribution_confidence", "properties"}


# ---------------------------------------------------------------------------
# 15. Models are frozen (immutable)
# ---------------------------------------------------------------------------

def test_models_are_frozen() -> None:
    """All delta models reject attribute mutation."""
    snap = _snap()
    with pytest.raises(Exception):  # noqa: B017
        snap.attribution_status = "changed"  # type: ignore[misc]

    change = FieldChange(field="x", old_value=1, new_value=2)
    with pytest.raises(Exception):  # noqa: B017
        change.field = "y"  # type: ignore[misc]

    result = DeltaResult(added=[], removed=[], changed=[])
    with pytest.raises(Exception):  # noqa: B017
        result.added = [snap]  # type: ignore[misc]

    entity = ChangedEntity(
        entity_id=uuid4(),
        canonical_identifier="x.com",
        entity_type="domain",
        changes=[],
    )
    with pytest.raises(Exception):  # noqa: B017
        entity.entity_type = "ip"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 16. Both lists empty -> empty delta
# ---------------------------------------------------------------------------

def test_both_lists_empty() -> None:
    """Two empty snapshot lists produce a zero-change delta."""
    result = compute_delta([], [])
    assert result.total_changes == 0
    assert result.added == []
    assert result.removed == []
    assert result.changed == []

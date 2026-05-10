"""Validate all example rule packs in ``examples/rulepacks/`` against the schema.

Every ``.json`` file in the directory is tested:
  1. JSON parses without error.
  2. Validates against ``schemas/rulepack-v1.json`` via ``jsonschema``.
  3. Validates via the Pydantic ``RulePack`` model (``$schema`` key stripped
     first, since the model uses ``extra="forbid"`` and does not define it).
  4. Contains at least one attribution rule.
  5. Has no duplicate ``rule_id`` values within the pack.

The test is parametrized by globbing the directory, so newly added packs are
automatically included without test changes.
"""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from expose.types.rulepack import RulePack

# ---------------------------------------------------------------------------
# Discover all rule pack JSON files
# ---------------------------------------------------------------------------
_RULEPACKS_DIR = Path(__file__).resolve().parent.parent / "examples" / "rulepacks"
_RULEPACK_FILES = sorted(_RULEPACKS_DIR.glob("*.json"))


def _pack_ids() -> list[str]:
    """Return stem names for readable pytest IDs."""
    return [p.stem for p in _RULEPACK_FILES]


@pytest.fixture(scope="module")
def rulepack_schema() -> dict:
    """Load the rulepack JSON Schema once per module."""
    schema_path = Path(__file__).resolve().parent.parent / "schemas" / "rulepack-v1.json"
    return json.loads(schema_path.read_text())


# ---------------------------------------------------------------------------
# Parametrized tests — one invocation per JSON file
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pack_path", _RULEPACK_FILES, ids=_pack_ids())
class TestExampleRulepacks:
    """Suite of validations applied to every example rule pack."""

    def test_json_parses(self, pack_path: Path) -> None:
        """File must be valid JSON."""
        data = json.loads(pack_path.read_text())
        assert isinstance(data, dict), f"{pack_path.name} root must be a JSON object"

    def test_validates_against_json_schema(
        self,
        pack_path: Path,
        rulepack_schema: dict,
    ) -> None:
        """File must pass JSON Schema Draft 2020-12 validation."""
        data = json.loads(pack_path.read_text())
        jsonschema.validate(instance=data, schema=rulepack_schema)

    def test_validates_via_pydantic_model(self, pack_path: Path) -> None:
        """File must load into the Pydantic RulePack model.

        The ``$schema`` key is an editor convention allowed by the JSON Schema
        but not defined on the Pydantic model (which uses ``extra="forbid"``).
        Strip it before validation.
        """
        data = json.loads(pack_path.read_text())
        data.pop("$schema", None)
        pack = RulePack.model_validate(data)
        assert pack.pack_id == data["pack_id"]

    def test_has_at_least_one_rule(self, pack_path: Path) -> None:
        """Every pack must contain at least one attribution rule."""
        data = json.loads(pack_path.read_text())
        assert len(data.get("attribution_rules", [])) >= 1, (
            f"{pack_path.name} has no attribution_rules"
        )

    def test_no_duplicate_rule_ids(self, pack_path: Path) -> None:
        """Rule IDs must be unique within a single pack."""
        data = json.loads(pack_path.read_text())
        rule_ids = [r["rule_id"] for r in data.get("attribution_rules", [])]
        duplicates = [rid for rid in rule_ids if rule_ids.count(rid) > 1]
        assert not duplicates, (
            f"{pack_path.name} has duplicate rule_id(s): {sorted(set(duplicates))}"
        )

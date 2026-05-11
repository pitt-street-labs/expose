"""Typed models for pipeline data structures.

Replaces pervasive ``dict[str, Any]`` usage in the rule evaluation engine,
provenance API, findings API, and scheduler API with validated Pydantic models.
All models accept plain dicts via ``model_validate`` for backward compatibility
with existing callers that pass raw dicts.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EntityData(BaseModel):
    """Typed representation of entity data for rule evaluation.

    Replaces ``dict[str, Any]`` in ``RuleEvaluator.evaluate()`` and predicate
    functions.  Accepts plain dicts via ``model_validate()`` for backward
    compatibility.
    """

    model_config = ConfigDict(extra="forbid")

    entity_type: str
    canonical_identifier: str
    properties: dict[str, Any] = Field(default_factory=dict)
    attribution_status: str = "unattributed"
    attribution_confidence: float = 0.0


class ScopeContext(BaseModel):
    """Typed representation of tenant authorization context for rule evaluation.

    Carries the data needed by scope-aware predicates (cloud ranges, apex
    domains, explicit identifiers, authorized patterns, etc.).  Accepts plain
    dicts via ``model_validate()`` for backward compatibility.

    Scope context keys are predicate-specific and vary across rule packs, so
    this model uses ``extra="allow"`` to accept arbitrary fields.  Common
    keys include: ``scope_domains``, ``cloud_ranges``, ``apex_domains``,
    ``authorized_asns``, ``explicit_entity_identifiers``,
    ``rejection_identifiers``, ``registrant_patterns``,
    ``nameserver_patterns``, ``naming_convention_patterns``,
    ``attributed_cert_fingerprints``.
    """

    model_config = ConfigDict(extra="allow")


class FindingSignal(BaseModel):
    """A single scored signal contributing to a finding's priority score."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    signal: str
    weight: int | float = 1


class ProvenanceRuleApplication(BaseModel):
    """Record of a single attribution rule application in the provenance chain."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    outcome: str
    confidence_delta: float = 0.0


__all__ = [
    "EntityData",
    "FindingSignal",
    "ProvenanceRuleApplication",
    "ScopeContext",
]

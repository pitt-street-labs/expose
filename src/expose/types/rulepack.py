"""Pydantic models mirroring `schemas/rulepack-v1.json`.

Rule packs are data, not code (per ADR-006 / SPEC §8.2). The engine consumes
rule packs and applies them deterministically; rule packs cannot extend the
predicate vocabulary — only engine updates can. This module mirrors that
contract field-for-field.
"""
from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal, Self
from typing import Annotated as Ann

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

# Patterns from schema:
#   pack_id / rule_id: lowercase-alphanumeric with internal dashes
#   pack_version / rule_version / formula_version: SemVer X.Y.Z
LowercaseSlug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")]
SemVer = Annotated[str, StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]


class RuleCategory(str, Enum):
    HIGH_CONFIDENCE_JOIN = "high_confidence_join"
    REGISTRANT_PIVOT = "registrant_pivot"
    INFRASTRUCTURE_CORRELATION = "infrastructure_correlation"
    NAMING_HEURISTIC = "naming_heuristic"
    CLOUD_AUTHORITATIVE = "cloud_authoritative"
    REJECTION_RULE = "rejection_rule"


class Outcome(str, Enum):
    PROMOTE = "promote"
    DEMOTE = "demote"
    NEUTRAL = "neutral"
    REJECT = "reject"


class Predicate(str, Enum):
    """Closed predicate vocabulary per SPEC §8.2.

    New predicates are added via engine updates, not rule pack changes. This
    enum IS the vocabulary; any rule using a value outside this enum is
    rejected at load time.
    """

    TARGET_HAS_CERTIFICATE_WITH_SAN_IN_SCOPE = "target_has_certificate_with_san_in_scope"
    TARGET_IP_IN_AUTHORIZED_CLOUD_ACCOUNT_RANGE = "target_ip_in_authorized_cloud_account_range"
    TARGET_REGISTRANT_MATCHES_AUTHORIZED_PATTERN = "target_registrant_matches_authorized_pattern"
    TARGET_SHARES_CERT_CHAIN_WITH_ATTRIBUTED_TARGET = "target_shares_cert_chain_with_attributed_target"
    TARGET_NAMESERVER_MATCHES_AUTHORIZED_PATTERN = "target_nameserver_matches_authorized_pattern"
    TARGET_ASN_IN_AUTHORIZED_LIST = "target_asn_in_authorized_list"
    TARGET_SUBDOMAIN_OF_AUTHORIZED_APEX = "target_subdomain_of_authorized_apex"
    TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE = "target_in_explicit_authorization_scope"
    TARGET_OBSERVED_BY_COLLECTORS_COUNT_GTE = "target_observed_by_collectors_count_gte"
    TARGET_FIRST_OBSERVED_WITHIN_DAYS = "target_first_observed_within_days"
    TARGET_HAS_EXPOSURE_INDICATOR = "target_has_exposure_indicator"
    TARGET_RESPONDS_WITH_AUTHORIZED_NAMING_CONVENTION = "target_responds_with_authorized_naming_convention"


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )


# === Conditions (recursive) =================================================
class PredicateCondition(StrictModel):
    predicate: Predicate
    params: dict[str, Any] | None = None


class AndCondition(BaseModel):
    """Schema does not specify additionalProperties for AndCondition — leave open."""

    model_config = ConfigDict(extra="allow", frozen=True)

    all_of: list["Condition"] = Field(min_length=1)


class OrCondition(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    any_of: list["Condition"] = Field(min_length=1)


class NotCondition(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    not_: "Condition" = Field(alias="not")


# `oneOf` from schema — discriminated by which key is present.
Condition = AndCondition | OrCondition | NotCondition | PredicateCondition

AndCondition.model_rebuild()
OrCondition.model_rebuild()
NotCondition.model_rebuild()


# === Action =================================================================
class Action(StrictModel):
    outcome: Outcome
    confidence_delta: float | None = Field(default=None, ge=-1.0, le=1.0)
    review_flag: bool | None = None
    review_reason: str | None = None

    @model_validator(mode="after")
    def _delta_required_for_promote_demote(self) -> Self:
        if self.outcome in (Outcome.PROMOTE, Outcome.DEMOTE) and self.confidence_delta is None:
            raise ValueError(
                f"`confidence_delta` is required when outcome is '{self.outcome.value}'"
            )
        return self


# === Attribution rule =======================================================
class AttributionRule(StrictModel):
    rule_id: LowercaseSlug
    rule_version: SemVer
    description: str
    category: RuleCategory | None = None
    when: Condition
    then: Action
    priority: int = 100
    enabled: bool = True


# === Lead score formula =====================================================
class LeadScoreWeights(BaseModel):
    """Schema does not specify additionalProperties for weights — allow extras."""

    model_config = ConfigDict(extra="allow", frozen=True)

    attribution_confidence: float = 20
    exposure_severity_max: float = 30
    tech_stack_risk: float = 25
    freshness: float = 10
    cloud_provider_factor: float = 15


class LeadScoreModifier(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    when: Condition
    then_multiply: float
    description: str | None = None


class CategoryThresholds(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    critical_priority: float = 80
    high_priority: float = 60
    medium_priority: float = 40
    low_priority: float = 20


class LeadScoreFormula(StrictModel):
    formula_version: SemVer
    weights: LeadScoreWeights
    modifiers: list[LeadScoreModifier]
    category_thresholds: CategoryThresholds | None = None


# === Rule pack root =========================================================
class TierThresholds(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    confirmed: float = Field(default=0.95, ge=0.0, le=1.0)
    high: float = Field(default=0.75, ge=0.0, le=1.0)
    medium: float = Field(default=0.5, ge=0.0, le=1.0)


class RulePackDependency(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    pack_id: str
    pack_version_constraint: str


class RulePack(StrictModel):
    """A versioned, declarative collection of attribution rules and lead-score
    formulas. Mirrors `schemas/rulepack-v1.json`.

    Note: the schema sets `additionalProperties: false`. The example pack
    `examples/rulepacks/example-baseline.json` includes a top-level `$schema`
    property as an editor-side convention; that is rejected by this model
    today (the bug is tracked separately — to be fixed by either removing
    `$schema` from the example or relaxing `additionalProperties` on the
    schema).
    """

    pack_id: LowercaseSlug
    pack_version: SemVer
    pack_format_version: Literal["v1"] = "v1"
    description: str | None = None
    depends_on: list[RulePackDependency] | None = None
    attribution_rules: list[AttributionRule]
    lead_score_formula: LeadScoreFormula
    tier_thresholds: TierThresholds | None = None

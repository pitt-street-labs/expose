"""Pydantic models mirroring the JSON Schemas in `schemas/`.

The schemas in `schemas/canonical-artifact-v1.json`, `schemas/manifest-v1.json`, and
`schemas/rulepack-v1.json` are the authoritative wire format. The Pydantic models here
mirror them for typed in-process use; CI verifies the two stay in sync (see
`tests/test_schema_sync.py`).

Sprint 1-2 lands the Manifest model end-to-end. Canonical artifact and rulepack models
follow as Sprint 5-7 lands the attribution engine and artifact generator.
"""
from expose.types.canonical import (
    Attribution,
    AttributionTier,
    CanonicalArtifact,
    CloudResource,
    CollectorHealth,
    Delta,
    DeltaAdded,
    DeltaChanged,
    DeltaRemoved,
    Exposure,
    Identifier,
    LeadScore,
    LLMEnrichment,
    OutsideAuthorizedScopeSummary,
    PrimaryIdentifier,
    Provenance,
    QuotaWarning,
    Target,
    TechStack,
)
from expose.types.canonical import (
    Run as CanonicalRun,
)
from expose.types.canonical import (
    Tenant as CanonicalTenant,
)
from expose.types.manifest import (
    Manifest,
    ManifestArtifact,
    ManifestPipeline,
    ManifestRun,
    ManifestSignature,
)
from expose.types.rulepack import (
    Action,
    AndCondition,
    AttributionRule,
    LeadScoreFormula,
    LeadScoreModifier,
    LeadScoreWeights,
    NotCondition,
    OrCondition,
    Outcome,
    Predicate,
    PredicateCondition,
    RuleCategory,
    RulePack,
    RulePackDependency,
    TierThresholds,
)
from expose.types.pipeline import (
    EntityData,
    FindingSignal,
    ProvenanceRuleApplication,
    ScopeContext,
)
from expose.types.collector_payloads import (
    CookieIssue,
    CorsMisconfig,
    DnsPayload,
    HttpPayload,
    MxExchange,
    PortScanPayload,
    TlsPayload,
    as_dns_payload,
    as_http_payload,
    as_port_scan_payload,
    as_tls_payload,
)
from expose.types.observation_props import ObservationProps
from expose.types.shared import EntityId, RunId, TenantId

__all__ = [
    "Action",
    "AndCondition",
    "Attribution",
    "AttributionRule",
    "AttributionTier",
    "CanonicalArtifact",
    "CanonicalRun",
    "CanonicalTenant",
    "CloudResource",
    "CollectorHealth",
    "Delta",
    "DeltaAdded",
    "DeltaChanged",
    "DeltaRemoved",
    "EntityData",
    "EntityId",
    "Exposure",
    "FindingSignal",
    "Identifier",
    "LLMEnrichment",
    "LeadScore",
    "LeadScoreFormula",
    "LeadScoreModifier",
    "LeadScoreWeights",
    "Manifest",
    "ManifestArtifact",
    "ManifestPipeline",
    "ManifestRun",
    "ManifestSignature",
    "NotCondition",
    "OrCondition",
    "Outcome",
    "OutsideAuthorizedScopeSummary",
    "Predicate",
    "PredicateCondition",
    "PrimaryIdentifier",
    "Provenance",
    "ProvenanceRuleApplication",
    "QuotaWarning",
    "RuleCategory",
    "RulePack",
    "RulePackDependency",
    "RunId",
    "ScopeContext",
    "Target",
    "TechStack",
    "TenantId",
    "TierThresholds",
    # -- Collector payload types (additive, #130) --
    "CookieIssue",
    "CorsMisconfig",
    "DnsPayload",
    "HttpPayload",
    "MxExchange",
    "ObservationProps",
    "PortScanPayload",
    "TlsPayload",
    "as_dns_payload",
    "as_http_payload",
    "as_port_scan_payload",
    "as_tls_payload",
]

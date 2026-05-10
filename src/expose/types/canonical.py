"""Pydantic models mirroring `schemas/canonical-artifact-v1.json`.

The canonical artifact is EXPOSE Core's sole deliverable per ADR-004. This
module mirrors the published JSON Schema field-for-field; the schema-sync
tests verify the two stay in lockstep.

Organization within this module follows the schema's `$defs` order so a
reader can pivot between schema and code line-for-line.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

# Reuse the regex-constrained string types from the manifest module.
from expose.types.manifest import GitSha1, Sha256Ref  # noqa: F401  (re-export below)

# Cert fingerprint regex: lowercase hex SHA-256 (no `sha256:` prefix per schema).
CertFingerprintSha256 = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]


# === Enums ===================================================================
class IdentifierType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    CIDR = "cidr"
    CLOUD_RESOURCE_ID = "cloud_resource_id"
    URL = "url"


class ExtendedIdentifierType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    CIDR = "cidr"
    CLOUD_RESOURCE_ID = "cloud_resource_id"
    URL = "url"
    CERTIFICATE_FINGERPRINT = "certificate_fingerprint"
    ASN = "asn"


class AttributionTier(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    REQUIRES_REVIEW = "requires_review"


class AttributionRuleOutcome(str, Enum):
    MATCHED_PROMOTE = "matched_promote"
    MATCHED_DEMOTE = "matched_demote"
    MATCHED_NEUTRAL = "matched_neutral"
    NO_MATCH = "no_match"
    ERROR = "error"


class ReviewReason(str, Enum):
    AMBIGUOUS_ATTRIBUTION = "ambiguous_attribution"
    NOVEL_CORRELATION_PATTERN = "novel_correlation_pattern"
    LLM_LOW_SELF_CONFIDENCE = "llm_low_self_confidence"
    RULE_ENGINE_LLM_DISAGREEMENT = "rule_engine_llm_disagreement"
    OUTSIDE_AUTHORIZED_SCOPE = "outside_authorized_scope"
    UNSANITIZABLE_OBSERVATION_CONTENT = "unsanitizable_observation_content"
    HIGH_VALUE_TARGET_LOW_CONFIDENCE = "high_value_target_low_confidence"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class DNSRecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"
    SOA = "SOA"
    PTR = "PTR"
    CAA = "CAA"


class TechFingerprintMethod(str, Enum):
    WAPPALYZER_RULES = "wappalyzer_rules"
    JA3_MATCH = "ja3_match"
    FAVICON_HASH = "favicon_hash"
    HEADER_PATTERN = "header_pattern"
    LLM_INFERENCE = "llm_inference"
    COMBINED = "combined"


class TechCategory(str, Enum):
    WEB_SERVER = "web_server"
    APPLICATION_SERVER = "application_server"
    FRAMEWORK = "framework"
    CMS = "cms"
    LANGUAGE = "language"
    DATABASE = "database"
    LOAD_BALANCER = "load_balancer"
    CDN = "cdn"
    WAF = "waf"
    AUTH_PROVIDER = "auth_provider"
    ANALYTICS = "analytics"
    OTHER = "other"


class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    OTHER = "other"
    UNKNOWN = "unknown"


class CloudServiceCategory(str, Enum):
    COMPUTE = "compute"
    LOAD_BALANCER = "load_balancer"
    CDN = "cdn"
    OBJECT_STORAGE = "object_storage"
    FUNCTION = "function"
    CONTAINER = "container"
    MANAGED_DATABASE = "managed_database"
    API_GATEWAY = "api_gateway"
    DNS = "dns"
    OTHER = "other"
    UNKNOWN = "unknown"


class LeadScoreCategory(str, Enum):
    INFORMATIONAL = "informational"
    LOW_PRIORITY = "low_priority"
    MEDIUM_PRIORITY = "medium_priority"
    HIGH_PRIORITY = "high_priority"
    CRITICAL_PRIORITY = "critical_priority"


class LLMEnrichmentProvider(str, Enum):
    OLLAMA = "ollama"
    ANTHROPIC_DIRECT = "anthropic_direct"
    OPENAI = "openai"
    GEMINI = "gemini"


class IndicatorSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CollectorStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILURE = "failure"
    SKIPPED = "skipped"
    RATE_LIMITED = "rate_limited"


class QuotaType(str, Enum):
    LLM_TOKEN_BUDGET = "llm_token_budget"
    LLM_DOLLAR_BUDGET = "llm_dollar_budget"
    COLLECTOR_API_RATE_LIMIT = "collector_api_rate_limit"
    COLLECTOR_API_DAILY_QUOTA = "collector_api_daily_quota"
    STORAGE_BYTES = "storage_bytes"
    CANDIDATE_COUNT = "candidate_count"
    CONCURRENT_RUNS = "concurrent_runs"


class QuotaSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    LIMIT_REACHED = "limit_reached"


class ScopeEnforcementMode(str, Enum):
    SOFT = "soft"
    MEDIUM = "medium"
    HARD = "hard"


class DeltaRemovalReason(str, Enum):
    NO_LONGER_OBSERVED = "no_longer_observed"
    ATTRIBUTION_DOWNGRADED_BELOW_THRESHOLD = "attribution_downgraded_below_threshold"
    ANALYST_REJECTED = "analyst_rejected"
    REMOVAL_UNCERTAIN_COLLECTOR_FAILURE = "removal_uncertain_collector_failure"
    SCOPE_CHANGED_NOW_OUTSIDE = "scope_changed_now_outside"
    TENANT_DATA_SUBJECT_REQUEST = "tenant_data_subject_request"


class DeltaChangeType(str, Enum):
    ATTRIBUTION_TIER_PROMOTED = "attribution_tier_promoted"
    ATTRIBUTION_TIER_DEMOTED = "attribution_tier_demoted"
    EXPOSURE_ADDED = "exposure_added"
    EXPOSURE_REMOVED = "exposure_removed"
    TECH_STACK_CHANGED = "tech_stack_changed"
    CLOUD_RESOURCE_ATTRIBUTION_CHANGED = "cloud_resource_attribution_changed"
    LEAD_SCORE_SIGNIFICANT_CHANGE = "lead_score_significant_change"
    REVIEW_STATUS_CHANGED = "review_status_changed"


# === Strict base ============================================================
class StrictModel(BaseModel):
    """Forbid extras and freeze instances — matches schema additionalProperties:false."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )


# === Run + Tenant ===========================================================
class Run(StrictModel):
    run_id: UUID
    started_at: datetime
    completed_at: datetime
    pipeline_version: GitSha1
    rule_pack_version: str | None = None
    scope_version: str | None = None
    previous_run_id: UUID | None = None


class Tenant(StrictModel):
    tenant_id: UUID
    tenant_name: str
    deployment_id: str | None = None


# === Identifiers ============================================================
class PrimaryIdentifier(StrictModel):
    type: IdentifierType
    value: str


class Identifier(StrictModel):
    type: ExtendedIdentifierType
    value: str
    first_observed_at: datetime
    last_observed_at: datetime | None = None


# === Attribution ============================================================
class AttributionRuleApplication(StrictModel):
    rule_id: str
    rule_version: str
    outcome: AttributionRuleOutcome
    confidence_contribution: float
    evidence_refs: list[str] | None = None


class ScopeMatch(BaseModel):
    """Schema marks `scope_match` without explicit additionalProperties; allow extras."""

    model_config = ConfigDict(extra="allow", frozen=True)

    in_scope: bool
    matched_scope_entries: list[str] | None = None
    outside_scope_reason: str | None = None


class Attribution(StrictModel):
    tier: AttributionTier
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    decision_path: list[AttributionRuleApplication]
    scope_match: ScopeMatch | None = None


# === Exposure ===============================================================
class OpenPort(StrictModel):
    port: int = Field(ge=1, le=65535)
    protocol: Protocol
    service_banner: str | None = None
    first_observed_at: datetime
    last_observed_at: datetime


class TLSCertificateSummary(StrictModel):
    fingerprint_sha256: CertFingerprintSha256
    issuer: str
    subject: str
    subject_alt_names: list[str] | None = None
    not_before: datetime
    not_after: datetime
    is_expired: bool | None = None
    is_self_signed: bool | None = None
    ct_log_entries: list[str] | None = None


class HTTPEndpoint(StrictModel):
    url: str
    status_code: int
    server_header: str | None = None
    title: str | None = None
    favicon_hash: str | None = None
    headers_hash: str | None = None
    first_observed_at: datetime
    last_observed_at: datetime


class DNSRecord(StrictModel):
    record_type: DNSRecordType
    value: str
    ttl: int | None = None
    first_observed_at: datetime
    last_observed_at: datetime


class ExposureIndicator(BaseModel):
    """Schema does not specify additionalProperties — allow extras for forward
    compatibility (new categorical indicators can be added without breaking
    consumers)."""

    model_config = ConfigDict(extra="allow", frozen=True)

    indicator: str
    severity: IndicatorSeverity
    evidence_ref: str | None = None


class Exposure(StrictModel):
    open_ports: list[OpenPort] | None = None
    tls_certificates: list[TLSCertificateSummary] | None = None
    http_endpoints: list[HTTPEndpoint] | None = None
    dns_records: list[DNSRecord] | None = None
    exposure_indicators: list[ExposureIndicator] | None = None


# === Tech stack =============================================================
class TechComponent(StrictModel):
    name: str
    version: str | None = None
    category: TechCategory
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_refs: list[str] | None = None


class TechStack(StrictModel):
    components: list[TechComponent] | None = None
    fingerprint_method: TechFingerprintMethod | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


# === Cloud resource =========================================================
class IPRangeMatch(BaseModel):
    """Schema does not specify additionalProperties — allow extras for
    provider-specific match details."""

    model_config = ConfigDict(extra="allow", frozen=True)

    manifest_source: str | None = None
    matched_range: str | None = None
    service_tag: str | None = None


class CloudResource(StrictModel):
    provider: CloudProvider | None = None
    service_category: CloudServiceCategory | None = None
    region: str | None = None
    resource_identifier: str | None = None
    ip_range_match: IPRangeMatch | None = None


# === Lead score =============================================================
class LeadScoreInputs(BaseModel):
    """Schema declares known inputs but does not constrain to them — allow extras
    so future formula versions can extend without breaking old consumers."""

    model_config = ConfigDict(extra="allow", frozen=True)

    attribution_confidence: float | None = None
    exposure_severity_max: str | None = None
    tech_stack_risk_indicators: list[str] | None = None
    freshness_days: int | None = None
    cloud_provider_factor: float | None = None


class LeadScore(StrictModel):
    score: float = Field(ge=0.0, le=100.0)
    formula_version: str
    inputs: LeadScoreInputs
    category: LeadScoreCategory | None = None


# === LLM enrichment =========================================================
class LLMEnrichment(StrictModel):
    provider: LLMEnrichmentProvider
    model: str
    ran_at: datetime
    structured_output: dict[str, Any] | None = None
    self_reported_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    tie_breaker_called: bool = False
    tie_breaker_provider: str | None = None


# === Provenance =============================================================
class ProvenanceSource(BaseModel):
    """Schema does not specify additionalProperties — allow extras."""

    model_config = ConfigDict(extra="allow", frozen=True)

    collector_id: str
    collector_version: str | None = None
    first_observed_at: datetime
    last_observed_at: datetime
    observation_count: int | None = Field(default=None, ge=1)


class Provenance(StrictModel):
    sources: list[ProvenanceSource]
    evidence_refs: list[Sha256Ref]


# === Target =================================================================
class Target(StrictModel):
    target_id: UUID
    primary_identifier: PrimaryIdentifier
    secondary_identifiers: list[Identifier] | None = None
    attribution: Attribution
    exposure: Exposure
    tech_stack: TechStack | None = None
    cloud_resource: CloudResource | None = None
    lead_score: LeadScore | None = None
    llm_enrichment: LLMEnrichment | None = None
    provenance: Provenance
    first_observed_at: datetime
    last_observed_at: datetime
    requires_analyst_review: bool = False
    review_reasons: list[ReviewReason] | None = None


# === Delta ===================================================================
class DeltaAdded(BaseModel):
    """Schema does not declare additionalProperties — allow extras for forward compat."""

    model_config = ConfigDict(extra="allow", frozen=True)

    target_id: UUID
    primary_identifier: PrimaryIdentifier
    discovery_path: list[str]


class DeltaRemoved(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    target_id: UUID
    primary_identifier: PrimaryIdentifier
    reason: DeltaRemovalReason
    removal_details: str | None = None


class DeltaChanged(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    target_id: UUID
    primary_identifier: PrimaryIdentifier
    change_types: list[DeltaChangeType]
    details: dict[str, Any] | None = None


class Delta(StrictModel):
    """`previous_run_id` is required-nullable per schema — must always serialize,
    even when `None` (first run for a tenant). Pydantic's `exclude_none` would
    otherwise drop the field, breaking schema validation."""

    # No default: must be passed explicitly. Combined with `to_dict_for_artifact`
    # below, this guarantees the field shows up in JSON even as `null`.
    previous_run_id: UUID | None
    added: list[DeltaAdded]
    removed: list[DeltaRemoved]
    changed: list[DeltaChanged]


# === Collector health =======================================================
class CollectorHealthError(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    error_type: str | None = None
    message: str | None = None
    occurred_at: datetime | None = None


class CollectorHealthEntry(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    collector_id: str
    collector_version: str | None = None
    status: CollectorStatus
    started_at: datetime
    completed_at: datetime
    observations_collected: int | None = Field(default=None, ge=0)
    errors: list[CollectorHealthError] | None = None


class CollectorHealth(StrictModel):
    collectors: list[CollectorHealthEntry]


# === Quota warnings + scope summary =========================================
class QuotaWarning(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    quota_type: QuotaType
    severity: QuotaSeverity
    details: str | None = None
    occurred_at: datetime | None = None


class OutsideAuthorizedScopeSummary(StrictModel):
    total_outside_scope_observations: int | None = Field(default=None, ge=0)
    outside_scope_targets_in_artifact: int | None = Field(default=None, ge=0)
    scope_enforcement_mode: ScopeEnforcementMode | None = None


# === Top-level canonical artifact ===========================================
class CanonicalArtifact(StrictModel):
    """The signed JSON artifact produced by a single EXPOSE pipeline run.

    Mirrors `schemas/canonical-artifact-v1.json`. Verified by
    `tests/test_schema_sync.py`.
    """

    schema_version: Literal["expose/v1"] = "expose/v1"
    run: Run
    tenant: Tenant
    targets: list[Target]
    delta_from_previous_run: Delta
    collector_health: CollectorHealth
    manifest_ref: str
    tenant_quota_warnings: list[QuotaWarning] | None = None
    outside_authorized_scope_summary: OutsideAuthorizedScopeSummary | None = None

    def to_dict_for_artifact(self) -> dict[str, Any]:
        """Serialize for the canonical.json.gz file.

        Uses `exclude_none=True` to drop optional absent fields (per schema:
        optional fields are NOT type-nullable and must be omitted when not
        present), then re-injects required-nullable fields like
        `delta_from_previous_run.previous_run_id` that the schema requires
        to be present even when `null`.
        """
        payload = self.model_dump(mode="json", exclude_none=True)
        # Required nullable: previous_run_id on Delta. Re-inject if dropped.
        delta = payload.get("delta_from_previous_run", {})
        if "previous_run_id" not in delta:
            delta["previous_run_id"] = None
            payload["delta_from_previous_run"] = delta
        return payload

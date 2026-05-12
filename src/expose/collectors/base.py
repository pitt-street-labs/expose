"""Collector ABC and supporting value types (per SPEC.md §6.1).

A collector is a pluggable module that, given a ``Seed``, yields ``Observation``
records into the pipeline. Collectors:

- Run with a tenant context propagated via ``CollectorConfig.tenant_id``
  (per ADR-007 multi-tenancy).
- Respect a per-source rate limit and a per-call timeout (SPEC §6.1).
- Never raise on individual observation failures; failures are surfaced as
  warnings on the observation itself or recorded in the next ``health_check``
  result. Catastrophic failures (auth invalid, source unreachable) do raise.
- Are tier-tagged (Tier 1 / 2 / 3 per SPEC §6.3); Tier-3 dispatch is gated
  upstream of ``expand`` by the dispatcher.

The collector ABC is intentionally minimal — concrete collectors land
sprint-by-sprint per SPEC §11.1; this module only commits to the contract.

Naming note: this module's ``CollectorHealthCheck`` is the *operational*
result of a single ``health_check()`` call. The canonical artifact's
``CollectorHealth`` (in ``expose.types.canonical``) is the *aggregate* per-run
health summary that ships in the artifact's ``collector_health`` section. The
two are deliberately distinct; do not collapse them.
"""

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from datetime import datetime
from enum import StrEnum
from typing import Any, ClassVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from expose.collectors.tiers import CollectorTier
from expose.types.canonical import (
    CollectorStatus,
    ExtendedIdentifierType,
    IdentifierType,
)


class StrictModel(BaseModel):
    """Base for value types in the collector framework.

    Mirrors the pattern in ``expose.types.canonical``: extras forbidden, frozen
    instances. Collector outputs flow into the canonical artifact path; strict
    typing here keeps the trust boundary tight.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )


# === Seeds ====================================================================
class SeedType(StrEnum):
    """Operator-provided seed types (per SPEC §10.1 ``seeds:`` config key).

    ``ENTITY`` is for downstream pivots — when the dispatcher feeds an existing
    graph entity back to a collector for deeper expansion (e.g., probing a
    confirmed subdomain that emerged from CT logs). The mapping from
    ``ENTITY`` seeds to entity types is the dispatcher's concern.
    """

    DOMAIN = "domain"
    ORGANIZATION = "organization"
    CLOUD_ACCOUNT = "cloud_account"
    ASN = "asn"
    IP = "ip"
    CIDR = "cidr"
    ENTITY = "entity"


class Seed(StrictModel):
    """Input to ``Collector.expand``.

    A seed is a typed, opaque-to-the-collector handle. The collector inspects
    ``seed_type`` and ``value``, executes its source-specific query, and
    yields observations. ``properties`` carries collector- or seed-type-
    specific extras (e.g., ``provider`` + ``account_id`` for a cloud-account
    seed) without inflating the schema.
    """

    seed_type: SeedType
    value: str
    properties: dict[str, Any] = Field(default_factory=dict)


# === Observations =============================================================
class ObservationType(StrEnum):
    """Categories of evidence a collector emits.

    Observation types are a flat enumeration; the dispatcher converts each one
    into the appropriate canonical entity/edge writes. Keeping the enum
    explicit (not an open string) lets mypy and the dispatcher exhaustively
    pattern-match.
    """

    DNS_RESOLUTION = "dns_resolution"
    DNS_RECORD = "dns_record"
    CT_LOG_ENTRY = "ct_log_entry"
    PASSIVE_DNS = "passive_dns"
    WHOIS_REGISTRATION = "whois_registration"
    RDAP_REGISTRATION = "rdap_registration"
    BGP_ASN_LOOKUP = "bgp_asn_lookup"
    CLOUD_IP_RANGE = "cloud_ip_range"
    SCANNER_HOST = "scanner_host"
    TLS_HANDSHAKE = "tls_handshake"
    HTTP_RESPONSE = "http_response"
    PORT_SCAN_RESULT = "port_scan_result"
    WAF_ORIGIN_DISCOVERY = "waf_origin_discovery"
    DARK_WEB_MENTION = "dark_web_mention"


class ObservationSubject(StrictModel):
    """The entity an observation is *about*.

    Identifier type uses the broader ``ExtendedIdentifierType`` (which adds
    ``certificate_fingerprint`` and ``asn``) rather than the narrower
    ``IdentifierType`` because some observation types (e.g., ``CT_LOG_ENTRY``)
    naturally subject a certificate, not just a domain.
    """

    identifier_type: ExtendedIdentifierType | IdentifierType
    identifier_value: str


class Observation(StrictModel):
    """One unit of evidence emitted by a collector.

    Observations flow Sanitization (SPEC §7) → graph upsert (SPEC §5) →
    attribution (SPEC §8). They are immutable (``frozen=True``); the
    sanitization layer produces a *new* canonicalized observation rather
    than mutating in place.

    ``evidence_blob`` is the raw bytes the collector saw — cert PEM, DNS
    response, HTTP headers — to be stored in object storage by content hash
    per SPEC §5.4. The blob is intentionally optional because some collectors
    (e.g., cloud IP-range manifests) operate over already-public references.

    ``warnings`` carries non-fatal issues (sanitization flagged a SAN, the
    source returned a partial result, a TTL was unparseable) so the
    dispatcher can persist them alongside the canonicalized observation.
    """

    collector_id: str
    collector_version: str
    tenant_id: UUID
    observation_type: ObservationType
    subject: ObservationSubject
    observed_at: datetime
    evidence_blob: bytes | None = None
    evidence_blob_content_type: str | None = None
    structured_payload: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


# === Collector configuration =================================================
class CollectorCredential(StrictModel):
    """One named credential resolved from the secrets backend (SPEC §6.4).

    Credentials are *fetched just-in-time per call* per SPEC §6.4. This value
    type is the resolved form — what the collector actually receives. The
    ``secret_value`` is held by reference (str) only for the duration of a
    single ``expand`` invocation; instances are not persisted.

    NOTE: We avoid ``pydantic.SecretStr`` here intentionally. SecretStr is a
    UI-redaction helper; the collector framework needs the bytes to call its
    upstream API. The dispatcher is responsible for not logging
    ``CollectorCredential`` instances.
    """

    name: str
    secret_value: str


class CollectorConfig(StrictModel):
    """Per-call configuration for a collector instance.

    Each ``Collector`` is constructed with a fresh ``CollectorConfig`` per run
    (or per batch within a run). The config carries *only* the data the
    collector needs to run one piece of work: tenant context, fresh
    credentials, rate-limit budget, timeouts. It does NOT carry tenant
    configuration (rule packs, scope, run schedules) — that lives elsewhere.

    ``credentials`` is a mapping from named slot to a resolved credential. A
    collector that only needs one key looks at ``credentials["api_key"]``;
    one that needs an ID + secret pair looks at ``credentials["client_id"]``
    and ``credentials["client_secret"]``. The slot vocabulary is per-collector
    and documented in the collector's own module.
    """

    tenant_id: UUID
    run_id: UUID
    rate_limit_per_minute: int | None = Field(default=None, gt=0)
    request_timeout_seconds: float = Field(default=30.0, gt=0.0)
    credentials: dict[str, CollectorCredential] = Field(default_factory=dict)
    user_agent: str = "expose-collector/0.1 (+https://github.com/pitt-street-labs/expose)"
    extra: dict[str, Any] = Field(default_factory=dict)


# === Collector health ========================================================
class CollectorHealthCheck(StrictModel):
    """Result of a single ``Collector.health_check()`` invocation.

    Distinct from the canonical artifact's ``CollectorHealth`` (which is the
    aggregate per-run summary). This type is the *call result*: did the
    pre-run reachability probe succeed? If not, the dispatcher records the
    reason and skips the collector for the run.

    ``status`` reuses the canonical ``CollectorStatus`` enum so the dispatcher
    can map call results into the artifact section without translation.
    """

    collector_id: str
    collector_version: str
    status: CollectorStatus
    checked_at: datetime
    latency_ms: float | None = Field(default=None, ge=0.0)
    error_message: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


# === Errors ==================================================================
class CollectorError(Exception):
    """Base class for catastrophic collector errors.

    Per SPEC §6.1, individual observation failures are *warnings*, not
    exceptions. A ``CollectorError`` is reserved for failures that mean the
    collector cannot make progress at all on this seed: invalid credentials,
    source unreachable beyond the configured timeout, schema mismatch the
    collector cannot recover from. The dispatcher catches these and records
    them in ``CollectorHealthCheck`` for the next health check.
    """


class CollectorAuthenticationError(CollectorError):
    """Credential rejected by the upstream source."""


class CollectorRateLimitError(CollectorError):
    """Upstream source signalled an unrecoverable rate-limit error.

    Routine 429 responses with retry-after that the collector handles
    internally are NOT this error. This is for cases where the rate-limit
    budget for the run has been exhausted and the collector cannot proceed.
    """


class CollectorSourceUnreachableError(CollectorError):
    """Source DNS / TLS / HTTP failures past the configured timeout."""


# === Abstract base ===========================================================
class Collector(ABC):
    """Abstract base class for all collector modules (SPEC §6.1).

    Subclass contract:

    1. Set the four class-level metadata attributes (``collector_id``,
       ``collector_version``, ``requires_credentials``, ``tier``).
    2. ``rate_limit_per_minute`` may be ``None`` (collector self-limits) or
       an integer enforced by the framework's rate-limiter.
    3. Implement ``expand`` — async generator yielding ``Observation`` records.
       Must respect ``CollectorConfig.request_timeout_seconds`` and configured
       rate limits. Must not raise on individual observation failures.
    4. Implement ``health_check`` — quick pre-run reachability probe.
       Returns a ``CollectorHealthCheck`` rather than raising on failure.

    The constructor takes a ``CollectorConfig`` so that collector instances
    are immutable per call/batch — no mutable global state, no thread-locals.
    This keeps tenant context tight and matches the dispatcher's
    "fresh instance per work item" semantics.

    Concrete collectors land sprint-by-sprint:
    - Sprint 3 — Tier 1 collectors (ct-crtsh, cloud-aws-ranges,
      cloud-azure-ranges, cloud-gcp-ranges, bgp-he-toolkit, whois-rdap).
    - Sprint 4 — Tier 2 collectors (pdns-securitytrails, iwide-shodan) and
      Tier 3 collectors (active-dns-resolve, active-tls-handshake,
      active-http-fingerprint).
    """

    # Class-level metadata. Concrete collectors override.
    collector_id: str = "abstract"
    collector_version: str = "0.0.0"
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None
    tier: CollectorTier = CollectorTier.TIER_1
    technique_ids: ClassVar[list[str]] = []

    def __init__(self, config: CollectorConfig) -> None:
        """Hold the per-call configuration.

        Concrete subclasses may override but should call ``super().__init__``
        first and otherwise treat ``self.config`` as read-only.
        """

        self.config = config

    @abstractmethod
    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Given a seed, yield observations.

        Implementations:

        - Must respect ``self.config.rate_limit_per_minute`` (or the
          framework-default rate limiter).
        - Must respect ``self.config.request_timeout_seconds`` per upstream
          call.
        - Must NOT raise on individual observation failures; surface them as
          ``Observation.warnings`` entries.
        - May raise ``CollectorError`` subclasses for catastrophic failure.
        - Must not write to the observation graph directly. Yielding into the
          dispatcher is the only persistence path (per SPEC §4.2 control-plane
          / data-plane separation).
        """

        # Concrete subclasses provide the implementation. The ``yield``
        # below makes mypy understand this is an async generator without
        # requiring an ``AsyncIterator`` materialization at typecheck time.
        if False:  # pragma: no cover  - signature scaffolding only
            yield  # type: ignore[unreachable]
        raise NotImplementedError

    @abstractmethod
    async def health_check(self) -> CollectorHealthCheck:
        """Quick pre-run reachability probe.

        Called by the dispatcher before each run; collectors that fail their
        health check are skipped for the run. Implementations should return a
        ``CollectorHealthCheck`` rather than raising — the dispatcher logs
        the result and proceeds.
        """

        raise NotImplementedError


__all__ = [
    "Collector",
    "CollectorAuthenticationError",
    "CollectorConfig",
    "CollectorCredential",
    "CollectorError",
    "CollectorHealthCheck",
    "CollectorRateLimitError",
    "CollectorSourceUnreachableError",
    "Observation",
    "ObservationSubject",
    "ObservationType",
    "Seed",
    "SeedType",
    "StrictModel",
]

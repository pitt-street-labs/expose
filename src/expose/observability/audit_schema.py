"""NIST SP 800-53 AU-2/AU-3 compliant audit event schema for EXPOSE.

Defines the canonical audit event model used by the EXPOSE audit logging
subsystem.  Every security-relevant action in EXPOSE emits an ``AuditEvent``
that satisfies the AU-3 content requirements:

- **When** (``timestamp``) — UTC time of the event.
- **Who** (``actor``) — authenticated principal or system identity.
- **What** (``action``) — human-readable description of the action.
- **On what** (``resource``) — the resource (entity, tenant, credential, etc.)
  acted upon.
- **Outcome** — ``success`` or ``failure`` (plus error detail in ``details``).

AU-11 retention mapping is supported via ``retention_category``.

The ``AuditEventType`` enumeration covers the AU-2 auditable event catalog
required for EASI platform operation: run lifecycle, entity CRUD, scope
enforcement, tenant management, credential operations, data lifecycle,
configuration changes, authentication, authorization, artifact signing,
scheduling, SIEM delivery, and credential resolution.

This module intentionally avoids ``hashlib`` and ``secrets`` (FIPS gate per
ADR-010).  UUIDs come from the stdlib ``uuid`` module which does not route
through Python's ``hashlib``.
"""

from __future__ import annotations

import re
from datetime import UTC as _UTC
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID
from uuid import uuid4 as _new_uuid

from pydantic import BaseModel, ConfigDict


class AuditEventType(StrEnum):
    """AU-2 auditable event catalog for EXPOSE.

    Each member maps to a class of security-relevant operation.  The string
    values are used as the ``event_type`` discriminator in serialized audit
    records.

    Extended for full NIST SP 800-53 AU-2 coverage (issue #107):
    authentication token lifecycle, authorization gate events, data-access
    reads, pipeline dispatch/enrichment, and credential CRUD.
    """

    # --- Run lifecycle ---
    RUN_STARTED = "run_started"
    RUN_COMPLETED = "run_completed"
    RUN_FAILED = "run_failed"

    # --- Entity lifecycle ---
    ENTITY_CREATED = "entity_created"
    ENTITY_UPDATED = "entity_updated"

    # --- Data access (AU-2: read operations) ---
    ENTITY_QUERIED = "entity_queried"
    ARTIFACT_DOWNLOADED = "artifact_downloaded"

    # --- Scope enforcement ---
    SCOPE_DENIAL = "scope_denial"

    # --- Tenant lifecycle ---
    TENANT_CREATED = "tenant_created"
    TENANT_DELETED = "tenant_deleted"

    # --- Credential operations ---
    CREDENTIAL_CREATED = "credential_created"
    CREDENTIAL_ACCESSED = "credential_accessed"
    CREDENTIAL_ROTATED = "credential_rotated"
    CREDENTIAL_DELETED = "credential_deleted"

    # --- Data lifecycle ---
    DATA_EXPORT = "data_export"
    DATA_DELETION = "data_deletion"

    # --- Configuration ---
    CONFIG_CHANGED = "config_changed"

    # --- Authentication ---
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    TOKEN_CREATED = "token_created"
    TOKEN_VALIDATION_FAILED = "token_validation_failed"

    # --- Authorization ---
    AUTHORIZATION_DENIED = "authorization_denied"
    TIER3_GATE_DENIED = "tier3_gate_denied"
    TENANT_ISOLATION_VIOLATION = "tenant_isolation_violation"

    # --- Artifact signing ---
    ARTIFACT_SIGNED = "artifact_signed"
    SIGNATURE_VERIFICATION_FAILED = "signature_verification_failed"

    # --- Scheduling ---
    SCHEDULE_CREATED = "schedule_created"
    SCHEDULE_DELETED = "schedule_deleted"
    SCHEDULE_UPDATED = "schedule_updated"

    # --- Pipeline operations ---
    COLLECTOR_DISPATCHED = "collector_dispatched"
    ENRICHMENT_COMPLETED = "enrichment_completed"

    # --- SIEM delivery ---
    SIEM_DELIVERY_FAILED = "siem_delivery_failed"

    # --- Credential resolution ---
    CREDENTIAL_RESOLUTION_FAILED = "credential_resolution_failed"


class AuditEvent(BaseModel):
    """Single NIST AU-3 compliant audit record.

    Every field maps to an AU-3 content requirement:

    - ``event_id`` — unique identifier for this audit record.
    - ``event_type`` — AU-2 event classification (see ``AuditEventType``).
    - ``timestamp`` — AU-3 *when*: UTC time of the event.
    - ``actor`` — AU-3 *who*: authenticated principal or ``"system"``.
    - ``action`` — AU-3 *what*: human-readable description of the action.
    - ``resource`` — AU-3 *on what*: identifier of the affected resource.
    - ``outcome`` — AU-3 *outcome*: ``"success"`` or ``"failure"``.
    - ``details`` — AU-3 *additional context*: free-form key-value pairs.
    - ``source_ip`` — originating IP address (when available).
    - ``tenant_id`` — tenant scope (multi-tenancy per ADR-007).
    - ``run_id`` — associated pipeline run (when applicable).
    - ``correlation_id`` — cross-system correlation token.
    - ``retention_category`` — AU-11 retention tier (default ``"standard"``).
    """

    model_config = ConfigDict(frozen=True)

    event_id: UUID
    event_type: AuditEventType
    timestamp: datetime
    actor: str
    action: str
    resource: str
    outcome: str
    details: dict[str, Any]
    source_ip: str | None = None
    tenant_id: UUID | None = None
    run_id: UUID | None = None
    correlation_id: str | None = None
    retention_category: str = "standard"


# ---------------------------------------------------------------------------
# Sensitive-key sanitization (issue #150)
# ---------------------------------------------------------------------------

# Compiled regex matching key names that may contain sensitive data.
# Case-insensitive matching against patterns: password, secret, token,
# api_key, credential.
_SENSITIVE_KEY_RE = re.compile(
    r"(password|secret|token|api_key|credential)",
    re.IGNORECASE,
)

_REDACTED = "[REDACTED]"


def sanitize_details(details: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *details* with sensitive values replaced.

    Keys whose names contain ``password``, ``secret``, ``token``,
    ``api_key``, or ``credential`` (case-insensitive, substring match)
    have their values replaced with ``"[REDACTED]"``.  Nested dicts are
    sanitized recursively.

    This function is called by :func:`~expose.observability.logging.emit_audit_event`
    before serialization to prevent accidental credential leakage into the
    audit log.

    Args:
        details: The free-form key-value dict from an ``AuditEvent``.

    Returns:
        A new dict with sensitive values redacted.  The original dict is
        never mutated.
    """
    sanitized: dict[str, Any] = {}
    for key, value in details.items():
        if _SENSITIVE_KEY_RE.search(key):
            sanitized[key] = _REDACTED
        elif isinstance(value, dict):
            sanitized[key] = sanitize_details(value)
        else:
            sanitized[key] = value
    return sanitized


# ---------------------------------------------------------------------------
# Retention configuration (AU-11)
# ---------------------------------------------------------------------------

#: Default retention categories and their periods in days.
#: Federal customers typically require 90-day minimum; ``extended`` covers
#: legal-hold scenarios.  Operators can override via ``AuditRetentionConfig``.
DEFAULT_RETENTION_DAYS: dict[str, int] = {
    "standard": 90,
    "extended": 365,
    "legal-hold": -1,  # -1 means indefinite / never auto-purge
}


class AuditRetentionConfig(BaseModel):
    """Configurable retention periods per AU-11 category.

    Operators can override the defaults to match their compliance posture.
    Negative values (``-1``) mean indefinite retention (legal holds).

    Example::

        config = AuditRetentionConfig(standard_days=180, extended_days=730)
    """

    model_config = ConfigDict(frozen=True)

    standard_days: int = 90
    extended_days: int = 365
    legal_hold_days: int = -1  # indefinite

    def days_for(self, category: str) -> int:
        """Return the retention period in days for the given category.

        Falls back to ``standard_days`` if the category is unrecognized.
        """
        mapping = {
            "standard": self.standard_days,
            "extended": self.extended_days,
            "legal-hold": self.legal_hold_days,
        }
        return mapping.get(category, self.standard_days)


# ---------------------------------------------------------------------------
# AuditLogger — high-level event emitter (issue #107)
# ---------------------------------------------------------------------------


class AuditLogger:
    """High-level audit event emitter for NIST AU-2/AU-3 compliance.

    Provides typed convenience methods for each category of auditable event.
    All methods build an ``AuditEvent``, then delegate to
    :func:`~expose.observability.logging.emit_audit_event` for append-only
    NDJSON output.

    Usage::

        audit = AuditLogger(retention=AuditRetentionConfig(standard_days=180))
        audit.log_auth_success(actor="admin@example.com", source_ip="10.0.0.1")

    Every method returns the emitted ``AuditEvent`` so callers can inspect
    or forward the record (e.g., to a SIEM adapter).

    Thread safety: ``AuditLogger`` is stateless beyond its frozen config;
    ``emit_audit_event`` serializes through the stdlib ``logging`` module
    which is thread-safe.
    """

    def __init__(
        self,
        *,
        retention: AuditRetentionConfig | None = None,
    ) -> None:
        self._retention = retention or AuditRetentionConfig()

    # -- internal builder --------------------------------------------------

    def _emit(
        self,
        *,
        event_type: AuditEventType,
        actor: str,
        action: str,
        resource: str,
        outcome: str,
        details: dict[str, Any] | None = None,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        run_id: UUID | None = None,
        correlation_id: str | None = None,
        retention_category: str = "standard",
    ) -> AuditEvent:
        """Build, emit, and return an ``AuditEvent``."""
        from expose.observability.logging import emit_audit_event  # noqa: PLC0415

        event = AuditEvent(
            event_id=_new_uuid(),
            event_type=event_type,
            timestamp=datetime.now(tz=_UTC),
            actor=actor,
            action=action,
            resource=resource,
            outcome=outcome,
            details=details or {},
            source_ip=source_ip,
            tenant_id=tenant_id,
            run_id=run_id,
            correlation_id=correlation_id,
            retention_category=retention_category,
        )
        emit_audit_event(event)
        return event

    # -- property ----------------------------------------------------------

    @property
    def retention(self) -> AuditRetentionConfig:
        """Return the retention configuration."""
        return self._retention

    # =====================================================================
    # Authentication events
    # =====================================================================

    def log_auth_success(
        self,
        *,
        actor: str,
        resource: str = "auth/session",
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log a successful authentication (login)."""
        return self._emit(
            event_type=AuditEventType.AUTH_SUCCESS,
            actor=actor,
            action="Authentication succeeded",
            resource=resource,
            outcome="success",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_auth_failure(
        self,
        *,
        actor: str,
        resource: str = "auth/session",
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log a failed authentication attempt."""
        return self._emit(
            event_type=AuditEventType.AUTH_FAILURE,
            actor=actor,
            action="Authentication failed",
            resource=resource,
            outcome="failure",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_token_created(
        self,
        *,
        actor: str,
        resource: str = "auth/token",
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log API token creation."""
        return self._emit(
            event_type=AuditEventType.TOKEN_CREATED,
            actor=actor,
            action="API token created",
            resource=resource,
            outcome="success",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_token_validation_failed(
        self,
        *,
        actor: str,
        resource: str = "auth/token",
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log a token validation failure."""
        return self._emit(
            event_type=AuditEventType.TOKEN_VALIDATION_FAILED,
            actor=actor,
            action="Token validation failed",
            resource=resource,
            outcome="failure",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    # =====================================================================
    # Authorization events
    # =====================================================================

    def log_scope_denial(
        self,
        *,
        actor: str,
        resource: str,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log a scope-based access refusal."""
        return self._emit(
            event_type=AuditEventType.SCOPE_DENIAL,
            actor=actor,
            action="Scope-based access denied",
            resource=resource,
            outcome="failure",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_authorization_denied(
        self,
        *,
        actor: str,
        resource: str,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log a general authorization denial."""
        return self._emit(
            event_type=AuditEventType.AUTHORIZATION_DENIED,
            actor=actor,
            action="Authorization denied",
            resource=resource,
            outcome="failure",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_tier3_gate_denied(
        self,
        *,
        actor: str,
        resource: str,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log a Tier-3 commercial gate denial."""
        return self._emit(
            event_type=AuditEventType.TIER3_GATE_DENIED,
            actor=actor,
            action="Tier-3 gate denied",
            resource=resource,
            outcome="failure",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_tenant_isolation_violation(
        self,
        *,
        actor: str,
        resource: str,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log a tenant isolation violation attempt."""
        return self._emit(
            event_type=AuditEventType.TENANT_ISOLATION_VIOLATION,
            actor=actor,
            action="Tenant isolation violation detected",
            resource=resource,
            outcome="failure",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
            retention_category="extended",
        )

    # =====================================================================
    # Data access events
    # =====================================================================

    def log_entity_queried(
        self,
        *,
        actor: str,
        resource: str,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log an entity query / data read."""
        return self._emit(
            event_type=AuditEventType.ENTITY_QUERIED,
            actor=actor,
            action="Entity queried",
            resource=resource,
            outcome="success",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_artifact_downloaded(
        self,
        *,
        actor: str,
        resource: str,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log an artifact download."""
        return self._emit(
            event_type=AuditEventType.ARTIFACT_DOWNLOADED,
            actor=actor,
            action="Artifact downloaded",
            resource=resource,
            outcome="success",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    # =====================================================================
    # Configuration events
    # =====================================================================

    def log_config_changed(
        self,
        *,
        actor: str,
        resource: str,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log a tenant configuration change."""
        return self._emit(
            event_type=AuditEventType.CONFIG_CHANGED,
            actor=actor,
            action="Configuration changed",
            resource=resource,
            outcome="success",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_schedule_created(
        self,
        *,
        actor: str,
        resource: str,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log schedule creation."""
        return self._emit(
            event_type=AuditEventType.SCHEDULE_CREATED,
            actor=actor,
            action="Schedule created",
            resource=resource,
            outcome="success",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_schedule_updated(
        self,
        *,
        actor: str,
        resource: str,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log schedule update."""
        return self._emit(
            event_type=AuditEventType.SCHEDULE_UPDATED,
            actor=actor,
            action="Schedule updated",
            resource=resource,
            outcome="success",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_schedule_deleted(
        self,
        *,
        actor: str,
        resource: str,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log schedule deletion."""
        return self._emit(
            event_type=AuditEventType.SCHEDULE_DELETED,
            actor=actor,
            action="Schedule deleted",
            resource=resource,
            outcome="success",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_credential_created(
        self,
        *,
        actor: str,
        resource: str,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log credential creation."""
        return self._emit(
            event_type=AuditEventType.CREDENTIAL_CREATED,
            actor=actor,
            action="Credential created",
            resource=resource,
            outcome="success",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_credential_rotated(
        self,
        *,
        actor: str,
        resource: str,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log credential rotation."""
        return self._emit(
            event_type=AuditEventType.CREDENTIAL_ROTATED,
            actor=actor,
            action="Credential rotated",
            resource=resource,
            outcome="success",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_credential_deleted(
        self,
        *,
        actor: str,
        resource: str,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log credential deletion."""
        return self._emit(
            event_type=AuditEventType.CREDENTIAL_DELETED,
            actor=actor,
            action="Credential deleted",
            resource=resource,
            outcome="success",
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    # =====================================================================
    # Pipeline events
    # =====================================================================

    def log_run_started(
        self,
        *,
        actor: str,
        resource: str,
        run_id: UUID | None = None,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log pipeline run start."""
        return self._emit(
            event_type=AuditEventType.RUN_STARTED,
            actor=actor,
            action="Pipeline run started",
            resource=resource,
            outcome="success",
            run_id=run_id,
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_run_completed(
        self,
        *,
        actor: str,
        resource: str,
        run_id: UUID | None = None,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log pipeline run completion."""
        return self._emit(
            event_type=AuditEventType.RUN_COMPLETED,
            actor=actor,
            action="Pipeline run completed",
            resource=resource,
            outcome="success",
            run_id=run_id,
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_run_failed(
        self,
        *,
        actor: str,
        resource: str,
        run_id: UUID | None = None,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log pipeline run failure."""
        return self._emit(
            event_type=AuditEventType.RUN_FAILED,
            actor=actor,
            action="Pipeline run failed",
            resource=resource,
            outcome="failure",
            run_id=run_id,
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_collector_dispatched(
        self,
        *,
        actor: str,
        resource: str,
        run_id: UUID | None = None,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log collector dispatch."""
        return self._emit(
            event_type=AuditEventType.COLLECTOR_DISPATCHED,
            actor=actor,
            action="Collector dispatched",
            resource=resource,
            outcome="success",
            run_id=run_id,
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )

    def log_enrichment_completed(
        self,
        *,
        actor: str,
        resource: str,
        run_id: UUID | None = None,
        source_ip: str | None = None,
        tenant_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log enrichment completion."""
        return self._emit(
            event_type=AuditEventType.ENRICHMENT_COMPLETED,
            actor=actor,
            action="Enrichment completed",
            resource=resource,
            outcome="success",
            run_id=run_id,
            source_ip=source_ip,
            tenant_id=tenant_id,
            details=details,
        )


__all__ = [
    "AuditEvent",
    "AuditEventType",
    "AuditLogger",
    "AuditRetentionConfig",
    "DEFAULT_RETENTION_DAYS",
    "sanitize_details",
]

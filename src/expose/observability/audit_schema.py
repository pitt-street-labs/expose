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
configuration changes, authentication, artifact signing, and scheduling.

This module intentionally avoids ``hashlib`` and ``secrets`` (FIPS gate per
ADR-010).  UUIDs come from the stdlib ``uuid`` module which does not route
through Python's ``hashlib``.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AuditEventType(StrEnum):
    """AU-2 auditable event catalog for EXPOSE.

    Each member maps to a class of security-relevant operation.  The string
    values are used as the ``event_type`` discriminator in serialized audit
    records.
    """

    # --- Run lifecycle ---
    RUN_STARTED = "run_started"
    RUN_COMPLETED = "run_completed"
    RUN_FAILED = "run_failed"

    # --- Entity lifecycle ---
    ENTITY_CREATED = "entity_created"
    ENTITY_UPDATED = "entity_updated"

    # --- Scope enforcement ---
    SCOPE_DENIAL = "scope_denial"

    # --- Tenant lifecycle ---
    TENANT_CREATED = "tenant_created"
    TENANT_DELETED = "tenant_deleted"

    # --- Credential operations ---
    CREDENTIAL_ACCESSED = "credential_accessed"
    CREDENTIAL_ROTATED = "credential_rotated"

    # --- Data lifecycle ---
    DATA_EXPORT = "data_export"
    DATA_DELETION = "data_deletion"

    # --- Configuration ---
    CONFIG_CHANGED = "config_changed"

    # --- Authentication ---
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"

    # --- Artifact signing ---
    ARTIFACT_SIGNED = "artifact_signed"

    # --- Scheduling ---
    SCHEDULE_CREATED = "schedule_created"
    SCHEDULE_DELETED = "schedule_deleted"


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


__all__ = [
    "AuditEvent",
    "AuditEventType",
]

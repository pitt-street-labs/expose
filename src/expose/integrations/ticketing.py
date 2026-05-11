"""Base ticketing adapter and shared models for finding escalation.

Provides the abstract ``TicketingAdapter`` that Jira and ServiceNow adapters
implement, plus the ``FindingTicket`` input model (derived from a
``LeadScore``), ``TicketResult`` response model, and ``TicketingConfig``
tenant-level configuration.

All models use Pydantic v2 with ``extra="forbid"`` and ``frozen=True``
(consistent with the rest of the EXPOSE model surface — see ADR-001).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "FindingTicket",
    "TicketResult",
    "TicketingAdapter",
    "TicketingConfig",
]

logger = logging.getLogger(__name__)


# === Models ===================================================================


class FindingTicket(BaseModel):
    """Input payload for creating a ticket from a lead-score finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entity_identifier: str = Field(min_length=1)
    entity_type: str
    score: int = Field(ge=0, le=100)
    priority_tier: str
    justification: str
    contributing_signals: list[str]
    tenant_id: UUID
    run_id: UUID | None = None


class TicketResult(BaseModel):
    """Outcome of a ticket creation attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    success: bool
    ticket_id: str | None = None
    ticket_url: str | None = None
    duplicate_of: str | None = None  # existing ticket if deduplicated
    error: str | None = None


class TicketingConfig(BaseModel):
    """Tenant-level ticketing integration configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    adapter_type: str  # "jira", "servicenow"
    endpoint: str = Field(min_length=1)
    auth_token: str = Field(min_length=1)
    project_key: str = Field(min_length=1)  # Jira project or ServiceNow assignment group
    min_score: int = Field(default=40, ge=0, le=100)
    enabled: bool = True


# === Abstract adapter =========================================================


class TicketingAdapter(ABC):
    """Protocol for ticketing system integrations.

    Each concrete adapter (Jira, ServiceNow) implements ``create_ticket``,
    ``check_duplicate``, and ``health_check``.  The pipeline calls these
    through the adapter interface without knowing the downstream system.
    """

    adapter_id: str
    display_name: str

    @abstractmethod
    async def create_ticket(self, finding: FindingTicket) -> TicketResult:
        """Create a ticket for a finding, or add a comment if a duplicate exists."""

    @abstractmethod
    async def check_duplicate(self, entity_identifier: str) -> str | None:
        """Return existing ticket ID if this entity already has an open ticket."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Return ``True`` if the ticketing endpoint is reachable and authenticated."""

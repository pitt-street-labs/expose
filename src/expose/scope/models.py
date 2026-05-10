"""Rich authorization scope models (per SPEC §10.1).

These Pydantic models represent the full authorization scope for a tenant,
extending beyond the minimal ``TenantAuthorizationScope`` in
``expose.collectors.tiers`` (which only checks explicit entity identifiers).

The scope is a list of :class:`ScopeRule` entries, each typed by
:class:`ScopeRuleType`.  Rules are either *inclusions* (default) or
*exclusions* (``include=False``).  Exclusions override inclusions — see
:mod:`expose.scope.matcher` for evaluation semantics.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ScopeRuleType(StrEnum):
    """Classification of a scope rule entry.

    Each type implies different matching semantics in
    :class:`expose.scope.matcher.ScopeMatcher`:

    - ``APEX_DOMAIN`` — includes all subdomains of the apex (and the apex itself).
    - ``EXACT_DOMAIN`` — exact string match on a single FQDN.
    - ``IP_ADDRESS`` — single IPv4 or IPv6 address.
    - ``CIDR`` — IP range containment check.
    - ``ASN`` — Autonomous System Number string match.
    - ``CLOUD_ACCOUNT`` — AWS account ID, Azure subscription, GCP project.
    - ``REGISTRANT_ORG`` — case-insensitive substring match on WHOIS registrant.
    - ``EXCLUSION_DOMAIN`` — explicitly exclude a subdomain (convenience alias
      for an ``EXACT_DOMAIN`` rule with ``include=False``; kept as a distinct
      type for clarity in scope configuration UIs).
    """

    APEX_DOMAIN = "apex_domain"
    EXACT_DOMAIN = "exact_domain"
    IP_ADDRESS = "ip_address"
    CIDR = "cidr"
    ASN = "asn"
    CLOUD_ACCOUNT = "cloud_account"
    REGISTRANT_ORG = "registrant_org"
    EXCLUSION_DOMAIN = "exclusion_domain"


class ScopeRule(BaseModel):
    """A single rule within a tenant's authorization scope.

    Each rule has a *type* (which determines matching semantics), a *value*
    (the pattern or identifier to match against), and an *include* flag
    (``True`` for inclusion, ``False`` for exclusion).

    Examples::

        ScopeRule(rule_type=ScopeRuleType.APEX_DOMAIN, value="example.com")
        ScopeRule(rule_type=ScopeRuleType.CIDR, value="192.0.2.0/24")
        ScopeRule(rule_type=ScopeRuleType.EXACT_DOMAIN, value="cdn.shared.net", include=False)
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_type: ScopeRuleType
    value: str
    include: bool = True


class AuthorizationScope(BaseModel):
    """The full authorization scope for a tenant (SPEC §10.1).

    Captures the tenant's authorized perimeter as a list of typed rules,
    plus metadata for audit trail and enforcement configuration.

    ``enforcement_mode`` mirrors the ``EnforcementMode`` enum in
    ``expose.collectors.tiers`` but is stored as a plain string here to
    avoid a circular import.  Valid values are ``"medium"`` and ``"hard"``.

    ``last_modified`` and ``modified_by`` provide an audit trail for scope
    changes — critical for compliance (ADR-008) and for generating accurate
    ``SCOPE_CHANGED_NOW_OUTSIDE`` delta events.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    rules: list[ScopeRule]
    enforcement_mode: str = "medium"
    last_modified: datetime
    modified_by: str

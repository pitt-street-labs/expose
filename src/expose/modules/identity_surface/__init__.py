# Copyright 2026 Korlogos / Pitt Street Labs. All rights reserved.
# This file is part of EXPOSE Commercial Modules and is NOT covered by the
# Apache 2.0 license that governs the core engine. Unauthorized copying,
# distribution, or use of this file is strictly prohibited. Contact
# licensing@korlogos.com for commercial licensing terms.

"""EXPOSE Identity Surface module (per ADR-009 product surfaces).

This module provides registrant-identity correlation and organizational
graph construction beyond EXPOSE Core's asset-centric reconnaissance.
Capabilities include:

- WHOIS/RDAP registrant pivot: clusters domains registered by the same
  entity despite name variations (fuzzy matching via ``difflib``).
- Organization graph: directed graph of parent/subsidiary, org-to-domain,
  org-to-IP-range, and org-to-email-infrastructure relationships built
  from registrant pivots, M&A discovery, and DNS relationship data.

Ethics gate: both ``RegistrantPivot`` and ``OrgGraphBuilder`` require
``per_tenant_authorization=True`` before performing any operations.
See ``IDENTITY_SURFACE_ETHICS.md`` for scope limitations, prohibited
uses, data retention, and consent requirements.

License gate: ``check_license()`` returns ``True`` when the module is
activated. Currently a placeholder per ADR-009 pending commercial
licensing infrastructure.
"""


def check_license() -> bool:
    """Return True if the Identity Surface module is licensed for use.

    Placeholder per ADR-009. Returns ``True`` unconditionally until the
    commercial licensing infrastructure is implemented. Production
    deployments will check a license key or entitlement token.
    """
    return True


__all__ = [
    "check_license",
]

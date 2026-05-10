"""GDPR/CCPA compliance module for EXPOSE Core.

Provides tenant-scoped data export (GDPR Article 20 -- data portability)
and data deletion (GDPR Article 17 -- right to erasure) against the
observation graph.

Both operations are tenant-scoped by construction: the underlying
repositories (per ADR-007) never cross tenant boundaries, and the
compliance layer adds audit logging and safety checks (dry-run defaults,
litigation-hold enforcement) on top.

Shipped components:

- ``DataExporter`` -- gathers all entities, relationships, and runs for a
  tenant into a portable ``TenantDataExport`` envelope.
- ``DataDeleter`` -- deletes all tenant data with dry-run safety,
  litigation-hold checks, and audit-grade structured logging.

References:
    - GDPR Article 17: Right to erasure ("right to be forgotten")
    - GDPR Article 20: Right to data portability
    - CCPA Section 1798.105: Right to deletion
    - ADR-007: Multi-tenancy (tenant scoping)
    - ADR-008: Data minimization
    - Issue #26: GDPR/CCPA tenant data export and deletion
"""

from expose.compliance.data_deletion import (
    DataDeleter,
    DeletionRequest,
    DeletionResult,
)
from expose.compliance.data_export import (
    DataExporter,
    ExportMetadata,
    TenantDataExport,
)

__all__ = [
    "DataDeleter",
    "DataExporter",
    "DeletionRequest",
    "DeletionResult",
    "ExportMetadata",
    "TenantDataExport",
]

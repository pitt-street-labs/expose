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
- ``MisuseDetector`` -- advisory heuristic checks for potentially
  unauthorized scanning behavior (per ADR-008 / ETHICS.md).

References:
    - GDPR Article 17: Right to erasure ("right to be forgotten")
    - GDPR Article 20: Right to data portability
    - CCPA Section 1798.105: Right to deletion
    - ADR-007: Multi-tenancy (tenant scoping)
    - ADR-008: Data minimization / ethics
    - Issue #26: GDPR/CCPA tenant data export and deletion
    - Issue #33: Misuse-detection patterns
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
from expose.compliance.misuse_detection import (
    MisuseAlert,
    MisuseDetector,
    MisuseIndicator,
    MisuseThresholds,
)

__all__ = [
    "DataDeleter",
    "DataExporter",
    "DeletionRequest",
    "DeletionResult",
    "ExportMetadata",
    "MisuseAlert",
    "MisuseDetector",
    "MisuseIndicator",
    "MisuseThresholds",
    "TenantDataExport",
]

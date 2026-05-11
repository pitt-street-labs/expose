"""EXPOSE SOC Threat Package module (per ADR-009 product surfaces).

This module produces actionable threat intelligence packages for SOC teams
from EXPOSE pipeline observations. It is EXPOSE's strongest commercial
differentiator, bridging attack-surface discovery and SOC workflow
integration.

Output formats:

- **STIX 2.1 Bundles** -- standard cyber threat intelligence packaging
  (conformant JSON, no ``stix2`` library dependency).
- **MISP Events** -- drop-in integration with MISP threat sharing platforms.
- **IoC Feeds** -- simple JSON indicator feeds for SIEM ingestion.
- **Suspicious Endpoint Detection** -- pattern-based flagging of
  high-risk endpoints (management ports, self-signed certs, debug headers,
  DNSBL-listed IPs, zone-transfer-permitting DNS).

License gate: ``check_license()`` returns ``True`` when the module is
activated. Currently a placeholder per ADR-009 pending commercial
licensing infrastructure.
"""

from expose.modules.soc_package.generator import (
    IoCEntry,
    MISPAttribute,
    MISPEvent,
    MISPTag,
    SocPackageGenerator,
    SuspiciousEndpoint,
)


def check_license() -> bool:
    """Return True if the SOC Threat Package module is licensed for use.

    Placeholder per ADR-009. Returns ``True`` unconditionally until the
    commercial licensing infrastructure is implemented. Production
    deployments will check a license key or entitlement token.
    """
    return True


__all__ = [
    "IoCEntry",
    "MISPAttribute",
    "MISPEvent",
    "MISPTag",
    "SocPackageGenerator",
    "SuspiciousEndpoint",
    "check_license",
]

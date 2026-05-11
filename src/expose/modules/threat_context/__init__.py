"""EXPOSE Threat Context module (per ADR-009 product surfaces).

This module provides threat intelligence enrichment beyond EXPOSE Core's
reconnaissance-focused collection. Capabilities include:

- Dark web aggregator queries (public APIs only -- HIBP, IntelX, DeHashed)
- Indicator classification (IoC, IoI, IoAc, IoP per SPEC)
- MITRE ATT&CK Resource Development (TA0042) mapping

License gate: ``check_license()`` returns ``True`` when the module is
activated. Currently a placeholder per ADR-009 pending commercial
licensing infrastructure.
"""


def check_license() -> bool:
    """Return True if the Threat Context module is licensed for use.

    Placeholder per ADR-009. Returns ``True`` unconditionally until the
    commercial licensing infrastructure is implemented. Production
    deployments will check a license key or entitlement token.
    """
    return True


__all__ = [
    "check_license",
]

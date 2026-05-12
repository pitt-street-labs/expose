"""Splunk HTTP Event Collector (HEC) adapter — open-core shim.

This module re-exports ``SplunkHECAdapter`` from the commercial SOC
package when available.  If the SOC package is not installed or
licensed, a stub class is provided that raises ``NotImplementedError``
on instantiation.

The full implementation lives in
``expose.modules.soc_package.integrations.splunk``.
"""

from __future__ import annotations

try:
    from expose.modules.soc_package.integrations.splunk import SplunkHECAdapter
except ImportError:
    from typing import Any
    from uuid import UUID

    from expose.integrations.siem import (
        DeliveryResult,
        SIEMAdapter,
        SIEMConfig,
    )

    class SplunkHECAdapter(SIEMAdapter):  # type: ignore[no-redef]
        """Stub — requires EXPOSE Pro or Enterprise license."""

        adapter_id = "splunk"
        display_name = "Splunk HTTP Event Collector"

        def __init__(
            self,
            config: SIEMConfig,
            *,
            index: str = "main",
            tenant_id: UUID | None = None,
        ) -> None:
            raise NotImplementedError(
                "SIEM integration requires EXPOSE Pro or Enterprise license"
            )

        async def send_observations(
            self,
            observations: list[dict[str, Any]],
            tenant_id: UUID,
        ) -> DeliveryResult:
            raise NotImplementedError(
                "SIEM integration requires EXPOSE Pro or Enterprise license"
            )

        async def send_finding(
            self,
            finding: dict[str, Any],
            tenant_id: UUID,
        ) -> DeliveryResult:
            raise NotImplementedError(
                "SIEM integration requires EXPOSE Pro or Enterprise license"
            )

        async def health_check(self) -> bool:
            raise NotImplementedError(
                "SIEM integration requires EXPOSE Pro or Enterprise license"
            )

__all__ = ["SplunkHECAdapter"]

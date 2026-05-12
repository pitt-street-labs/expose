"""Microsoft Sentinel (Log Analytics Data Collector API) adapter — open-core shim.

This module re-exports ``SentinelAdapter`` from the commercial SOC
package when available.  If the SOC package is not installed or
licensed, a stub class is provided that raises ``NotImplementedError``
on instantiation.

The full implementation lives in
``expose.modules.soc_package.integrations.sentinel``.
"""

from __future__ import annotations

try:
    from expose.modules.soc_package.integrations.sentinel import SentinelAdapter
except ImportError:
    from typing import Any
    from uuid import UUID

    from expose.integrations.siem import (
        DeliveryResult,
        SIEMAdapter,
        SIEMConfig,
    )

    class SentinelAdapter(SIEMAdapter):  # type: ignore[no-redef]
        """Stub — requires EXPOSE Pro or Enterprise license."""

        adapter_id = "sentinel"
        display_name = "Microsoft Sentinel"

        def __init__(
            self,
            config: SIEMConfig,
            *,
            workspace_id: str = "",
            tenant_id: UUID | None = None,
        ) -> None:
            raise NotImplementedError(
                "SIEM integration requires EXPOSE Pro or Enterprise license"
            )

        @staticmethod
        def build_signature(
            workspace_id: str,
            shared_key: str,
            date: str,
            content_length: int,
            method: str = "POST",
            content_type: str = "application/json",
            resource: str = "/api/logs",
        ) -> str:
            """Stub — raises NotImplementedError."""
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

__all__ = ["SentinelAdapter"]

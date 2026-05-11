"""Splunk HTTP Event Collector (HEC) adapter.

Sends EXPOSE observations and findings to Splunk via the HEC ``/services/
collector/event`` endpoint.  Events are mapped to the Splunk Common
Information Model (CIM) and delivered as newline-delimited JSON (the
native HEC batch format).

Auth: ``Authorization: Splunk {token}``

Sourcetypes:
- ``expose:observation`` for observation batches
- ``expose:finding`` for individual findings

See https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any
from uuid import UUID

import httpx

from expose.integrations.siem import DeliveryResult, SIEMAdapter, SIEMConfig

__all__ = ["SplunkHECAdapter"]

logger = logging.getLogger(__name__)


class SplunkHECAdapter(SIEMAdapter):
    """Splunk HTTP Event Collector adapter."""

    adapter_id = "splunk"
    display_name = "Splunk HTTP Event Collector"

    def __init__(self, config: SIEMConfig, *, index: str = "main") -> None:
        super().__init__(config)
        self._index = index

    # ----- public interface ---------------------------------------------------

    async def send_observations(
        self,
        observations: list[dict[str, Any]],
        tenant_id: UUID,
    ) -> DeliveryResult:
        """Batch-deliver observations as CIM-mapped HEC events."""
        if not self._config.enabled:
            return DeliveryResult(
                adapter_id=self.adapter_id,
                success=True,
                events_sent=0,
                events_failed=0,
                duration_ms=0.0,
            )

        start = time.monotonic()
        total_sent = 0
        total_failed = 0

        # Process in batch_size chunks.
        for i in range(0, len(observations), self._config.batch_size):
            batch = observations[i : i + self._config.batch_size]
            hec_events = [self._map_observation_to_hec(obs, tenant_id) for obs in batch]
            payload = "\n".join(
                json.dumps(evt, separators=(",", ":"), sort_keys=True) for evt in hec_events
            )

            try:
                response = await self._post_with_retry(
                    self._hec_url,
                    headers=self._auth_headers,
                    content=payload.encode(),
                )
                if 200 <= response.status_code < 300:  # noqa: PLR2004
                    total_sent += len(batch)
                else:
                    total_failed += len(batch)
            except (httpx.HTTPError, httpx.HTTPStatusError):
                total_failed += len(batch)

        return self._timed_result(
            success=total_failed == 0,
            events_sent=total_sent,
            events_failed=total_failed,
            start=start,
            error=f"{total_failed} events failed" if total_failed else None,
        )

    async def send_finding(
        self,
        finding: dict[str, Any],
        tenant_id: UUID,
    ) -> DeliveryResult:
        """Deliver a single finding as an HEC event."""
        if not self._config.enabled:
            return DeliveryResult(
                adapter_id=self.adapter_id,
                success=True,
                events_sent=0,
                events_failed=0,
                duration_ms=0.0,
            )

        start = time.monotonic()
        hec_event = self._map_finding_to_hec(finding, tenant_id)
        payload = json.dumps(hec_event, separators=(",", ":"), sort_keys=True)

        try:
            response = await self._post_with_retry(
                self._hec_url,
                headers=self._auth_headers,
                content=payload.encode(),
            )
            success = 200 <= response.status_code < 300  # noqa: PLR2004
            return self._timed_result(
                success=success,
                events_sent=1 if success else 0,
                events_failed=0 if success else 1,
                start=start,
                error=None if success else f"HTTP {response.status_code}",
            )
        except (httpx.HTTPError, httpx.HTTPStatusError) as exc:
            return self._timed_result(
                success=False,
                events_sent=0,
                events_failed=1,
                start=start,
                error=str(exc),
            )

    async def health_check(self) -> bool:
        """Check HEC reachability with a GET to the health endpoint."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self._config.endpoint.rstrip('/')}/services/collector/health/1.0",
                    headers=self._auth_headers,
                    timeout=5.0,
                )
            return 200 <= response.status_code < 300  # noqa: PLR2004
        except httpx.HTTPError:
            return False

    # ----- internal helpers ---------------------------------------------------

    @property
    def _hec_url(self) -> str:
        return f"{self._config.endpoint.rstrip('/')}/services/collector/event"

    @property
    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Splunk {self._config.auth_token}",
            "Content-Type": "application/json",
        }

    def _map_observation_to_hec(
        self,
        obs: dict[str, Any],
        tenant_id: UUID,
    ) -> dict[str, Any]:
        """Map an EXPOSE observation dict to a Splunk HEC envelope with CIM fields."""
        entity_id = obs.get("entity_identifier", "unknown")
        return {
            "index": self._index,
            "sourcetype": "expose:observation",
            "host": entity_id,
            "source": f"expose:tenant:{tenant_id}",
            "event": {
                "tenant_id": str(tenant_id),
                "entity_identifier": entity_id,
                "observation_type": obs.get("observation_type", "unknown"),
                "collector_id": obs.get("collector_id"),
                "observed_at": obs.get("observed_at"),
                "severity": obs.get("severity", "info"),
                "raw_data": obs.get("data"),
                # CIM Data Model fields (Network Traffic / Endpoint)
                "src": obs.get("source_ip"),
                "dest": obs.get("dest_ip"),
                "dest_port": obs.get("dest_port"),
                "transport": obs.get("protocol"),
                "app": obs.get("service_name"),
            },
        }

    def _map_finding_to_hec(
        self,
        finding: dict[str, Any],
        tenant_id: UUID,
    ) -> dict[str, Any]:
        """Map an EXPOSE finding dict to a Splunk HEC envelope."""
        return {
            "index": self._index,
            "sourcetype": "expose:finding",
            "host": finding.get("entity_identifier", "unknown"),
            "source": f"expose:tenant:{tenant_id}",
            "event": {
                "tenant_id": str(tenant_id),
                "finding_id": finding.get("finding_id"),
                "title": finding.get("title"),
                "severity": finding.get("severity", "info"),
                "description": finding.get("description"),
                "entity_identifier": finding.get("entity_identifier"),
                "indicators": finding.get("indicators"),
            },
        }
